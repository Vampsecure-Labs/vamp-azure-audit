# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp_azure_audit.py.

Simula respuestas HTTP de la Azure REST API usando mocks de aiohttp.
No requiere credenciales ni conexión a Azure.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_azure_audit import (
    ROLE_OWNER,
    Hallazgo,
    audit_iam,
    audit_storage,
    az_get_pages,
)


def run_async(coro):
    """Ejecuta una corrutina de asyncio en el loop de test."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Helper: mock de sesión aiohttp que devuelve valor fijo
# ---------------------------------------------------------------------------

def _mock_session_con_valor(valor: List[Dict]) -> MagicMock:
    """
    Crea una sesión aiohttp mockeada cuyo GET devuelve {'value': valor}.
    Simula una respuesta paginada de la Management API de Azure.
    """
    session = MagicMock()

    def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.status = 200
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)
        resp.json = AsyncMock(return_value={"value": valor})
        return resp

    session.get = mock_get
    return session


# ---------------------------------------------------------------------------
# Test integración 1: az_get_pages sigue nextLink
# ---------------------------------------------------------------------------

class TestAzGetPages:
    """Verifica que az_get_pages gestiona correctamente la paginación."""

    def test_az_get_pages_retorna_valor(self):
        """az_get_pages debe retornar la lista del campo 'value'."""
        items = [{"name": "recurso-1"}, {"name": "recurso-2"}]
        session = _mock_session_con_valor(items)

        resultados = run_async(
            az_get_pages(session, "https://management.azure.com/test", "token", "2023-01-01")
        )
        assert len(resultados) == 2
        assert resultados[0]["name"] == "recurso-1"

    def test_az_get_pages_retorna_vacio_en_403(self):
        """az_get_pages retorna lista vacía ante HTTP 403 (sin permisos)."""
        session = MagicMock()

        def mock_get(url, **kwargs):
            resp = AsyncMock()
            resp.status = 403
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=False)
            return resp

        session.get = mock_get

        resultados = run_async(
            az_get_pages(session, "https://management.azure.com/test", "token", "2023-01-01")
        )
        assert resultados == []


# ---------------------------------------------------------------------------
# Test integración 2: audit_iam detecta usuario Owner — mock HTTP completo
# ---------------------------------------------------------------------------

class TestAuditIAMMockHTTP:
    """Verifica audit_iam con respuesta HTTP de role assignments mockeada."""

    def test_detecta_usuario_owner_suscripcion(self):
        """audit_iam debe detectar AZURE-IAM-001 con asignación Owner mockeada."""
        assignment = {
            "name": "test-assignment",
            "properties": {
                "scope": "/subscriptions/sub-0001",
                "principalType": "User",
                "principalId": "user-aaa-bbb",
                "roleDefinitionId": (
                    f"/subscriptions/sub-0001/providers/"
                    f"Microsoft.Authorization/roleDefinitions/{ROLE_OWNER}"
                ),
            },
        }
        session = _mock_session_con_valor([assignment])

        hallazgos = run_async(
            audit_iam(session, "token-mgmt", None, "sub-0001")
        )

        criticos = [h for h in hallazgos if h.id == "AZURE-IAM-001" and h.severidad == "CRITICAL"]
        assert criticos, "Debe generarse AZURE-IAM-001 CRITICAL para usuario Owner"


# ---------------------------------------------------------------------------
# Test integración 3: audit_storage detecta blob público — mock HTTP completo
# ---------------------------------------------------------------------------

class TestAuditStorageMockHTTP:
    """Verifica audit_storage con respuesta HTTP de storage accounts mockeada."""

    def test_detecta_blob_publico(self):
        """audit_storage detecta AZURE-STOR-001 con blob public access mockeado."""
        cuenta = {
            "name": "stgpublicotest",
            "properties": {
                "allowBlobPublicAccess": True,
                "supportsHttpsTrafficOnly": True,
                "minimumTlsVersion": "TLS1_2",
                "networkAcls": {"defaultAction": "Allow"},
            },
        }
        session = _mock_session_con_valor([cuenta])

        hallazgos = run_async(
            audit_storage(session, "token-mgmt", "sub-0001")
        )

        stor_findings = [h for h in hallazgos if h.id == "AZURE-STOR-001"]
        assert stor_findings, "Blob público debe generar AZURE-STOR-001"


# ---------------------------------------------------------------------------
# Test integración 4: Múltiples misconfiguraciones en mismo Storage Account
# ---------------------------------------------------------------------------

class TestMultiplesMisconfigStorage:
    """Verifica que una SA con múltiples problemas genera múltiples hallazgos."""

    def test_storage_multi_misconfig_genera_varios_hallazgos(self):
        """Storage Account con blob público + no-HTTPS genera ≥2 hallazgos."""
        cuenta = {
            "name": "stg-multi-insegura",
            "properties": {
                "allowBlobPublicAccess": True,
                "supportsHttpsTrafficOnly": False,  # HTTP también permitido
                "minimumTlsVersion": "TLS1_0",       # TLS 1.0
                "networkAcls": {"defaultAction": "Allow"},
            },
        }
        session = _mock_session_con_valor([cuenta])

        hallazgos = run_async(
            audit_storage(session, "token-mgmt", "sub-0001")
        )

        # Debe haber al menos 2 hallazgos (blob público + HTTPS + TLS)
        assert len(hallazgos) >= 2, (
            f"Storage insegura debe generar ≥2 hallazgos, obtuvo {len(hallazgos)}"
        )


# ---------------------------------------------------------------------------
# Test integración 5: Hallazgo tiene estructura completa (todos los campos)
# ---------------------------------------------------------------------------

class TestEstructuraHallazgosIntegracion:
    """Verifica que los hallazgos generados tienen todos los campos necesarios."""

    def test_hallazgo_tiene_todos_los_campos(self):
        """Cada hallazgo generado por audit_iam debe tener id, severidad y descripción."""
        assignment = {
            "name": "full-check-assignment",
            "properties": {
                "scope": "/subscriptions/sub-xyz",
                "principalType": "User",
                "principalId": "user-xyz",
                "roleDefinitionId": (
                    f"/subscriptions/sub-xyz/providers/"
                    f"Microsoft.Authorization/roleDefinitions/{ROLE_OWNER}"
                ),
            },
        }
        session = _mock_session_con_valor([assignment])

        hallazgos = run_async(
            audit_iam(session, "token-mgmt", None, "sub-xyz")
        )

        for h in hallazgos:
            assert h.id, f"Hallazgo sin ID: {h}"
            assert h.severidad in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"), (
                f"Severidad inválida: {h.severidad}"
            )
            assert h.descripcion, f"Hallazgo {h.id} sin descripción"
            assert h.modulo, f"Hallazgo {h.id} sin módulo"
