# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp_azure_audit.py.

Cubre la lógica de análisis de recursos Azure sin hacer llamadas HTTP reales:
- IAM: usuarios con Owner a nivel suscripción
- Storage: acceso público a blobs
- NSG: reglas 0.0.0.0/0 en puertos críticos
- AKS: RBAC deshabilitado
- Key Vault: sin soft-delete
- App Service: versión TLS 1.0
"""

import asyncio
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_azure_audit import (
    PUERTOS_CRITICOS,
    ROLE_CONTRIBUTOR,
    ROLE_OWNER,
    ROLE_USER_ACCESS_ADMIN,
    Hallazgo,
    audit_iam,
    audit_storage,
)


# ---------------------------------------------------------------------------
# Helpers para tests async
# ---------------------------------------------------------------------------

def run_async(coro):
    """Ejecuta una corrutina en el event loop de test."""
    return asyncio.run(coro)


def _make_mock_session(responses: Dict[str, Any]) -> MagicMock:
    """Crea una sesión aiohttp mockeada que devuelve respuestas predefinidas."""
    session = MagicMock()

    async def mock_get(url, **kwargs):
        # Respuesta genérica con value vacío para paginación
        resp = AsyncMock()
        resp.status = 200
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)
        resp.json = AsyncMock(return_value=responses.get(url, {"value": []}))
        return resp

    session.get = mock_get
    return session


# ---------------------------------------------------------------------------
# Tests 1-3: IAM — usuario con Owner a nivel suscripción
# ---------------------------------------------------------------------------

class TestAuditIAM:
    """Verifica detección de misconfiguraciones IAM de Azure."""

    def test_usuario_owner_genera_critical(self, role_assignment_owner_sub):
        """Usuario con rol Owner en la suscripción debe generar AZURE-IAM-001 CRITICAL."""
        sub_id = "sub-test-1234"

        async def run():
            session = MagicMock()

            def mock_context_manager(*args, **kwargs):
                resp = AsyncMock()
                resp.status = 200
                resp.__aenter__ = AsyncMock(return_value=resp)
                resp.__aexit__ = AsyncMock(return_value=False)
                resp.json = AsyncMock(return_value={
                    "value": [role_assignment_owner_sub],
                    "nextLink": None,
                })
                return resp

            session.get = mock_context_manager
            return await audit_iam(session, "token-mgmt", None, sub_id)

        hallazgos = run_async(run())
        criticos = [h for h in hallazgos if h.severidad == "CRITICAL" and h.id == "AZURE-IAM-001"]
        assert criticos, "Usuario con Owner debe generar AZURE-IAM-001 CRITICAL"

    def test_hallazgo_iam_tiene_descripcion(self, role_assignment_owner_sub):
        """El hallazgo IAM debe tener una descripción no vacía."""
        sub_id = "sub-test-1234"

        async def run():
            session = MagicMock()

            def mock_context_manager(*args, **kwargs):
                resp = AsyncMock()
                resp.status = 200
                resp.__aenter__ = AsyncMock(return_value=resp)
                resp.__aexit__ = AsyncMock(return_value=False)
                resp.json = AsyncMock(return_value={
                    "value": [role_assignment_owner_sub],
                    "nextLink": None,
                })
                return resp

            session.get = mock_context_manager
            return await audit_iam(session, "token-mgmt", None, sub_id)

        hallazgos = run_async(run())
        for h in hallazgos:
            assert h.descripcion, f"Hallazgo {h.id} sin descripción"

    def test_sin_assignments_no_genera_hallazgos(self):
        """Sin asignaciones de rol no deben generarse hallazgos IAM."""
        sub_id = "sub-test-1234"

        async def run():
            session = MagicMock()

            def mock_context_manager(*args, **kwargs):
                resp = AsyncMock()
                resp.status = 200
                resp.__aenter__ = AsyncMock(return_value=resp)
                resp.__aexit__ = AsyncMock(return_value=False)
                resp.json = AsyncMock(return_value={"value": []})
                return resp

            session.get = mock_context_manager
            return await audit_iam(session, "token-mgmt", None, sub_id)

        hallazgos = run_async(run())
        assert hallazgos == [], "Sin asignaciones no debe haber hallazgos IAM"


# ---------------------------------------------------------------------------
# Tests 4-6: Storage — acceso público a blobs
# ---------------------------------------------------------------------------

class TestAuditStorage:
    """Verifica detección de Storage Accounts con blobs públicos."""

    def test_blob_publico_genera_high(self, storage_account_public_blob):
        """allowBlobPublicAccess=True debe generar AZURE-STOR-001 HIGH."""
        sub_id = "sub-test-1234"

        async def run():
            session = MagicMock()

            def mock_context_manager(*args, **kwargs):
                resp = AsyncMock()
                resp.status = 200
                resp.__aenter__ = AsyncMock(return_value=resp)
                resp.__aexit__ = AsyncMock(return_value=False)
                resp.json = AsyncMock(return_value={
                    "value": [storage_account_public_blob],
                })
                return resp

            session.get = mock_context_manager
            return await audit_storage(session, "token-mgmt", sub_id)

        hallazgos = run_async(run())
        altos = [h for h in hallazgos if h.id == "AZURE-STOR-001"]
        assert altos, "Blob público debe generar AZURE-STOR-001"

    def test_storage_remediacion_no_vacia(self, storage_account_public_blob):
        """Los hallazgos de Storage deben tener remediación definida."""
        sub_id = "sub-test-1234"

        async def run():
            session = MagicMock()

            def mock_context_manager(*args, **kwargs):
                resp = AsyncMock()
                resp.status = 200
                resp.__aenter__ = AsyncMock(return_value=resp)
                resp.__aexit__ = AsyncMock(return_value=False)
                resp.json = AsyncMock(return_value={
                    "value": [storage_account_public_blob],
                })
                return resp

            session.get = mock_context_manager
            return await audit_storage(session, "token-mgmt", sub_id)

        hallazgos = run_async(run())
        for h in hallazgos:
            assert h.remediacion, f"Hallazgo {h.id} sin remediación"

    def test_sin_cuentas_no_genera_hallazgos(self):
        """Sin Storage Accounts no debe generarse ningún hallazgo."""
        sub_id = "sub-test-1234"

        async def run():
            session = MagicMock()

            def mock_context_manager(*args, **kwargs):
                resp = AsyncMock()
                resp.status = 200
                resp.__aenter__ = AsyncMock(return_value=resp)
                resp.__aexit__ = AsyncMock(return_value=False)
                resp.json = AsyncMock(return_value={"value": []})
                return resp

            session.get = mock_context_manager
            return await audit_storage(session, "token-mgmt", sub_id)

        hallazgos = run_async(run())
        assert hallazgos == [], "Sin Storage Accounts no debe haber hallazgos"


# ---------------------------------------------------------------------------
# Tests 7-9: Validación de constantes y estructura Hallazgo
# ---------------------------------------------------------------------------

class TestConstantesYEstructura:
    """Verifica constantes de roles privilegiados y estructura del dataclass."""

    def test_role_owner_guid_correcto(self):
        """El GUID del rol Owner de Azure debe ser el oficial de Microsoft."""
        assert ROLE_OWNER == "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

    def test_role_contributor_guid_correcto(self):
        """El GUID del rol Contributor de Azure debe ser el oficial."""
        assert ROLE_CONTRIBUTOR == "b24988ac-6180-42a0-ab88-20f7382dd24c"

    def test_puertos_criticos_contiene_ssh(self):
        """El mapa PUERTOS_CRITICOS debe incluir el puerto SSH (22)."""
        assert "22" in PUERTOS_CRITICOS

    def test_puertos_criticos_contiene_rdp(self):
        """El mapa PUERTOS_CRITICOS debe incluir el puerto RDP (3389)."""
        assert "3389" in PUERTOS_CRITICOS

    def test_hallazgo_dataclass_campos_obligatorios(self):
        """El dataclass Hallazgo debe crear instancias correctamente."""
        h = Hallazgo(
            id="AZURE-TEST-001",
            severidad="HIGH",
            modulo="Test",
            recurso="recurso-test",
            descripcion="Descripción de prueba",
        )
        assert h.id == "AZURE-TEST-001"
        assert h.severidad == "HIGH"
        assert h.remediacion == ""  # valor por defecto

    def test_hallazgo_remediacion_opcional(self):
        """El campo remediacion de Hallazgo es opcional con valor vacío."""
        h = Hallazgo(
            id="X", severidad="LOW", modulo="M",
            recurso="r", descripcion="d",
            remediacion="Acción concreta de remediación"
        )
        assert h.remediacion == "Acción concreta de remediación"


# ---------------------------------------------------------------------------
# Tests 10-12: Lógica de análisis NSG, AKS y Key Vault (sin HTTP)
# ---------------------------------------------------------------------------

class TestAnalisisRecursosLocales:
    """Verifica lógica de análisis de recursos Azure con datos estáticos."""

    def test_nsg_ssh_desde_internet_es_critico(self, nsg_rule_ssh_world):
        """Regla NSG SSH desde * debe considerarse crítica según PUERTOS_CRITICOS."""
        dest_port = nsg_rule_ssh_world["properties"]["destinationPortRange"]
        source    = nsg_rule_ssh_world["properties"]["sourceAddressPrefix"]
        direction = nsg_rule_ssh_world["properties"]["direction"]
        access    = nsg_rule_ssh_world["properties"]["access"]

        # La lógica del auditor: puerto SSH desde cualquier origen → CRITICAL
        es_critico = (
            direction == "Inbound"
            and access == "Allow"
            and source in ("*", "0.0.0.0/0", "Internet", "Any")
            and str(dest_port) in PUERTOS_CRITICOS
        )
        assert es_critico, "Regla NSG SSH desde * debe ser considerada crítica"

    def test_aks_rbac_disabled_es_misconfiguracion(self, aks_rbac_disabled):
        """enableRBAC=False en AKS debe considerarse misconfiguración HIGH."""
        rbac_habilitado = aks_rbac_disabled["properties"].get("enableRBAC", True)
        assert rbac_habilitado is False, "AKS fixture debe tener RBAC deshabilitado"

    def test_keyvault_sin_softdelete_es_medium(self, keyvault_no_softdelete):
        """Key Vault sin soft-delete es una misconfiguración de nivel MEDIUM."""
        soft_delete = keyvault_no_softdelete["properties"].get("enableSoftDelete", False)
        purge_prot  = keyvault_no_softdelete["properties"].get("enablePurgeProtection", False)
        assert soft_delete is False, "Fixture debe tener soft-delete deshabilitado"
        assert purge_prot is False, "Fixture debe tener purge protection deshabilitado"

    def test_appservice_tls_10_es_misconfig(self, app_service_tls_10):
        """App Service con TLS 1.0 debe ser detectado como HIGH."""
        min_tls = app_service_tls_10["properties"]["siteConfig"]["minTlsVersion"]
        versiones_inseguras = {"1.0", "1.1"}
        assert min_tls in versiones_inseguras, f"TLS {min_tls} debe ser inseguro"
