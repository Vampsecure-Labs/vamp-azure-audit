# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidas para la suite de test de vamp-azure-audit.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Fixtures de datos de API Azure simulados
# ---------------------------------------------------------------------------

@pytest.fixture
def role_assignment_owner_sub() -> dict:
    """Asignación de rol Owner a un usuario a nivel de suscripción."""
    return {
        "name": "assign-001",
        "properties": {
            "scope": "/subscriptions/sub-test-1234",
            "principalType": "User",
            "principalId": "user-guid-001",
            "roleDefinitionId": (
                "/subscriptions/sub-test-1234/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"  # Owner GUID
            ),
        },
    }


@pytest.fixture
def storage_account_public_blob() -> dict:
    """Storage account con acceso público a blobs habilitado."""
    return {
        "name": "stgpublictest",
        "id": "/subscriptions/sub-test-1234/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/stgpublictest",
        "properties": {
            "allowBlobPublicAccess": True,
            "supportsHttpsTrafficOnly": True,
            "minimumTlsVersion": "TLS1_2",
            "networkAcls": {"defaultAction": "Allow"},
        },
    }


@pytest.fixture
def nsg_rule_ssh_world() -> dict:
    """Regla NSG que permite SSH desde 0.0.0.0/0."""
    return {
        "name": "allow-ssh-world",
        "properties": {
            "priority": 100,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Tcp",
            "sourceAddressPrefix": "*",
            "sourcePortRange": "*",
            "destinationAddressPrefix": "*",
            "destinationPortRange": "22",
        },
    }


@pytest.fixture
def aks_rbac_disabled() -> dict:
    """Clúster AKS con RBAC deshabilitado."""
    return {
        "name": "aks-inseguro",
        "id": "/subscriptions/sub-test-1234/resourceGroups/rg1/providers/Microsoft.ContainerService/managedClusters/aks-inseguro",
        "properties": {
            "enableRBAC": False,
            "apiServerAccessProfile": {"enablePrivateCluster": False},
        },
    }


@pytest.fixture
def keyvault_no_softdelete() -> dict:
    """Key Vault sin soft-delete habilitado."""
    return {
        "name": "kv-nosoftdelete",
        "id": "/subscriptions/sub-test-1234/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv-nosoftdelete",
        "properties": {
            "enableSoftDelete": False,
            "enablePurgeProtection": False,
        },
    }


@pytest.fixture
def app_service_tls_10() -> dict:
    """App Service con versión mínima TLS 1.0."""
    return {
        "name": "webapp-insegura",
        "id": "/subscriptions/sub-test-1234/resourceGroups/rg1/providers/Microsoft.Web/sites/webapp-insegura",
        "properties": {
            "siteConfig": {
                "minTlsVersion": "1.0",
                "ftpsState": "AllAllowed",
                "http20Enabled": False,
            },
            "httpsOnly": False,
        },
    }
