# © VampSecure Studios — VampSecure Labs Security Research Division
"""vamp-azure-audit — Auditor de seguridad de Microsoft Azure.

Herramienta de auditoría de entornos Azure mediante la REST API oficial.
Detecta misconfiguraciones en IAM, Storage, AKS, App Services, NSG,
Key Vault y Microsoft Defender for Cloud.

Uso exclusivo en entornos donde se dispone de autorización explícita.
"""

import argparse
import asyncio
import json
import os
import sys
import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple

import aiohttp
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

# ---------------------------------------------------------------------------
# Constantes globales
# ---------------------------------------------------------------------------
VERSION = "1.1"
AZURE_MGMT = "https://management.azure.com"
AZURE_GRAPH = "https://graph.microsoft.com"
AZURE_LOGIN = "https://login.microsoftonline.com"

# Scope para la Management API
SCOPE_MGMT = "https://management.azure.com/.default"
# Scope para Microsoft Graph
SCOPE_GRAPH = "https://graph.microsoft.com/.default"

# Puertos considerados críticos si se exponen a Internet
PUERTOS_CRITICOS: Dict[str, str] = {
    "22": "SSH",
    "23": "Telnet",
    "25": "SMTP",
    "53": "DNS",
    "80": "HTTP",
    "110": "POP3",
    "135": "RPC",
    "139": "NetBIOS",
    "445": "SMB",
    "1433": "SQL Server",
    "1521": "Oracle DB",
    "3306": "MySQL",
    "3389": "RDP",
    "5432": "PostgreSQL",
    "5900": "VNC",
    "6379": "Redis",
    "8080": "HTTP-Alt",
    "9200": "Elasticsearch",
    "11211": "Memcached",
    "27017": "MongoDB",
    "50000": "SAP",
}

# GUIDs de roles built-in de Azure que se consideran privilegiados
ROLE_OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
ROLE_CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
ROLE_USER_ACCESS_ADMIN = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"

# Servicios de Defender for Cloud a verificar
SERVICIOS_DEFENDER: Dict[str, str] = {
    "VirtualMachines": "Máquinas Virtuales",
    "SqlServers": "SQL Servers",
    "AppServices": "App Services",
    "StorageAccounts": "Storage Accounts",
    "Containers": "Containers",
    "KeyVaults": "Key Vaults",
    "Arm": "Azure Resource Manager",
    "Dns": "DNS",
    "OpenSourceRelationalDatabases": "Bases de Datos OSS",
}

console = Console()


# ---------------------------------------------------------------------------
# Dataclass de hallazgo
# ---------------------------------------------------------------------------
@dataclass
class Hallazgo:
    """Representa un hallazgo de seguridad detectado durante la auditoría."""
    id: str
    severidad: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    modulo: str             # Módulo que generó el hallazgo
    recurso: str            # Nombre o ID del recurso afectado
    descripcion: str        # Descripción breve del problema
    remediacion: str = ""   # Pasos de remediación recomendados
    detalle: str = ""       # Detalle técnico adicional


# ---------------------------------------------------------------------------
# Colores por severidad para Rich
# ---------------------------------------------------------------------------
COLORES_SEVERIDAD: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "white",
}

ICONOS_SEVERIDAD: Dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


# ---------------------------------------------------------------------------
# Autenticación OAuth2
# ---------------------------------------------------------------------------
async def obtener_token(
    session: aiohttp.ClientSession,
    tenant: str,
    client_id: str,
    client_secret: str,
    scope: str,
) -> str:
    """Obtiene token OAuth2 para la API de Azure via client_credentials.

    Parámetros:
        session       -- Sesión aiohttp activa.
        tenant        -- ID del tenant de Azure (GUID o dominio).
        client_id     -- Application (client) ID del Service Principal.
        client_secret -- Secreto del Service Principal.
        scope         -- Scope de la API objetivo.

    Retorna el access_token como string.
    """
    url = f"{AZURE_LOGIN}/{tenant}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
    }
    async with session.post(url, data=data) as resp:
        if resp.status != 200:
            cuerpo = await resp.text()
            raise RuntimeError(
                f"Error de autenticación Azure (HTTP {resp.status}): {cuerpo[:300]}"
            )
        payload = await resp.json()
        return payload["access_token"]


# ---------------------------------------------------------------------------
# Helper de paginación para la Management API
# ---------------------------------------------------------------------------
async def az_get_pages(
    session: aiohttp.ClientSession,
    url: str,
    token: str,
    api_version: str,
) -> List[Dict[str, Any]]:
    """Consulta paginada de la API de Azure Management.

    Sigue automáticamente los enlaces 'nextLink' para recopilar todos
    los resultados de una consulta paginada.

    Parámetros:
        session     -- Sesión aiohttp activa.
        url         -- URL base del recurso (sin api-version).
        token       -- Access token de Management API.
        api_version -- Versión de API a usar en la query string.

    Retorna lista de objetos del campo 'value'.
    """
    headers = {"Authorization": f"Bearer {token}"}
    sep = "&" if "?" in url else "?"
    full_url = f"{url}{sep}api-version={api_version}"
    items: List[Dict[str, Any]] = []

    while full_url:
        async with session.get(full_url, headers=headers) as resp:
            if resp.status == 403:
                ruta = full_url.split("?")[0].split("/")[-1]
                console.print(f"  [yellow]⚠ Sin permisos para: {ruta}[/]")
                break
            if resp.status == 404:
                # Recurso no existe o proveedor no registrado en la suscripción
                break
            if resp.status == 429:
                # Throttling: esperar y reintentar
                await asyncio.sleep(5)
                continue
            if resp.status != 200:
                break
            data = await resp.json()
            items.extend(data.get("value", []))
            full_url = data.get("nextLink")

    return items


async def az_get_single(
    session: aiohttp.ClientSession,
    url: str,
    token: str,
    api_version: str,
) -> Optional[Dict[str, Any]]:
    """Obtiene un único recurso de la Management API.

    Retorna el JSON de la respuesta o None si no existe o hay error.
    """
    headers = {"Authorization": f"Bearer {token}"}
    sep = "&" if "?" in url else "?"
    full_url = f"{url}{sep}api-version={api_version}"

    async with session.get(full_url, headers=headers) as resp:
        if resp.status in (403, 404):
            return None
        if resp.status == 200:
            return await resp.json()
        return None


async def graph_get_pages(
    session: aiohttp.ClientSession,
    url: str,
    token: str,
) -> List[Dict[str, Any]]:
    """Consulta paginada de Microsoft Graph API.

    Parámetros:
        session -- Sesión aiohttp activa.
        url     -- URL completa de Graph incluyendo parámetros OData.
        token   -- Access token de Microsoft Graph.

    Retorna lista de objetos del campo 'value'.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    items: List[Dict[str, Any]] = []
    full_url: Optional[str] = url

    while full_url:
        async with session.get(full_url, headers=headers) as resp:
            if resp.status == 403:
                console.print("  [yellow]⚠ Sin permisos para Microsoft Graph[/]")
                break
            if resp.status != 200:
                break
            data = await resp.json()
            items.extend(data.get("value", []))
            full_url = data.get("@odata.nextLink")

    return items


# ---------------------------------------------------------------------------
# Módulo IAM
# ---------------------------------------------------------------------------
async def audit_iam(
    session: aiohttp.ClientSession,
    token_mgmt: str,
    token_graph: Optional[str],
    subscription_id: str,
) -> List[Hallazgo]:
    """Audita asignaciones de roles y usuarios invitados en el plano IAM.

    Comprobaciones:
        AZURE-IAM-001 — Usuario con Owner/Contributor a nivel de suscripción.
        AZURE-IAM-002 — Service Principal con Owner a nivel de suscripción.
        AZURE-IAM-003 — Usuario invitado (Guest) con roles privilegiados.
    """
    hallazgos: List[Hallazgo] = []
    base_url = f"{AZURE_MGMT}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments"

    assignments = await az_get_pages(session, base_url, token_mgmt, "2022-04-01")

    scope_sub = f"/subscriptions/{subscription_id}"

    # Recopilar IDs de usuarios invitados si tenemos token de Graph
    guest_ids: set = set()
    if token_graph:
        graph_url = (
            f"{AZURE_GRAPH}/v1.0/users"
            "?$filter=userType eq 'Guest'"
            "&$select=id,displayName,userPrincipalName"
        )
        guests = await graph_get_pages(session, graph_url, token_graph)
        for g in guests:
            gid = g.get("id")
            if gid:
                guest_ids.add(gid)

    for asig in assignments:
        props = asig.get("properties", {})
        scope = props.get("scope", "")
        principal_type = props.get("principalType", "")
        principal_id = props.get("principalId", "")
        role_def_id = props.get("roleDefinitionId", "")

        # Extraer el GUID del rol (últimos 36 caracteres del path)
        role_guid = role_def_id.split("/")[-1] if role_def_id else ""

        es_scope_sub = scope in ("/", scope_sub) or scope == f"/subscriptions/{subscription_id}/"
        es_rol_owner = role_guid == ROLE_OWNER
        es_rol_priv = role_guid in (ROLE_OWNER, ROLE_CONTRIBUTOR, ROLE_USER_ACCESS_ADMIN)
        nombre_recurso = asig.get("name", principal_id)

        # IAM-001: Usuario con Owner o Contributor a nivel de suscripción
        if es_scope_sub and principal_type == "User" and es_rol_priv:
            nombre_rol = {
                ROLE_OWNER: "Owner",
                ROLE_CONTRIBUTOR: "Contributor",
                ROLE_USER_ACCESS_ADMIN: "User Access Administrator",
            }.get(role_guid, role_guid)
            hallazgos.append(Hallazgo(
                id="AZURE-IAM-001",
                severidad="CRITICAL",
                modulo="IAM",
                recurso=nombre_recurso,
                descripcion=f"Usuario con rol '{nombre_rol}' a nivel de suscripción",
                remediacion=(
                    "Aplicar principio de mínimo privilegio. Asignar roles a nivel de "
                    "grupo de recursos o recurso específico. Usar PIM (Privileged Identity "
                    "Management) para acceso just-in-time."
                ),
                detalle=f"PrincipalId: {principal_id} | Scope: {scope}",
            ))

        # IAM-002: Service Principal con Owner a nivel de suscripción
        if es_scope_sub and principal_type == "ServicePrincipal" and es_rol_owner:
            hallazgos.append(Hallazgo(
                id="AZURE-IAM-002",
                severidad="HIGH",
                modulo="IAM",
                recurso=nombre_recurso,
                descripcion="Service Principal con rol Owner a nivel de suscripción",
                remediacion=(
                    "Reducir el scope del Service Principal al grupo de recursos o "
                    "recursos mínimos necesarios. Rotar el secreto inmediatamente si "
                    "fue comprometido."
                ),
                detalle=f"PrincipalId: {principal_id} | Scope: {scope}",
            ))

        # IAM-003: Usuario invitado con roles privilegiados
        if principal_id in guest_ids and es_rol_priv:
            nombre_rol = {
                ROLE_OWNER: "Owner",
                ROLE_CONTRIBUTOR: "Contributor",
                ROLE_USER_ACCESS_ADMIN: "User Access Administrator",
            }.get(role_guid, role_guid)
            hallazgos.append(Hallazgo(
                id="AZURE-IAM-003",
                severidad="HIGH",
                modulo="IAM",
                recurso=nombre_recurso,
                descripcion=f"Usuario invitado (Guest) con rol privilegiado '{nombre_rol}'",
                remediacion=(
                    "Revisar si el acceso del usuario invitado es necesario. "
                    "Eliminar el rol privilegiado o convertir al usuario en miembro. "
                    "Aplicar Conditional Access para cuentas externas."
                ),
                detalle=f"GuestId: {principal_id} | Scope: {scope}",
            ))

    return hallazgos


# ---------------------------------------------------------------------------
# Módulo Storage Accounts
# ---------------------------------------------------------------------------
async def audit_storage(
    session: aiohttp.ClientSession,
    token_mgmt: str,
    subscription_id: str,
) -> List[Hallazgo]:
    """Audita Storage Accounts en busca de misconfiguraciones de seguridad.

    Comprobaciones:
        AZURE-STOR-001 — Acceso público a blobs habilitado.
        AZURE-STOR-002 — Tráfico HTTP (no-HTTPS) permitido.
        AZURE-STOR-003 — Sin restricciones de red (acceso desde cualquier IP).
        AZURE-STOR-004 — Versión TLS mínima inferior a 1.2.
    """
    hallazgos: List[Hallazgo] = []
    url = (
        f"{AZURE_MGMT}/subscriptions/{subscription_id}"
        "/providers/Microsoft.Storage/storageAccounts"
    )
    cuentas = await az_get_pages(session, url, token_mgmt, "2023-01-01")

    for cuenta in cuentas:
        nombre = cuenta.get("name", cuenta.get("id", "desconocido"))
        props = cuenta.get("properties", {})

        # STOR-001: Acceso público a blobs
        if props.get("allowBlobPublicAccess") is True:
            hallazgos.append(Hallazgo(
                id="AZURE-STOR-001",
                severidad="HIGH",
                modulo="Storage",
                recurso=nombre,
                descripcion="Acceso público a blobs habilitado en Storage Account",
                remediacion=(
                    "Deshabilitar 'allowBlobPublicAccess' en las propiedades de la "
                    "Storage Account. Revisar que ningún contenedor tenga acceso anónimo."
                ),
                detalle=f"Storage Account: {nombre}",
            ))

        # STOR-002: HTTP permitido (HTTPS no forzado)
        if props.get("supportsHttpsTrafficOnly") is False:
            hallazgos.append(Hallazgo(
                id="AZURE-STOR-002",
                severidad="HIGH",
                modulo="Storage",
                recurso=nombre,
                descripcion="Tráfico HTTP no cifrado permitido en Storage Account",
                remediacion=(
                    "Habilitar 'supportsHttpsTrafficOnly = true' para forzar conexiones "
                    "cifradas. Verificar que las aplicaciones cliente usan HTTPS."
                ),
                detalle=f"Storage Account: {nombre}",
            ))

        # STOR-003: Sin restricciones de red
        network_acls = props.get("networkAcls", {})
        default_action = network_acls.get("defaultAction", "Allow")
        ip_rules = network_acls.get("ipRules", [])
        vnet_rules = network_acls.get("virtualNetworkRules", [])

        if default_action == "Allow" and not ip_rules and not vnet_rules:
            hallazgos.append(Hallazgo(
                id="AZURE-STOR-003",
                severidad="MEDIUM",
                modulo="Storage",
                recurso=nombre,
                descripcion="Storage Account accesible desde cualquier red sin restricciones",
                remediacion=(
                    "Configurar 'networkAcls.defaultAction = Deny' y añadir solo las "
                    "IPs o VNets autorizadas. Habilitar Service Endpoints o Private Endpoints."
                ),
                detalle=f"DefaultAction: {default_action} | IPRules: 0 | VNetRules: 0",
            ))

        # STOR-004: TLS mínimo inferior a 1.2
        min_tls = props.get("minimumTlsVersion", "TLS1_0")
        if min_tls not in ("TLS1_2", "TLS1_3"):
            hallazgos.append(Hallazgo(
                id="AZURE-STOR-004",
                severidad="MEDIUM",
                modulo="Storage",
                recurso=nombre,
                descripcion=f"Versión TLS mínima configurada: {min_tls} (se requiere TLS 1.2+)",
                remediacion=(
                    "Establecer 'minimumTlsVersion = TLS1_2' en la Storage Account. "
                    "Verificar que los clientes son compatibles con TLS 1.2."
                ),
                detalle=f"TLS actual: {min_tls}",
            ))

    return hallazgos


# ---------------------------------------------------------------------------
# Módulo AKS (Azure Kubernetes Service)
# ---------------------------------------------------------------------------
async def audit_aks(
    session: aiohttp.ClientSession,
    token_mgmt: str,
    subscription_id: str,
) -> List[Hallazgo]:
    """Audita clústeres AKS en busca de misconfiguraciones de seguridad.

    Comprobaciones:
        AZURE-AKS-001 — RBAC desactivado en clúster.
        AZURE-AKS-002 — API server accesible públicamente.
        AZURE-AKS-003 — Sin NetworkPolicy configurada.
        AZURE-AKS-004 — Versión de Kubernetes desactualizada (< 1.27).
    """
    hallazgos: List[Hallazgo] = []
    url = (
        f"{AZURE_MGMT}/subscriptions/{subscription_id}"
        "/providers/Microsoft.ContainerService/managedClusters"
    )
    clusters = await az_get_pages(session, url, token_mgmt, "2023-07-01")

    VERSION_MIN_K8S = (1, 27)

    for cluster in clusters:
        nombre = cluster.get("name", cluster.get("id", "desconocido"))
        props = cluster.get("properties", {})

        # AKS-001: RBAC desactivado
        if props.get("enableRBAC") is False:
            hallazgos.append(Hallazgo(
                id="AZURE-AKS-001",
                severidad="CRITICAL",
                modulo="AKS",
                recurso=nombre,
                descripcion="RBAC desactivado en clúster AKS — acceso sin control de roles",
                remediacion=(
                    "Habilitar RBAC en el clúster AKS. Migrar las autorizaciones actuales "
                    "a roles y rolebindings de Kubernetes. RBAC no se puede activar en un "
                    "clúster existente sin recrearlo."
                ),
                detalle=f"Cluster: {nombre} | enableRBAC: False",
            ))

        # AKS-002: API server público
        api_profile = props.get("apiServerAccessProfile", {})
        if not api_profile.get("enablePrivateCluster", False):
            hallazgos.append(Hallazgo(
                id="AZURE-AKS-002",
                severidad="HIGH",
                modulo="AKS",
                recurso=nombre,
                descripcion="API server de AKS accesible públicamente desde Internet",
                remediacion=(
                    "Habilitar 'enablePrivateCluster = true' al crear el clúster o migrar "
                    "a un clúster privado. Mientras tanto, restringir mediante "
                    "'authorizedIPRanges' en el perfil de acceso al API server."
                ),
                detalle=f"Cluster: {nombre} | enablePrivateCluster: False",
            ))

        # AKS-003: Sin NetworkPolicy
        network_profile = props.get("networkProfile", {})
        network_plugin = network_profile.get("networkPlugin")
        network_policy = network_profile.get("networkPolicy")

        if network_plugin and not network_policy:
            hallazgos.append(Hallazgo(
                id="AZURE-AKS-003",
                severidad="HIGH",
                modulo="AKS",
                recurso=nombre,
                descripcion="Sin NetworkPolicy configurada — pods pueden comunicarse sin restricciones",
                remediacion=(
                    "Configurar 'networkPolicy' (azure, calico o cilium) en el networkProfile. "
                    "Implementar políticas de red least-privilege entre namespaces y pods."
                ),
                detalle=f"Plugin: {network_plugin} | Policy: None",
            ))

        # AKS-004: Versión de Kubernetes desactualizada (< 1.27 mínimo recomendado general)
        k8s_version = props.get("kubernetesVersion", "")
        if k8s_version:
            try:
                partes = k8s_version.split(".")
                mayor = int(partes[0])
                menor = int(partes[1].split("-")[0]) if len(partes) > 1 else 0
                if (mayor, menor) < VERSION_MIN_K8S:
                    hallazgos.append(Hallazgo(
                        id="AZURE-AKS-004",
                        severidad="MEDIUM",
                        modulo="AKS",
                        recurso=nombre,
                        descripcion=(
                            f"Versión de Kubernetes {k8s_version} desactualizada "
                            f"(mínimo recomendado: {'.'.join(str(v) for v in VERSION_MIN_K8S)})"
                        ),
                        remediacion=(
                            "Actualizar el clúster AKS a una versión soportada. "
                            "Planificar ventana de mantenimiento y probar en entorno de staging."
                        ),
                        detalle=f"Versión actual: {k8s_version}",
                    ))
            except (ValueError, IndexError):
                pass

        # AKS-005: Versión vulnerable al CVE-2026-33105 (escalada de privilegios AKS)
        # Se usa 'currentKubernetesVersion' (la versión en ejecución real) cuando está disponible
        k8s_version_actual = props.get("currentKubernetesVersion") or k8s_version
        if k8s_version_actual and _version_vulnerable_cve_2026_33105(k8s_version_actual):
            hallazgos.append(Hallazgo(
                id="AZURE-AKS-005",
                severidad="CRITICAL",
                modulo="AKS",
                recurso=nombre,
                descripcion=(
                    f"Versión de Kubernetes {k8s_version_actual} vulnerable a "
                    "CVE-2026-33105 (escalada de privilegios en AKS)"
                ),
                remediacion=(
                    "Actualizar el clúster AKS a la versión parcheada: "
                    "≥1.29.15, ≥1.30.11 o ≥1.31.7 según la rama actual. "
                    "Planificar ventana de mantenimiento urgente y probar en staging antes del despliegue."
                ),
                detalle=f"Cluster: {nombre} | Versión: {k8s_version_actual} | CVE: CVE-2026-33105",
            ))

        # AKS-006: API server expuesto públicamente (sin private cluster habilitado)
        # Respuesta directa al advisory CVE-2026-33105 — el API server público amplía la
        # superficie de ataque explotable con la vulnerabilidad de escalada
        if not api_profile.get("enablePrivateCluster", False):
            hallazgos.append(Hallazgo(
                id="AZURE-AKS-006",
                severidad="HIGH",
                modulo="AKS",
                recurso=nombre,
                descripcion="API server de AKS expuesto públicamente (cluster no privado)",
                remediacion=(
                    "Migrar el clúster AKS a modo privado habilitando 'enablePrivateCluster = true', "
                    "o restringir el acceso mediante 'authorizedIPRanges' en el perfil de acceso. "
                    "Un API server público amplía la superficie de ataque explotable."
                ),
                detalle=f"Cluster: {nombre} | enablePrivateCluster: False",
            ))

    return hallazgos


# ---------------------------------------------------------------------------
# Módulo App Services
# ---------------------------------------------------------------------------
async def audit_appservices(
    session: aiohttp.ClientSession,
    token_mgmt: str,
    subscription_id: str,
) -> List[Hallazgo]:
    """Audita Azure App Services en busca de misconfiguraciones.

    Comprobaciones:
        AZURE-APP-001 — HTTPS no forzado en App Service.
        AZURE-APP-002 — Remote debugging habilitado.
        AZURE-APP-003 — TLS mínimo inferior a 1.2 en configuración web.
        AZURE-APP-004 — FTP sin cifrar habilitado (AllAllowed).
    """
    hallazgos: List[Hallazgo] = []
    url = (
        f"{AZURE_MGMT}/subscriptions/{subscription_id}"
        "/providers/Microsoft.Web/sites"
    )
    sites = await az_get_pages(session, url, token_mgmt, "2022-03-01")

    for site in sites:
        nombre = site.get("name", site.get("id", "desconocido"))
        site_id = site.get("id", "")
        props = site.get("properties", {})

        # APP-001: HTTPS no forzado
        if props.get("httpsOnly") is False:
            hallazgos.append(Hallazgo(
                id="AZURE-APP-001",
                severidad="HIGH",
                modulo="AppServices",
                recurso=nombre,
                descripcion="App Service no fuerza conexiones HTTPS",
                remediacion=(
                    "Habilitar 'httpsOnly = true' en las propiedades del App Service. "
                    "Configurar redirección HTTP→HTTPS si se requiere compatibilidad."
                ),
                detalle=f"Site: {nombre} | httpsOnly: False",
            ))

        # Obtener configuración detallada del site (siteConfig)
        if site_id:
            config_url = f"{AZURE_MGMT}{site_id}/config/web"
            config_data = await az_get_single(session, config_url, token_mgmt, "2022-03-01")

            if config_data:
                site_config = config_data.get("properties", {})

                # APP-002: Remote debugging habilitado
                if site_config.get("remoteDebuggingEnabled") is True:
                    hallazgos.append(Hallazgo(
                        id="AZURE-APP-002",
                        severidad="HIGH",
                        modulo="AppServices",
                        recurso=nombre,
                        descripcion="Remote debugging habilitado en App Service (riesgo de ejecución remota)",
                        remediacion=(
                            "Deshabilitar 'remoteDebuggingEnabled' en la configuración del "
                            "App Service. El debugging remoto solo debe activarse "
                            "temporalmente y en entornos controlados."
                        ),
                        detalle=f"Site: {nombre} | remoteDebuggingEnabled: True",
                    ))

                # APP-003: TLS mínimo inferior a 1.2
                min_tls = site_config.get("minTlsVersion", "1.0")
                if min_tls not in ("1.2", "1.3"):
                    hallazgos.append(Hallazgo(
                        id="AZURE-APP-003",
                        severidad="MEDIUM",
                        modulo="AppServices",
                        recurso=nombre,
                        descripcion=f"TLS mínimo {min_tls} en App Service (se requiere 1.2+)",
                        remediacion=(
                            "Configurar 'minTlsVersion = 1.2' en la configuración del App Service. "
                            "Actualizar dependencias y clientes que no soporten TLS 1.2."
                        ),
                        detalle=f"Site: {nombre} | minTlsVersion: {min_tls}",
                    ))

                # APP-004: FTP sin cifrar habilitado
                ftps_state = site_config.get("ftpsState", "AllAllowed")
                if ftps_state == "AllAllowed":
                    hallazgos.append(Hallazgo(
                        id="AZURE-APP-004",
                        severidad="MEDIUM",
                        modulo="AppServices",
                        recurso=nombre,
                        descripcion="FTP sin cifrar habilitado en App Service",
                        remediacion=(
                            "Establecer 'ftpsState = FtpsOnly' o 'Disabled' según necesidades. "
                            "FTP plano transmite credenciales y datos en texto claro."
                        ),
                        detalle=f"Site: {nombre} | ftpsState: {ftps_state}",
                    ))

    return hallazgos


# ---------------------------------------------------------------------------
# Módulo Network Security Groups (NSG)
# ---------------------------------------------------------------------------
async def audit_nsg(
    session: aiohttp.ClientSession,
    token_mgmt: str,
    subscription_id: str,
) -> List[Hallazgo]:
    """Audita Network Security Groups en busca de reglas peligrosas.

    Comprobaciones:
        AZURE-NSG-001 — Puertos críticos expuestos a Internet (0.0.0.0/0).
        AZURE-NSG-002 — Regla que permite todo el tráfico entrante de Internet.
    """
    hallazgos: List[Hallazgo] = []
    url = (
        f"{AZURE_MGMT}/subscriptions/{subscription_id}"
        "/providers/Microsoft.Network/networkSecurityGroups"
    )
    nsgs = await az_get_pages(session, url, token_mgmt, "2023-05-01")

    ORIGENES_PUBLICOS = {"*", "0.0.0.0/0", "Internet", "Any"}

    for nsg in nsgs:
        nombre_nsg = nsg.get("name", nsg.get("id", "desconocido"))
        props = nsg.get("properties", {})
        reglas = props.get("securityRules", []) + props.get("defaultSecurityRules", [])

        for regla in reglas:
            r_props = regla.get("properties", {})
            nombre_regla = regla.get("name", "sin-nombre")

            # Solo reglas de entrada que permiten tráfico
            if r_props.get("direction") != "Inbound":
                continue
            if r_props.get("access") != "Allow":
                continue

            origen = r_props.get("sourceAddressPrefix", "")
            origenes = r_props.get("sourceAddressPrefixes", [])
            todos_origenes = set([origen] + origenes)

            # Verificar si alguna fuente es pública
            es_publico = bool(todos_origenes.intersection(ORIGENES_PUBLICOS))
            if not es_publico:
                continue

            dest_port = r_props.get("destinationPortRange", "")
            dest_ports = r_props.get("destinationPortRanges", [])

            # NSG-002: Regla permite TODO el tráfico
            if dest_port == "*":
                hallazgos.append(Hallazgo(
                    id="AZURE-NSG-002",
                    severidad="CRITICAL",
                    modulo="NSG",
                    recurso=f"{nombre_nsg}/{nombre_regla}",
                    descripcion=f"Regla NSG permite TODO el tráfico entrante de Internet",
                    remediacion=(
                        "Eliminar o restringir la regla que abre todos los puertos. "
                        "Aplicar reglas específicas para los servicios necesarios y "
                        "denegar el resto. Revisar el diseño de segmentación de red."
                    ),
                    detalle=f"NSG: {nombre_nsg} | Regla: {nombre_regla} | Origen: {origen}",
                ))
                continue

            # NSG-001: Puertos críticos expuestos
            todos_puertos = list(dest_ports) + ([dest_port] if dest_port else [])
            for puerto in todos_puertos:
                # Gestionar rangos de puertos (ej: "3000-4000")
                puertos_a_verificar = []
                if "-" in str(puerto):
                    try:
                        inicio, fin = puerto.split("-")
                        for p in PUERTOS_CRITICOS:
                            if int(inicio) <= int(p) <= int(fin):
                                puertos_a_verificar.append(p)
                    except ValueError:
                        pass
                else:
                    puertos_a_verificar = [str(puerto)]

                for p in puertos_a_verificar:
                    if p in PUERTOS_CRITICOS:
                        servicio = PUERTOS_CRITICOS[p]
                        hallazgos.append(Hallazgo(
                            id="AZURE-NSG-001",
                            severidad="CRITICAL",
                            modulo="NSG",
                            recurso=f"{nombre_nsg}/{nombre_regla}",
                            descripcion=(
                                f"Puerto {p}/{servicio} expuesto a Internet (0.0.0.0/0)"
                            ),
                            remediacion=(
                                f"Restringir acceso al puerto {p} ({servicio}) solo a IPs "
                                "autorizadas o rangos corporativos. Considerar usar "
                                "Azure Bastion para RDP/SSH y Private Endpoints para bases de datos."
                            ),
                            detalle=(
                                f"NSG: {nombre_nsg} | Regla: {nombre_regla} | "
                                f"Puerto: {p} | Servicio: {servicio} | Origen: {origen}"
                            ),
                        ))

    return hallazgos


# ---------------------------------------------------------------------------
# Módulo Key Vault
# ---------------------------------------------------------------------------
async def audit_keyvault(
    session: aiohttp.ClientSession,
    token_mgmt: str,
    subscription_id: str,
) -> List[Hallazgo]:
    """Audita Azure Key Vaults en busca de misconfiguraciones.

    Comprobaciones:
        AZURE-KV-001 — Soft Delete no habilitado.
        AZURE-KV-002 — Purge Protection no habilitado.
        AZURE-KV-003 — Key Vault accesible desde cualquier red.
        AZURE-KV-004 — Acceso de red público habilitado sin restricciones.
    """
    hallazgos: List[Hallazgo] = []
    url = (
        f"{AZURE_MGMT}/subscriptions/{subscription_id}"
        "/providers/Microsoft.KeyVault/vaults"
    )
    vaults = await az_get_pages(session, url, token_mgmt, "2023-02-01")

    for vault in vaults:
        nombre = vault.get("name", vault.get("id", "desconocido"))
        props = vault.get("properties", {})

        # KV-001: Soft Delete no habilitado
        if props.get("enableSoftDelete") is False:
            hallazgos.append(Hallazgo(
                id="AZURE-KV-001",
                severidad="HIGH",
                modulo="KeyVault",
                recurso=nombre,
                descripcion="Soft Delete no habilitado en Key Vault — borrado inmediato y permanente",
                remediacion=(
                    "Habilitar 'enableSoftDelete = true'. Con Soft Delete activado, "
                    "los objetos eliminados se conservan 90 días y pueden recuperarse. "
                    "Nota: en nuevos vaults está habilitado por defecto."
                ),
                detalle=f"KeyVault: {nombre} | enableSoftDelete: False",
            ))

        # KV-002: Purge Protection no habilitado
        if not props.get("enablePurgeProtection", False):
            hallazgos.append(Hallazgo(
                id="AZURE-KV-002",
                severidad="MEDIUM",
                modulo="KeyVault",
                recurso=nombre,
                descripcion="Purge Protection no habilitado — posible eliminación permanente forzada",
                remediacion=(
                    "Habilitar 'enablePurgeProtection = true' para evitar que secretos, "
                    "claves y certificados eliminados puedan ser purgados antes del período "
                    "de retención. Requerido para cumplimiento FIPS 140-2."
                ),
                detalle=f"KeyVault: {nombre} | enablePurgeProtection: False/None",
            ))

        # KV-003: Acceso de red sin restricciones
        network_acls = props.get("networkAcls", {})
        default_action = network_acls.get("defaultAction", "Allow")

        if default_action == "Allow":
            hallazgos.append(Hallazgo(
                id="AZURE-KV-003",
                severidad="HIGH",
                modulo="KeyVault",
                recurso=nombre,
                descripcion="Key Vault accesible desde cualquier red — sin restricciones de ACL",
                remediacion=(
                    "Configurar 'networkAcls.defaultAction = Deny' y añadir solo las "
                    "IPs o VNets que necesiten acceso. Habilitar Private Endpoints "
                    "para acceso desde VNets de Azure."
                ),
                detalle=f"KeyVault: {nombre} | defaultAction: Allow",
            ))

        # KV-004: Acceso público de red habilitado
        public_network = props.get("publicNetworkAccess", "Enabled")
        ip_rules = network_acls.get("ipRules", []) if network_acls else []
        vnet_rules = network_acls.get("virtualNetworkRules", []) if network_acls else []

        if public_network == "Enabled" and not ip_rules and not vnet_rules:
            hallazgos.append(Hallazgo(
                id="AZURE-KV-004",
                severidad="HIGH",
                modulo="KeyVault",
                recurso=nombre,
                descripcion="Key Vault con acceso público habilitado sin restricciones de IP o VNet",
                remediacion=(
                    "Deshabilitar 'publicNetworkAccess' o añadir restricciones de red. "
                    "Preferiblemente usar Private Endpoints y deshabilitar el acceso público."
                ),
                detalle=f"KeyVault: {nombre} | publicNetworkAccess: Enabled | Sin reglas de red",
            ))

        # KV-005: RBAC vs Access Policies — respuesta al CVE-2026-62825 Key Vault EoP
        enable_rbac = props.get("enableRbacAuthorization", False)
        access_policies = props.get("accessPolicies", [])

        # KV-005 (MEDIUM): uso de Access Policies legacy en lugar de RBAC
        if not enable_rbac and access_policies:
            hallazgos.append(Hallazgo(
                id="AZURE-KV-005",
                severidad="MEDIUM",
                modulo="KeyVault",
                recurso=nombre,
                descripcion="Key Vault usa Access Policies legacy en lugar de RBAC — más permisivas y sin soporte de condiciones",
                remediacion=(
                    "Migrar de Access Policies a autorización RBAC habilitando "
                    "'enableRbacAuthorization = true'. Las Access Policies no soportan "
                    "condiciones de acceso y son el vector del CVE-2026-62825. "
                    "Usar 'az keyvault update --enable-rbac-authorization true'."
                ),
                detalle=(
                    f"KeyVault: {nombre} | enableRbacAuthorization: False | "
                    f"Access Policies configuradas: {len(access_policies)}"
                ),
            ))

        # KV-005 (HIGH): vault accesible desde todas las redes (agravante del CVE-2026-62825)
        if default_action == "Allow":
            hallazgos.append(Hallazgo(
                id="AZURE-KV-005",
                severidad="HIGH",
                modulo="KeyVault",
                recurso=nombre,
                descripcion="Key Vault accesible desde 'All networks' — sin restricción de red (contexto CVE-2026-62825)",
                remediacion=(
                    "Configurar 'networkAcls.defaultAction = Deny' y añadir solo las IPs "
                    "o VNets autorizadas. Combinar con migración a RBAC para mitigar "
                    "completamente el vector CVE-2026-62825."
                ),
                detalle=f"KeyVault: {nombre} | networkAcls.defaultAction: Allow",
            ))

    return hallazgos


# ---------------------------------------------------------------------------
# Módulo Microsoft Defender for Cloud
# ---------------------------------------------------------------------------
async def audit_defender(
    session: aiohttp.ClientSession,
    token_mgmt: str,
    subscription_id: str,
) -> List[Hallazgo]:
    """Audita la configuración de Microsoft Defender for Cloud.

    Comprobaciones:
        AZURE-DEF-001 — Defender no activo para un tipo de servicio.
        AZURE-DEF-002 — Sin contacto de seguridad configurado.
    """
    hallazgos: List[Hallazgo] = []

    # Obtener pricings de Defender
    url_pricing = (
        f"{AZURE_MGMT}/subscriptions/{subscription_id}"
        "/providers/Microsoft.Security/pricings"
    )
    pricings = await az_get_pages(session, url_pricing, token_mgmt, "2024-01-01")

    pricings_dict: Dict[str, str] = {}
    for p in pricings:
        nombre_svc = p.get("name", "")
        props = p.get("properties", {})
        tier = props.get("pricingTier", "Free")
        pricings_dict[nombre_svc] = tier

    for svc_id, svc_nombre in SERVICIOS_DEFENDER.items():
        tier = pricings_dict.get(svc_id, "Free")
        if tier == "Free":
            hallazgos.append(Hallazgo(
                id="AZURE-DEF-001",
                severidad="HIGH",
                modulo="Defender",
                recurso=svc_id,
                descripcion=f"Microsoft Defender no activo para {svc_nombre} (plan Free)",
                remediacion=(
                    f"Habilitar Microsoft Defender for {svc_nombre} actualizando el "
                    f"pricing tier a 'Standard'. Proporciona detección de amenazas, "
                    "alertas de seguridad y recomendaciones avanzadas."
                ),
                detalle=f"Servicio: {svc_id} | Tier actual: Free",
            ))

    # Verificar contacto de seguridad
    url_contacts = (
        f"{AZURE_MGMT}/subscriptions/{subscription_id}"
        "/providers/Microsoft.Security/securityContacts"
    )
    contacts = await az_get_pages(session, url_contacts, token_mgmt, "2020-01-01-preview")

    if not contacts:
        hallazgos.append(Hallazgo(
            id="AZURE-DEF-002",
            severidad="MEDIUM",
            modulo="Defender",
            recurso=subscription_id,
            descripcion="Sin contacto de seguridad configurado en Microsoft Defender for Cloud",
            remediacion=(
                "Configurar al menos un contacto de seguridad con email válido en "
                "Microsoft Defender for Cloud > Configuración del entorno > Notificaciones. "
                "Las alertas críticas no llegarán sin contacto configurado."
            ),
            detalle="securityContacts: vacío",
        ))

    return hallazgos


# ---------------------------------------------------------------------------
# Helper: verificación de versión vulnerable CVE-2026-33105
# ---------------------------------------------------------------------------
def _version_vulnerable_cve_2026_33105(version: str) -> bool:
    """Comprueba si una versión de Kubernetes es vulnerable al CVE-2026-33105.

    Versiones mínimas seguras según el advisory oficial:
        - Rama 1.29: ≥ 1.29.15
        - Rama 1.30: ≥ 1.30.11
        - Rama 1.31: ≥ 1.31.7
        - Ramas < 1.29: EOL, sin parche disponible → se consideran vulnerables.
        - Ramas > 1.31: no catalogadas en el advisory → se asumen no vulnerables.

    Parámetros:
        version -- Cadena de versión de Kubernetes (p.ej. '1.30.5').

    Retorna True si la versión es vulnerable, False en caso contrario.
    """
    try:
        partes = version.split(".")
        mayor = int(partes[0])
        menor = int(partes[1].split("-")[0]) if len(partes) > 1 else 0
        patch = int(partes[2].split("-")[0]) if len(partes) > 2 else 0
    except (ValueError, IndexError):
        return False

    # Solo aplica a Kubernetes v1.x
    if mayor != 1:
        return False

    # Versiones anteriores a 1.29 — EOL, sin parche disponible
    if menor < 29:
        return True

    # Parches mínimos seguros por rama
    parches_seguros = {29: 15, 30: 11, 31: 7}

    if menor in parches_seguros:
        return patch < parches_seguros[menor]

    # Ramas > 1.31 no catalogadas en el advisory → no se marcan como vulnerables
    return False


# ---------------------------------------------------------------------------
# Módulo Enterprise Applications y Conditional Access (Entra ID)
# ---------------------------------------------------------------------------
async def audit_ent(
    session: aiohttp.ClientSession,
    token_graph: Optional[str],
    subscription_id: str,
) -> List[Hallazgo]:
    """Audita aplicaciones empresariales y Conditional Access de Entra ID.

    Respuesta al CVE-2026-69836 (Entra ID RCE). Requiere token de Microsoft Graph
    con scopes Policy.Read.All y Application.Read.All.

    Comprobaciones:
        AZURE-ENT-001 — Políticas de Conditional Access.
        AZURE-ENT-002 — Enterprise Apps con permisos de escritura masiva.
        AZURE-ENT-003 — Service Principals con credenciales expiradas o por expirar.
    """
    hallazgos: List[Hallazgo] = []

    if not token_graph:
        console.print(
            "  [yellow]⚠ Sin token de Microsoft Graph — módulo ENT omitido "
            "(requiere scopes Policy.Read.All y Application.Read.All)[/]"
        )
        return hallazgos

    # -----------------------------------------------------------------
    # ENT-001: Conditional Access Policies
    # -----------------------------------------------------------------
    url_ca = f"{AZURE_GRAPH}/v1.0/identity/conditionalAccess/policies"
    politicas = await graph_get_pages(session, url_ca, token_graph)

    # Separar por estado
    politicas_activas = [p for p in politicas if p.get("state") == "enabled"]
    politicas_deshabilitadas = [
        p for p in politicas
        if p.get("state") in ("disabled", "enabledForReportingButNotEnforced")
    ]

    if not politicas_activas:
        # Sin ninguna política activa — máximo riesgo
        hallazgos.append(Hallazgo(
            id="AZURE-ENT-001",
            severidad="CRITICAL",
            modulo="EnterpriseApps",
            recurso="identity/conditionalAccess/policies",
            descripcion="Sin Conditional Access activo — todos los accesos sin MFA ni restricción de red",
            remediacion=(
                "Crear al menos una política de Conditional Access que exija MFA "
                "para todos los usuarios. Revisar el advisory CVE-2026-69836 sobre "
                "autenticación en Entra ID. Habilitar Named Locations para restringir "
                "el acceso por red o país de origen."
            ),
            detalle=f"Políticas activas: 0 | Total en el tenant: {len(politicas)}",
        ))
    else:
        # Verificar cobertura de 'All users' y 'All apps'
        cubre_todos_usuarios = any(
            "All" in p.get("conditions", {}).get("users", {}).get("includeUsers", [])
            for p in politicas_activas
        )
        cubre_todas_apps = any(
            "All" in p.get("conditions", {}).get("applications", {}).get("includeApplications", [])
            for p in politicas_activas
        )

        if not cubre_todos_usuarios or not cubre_todas_apps:
            hallazgos.append(Hallazgo(
                id="AZURE-ENT-001",
                severidad="HIGH",
                modulo="EnterpriseApps",
                recurso="identity/conditionalAccess/policies",
                descripcion="Políticas de Conditional Access no cubren 'All users' o 'All apps'",
                remediacion=(
                    "Ampliar las políticas de Conditional Access para cubrir todos los "
                    "usuarios y todas las aplicaciones. Usar exclusiones específicas en "
                    "lugar de no incluir grupos enteros."
                ),
                detalle=(
                    f"Políticas activas: {len(politicas_activas)} | "
                    f"Cubre todos usuarios: {cubre_todos_usuarios} | "
                    f"Cubre todas apps: {cubre_todas_apps}"
                ),
            ))

        # Políticas en modo solo-reporte o deshabilitadas
        if politicas_deshabilitadas:
            nombres = ", ".join(
                p.get("displayName", p.get("id", "?"))[:30]
                for p in politicas_deshabilitadas[:5]
            )
            hallazgos.append(Hallazgo(
                id="AZURE-ENT-001",
                severidad="MEDIUM",
                modulo="EnterpriseApps",
                recurso="identity/conditionalAccess/policies",
                descripcion=(
                    f"Políticas de Conditional Access en estado deshabilitado o "
                    f"solo-reporte ({len(politicas_deshabilitadas)})"
                ),
                remediacion=(
                    "Activar las políticas en modo 'Report-only' o deshabilitadas. "
                    "El modo report-only registra eventos pero no protege activamente. "
                    "Habilitar tras validar que no bloquea usuarios legítimos."
                ),
                detalle=f"Políticas deshabilitadas/report-only: {nombres}",
            ))

    # -----------------------------------------------------------------
    # ENT-002: Enterprise Apps con permisos excesivos de escritura masiva
    # -----------------------------------------------------------------
    PERMISOS_EXCESIVOS = {
        "Directory.ReadWrite.All",
        "Mail.ReadWrite",
        "Files.ReadWrite.All",
        "User.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
    }

    url_sp = (
        f"{AZURE_GRAPH}/v1.0/servicePrincipals"
        "?$select=displayName,appId,oauth2PermissionScopes,appRoles"
    )
    service_principals = await graph_get_pages(session, url_sp, token_graph)

    for sp in service_principals:
        nombre_sp = sp.get("displayName", sp.get("appId", "desconocido"))
        permisos_encontrados: set = set()

        # Revisar permisos delegados (oauth2PermissionScopes)
        for scope in sp.get("oauth2PermissionScopes", []):
            valor = scope.get("value", "")
            if valor in PERMISOS_EXCESIVOS:
                permisos_encontrados.add(valor)

        # Revisar permisos de aplicación (appRoles)
        for role in sp.get("appRoles", []):
            valor = role.get("value", "")
            if valor in PERMISOS_EXCESIVOS:
                permisos_encontrados.add(valor)

        if permisos_encontrados:
            hallazgos.append(Hallazgo(
                id="AZURE-ENT-002",
                severidad="HIGH",
                modulo="EnterpriseApps",
                recurso=nombre_sp,
                descripcion="Enterprise App con permisos de escritura masiva sobre el directorio o datos",
                remediacion=(
                    "Revisar si la aplicación necesita realmente estos permisos y reducirlos "
                    "al mínimo indispensable. Sustituir permisos .ReadWrite.All por permisos "
                    "específicos de menor alcance. Aplicar el principio de mínimo privilegio "
                    "en todas las aplicaciones de Entra ID."
                ),
                detalle=f"App: {nombre_sp} | Permisos excesivos: {', '.join(sorted(permisos_encontrados))}",
            ))

    # -----------------------------------------------------------------
    # ENT-003: Service Principals con credenciales expiradas o por expirar
    # -----------------------------------------------------------------
    ahora = datetime.datetime.utcnow()
    limite_urgente = ahora + datetime.timedelta(days=30)

    url_sp_creds = (
        f"{AZURE_GRAPH}/v1.0/servicePrincipals"
        "?$select=displayName,passwordCredentials,keyCredentials"
    )
    sps_creds = await graph_get_pages(session, url_sp_creds, token_graph)

    for sp in sps_creds:
        nombre_sp = sp.get("displayName", "desconocido")

        # Combinar credenciales de contraseña y de certificado
        todas_credenciales = (
            [(c, "password") for c in sp.get("passwordCredentials", [])]
            + [(c, "key") for c in sp.get("keyCredentials", [])]
        )

        for cred, tipo_cred in todas_credenciales:
            end_dt_str = cred.get("endDateTime", "")
            if not end_dt_str:
                continue

            try:
                # Normalizar formato ISO 8601 (puede incluir 'Z' o '+00:00')
                end_dt = datetime.datetime.fromisoformat(
                    end_dt_str.replace("Z", "+00:00")
                ).replace(tzinfo=None)
            except (ValueError, AttributeError):
                continue

            hint = cred.get("displayName") or "sin-nombre"

            if end_dt < ahora:
                # Credencial ya expirada — el SP puede estar usando credenciales inválidas
                hallazgos.append(Hallazgo(
                    id="AZURE-ENT-003",
                    severidad="HIGH",
                    modulo="EnterpriseApps",
                    recurso=nombre_sp,
                    descripcion=f"Service Principal con credencial {tipo_cred} expirada aún registrada",
                    remediacion=(
                        "Rotar o eliminar la credencial expirada del Service Principal. "
                        "Implementar un proceso de rotación automática. "
                        "Revisar si el Service Principal sigue siendo necesario."
                    ),
                    detalle=(
                        f"SP: {nombre_sp} | Credencial: {hint} | "
                        f"Tipo: {tipo_cred} | Expiró: {end_dt.strftime('%Y-%m-%d')}"
                    ),
                ))
            elif end_dt < limite_urgente:
                # Credencial próxima a expirar — rotación urgente
                dias_restantes = (end_dt - ahora).days
                hallazgos.append(Hallazgo(
                    id="AZURE-ENT-003",
                    severidad="MEDIUM",
                    modulo="EnterpriseApps",
                    recurso=nombre_sp,
                    descripcion=(
                        f"Service Principal con credencial {tipo_cred} "
                        f"que expira en {dias_restantes} día(s)"
                    ),
                    remediacion=(
                        "Rotar la credencial del Service Principal antes de que expire. "
                        "Implementar alertas automáticas de expiración. "
                        "Considerar el uso de identidades gestionadas (Managed Identities) "
                        "para eliminar la gestión manual de secretos."
                    ),
                    detalle=(
                        f"SP: {nombre_sp} | Credencial: {hint} | "
                        f"Tipo: {tipo_cred} | Expira: {end_dt.strftime('%Y-%m-%d')}"
                    ),
                ))

    return hallazgos


# ---------------------------------------------------------------------------
# Cálculo de puntuación / grade
# ---------------------------------------------------------------------------
def compute_grade(hallazgos: List[Hallazgo]) -> str:
    """Calcula la calificación de seguridad global basándose en los hallazgos.

    Escala: A+ (sin problemas graves) hasta F (múltiples críticos).
    """
    crit = sum(1 for h in hallazgos if h.severidad == "CRITICAL")
    high = sum(1 for h in hallazgos if h.severidad == "HIGH")
    med = sum(1 for h in hallazgos if h.severidad == "MEDIUM")

    if crit == 0 and high == 0 and med == 0:
        return "A+"
    if crit == 0 and high == 0:
        return "A"
    if crit == 0 and high <= 2:
        return "B"
    if crit == 0 and high <= 5:
        return "C"
    if crit <= 1 or (crit == 0 and high <= 8):
        return "D"
    if crit <= 3:
        return "E"
    return "F"


def color_grade(grade: str) -> str:
    """Retorna el color Rich correspondiente a la calificación."""
    mapping = {
        "A+": "bold green",
        "A": "green",
        "B": "yellow",
        "C": "yellow",
        "D": "red",
        "E": "bold red",
        "F": "bold red",
    }
    return mapping.get(grade, "white")


# ---------------------------------------------------------------------------
# Generador de informe HTML
# ---------------------------------------------------------------------------
def generar_html(
    hallazgos: List[Hallazgo],
    subscription_id: str,
    tenant_id: str,
    grade: str,
    modulos_ejecutados: List[str],
    fecha_inicio: datetime.datetime,
    fecha_fin: datetime.datetime,
) -> str:
    """Genera un informe HTML completo de la auditoría en estilo dark-theme VSL.

    Incluye cabecera con metadata, tabla de hallazgos codificada por severidad,
    sección de remediaciones agrupadas por módulo y footer corporativo.
    """
    fecha_str = fecha_fin.strftime("%Y-%m-%d %H:%M:%S UTC")
    duracion = int((fecha_fin - fecha_inicio).total_seconds())

    # Contadores por severidad
    contadores: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for h in hallazgos:
        contadores[h.severidad] = contadores.get(h.severidad, 0) + 1

    # Colores HTML por severidad
    colores_html = {
        "CRITICAL": "#e11d48",
        "HIGH": "#f97316",
        "MEDIUM": "#f59e0b",
        "LOW": "#60a5fa",
        "INFO": "#94a3b8",
    }

    colores_grade = {
        "A+": "#34d399", "A": "#34d399", "B": "#86efac",
        "C": "#f59e0b", "D": "#f97316", "E": "#e11d48", "F": "#e11d48",
    }
    color_g = colores_grade.get(grade, "#94a3b8")

    # Generar filas de la tabla
    filas_html = ""
    for h in hallazgos:
        color_sev = colores_html.get(h.severidad, "#94a3b8")
        icono = ICONOS_SEVERIDAD.get(h.severidad, "⚪")
        detalle_esc = h.detalle.replace("<", "&lt;").replace(">", "&gt;") if h.detalle else ""
        desc_esc = h.descripcion.replace("<", "&lt;").replace(">", "&gt;")
        rec_esc = h.remediacion.replace("<", "&lt;").replace(">", "&gt;")
        recurso_esc = h.recurso.replace("<", "&lt;").replace(">", "&gt;")
        fila = f"""
        <tr>
          <td><span class="badge-sev" style="background:{color_sev}20;color:{color_sev};border:1px solid {color_sev}40">{icono} {h.severidad}</span></td>
          <td><code class="finding-id">{h.id}</code></td>
          <td><span class="modulo-badge">{h.modulo}</span></td>
          <td class="recurso-cell">{recurso_esc}</td>
          <td>{desc_esc}</td>
          <td class="rem-cell">{rec_esc}</td>
        </tr>"""
        if detalle_esc:
            fila += f"""
        <tr class="detalle-row">
          <td colspan="6"><span class="detalle-label">Detalle técnico:</span> <code>{detalle_esc}</code></td>
        </tr>"""
        filas_html += fila

    # Generar sección de resumen por módulo
    modulos_hallazgos: Dict[str, List[Hallazgo]] = {}
    for h in hallazgos:
        modulos_hallazgos.setdefault(h.modulo, []).append(h)

    resumen_modulos = ""
    for mod, mod_hallazgos in sorted(modulos_hallazgos.items()):
        crit_m = sum(1 for h in mod_hallazgos if h.severidad == "CRITICAL")
        high_m = sum(1 for h in mod_hallazgos if h.severidad == "HIGH")
        med_m = sum(1 for h in mod_hallazgos if h.severidad == "MEDIUM")
        resumen_modulos += f"""
        <div class="mod-card">
          <div class="mod-header"><span class="mod-nombre">{mod}</span>
            <span class="mod-stats">
              {f'<span class="stat-badge" style="color:#e11d48">{crit_m} CRITICAL</span>' if crit_m else ''}
              {f'<span class="stat-badge" style="color:#f97316">{high_m} HIGH</span>' if high_m else ''}
              {f'<span class="stat-badge" style="color:#f59e0b">{med_m} MEDIUM</span>' if med_m else ''}
            </span>
          </div>
          <ul class="mod-lista">
            {''.join(f"<li><code>{h.id}</code> — {h.descripcion.replace('<','&lt;').replace('>','&gt;')}</li>" for h in mod_hallazgos)}
          </ul>
        </div>"""

    modulos_str = ", ".join(modulos_ejecutados)

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>vamp-azure-audit — {subscription_id[:12]}... — {fecha_fin.strftime('%Y-%m-%d')}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #080b14;
    --bg2: #0d1120;
    --card: #0f1524;
    --card2: #131929;
    --border: #1e2d4a;
    --text: #e2e8f0;
    --text-muted: #64748b;
    --crimson: #e11d48;
    --green: #34d399;
    --amber: #f59e0b;
    --blue: #60a5fa;
    --orange: #f97316;
    --font: 'Inter', system-ui, sans-serif;
    --mono: 'JetBrains Mono', 'Fira Code', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); font-size: 14px; line-height: 1.6; }}
  a {{ color: var(--blue); text-decoration: none; }}
  code {{ font-family: var(--mono); font-size: 12px; }}

  .header {{
    background: linear-gradient(135deg, #0a0f1e 0%, #0f1830 50%, #0a1020 100%);
    border-bottom: 1px solid var(--border);
    padding: 32px 40px;
    display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 20px;
  }}
  .header-left h1 {{ font-size: 22px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }}
  .header-left h1 span {{ color: var(--crimson); }}
  .header-left .subtitle {{ color: var(--text-muted); font-size: 12px; margin-top: 4px; font-family: var(--mono); }}
  .grade-badge {{
    width: 72px; height: 72px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 28px; font-weight: 800; border: 3px solid;
    color: {color_g}; border-color: {color_g};
    background: {color_g}15;
  }}

  .meta-bar {{
    background: var(--bg2); border-bottom: 1px solid var(--border);
    padding: 16px 40px; display: flex; gap: 32px; flex-wrap: wrap;
  }}
  .meta-item {{ display: flex; flex-direction: column; gap: 2px; }}
  .meta-label {{ font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); }}
  .meta-value {{ font-family: var(--mono); font-size: 12px; color: var(--text); }}

  .stats-row {{
    padding: 24px 40px; display: flex; gap: 16px; flex-wrap: wrap;
  }}
  .stat-card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 16px 20px; min-width: 120px;
    display: flex; flex-direction: column; gap: 4px;
  }}
  .stat-number {{ font-size: 28px; font-weight: 700; font-family: var(--mono); }}
  .stat-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); }}

  .section {{ padding: 0 40px 32px; }}
  .section-title {{
    font-size: 13px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 1.5px; color: var(--text-muted);
    border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 20px;
  }}

  .table-wrap {{ overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card); }}
  thead th {{
    background: var(--card2); padding: 10px 14px;
    font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
    color: var(--text-muted); text-align: left; border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }}
  tbody tr {{ border-bottom: 1px solid var(--border)15; }}
  tbody tr:hover {{ background: var(--card2); }}
  tbody td {{ padding: 10px 14px; vertical-align: top; font-size: 13px; }}
  .detalle-row td {{
    background: #060a15; padding: 6px 14px 10px 28px;
    font-size: 11px; color: var(--text-muted); border-bottom: 1px solid var(--border);
  }}
  .detalle-label {{ color: var(--blue); font-weight: 500; }}

  .badge-sev {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 600; font-family: var(--mono);
    white-space: nowrap;
  }}
  .finding-id {{
    color: var(--blue); font-size: 11px;
    background: var(--blue)15; padding: 2px 6px; border-radius: 4px;
    white-space: nowrap;
  }}
  .modulo-badge {{
    font-size: 11px; background: #1e2d4a; color: #93c5fd;
    padding: 2px 8px; border-radius: 4px; white-space: nowrap;
  }}
  .recurso-cell {{ font-family: var(--mono); font-size: 12px; color: #94a3b8; max-width: 200px; word-break: break-all; }}
  .rem-cell {{ max-width: 260px; font-size: 12px; color: #94a3b8; }}

  .mod-card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 16px 20px; margin-bottom: 12px;
  }}
  .mod-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 10px; flex-wrap: wrap; }}
  .mod-nombre {{ font-weight: 600; font-size: 14px; }}
  .mod-stats {{ display: flex; gap: 8px; flex-wrap: wrap; }}
  .stat-badge {{ font-size: 11px; font-weight: 600; font-family: var(--mono); }}
  .mod-lista {{ list-style: none; padding: 0; display: flex; flex-direction: column; gap: 4px; }}
  .mod-lista li {{ font-size: 12px; color: var(--text-muted); }}
  .mod-lista li code {{ color: var(--blue); }}

  .empty-state {{
    text-align: center; padding: 48px; color: var(--text-muted);
  }}
  .empty-state .big {{ font-size: 40px; margin-bottom: 8px; }}

  .footer {{
    border-top: 1px solid var(--border); padding: 20px 40px;
    display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;
    background: var(--bg2); color: var(--text-muted); font-size: 11px;
  }}
  .footer .brand {{ font-weight: 600; color: var(--crimson); }}
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <h1>vamp-<span>azure</span>-audit <span style="font-size:13px;color:#475569;font-weight:400">v{VERSION}</span></h1>
    <div class="subtitle">VampSecure Labs Security Research Division &bull; Informe de Auditoría Azure</div>
  </div>
  <div class="grade-badge" title="Calificación global de seguridad">{grade}</div>
</div>

<div class="meta-bar">
  <div class="meta-item"><div class="meta-label">Subscription ID</div><div class="meta-value">{subscription_id}</div></div>
  <div class="meta-item"><div class="meta-label">Tenant ID</div><div class="meta-value">{tenant_id}</div></div>
  <div class="meta-item"><div class="meta-label">Fecha de auditoría</div><div class="meta-value">{fecha_str}</div></div>
  <div class="meta-item"><div class="meta-label">Duración</div><div class="meta-value">{duracion}s</div></div>
  <div class="meta-item"><div class="meta-label">Módulos ejecutados</div><div class="meta-value">{modulos_str}</div></div>
</div>

<div class="stats-row">
  <div class="stat-card">
    <div class="stat-number" style="color:#e11d48">{contadores['CRITICAL']}</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:#f97316">{contadores['HIGH']}</div>
    <div class="stat-label">High</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:#f59e0b">{contadores['MEDIUM']}</div>
    <div class="stat-label">Medium</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:#60a5fa">{contadores['LOW']}</div>
    <div class="stat-label">Low</div>
  </div>
  <div class="stat-card">
    <div class="stat-number">{len(hallazgos)}</div>
    <div class="stat-label">Total</div>
  </div>
</div>

<div class="section">
  <div class="section-title">Hallazgos de seguridad</div>
  {'<div class="empty-state"><div class="big">✅</div><div>Sin hallazgos — la suscripción supera todas las comprobaciones ejecutadas.</div></div>' if not hallazgos else f'''
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Severidad</th>
          <th>ID</th>
          <th>Módulo</th>
          <th>Recurso</th>
          <th>Descripción</th>
          <th>Remediación</th>
        </tr>
      </thead>
      <tbody>
        {filas_html}
      </tbody>
    </table>
  </div>'''}
</div>

{'<div class="section"><div class="section-title">Resumen por módulo</div>' + resumen_modulos + '</div>' if modulos_hallazgos else ''}

<div class="footer">
  <div>
    <span class="brand">© VampSecure Studios</span> — VampSecure Labs Security Research Division &bull;
    Herramienta de uso exclusivo en entornos con autorización expresa.
  </div>
  <div>vamp-azure-audit v{VERSION} &bull; {fecha_str}</div>
</div>

</body>
</html>"""

    return html


# ---------------------------------------------------------------------------
# Presentación en consola
# ---------------------------------------------------------------------------
def mostrar_banner() -> None:
    """Muestra el banner de inicio de la herramienta."""
    banner = Text()
    banner.append("  ██╗   ██╗ █████╗ ███╗   ███╗██████╗ \n", style="bold red")
    banner.append("  ██║   ██║██╔══██╗████╗ ████║██╔══██╗\n", style="bold red")
    banner.append("  ██║   ██║███████║██╔████╔██║██████╔╝\n", style="bold red")
    banner.append("  ╚██╗ ██╔╝██╔══██║██║╚██╔╝██║██╔═══╝ \n", style="red")
    banner.append("   ╚████╔╝ ██║  ██║██║ ╚═╝ ██║██║     \n", style="red")
    banner.append("    ╚═══╝  ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     \n", style="red")
    banner.append(f"\n  vamp-azure-audit v{VERSION}", style="bold white")
    banner.append("  —  Azure Security Auditor\n", style="dim white")
    banner.append("  VampSecure Labs Security Research Division\n", style="dim red")
    console.print(Panel(banner, border_style="red", padding=(0, 1)))


def mostrar_tabla_hallazgos(hallazgos: List[Hallazgo]) -> None:
    """Muestra la tabla de hallazgos en la consola usando Rich."""
    if not hallazgos:
        console.print("\n[bold green]✅ Sin hallazgos detectados — la suscripción supera todas las comprobaciones.[/]\n")
        return

    tabla = Table(
        title=f"[bold]Hallazgos de seguridad — {len(hallazgos)} total[/]",
        box=box.ROUNDED,
        border_style="dim blue",
        header_style="bold cyan",
        show_lines=True,
        padding=(0, 1),
    )
    tabla.add_column("Severidad", min_width=10, no_wrap=True)
    tabla.add_column("ID", style="cyan", min_width=16, no_wrap=True)
    tabla.add_column("Módulo", min_width=10, no_wrap=True)
    tabla.add_column("Recurso", min_width=18)
    tabla.add_column("Descripción", min_width=36)
    tabla.add_column("Remediación", min_width=30)

    for h in hallazgos:
        color = COLORES_SEVERIDAD.get(h.severidad, "white")
        icono = ICONOS_SEVERIDAD.get(h.severidad, "⚪")
        tabla.add_row(
            f"[{color}]{icono} {h.severidad}[/]",
            f"[cyan]{h.id}[/]",
            h.modulo,
            f"[dim]{h.recurso[:40]}[/]",
            h.descripcion,
            f"[dim]{h.remediacion[:80]}…[/]" if len(h.remediacion) > 80 else f"[dim]{h.remediacion}[/]",
        )

    console.print()
    console.print(tabla)
    console.print()


def mostrar_resumen(hallazgos: List[Hallazgo], grade: str, duracion: float) -> None:
    """Muestra el resumen final de la auditoría."""
    crit = sum(1 for h in hallazgos if h.severidad == "CRITICAL")
    high = sum(1 for h in hallazgos if h.severidad == "HIGH")
    med = sum(1 for h in hallazgos if h.severidad == "MEDIUM")
    low = sum(1 for h in hallazgos if h.severidad == "LOW")

    color_g = color_grade(grade)

    resumen = Text()
    resumen.append("  Calificación global: ", style="bold")
    resumen.append(f"  {grade}  ", style=f"bold {color_g} on default")
    resumen.append("\n\n")
    resumen.append(f"  🔴 Critical: {crit}   🟠 High: {high}   🟡 Medium: {med}   🔵 Low: {low}\n", style="bold")
    resumen.append(f"\n  Total hallazgos: {len(hallazgos)}   Duración: {duracion:.1f}s\n", style="dim")

    console.print(Panel(resumen, title="[bold]Resumen de Auditoría[/]", border_style=color_g, padding=(0, 1)))


# ---------------------------------------------------------------------------
# Entrypoint principal
# ---------------------------------------------------------------------------
async def ejecutar_auditoria(args: argparse.Namespace) -> List[Hallazgo]:
    """Orquesta la ejecución de todos los módulos de auditoría seleccionados."""

    tenant = args.tenant_id
    client_id = args.client_id
    client_secret = args.client_secret
    subscription_id = args.subscription_id

    todos_hallazgos: List[Hallazgo] = []

    async with aiohttp.ClientSession() as session:
        console.print("\n[bold cyan]→ Autenticando en Azure...[/]")

        # Token para Management API
        try:
            token_mgmt = await obtener_token(session, tenant, client_id, client_secret, SCOPE_MGMT)
            console.print("  [green]✓ Token Management API obtenido[/]")
        except RuntimeError as e:
            console.print(f"  [bold red]✗ Error obteniendo token Management: {e}[/]")
            sys.exit(1)

        # Token para Graph API (opcional — requerido por módulos IAM y ENT)
        token_graph: Optional[str] = None
        modulo_iam = not args.modulos or "iam" in args.modulos
        modulo_ent = not args.modulos or "ent" in args.modulos
        if modulo_iam or modulo_ent:
            try:
                token_graph = await obtener_token(session, tenant, client_id, client_secret, SCOPE_GRAPH)
                console.print("  [green]✓ Token Microsoft Graph obtenido[/]")
            except RuntimeError:
                console.print("  [yellow]⚠ Sin acceso a Microsoft Graph — comprobaciones de usuarios Guest omitidas[/]")

        console.print()

        # Determinar módulos a ejecutar
        modulos_disponibles = {
            "iam": ("IAM / Roles", audit_iam),
            "storage": ("Storage Accounts", audit_storage),
            "aks": ("Azure Kubernetes Service", audit_aks),
            "appservices": ("App Services", audit_appservices),
            "nsg": ("Network Security Groups", audit_nsg),
            "keyvault": ("Key Vault", audit_keyvault),
            "defender": ("Microsoft Defender for Cloud", audit_defender),
            "ent": ("Enterprise Apps & Conditional Access (Entra ID)", audit_ent),
        }

        modulos_a_ejecutar = args.modulos if args.modulos else list(modulos_disponibles.keys())
        modulos_ejecutados: List[str] = []

        for mod_id in modulos_a_ejecutar:
            if mod_id not in modulos_disponibles:
                console.print(f"  [yellow]⚠ Módulo desconocido: {mod_id}[/]")
                continue

            mod_nombre, mod_func = modulos_disponibles[mod_id]
            console.print(f"[bold cyan]→ Auditando {mod_nombre}...[/]")

            try:
                if mod_id == "iam":
                    hallazgos_mod = await mod_func(session, token_mgmt, token_graph, subscription_id)
                elif mod_id == "ent":
                    # ENT solo requiere token de Graph y el subscription_id de contexto
                    hallazgos_mod = await mod_func(session, token_graph, subscription_id)
                elif mod_id in ("storage", "aks", "appservices", "nsg", "keyvault", "defender"):
                    hallazgos_mod = await mod_func(session, token_mgmt, subscription_id)
                else:
                    continue

                todos_hallazgos.extend(hallazgos_mod)
                modulos_ejecutados.append(mod_nombre)

                if hallazgos_mod:
                    crits = sum(1 for h in hallazgos_mod if h.severidad == "CRITICAL")
                    highs = sum(1 for h in hallazgos_mod if h.severidad == "HIGH")
                    console.print(
                        f"  [yellow]⚠ {len(hallazgos_mod)} hallazgo(s)[/] "
                        f"{'[bold red](' + str(crits) + ' CRITICAL)[/] ' if crits else ''}"
                        f"{'[red](' + str(highs) + ' HIGH)[/]' if highs else ''}"
                    )
                else:
                    console.print("  [green]✓ Sin hallazgos en este módulo[/]")

            except Exception as exc:  # noqa: BLE001
                console.print(f"  [red]✗ Error en módulo {mod_nombre}: {exc}[/]")

        return todos_hallazgos


def main() -> None:
    """Punto de entrada del CLI vamp-azure-audit."""
    parser = argparse.ArgumentParser(
        prog="vamp-azure-audit",
        description=(
            "vamp-azure-audit — Auditor de seguridad de Microsoft Azure.\n"
            "VampSecure Labs Security Research Division.\n"
            "Uso exclusivo en entornos con autorización expresa."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Argumentos de autenticación
    auth_group = parser.add_argument_group("Autenticación Azure")
    auth_group.add_argument(
        "--subscription-id", "-s",
        default=os.environ.get("AZURE_SUBSCRIPTION_ID"),
        help="ID de la suscripción Azure (env: AZURE_SUBSCRIPTION_ID)",
    )
    auth_group.add_argument(
        "--tenant-id", "-t",
        default=os.environ.get("AZURE_TENANT_ID"),
        help="ID del tenant de Azure (env: AZURE_TENANT_ID)",
    )
    auth_group.add_argument(
        "--client-id",
        default=os.environ.get("AZURE_CLIENT_ID"),
        help="Application (client) ID del Service Principal (env: AZURE_CLIENT_ID)",
    )
    auth_group.add_argument(
        "--client-secret",
        default=os.environ.get("AZURE_CLIENT_SECRET"),
        help="Secreto del Service Principal (env: AZURE_CLIENT_SECRET)",
    )

    # Módulos
    parser.add_argument(
        "--modulos", "-m",
        nargs="+",
        choices=["iam", "storage", "aks", "appservices", "nsg", "keyvault", "defender", "ent"],
        metavar="MODULO",
        help=(
            "Módulos a ejecutar (por defecto: todos). "
            "Opciones: iam storage aks appservices nsg keyvault defender ent"
        ),
    )

    # Salida
    output_group = parser.add_argument_group("Salida")
    output_group.add_argument(
        "--output-html",
        metavar="FICHERO.html",
        help="Guardar informe en formato HTML",
    )
    output_group.add_argument(
        "--output-json",
        metavar="FICHERO.json",
        help="Guardar hallazgos en formato JSON",
    )
    output_group.add_argument(
        "--version", "-V",
        action="version",
        version=f"vamp-azure-audit v{VERSION} — VampSecure Labs Security Research Division",
    )

    args = parser.parse_args()

    # Validar credenciales obligatorias
    faltan = []
    if not args.subscription_id:
        faltan.append("--subscription-id / AZURE_SUBSCRIPTION_ID")
    if not args.tenant_id:
        faltan.append("--tenant-id / AZURE_TENANT_ID")
    if not args.client_id:
        faltan.append("--client-id / AZURE_CLIENT_ID")
    if not args.client_secret:
        faltan.append("--client-secret / AZURE_CLIENT_SECRET")

    mostrar_banner()

    if faltan:
        console.print("[bold red]✗ Faltan credenciales obligatorias:[/]")
        for f in faltan:
            console.print(f"  [red]•[/] {f}")
        sys.exit(1)

    console.print(f"[dim]  Suscripción: {args.subscription_id}[/]")
    console.print(f"[dim]  Tenant: {args.tenant_id}[/]")
    console.print()

    fecha_inicio = datetime.datetime.utcnow()

    # Ejecutar auditoría
    hallazgos = asyncio.run(ejecutar_auditoria(args))

    fecha_fin = datetime.datetime.utcnow()
    duracion = (fecha_fin - fecha_inicio).total_seconds()

    # Calcular calificación
    grade = compute_grade(hallazgos)

    # Mostrar resultados en consola
    mostrar_tabla_hallazgos(hallazgos)
    mostrar_resumen(hallazgos, grade, duracion)

    # Guardar HTML
    if args.output_html:
        modulos_ejecutados = args.modulos if args.modulos else [
            "IAM", "Storage", "AKS", "AppServices", "NSG", "KeyVault", "Defender"
        ]
        html_content = generar_html(
            hallazgos,
            subscription_id=args.subscription_id,
            tenant_id=args.tenant_id,
            grade=grade,
            modulos_ejecutados=modulos_ejecutados,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
        )
        try:
            with open(args.output_html, "w", encoding="utf-8") as fh:
                fh.write(html_content)
            console.print(f"[green]✓ Informe HTML guardado en: {args.output_html}[/]")
        except OSError as e:
            console.print(f"[red]✗ Error guardando HTML: {e}[/]")

    # Guardar JSON
    if args.output_json:
        datos_json = {
            "meta": {
                "herramienta": "vamp-azure-audit",
                "version": VERSION,
                "autor": "VampSecure Studios — VampSecure Labs Security Research Division",
                "subscription_id": args.subscription_id,
                "tenant_id": args.tenant_id,
                "fecha_inicio": fecha_inicio.isoformat() + "Z",
                "fecha_fin": fecha_fin.isoformat() + "Z",
                "duracion_segundos": round(duracion, 2),
                "grade": grade,
                "modulos": args.modulos or ["iam", "storage", "aks", "appservices", "nsg", "keyvault", "defender", "ent"],
            },
            "resumen": {
                "total": len(hallazgos),
                "CRITICAL": sum(1 for h in hallazgos if h.severidad == "CRITICAL"),
                "HIGH": sum(1 for h in hallazgos if h.severidad == "HIGH"),
                "MEDIUM": sum(1 for h in hallazgos if h.severidad == "MEDIUM"),
                "LOW": sum(1 for h in hallazgos if h.severidad == "LOW"),
                "INFO": sum(1 for h in hallazgos if h.severidad == "INFO"),
            },
            "hallazgos": [
                {
                    "id": h.id,
                    "severidad": h.severidad,
                    "modulo": h.modulo,
                    "recurso": h.recurso,
                    "descripcion": h.descripcion,
                    "remediacion": h.remediacion,
                    "detalle": h.detalle,
                }
                for h in hallazgos
            ],
        }
        try:
            with open(args.output_json, "w", encoding="utf-8") as fh:
                json.dump(datos_json, fh, ensure_ascii=False, indent=2)
            console.print(f"[green]✓ Hallazgos JSON guardados en: {args.output_json}[/]")
        except OSError as e:
            console.print(f"[red]✗ Error guardando JSON: {e}[/]")

    # Código de salida según severidad
    crit_count = sum(1 for h in hallazgos if h.severidad == "CRITICAL")
    high_count = sum(1 for h in hallazgos if h.severidad == "HIGH")

    if crit_count > 0:
        sys.exit(2)
    elif high_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
