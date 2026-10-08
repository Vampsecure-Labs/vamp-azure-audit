<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

  <img src="https://github.com/Vampsecure-Labs/vamp-azure-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>
# vamp-azure-audit

**Microsoft Azure Security Auditor — VampSecure Labs Security Research Division**

Herramienta CLI de auditoría de seguridad para entornos Microsoft Azure. Detecta misconfiguraciones críticas en IAM, Storage Accounts, AKS, App Services, Network Security Groups, Key Vault y Microsoft Defender for Cloud utilizando exclusivamente la REST API oficial de Azure (sin SDKs pesados).

> **USO EXCLUSIVO EN ENTORNOS CON AUTORIZACIÓN EXPRESA.**
> Esta herramienta está diseñada para evaluaciones de seguridad autorizadas. Su uso en entornos sin autorización puede ser ilegal.

---

## Instalación

```bash
pip install vamp-azure-audit
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-azure-audit
```

O desde el repositorio:

```bash
git clone https://github.com/Vampsecure-Labs/vamp-azure-audit
cd vamp-azure-audit
pip install -e .
```

**Dependencias:** `aiohttp>=3.9.0`, `rich>=13.7.0`, Python 3.9+

---

## Configuración

El Service Principal necesita los siguientes permisos:

- **Management API:** rol `Reader` en la suscripción + `Microsoft.Security/pricings/read`
- **Microsoft Graph:** `User.Read.All` (para detección de usuarios Guest con privilegios)

Crear Service Principal con rol Reader:

```bash
az ad sp create-for-rbac --name "vamp-azure-audit" --role "Reader" \
  --scopes /subscriptions/<SUBSCRIPTION_ID>
```

---

## Variables de entorno

| Variable                | Descripción                                      |
|-------------------------|--------------------------------------------------|
| `AZURE_SUBSCRIPTION_ID` | ID de la suscripción Azure a auditar             |
| `AZURE_TENANT_ID`       | ID del tenant de Azure (Directory ID)            |
| `AZURE_CLIENT_ID`       | Application (client) ID del Service Principal   |
| `AZURE_CLIENT_SECRET`   | Secreto del Service Principal                    |

---

## Uso

### Auditoría completa (todos los módulos)

```bash
export AZURE_SUBSCRIPTION_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AZURE_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AZURE_CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AZURE_CLIENT_SECRET="tu-secreto"

vamp-azure-audit
```

### Con flags explícitos

```bash
vamp-azure-audit \
  --subscription-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --tenant-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --client-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --client-secret "tu-secreto"
```

### Módulos específicos

```bash
# Solo IAM y NSG
vamp-azure-audit --modulos iam nsg

# Solo Storage y Key Vault
vamp-azure-audit --modulos storage keyvault

# Solo Defender for Cloud
vamp-azure-audit --modulos defender
```

### Exportar informes

```bash
# Generar informe HTML
vamp-azure-audit --output-html informe-azure.html

# Generar JSON para integración con otras herramientas
vamp-azure-audit --output-json hallazgos.json

# HTML + JSON en el mismo pase
vamp-azure-audit --output-html informe.html --output-json hallazgos.json
```

---

## Módulos disponibles

| Módulo        | Flag           | Descripción                                                       |
|---------------|----------------|-------------------------------------------------------------------|
| IAM           | `iam`          | Roles privilegiados a nivel de suscripción, usuarios Guest        |
| Storage       | `storage`      | Acceso público a blobs, HTTP, TLS, restricciones de red           |
| AKS           | `aks`          | RBAC, API server público, NetworkPolicy, versiones desactualizadas|
| App Services  | `appservices`  | HTTPS, remote debugging, TLS, FTP sin cifrar                      |
| NSG           | `nsg`          | Puertos críticos expuestos a Internet, reglas abiertas            |
| Key Vault     | `keyvault`     | Soft Delete, Purge Protection, acceso de red                      |
| Defender      | `defender`     | Planes de Defender for Cloud, contacto de seguridad               |

---

## Hallazgos detectados

| ID             | Severidad | Descripción                                                |
|----------------|-----------|------------------------------------------------------------|
| AZURE-IAM-001  | CRITICAL  | Usuario con Owner/Contributor a nivel de suscripción        |
| AZURE-IAM-002  | HIGH      | Service Principal con Owner a nivel de suscripción          |
| AZURE-IAM-003  | HIGH      | Usuario Guest con roles privilegiados                       |
| AZURE-STOR-001 | HIGH      | Acceso público a blobs habilitado                           |
| AZURE-STOR-002 | HIGH      | Tráfico HTTP (sin cifrar) permitido                         |
| AZURE-STOR-003 | MEDIUM    | Sin restricciones de red en Storage Account                 |
| AZURE-STOR-004 | MEDIUM    | TLS mínimo inferior a 1.2                                   |
| AZURE-AKS-001  | CRITICAL  | RBAC desactivado en clúster AKS                             |
| AZURE-AKS-002  | HIGH      | API server de AKS accesible públicamente                    |
| AZURE-AKS-003  | HIGH      | Sin NetworkPolicy configurada                               |
| AZURE-AKS-004  | MEDIUM    | Versión de Kubernetes desactualizada                        |
| AZURE-APP-001  | HIGH      | App Service no fuerza HTTPS                                 |
| AZURE-APP-002  | HIGH      | Remote debugging habilitado                                 |
| AZURE-APP-003  | MEDIUM    | TLS mínimo inferior a 1.2 en App Service                    |
| AZURE-APP-004  | MEDIUM    | FTP sin cifrar habilitado                                   |
| AZURE-NSG-001  | CRITICAL  | Puerto crítico expuesto a Internet (0.0.0.0/0)              |
| AZURE-NSG-002  | CRITICAL  | Regla NSG permite todo el tráfico entrante                   |
| AZURE-KV-001   | HIGH      | Soft Delete no habilitado en Key Vault                       |
| AZURE-KV-002   | MEDIUM    | Purge Protection no habilitado                              |
| AZURE-KV-003   | HIGH      | Key Vault accesible desde cualquier red                     |
| AZURE-KV-004   | HIGH      | Acceso público habilitado sin restricciones                 |
| AZURE-DEF-001  | HIGH      | Microsoft Defender no activo para un servicio               |
| AZURE-DEF-002  | MEDIUM    | Sin contacto de seguridad configurado                       |

---

## Ejemplo de salida

```
  ██╗   ██╗ █████╗ ███╗   ███╗██████╗
  ██║   ██║██╔══██╗████╗ ████║██╔══██╗
  ██║   ██║███████║██╔████╔██║██████╔╝
  ╚██╗ ██╔╝██╔══██║██║╚██╔╝██║██╔═══╝
   ╚████╔╝ ██║  ██║██║ ╚═╝ ██║██║
    ╚═══╝  ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝

  vamp-azure-audit v1.1  —  Azure Security Auditor
  VampSecure Labs Security Research Division

→ Autenticando en Azure...
  ✓ Token Management API obtenido
  ✓ Token Microsoft Graph obtenido

→ Auditando IAM / Roles...
  ⚠ 2 hallazgo(s) (1 CRITICAL) (1 HIGH)
→ Auditando Storage Accounts...
  ⚠ 3 hallazgo(s) (2 HIGH)
→ Auditando Network Security Groups...
  ⚠ 1 hallazgo(s) (1 CRITICAL)
...

╭─ Resumen de Auditoría ──────────────────────╮
│  Calificación global:   D                   │
│                                             │
│  🔴 Critical: 2   🟠 High: 5   🟡 Medium: 4│
│                                             │
│  Total hallazgos: 11   Duración: 8.3s       │
╰─────────────────────────────────────────────╯
```

---

## Códigos de salida

| Código | Significado                                      |
|--------|--------------------------------------------------|
| `0`    | Sin hallazgos CRITICAL ni HIGH                   |
| `1`    | Hallazgos HIGH detectados (sin CRITICAL)         |
| `2`    | Hallazgos CRITICAL detectados                    |

Útil para integración en pipelines CI/CD:

```bash
vamp-azure-audit --output-json hallazgos.json
if [ $? -eq 2 ]; then
  echo "BLOQUEADO: Hallazgos críticos en Azure"
  exit 1
fi
```

---

## Licencia

AGPL-3.0 License — Copyright © VampSecure Studios — VampSecure Labs Security Research Division

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.

---

© VampSecure Studios — VampSecure Labs Security Research Division

## Sample Output

```
$ vamp-azure-audit

  vamp-azure-audit v1.1  —  Azure Security Auditor
  VampSecure Labs Security Research Division

  → Autenticando en Azure...
  ✓ Token Management API obtenido
  ✓ Token Microsoft Graph obtenido
  ✓ Subscription: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx  (ejemplo-corp)

  → Auditando IAM / Roles...
  ✗ AZURE-IAM-001 CRITICAL — john.doe@example.com: rol Owner a nivel de suscripción
  ✗ AZURE-IAM-002 HIGH     — sp-legacy-deploy: Service Principal con rol Owner
  ✓ Sin usuarios Guest con roles privilegiados

  → Auditando Storage Accounts...
  ✗ AZURE-STOR-001 HIGH    — storage-public-demo: acceso público a blobs habilitado
  ✗ AZURE-STOR-002 HIGH    — storage-legacy-logs: tráfico HTTP (sin cifrar) permitido
  ✓ TLS 1.2 configurado en 3 de 3 Storage Accounts restantes

  → Auditando Network Security Groups...
  ✗ AZURE-NSG-001 CRITICAL — nsg-dev-open: RDP (3389) expuesto a 0.0.0.0/0
  ✗ AZURE-NSG-001 CRITICAL — nsg-legacy-mgmt: SSH (22) expuesto a 0.0.0.0/0

  → Auditando Key Vault...
  ✗ AZURE-KV-001 HIGH      — kv-prod-secrets: Soft Delete no habilitado
  ✗ AZURE-KV-003 HIGH      — kv-dev-api: accesible desde cualquier red (sin restricciones)

  → Auditando Microsoft Defender for Cloud...
  ✗ AZURE-DEF-001 HIGH     — Defender for Servers: no activo
  ✓ Contacto de seguridad configurado

  ╭─ Resumen de Auditoría ────────────────────────────╮
  │  Calificación global:   D                         │
  │  🔴 Critical: 3   🟠 High: 7   🟡 Medium: 2      │
  │  Total hallazgos: 12   Módulos: 7   Duración: 11.4s│
  ╰───────────────────────────────────────────────────╯

  Exit code: 2  (CRITICAL findings detected)
```

## Why vamp-azure-audit vs Prowler · ScoutSuite · Microsoft Defender for Cloud

| Feature | vamp-azure-audit | Prowler | ScoutSuite | MS Defender for Cloud |
|---------|-----------------|---------|------------|----------------------|
| Direct Azure REST API (no SDK) | ✅ | ⚠️ (Azure SDK) | ⚠️ (Azure SDK) | ❌ (Azure-native) |
| Portable offline CLI | ✅ | ⚠️ | ⚠️ | ❌ (portal only) |
| CIS Azure Benchmark aligned | ✅ | ✅ | ✅ | ✅ (subset) |
| MCSB (Microsoft Cloud Security Benchmark) | ✅ | ⚠️ partial | ⚠️ partial | ✅ |
| AKS security checks | ✅ | ✅ | ⚠️ | ✅ |
| Guest user privilege detection via Graph API | ✅ | ⚠️ | ⚠️ | ✅ |
| VSL client report (HTML/PDF) | ✅ | ⚠️ HTML | ⚠️ HTML | ❌ (portal only) |
| CI/CD exit codes (0/1/2) | ✅ | ✅ | ⚠️ | ❌ |
| Works without Azure portal access | ✅ | ✅ | ✅ | ❌ |
| License | AGPL-3.0 | Apache 2.0 | GPL-2.0 | proprietary |

**Key differentiators:**

- **Raw Azure REST API**: calls `management.azure.com` and `graph.microsoft.com` directly via aiohttp — no Azure SDK, no `az` CLI install required. Minimal dependency footprint suitable for CI container images.
- **Guest user privilege detection**: queries Microsoft Graph `User.Read.All` to detect external (Guest) accounts holding Owner/Contributor/User Access Administrator roles — a misconfiguration that SDK-only tools relying solely on ARM RBAC often miss.
- **23 finding types across 7 modules in one pass**: IAM, Storage, AKS, App Services, NSG, Key Vault, and Defender for Cloud audited asynchronously with severity-graded Rich console output.
- **Portable engagement tool**: a Service Principal with `Reader` + `Microsoft.Security/pricings/read` + `User.Read.All` is the full permission requirement. No Azure portal, no Defender subscription, no additional agents to deploy.

## Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| AZURE-IAM-001 | User account with Owner or Contributor role at subscription scope | CIS Azure 1.21 / MCSB IM-2 | CRITICAL |
| AZURE-IAM-002 | Service Principal with Owner role at subscription scope | CIS Azure 1.22 / MCSB IM-2 | HIGH |
| AZURE-IAM-003 | Guest (external) user with privileged role assignment | CIS Azure 1.3 / MCSB IM-1 | HIGH |
| AZURE-STOR-001 | Storage Account with public blob access enabled | CIS Azure 3.7 / MCSB DP-1 / NIST SP 800-53 AC-3 | HIGH |
| AZURE-STOR-002 | Storage Account permitting unencrypted HTTP traffic | CIS Azure 3.1 / MCSB DP-3 | HIGH |
| AZURE-STOR-003 | Storage Account without network access restrictions configured | CIS Azure 3.8 / NIST SP 800-53 SC-7 | MEDIUM |
| AZURE-STOR-004 | Minimum TLS version below 1.2 on Storage Account | CIS Azure 3.15 / MCSB NS-8 | MEDIUM |
| AZURE-AKS-001 | RBAC disabled on AKS cluster | CIS Azure 8.5 / MCSB IM-8 | CRITICAL |
| AZURE-AKS-002 | AKS API server endpoint publicly accessible | CIS Azure 8.2 / MCSB NS-1 | HIGH |
| AZURE-AKS-003 | No NetworkPolicy configured on AKS cluster | CIS Azure 8.6 / MCSB NS-2 | HIGH |
| AZURE-NSG-001 | Critical port (SSH/RDP/WinRM) exposed to `0.0.0.0/0` via NSG rule | CIS Azure 6.1 / MCSB NS-1 | CRITICAL |
| AZURE-NSG-002 | NSG rule allows all inbound traffic from any source | CIS Azure 6.x / NIST SP 800-53 SC-7 | CRITICAL |
| AZURE-KV-001 | Key Vault without Soft Delete enabled | CIS Azure 8.4 / MCSB DP-8 | HIGH |
| AZURE-KV-003 | Key Vault accessible from any network (no firewall restrictions) | CIS Azure 8.7 / MCSB NS-2 | HIGH |
| AZURE-DEF-001 | Microsoft Defender plan not active for a monitored service tier | CIS Azure 2.x / MCSB LT-1 | HIGH |
| AZURE-DEF-002 | No security contact email configured in Defender for Cloud | CIS Azure 2.14 / MCSB IR-2 | MEDIUM |

## Versión
v1.1 — VampSecure Labs Security Research Division
