<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

  <img src="https://github.com/Vampsecure-Labs/vamp-azure-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>
# vamp-azure-audit

**Microsoft Azure Security Auditor — VampSecure Labs Security Research Division**

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

CLI security audit tool for Microsoft Azure environments. Detects critical misconfigurations in IAM, Storage Accounts, AKS, App Services, Network Security Groups, Key Vault, and Microsoft Defender for Cloud using exclusively the official Azure REST API (no heavy SDKs required).

> **FOR USE EXCLUSIVELY IN ENVIRONMENTS WITH EXPLICIT AUTHORIZATION.**
> This tool is designed for authorized security assessments. Its use in unauthorized environments may be illegal.

---

### Installation

```bash
pip install vamp-azure-audit
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-azure-audit
```

Or from the repository:

```bash
git clone https://github.com/Vampsecure-Labs/vamp-azure-audit
cd vamp-azure-audit
pip install -e .
```

**Dependencies:** `aiohttp>=3.9.0`, `rich>=13.7.0`, Python 3.9+

---

### Configuration

The Service Principal requires the following permissions:

- **Management API:** `Reader` role on the subscription + `Microsoft.Security/pricings/read`
- **Microsoft Graph:** `User.Read.All` (for detecting Guest users with privileged roles)

Create Service Principal with Reader role:

```bash
az ad sp create-for-rbac --name "vamp-azure-audit" --role "Reader" \
  --scopes /subscriptions/<SUBSCRIPTION_ID>
```

---

### Environment Variables

| Variable                | Description                                      |
|-------------------------|--------------------------------------------------|
| `AZURE_SUBSCRIPTION_ID` | ID of the Azure subscription to audit            |
| `AZURE_TENANT_ID`       | Azure tenant ID (Directory ID)                   |
| `AZURE_CLIENT_ID`       | Application (client) ID of the Service Principal |
| `AZURE_CLIENT_SECRET`   | Service Principal secret                         |

---

### Usage

#### Full audit (all modules)

```bash
export AZURE_SUBSCRIPTION_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AZURE_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AZURE_CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AZURE_CLIENT_SECRET="your-secret"

vamp-azure-audit
```

#### With explicit flags

```bash
vamp-azure-audit \
  --subscription-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --tenant-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --client-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --client-secret "your-secret"
```

#### Specific modules

```bash
# IAM and NSG only
vamp-azure-audit --modulos iam nsg

# Storage and Key Vault only
vamp-azure-audit --modulos storage keyvault

# Defender for Cloud only
vamp-azure-audit --modulos defender
```

#### Export reports

```bash
# Generate HTML report
vamp-azure-audit --output-html azure-report.html

# Generate JSON for integration with other tools
vamp-azure-audit --output-json findings.json

# HTML + JSON in the same pass
vamp-azure-audit --output-html report.html --output-json findings.json
```

---

### Available Modules

| Module        | Flag           | Description                                                       |
|---------------|----------------|-------------------------------------------------------------------|
| IAM           | `iam`          | Privileged roles at subscription level, Guest users              |
| Storage       | `storage`      | Public blob access, HTTP, TLS, network restrictions               |
| AKS           | `aks`          | RBAC, public API server, NetworkPolicy, outdated versions        |
| App Services  | `appservices`  | HTTPS, remote debugging, TLS, unencrypted FTP                    |
| NSG           | `nsg`          | Critical ports exposed to the Internet, open rules               |
| Key Vault     | `keyvault`     | Soft Delete, Purge Protection, network access                    |
| Defender      | `defender`     | Defender for Cloud plans, security contact                       |

---

### Detected Findings

| ID             | Severity | Description                                                |
|----------------|-----------|------------------------------------------------------------|
| AZURE-IAM-001  | CRITICAL  | User with Owner/Contributor role at subscription scope     |
| AZURE-IAM-002  | HIGH      | Service Principal with Owner role at subscription scope    |
| AZURE-IAM-003  | HIGH      | Guest user with privileged roles                           |
| AZURE-STOR-001 | HIGH      | Public blob access enabled                                 |
| AZURE-STOR-002 | HIGH      | Unencrypted HTTP traffic allowed                           |
| AZURE-STOR-003 | MEDIUM    | No network restrictions on Storage Account                 |
| AZURE-STOR-004 | MEDIUM    | Minimum TLS version below 1.2                              |
| AZURE-AKS-001  | CRITICAL  | RBAC disabled on AKS cluster                               |
| AZURE-AKS-002  | HIGH      | AKS API server publicly accessible                         |
| AZURE-AKS-003  | HIGH      | No NetworkPolicy configured                                |
| AZURE-AKS-004  | MEDIUM    | Outdated Kubernetes version                                |
| AZURE-APP-001  | HIGH      | App Service does not enforce HTTPS                         |
| AZURE-APP-002  | HIGH      | Remote debugging enabled                                   |
| AZURE-APP-003  | MEDIUM    | Minimum TLS below 1.2 on App Service                       |
| AZURE-APP-004  | MEDIUM    | Unencrypted FTP enabled                                    |
| AZURE-NSG-001  | CRITICAL  | Critical port exposed to the Internet (0.0.0.0/0)         |
| AZURE-NSG-002  | CRITICAL  | NSG rule allows all inbound traffic                        |
| AZURE-KV-001   | HIGH      | Soft Delete not enabled on Key Vault                       |
| AZURE-KV-002   | MEDIUM    | Purge Protection not enabled                               |
| AZURE-KV-003   | HIGH      | Key Vault accessible from any network                      |
| AZURE-KV-004   | HIGH      | Public access enabled without restrictions                 |
| AZURE-DEF-001  | HIGH      | Microsoft Defender not active for a service                |
| AZURE-DEF-002  | MEDIUM    | No security contact configured                             |

---

### Sample Output

```
$ vamp-azure-audit

  vamp-azure-audit v1.2  —  Azure Security Auditor
  VampSecure Labs Security Research Division

  → Authenticating to Azure...
  ✓ Management API token obtained
  ✓ Microsoft Graph token obtained
  ✓ Subscription: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx  (example-corp)

  → Auditing IAM / Roles...
  ✗ AZURE-IAM-001 CRITICAL — john.doe@example.com: Owner role at subscription scope
  ✗ AZURE-IAM-002 HIGH     — sp-legacy-deploy: Service Principal with Owner role
  ✓ No Guest users with privileged roles

  → Auditing Storage Accounts...
  ✗ AZURE-STOR-001 HIGH    — storage-public-demo: public blob access enabled
  ✗ AZURE-STOR-002 HIGH    — storage-legacy-logs: unencrypted HTTP traffic allowed
  ✓ TLS 1.2 configured on 3 of 3 remaining Storage Accounts

  → Auditing Network Security Groups...
  ✗ AZURE-NSG-001 CRITICAL — nsg-dev-open: RDP (3389) exposed to 0.0.0.0/0
  ✗ AZURE-NSG-001 CRITICAL — nsg-legacy-mgmt: SSH (22) exposed to 0.0.0.0/0

  → Auditing Key Vault...
  ✗ AZURE-KV-001 HIGH      — kv-prod-secrets: Soft Delete not enabled
  ✗ AZURE-KV-003 HIGH      — kv-dev-api: accessible from any network (no restrictions)

  → Auditing Microsoft Defender for Cloud...
  ✗ AZURE-DEF-001 HIGH     — Defender for Servers: not active
  ✓ Security contact configured

  ╭─ Audit Summary ───────────────────────────────────╮
  │  Global rating:   D                               │
  │  🔴 Critical: 3   🟠 High: 7   🟡 Medium: 2      │
  │  Total findings: 12   Modules: 7   Duration: 11.4s│
  ╰───────────────────────────────────────────────────╯

  Exit code: 2  (CRITICAL findings detected)
```

---

### Exit Codes

| Code | Meaning                                          |
|------|--------------------------------------------------|
| `0`  | No CRITICAL or HIGH findings                     |
| `1`  | HIGH findings detected (no CRITICAL)             |
| `2`  | CRITICAL findings detected                       |

Useful for CI/CD pipeline integration:

```bash
vamp-azure-audit --output-json findings.json
if [ $? -eq 2 ]; then
  echo "BLOCKED: Critical findings in Azure"
  exit 1
fi
```

---

### Why vamp-azure-audit vs Prowler · ScoutSuite · Microsoft Defender for Cloud

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

### Check Coverage

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

### Version History

| Version | Main changes |
|---------|-------------|
| v1.2 | Bilingual README (EN/ES) |
| v1.1 | Initial public release: 7 modules, 23 findings, direct Azure REST API, no SDK dependency |

---

© VampSecure Studios — VampSecure Labs Security Research Division  
For use in authorized audits only. Unauthorized use is illegal.

---

<a name="español"></a>
## 🇪🇸 Español

Herramienta CLI de auditoría de seguridad para entornos Microsoft Azure. Detecta misconfiguraciones críticas en IAM, Storage Accounts, AKS, App Services, Network Security Groups, Key Vault y Microsoft Defender for Cloud utilizando exclusivamente la REST API oficial de Azure (sin SDKs pesados).

> **USO EXCLUSIVO EN ENTORNOS CON AUTORIZACIÓN EXPRESA.**
> Esta herramienta está diseñada para evaluaciones de seguridad autorizadas. Su uso en entornos sin autorización puede ser ilegal.

---

### Instalación

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

### Configuración

El Service Principal necesita los siguientes permisos:

- **Management API:** rol `Reader` en la suscripción + `Microsoft.Security/pricings/read`
- **Microsoft Graph:** `User.Read.All` (para detección de usuarios Guest con privilegios)

Crear Service Principal con rol Reader:

```bash
az ad sp create-for-rbac --name "vamp-azure-audit" --role "Reader" \
  --scopes /subscriptions/<SUBSCRIPTION_ID>
```

---

### Variables de entorno

| Variable                | Descripción                                      |
|-------------------------|--------------------------------------------------|
| `AZURE_SUBSCRIPTION_ID` | ID de la suscripción Azure a auditar             |
| `AZURE_TENANT_ID`       | ID del tenant de Azure (Directory ID)            |
| `AZURE_CLIENT_ID`       | Application (client) ID del Service Principal   |
| `AZURE_CLIENT_SECRET`   | Secreto del Service Principal                    |

---

### Uso

#### Auditoría completa (todos los módulos)

```bash
export AZURE_SUBSCRIPTION_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AZURE_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AZURE_CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AZURE_CLIENT_SECRET="tu-secreto"

vamp-azure-audit
```

#### Con flags explícitos

```bash
vamp-azure-audit \
  --subscription-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --tenant-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --client-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --client-secret "tu-secreto"
```

#### Módulos específicos

```bash
# Solo IAM y NSG
vamp-azure-audit --modulos iam nsg

# Solo Storage y Key Vault
vamp-azure-audit --modulos storage keyvault

# Solo Defender for Cloud
vamp-azure-audit --modulos defender
```

#### Exportar informes

```bash
# Generar informe HTML
vamp-azure-audit --output-html informe-azure.html

# Generar JSON para integración con otras herramientas
vamp-azure-audit --output-json hallazgos.json

# HTML + JSON en el mismo pase
vamp-azure-audit --output-html informe.html --output-json hallazgos.json
```

---

### Módulos disponibles

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

### Hallazgos detectados

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

### Ejemplo de salida

```
$ vamp-azure-audit

  vamp-azure-audit v1.2  —  Azure Security Auditor
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

  Exit code: 2  (hallazgos CRITICAL detectados)
```

---

### Códigos de salida

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

### Why vamp-azure-audit vs Prowler · ScoutSuite · Microsoft Defender for Cloud

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

**Diferenciadores clave:**

- **API REST de Azure directa**: llama a `management.azure.com` y `graph.microsoft.com` directamente mediante aiohttp — sin Azure SDK ni instalación de `az` CLI. Superficie de dependencias mínima apta para imágenes de contenedores CI.
- **Detección de privilegios en usuarios Guest**: consulta Microsoft Graph `User.Read.All` para detectar cuentas externas (Guest) con roles de Owner/Contributor/User Access Administrator — una misconfiguración que herramientas que dependen solo de ARM RBAC suelen pasar por alto.
- **23 tipos de hallazgos en 7 módulos en un solo pase**: IAM, Storage, AKS, App Services, NSG, Key Vault y Defender for Cloud auditados de forma asíncrona con salida de consola Rich graduada por severidad.
- **Herramienta de compromiso portable**: un Service Principal con `Reader` + `Microsoft.Security/pricings/read` + `User.Read.All` es el requisito de permisos completo. Sin portal Azure, sin suscripción a Defender, sin agentes adicionales que desplegar.

### Cobertura de checks

| Check ID | Descripción | Estándar | Severidad |
|----------|-------------|----------|-----------|
| AZURE-IAM-001 | Cuenta de usuario con rol Owner o Contributor a nivel de suscripción | CIS Azure 1.21 / MCSB IM-2 | CRITICAL |
| AZURE-IAM-002 | Service Principal con rol Owner a nivel de suscripción | CIS Azure 1.22 / MCSB IM-2 | HIGH |
| AZURE-IAM-003 | Usuario Guest (externo) con asignación de rol privilegiado | CIS Azure 1.3 / MCSB IM-1 | HIGH |
| AZURE-STOR-001 | Storage Account con acceso público a blobs habilitado | CIS Azure 3.7 / MCSB DP-1 / NIST SP 800-53 AC-3 | HIGH |
| AZURE-STOR-002 | Storage Account que permite tráfico HTTP sin cifrar | CIS Azure 3.1 / MCSB DP-3 | HIGH |
| AZURE-STOR-003 | Storage Account sin restricciones de acceso de red configuradas | CIS Azure 3.8 / NIST SP 800-53 SC-7 | MEDIUM |
| AZURE-STOR-004 | Versión TLS mínima inferior a 1.2 en Storage Account | CIS Azure 3.15 / MCSB NS-8 | MEDIUM |
| AZURE-AKS-001 | RBAC deshabilitado en clúster AKS | CIS Azure 8.5 / MCSB IM-8 | CRITICAL |
| AZURE-AKS-002 | Endpoint del API server de AKS accesible públicamente | CIS Azure 8.2 / MCSB NS-1 | HIGH |
| AZURE-AKS-003 | Sin NetworkPolicy configurada en el clúster AKS | CIS Azure 8.6 / MCSB NS-2 | HIGH |
| AZURE-NSG-001 | Puerto crítico (SSH/RDP/WinRM) expuesto a `0.0.0.0/0` vía regla NSG | CIS Azure 6.1 / MCSB NS-1 | CRITICAL |
| AZURE-NSG-002 | Regla NSG que permite todo el tráfico entrante desde cualquier origen | CIS Azure 6.x / NIST SP 800-53 SC-7 | CRITICAL |
| AZURE-KV-001 | Key Vault sin Soft Delete habilitado | CIS Azure 8.4 / MCSB DP-8 | HIGH |
| AZURE-KV-003 | Key Vault accesible desde cualquier red (sin restricciones de firewall) | CIS Azure 8.7 / MCSB NS-2 | HIGH |
| AZURE-DEF-001 | Plan de Microsoft Defender no activo para un nivel de servicio monitorizado | CIS Azure 2.x / MCSB LT-1 | HIGH |
| AZURE-DEF-002 | Sin correo electrónico de contacto de seguridad configurado en Defender for Cloud | CIS Azure 2.14 / MCSB IR-2 | MEDIUM |

### Licencia

AGPL-3.0 License — Copyright © VampSecure Studios — VampSecure Labs Security Research Division

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.2 | README bilingüe (EN/ES) |
| v1.1 | Primera versión pública: 7 módulos, 23 hallazgos, API REST de Azure directa, sin dependencia SDK |

---

© VampSecure Studios — VampSecure Labs Security Research Division
