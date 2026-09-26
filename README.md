<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
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

## Versión
v1.1 — VampSecure Labs Security Research Division
