# SOC Sentinel — Security Log Analyzer & Forensic Reporting

Plataforma web de ciberseguridad para analistas de **SOC Nivel 2**, orientada al análisis forense de logs exportados de SIEMs, enriquecimiento de telemetría mediante **Threat Intelligence (VirusTotal & AbuseIPDB)** y generación automatizada de informes técnicos y ejecutivos en PDF.

---

## 🚀 Características Principales

### 1. Pantalla de Carga & Visualización (.xlsx SIEM)
- **Importación universal de archivos Excel (.xlsx)**: Mapeo inteligente de cabeceras SIEM heterogéneas (`Timestamp`, `Source_IP`, `Destination_IP`, `User`, `Action`, `Event_Type`, `Severity`, `Message`, `Device`, etc.).
- **Vista previa interactiva**: Tabla de registros con filtrado en tiempo real por usuario, dirección IP o tipo de evento.
- **Escenario de prueba inmediato**: Botón integrado para cargar un dataset simulado de incidentes corporativos reales (fuerza bruta, escalamiento de privilegios, movimiento lateral y comandos anómalos).
- **Descarga de plantilla**: Permite generar y descargar una plantilla `.xlsx` directamente desde el navegador.

### 2. Dashboard de Ciberseguridad Interactivo
- **KPIs clave**: Total de registros analizados, hallazgos categorizados por criticidad (Crítico, Alto, Medio, Bajo), IPs origen únicas y cuentas de usuario activas.
- **Telemetría de Threat Intelligence**: Banner de estado con total de IPs consultadas y detección de hosts maliciosos externos.
- **Gráficos interactivos (Recharts)**:
  - Ratio de criticidad de eventos (Gráfico de pastel/dona) con tooltips optimizados para temas claro y oscuro.
  - Distribución de hallazgos por tácticas y técnicas de ataque (Gráfico de barras horizontal).
  - Línea de tiempo de eventos por severidad (Gráfico de área acumulada temporal).
  - Ranking de principales IPs origen con distintivos de reputación (**VirusTotal** y **AbuseIPDB**).
  - Clasificación de eventos según su acción o categoría SIEM.

### 3. Motor Analítico Forense con Rigor Cero-Alucinación
El motor correlaciona registros inmutables sin inventar datos, sustentando cada hallazgo con los IDs de log de origen:
1. **Fuerza Bruta (MITRE ATT&CK T1110)**: Detecta ráfagas de autenticaciones fallidas por IP y usuario en ventanas temporales estrechas, alertando con criticidad máxima si hubo un inicio de sesión exitoso posterior al ataque.
2. **Inicios de Sesión Sospechosos (MITRE ATT&CK T1078)**: Identifica "viajes imposibles" y alternancias rápidas de IP pública (< 5 minutos), además de accesos repetidos en horarios no laborales (22:00 a 06:00).
3. **Escalamiento de Privilegios (MITRE ATT&CK T1078.002)**: Detecta uso de privilegios sensibles (`SeDebugPrivilege`, `sudo`, `runas`) y modificaciones no autorizadas en grupos de administración (`Domain Admins`).
4. **Ejecución de Comandos Anómalos (MITRE ATT&CK T1059 / T1059.001)**: Identifica PowerShell ofuscado (`-EncodedCommand`, `-w hidden`, `downloadstring`), utilidades de reconocimiento (`whoami`, `systeminfo`), herramientas ofensivas (`mimikatz`, `psexec`) y utilidades de exfiltración.
5. **Movimiento Lateral (MITRE ATT&CK T1021 / T1550.002)**: Correlaciona accesos remotos entre múltiples estaciones de trabajo vía SMB/RDP/WinRM con indicadores de Pass-the-Hash y relay de credenciales.
- **Inspector de logs relacionados**: Modal para auditar y revisar línea por línea los registros exactos que justifican cada hallazgo.

### 4. Inteligencia de Amenazas Externa (VirusTotal & AbuseIPDB)
- **Consulta de reputación para Source IPs**:
  - **AbuseIPDB (API v2)**: Puntuación de confianza de abuso (`Abuse Confidence Score`), volumen histórico de reportes maliciosos, proveedor de servicios de Internet (`ISP`), tipo de uso (`usageType`) y país de origen.
  - **VirusTotal (API v3)**: Motores de seguridad que catalogan la IP como maliciosa (`last_analysis_stats`), ratio de detección sobre proveedores globales (ej. `16/94 vendors`) y reputación del sistema autónomo (`AS Owner`).
- **Arquitectura Segura (Cero localStorage / Protección contra XSS)**:
  - Las claves de API **NUNCA** se almacenan en el `localStorage` del navegador para evitar su extracción por código JavaScript no autorizado.
  - **Variables de Entorno del Servidor (`.env.local`)**: Modo recomendado donde `process.env.ABUSEIPDB_API_KEY` y `process.env.VIRUSTOTAL_API_KEY` se ejecutan exclusivamente en el entorno de backend de Next.js sin exponerse al cliente.
  - **Cookies de Sesión Seguras `HttpOnly`**: Si el analista ingresa claves desde la interfaz, se envían al endpoint `/api/threat-intel/keys` que establece cookies con directivas `HttpOnly`, `SameSite=Strict` y `Secure`, inaccesibles para cualquier script de cliente vía `document.cookie`.
- **Filtrado RFC 1918 automático**: Las IPs de subredes privadas (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`, nombres de host internos) se categorizan instantáneamente como `Private`, evitando consumo innecesario de cuota de API.
- **Modo demostración SOC**: Si el usuario no ha ingresado claves personales, la plataforma provee telemetría de laboratorio de alta fidelidad para IPs atacantes conocidas (ej. `198.51.100.45`), permitiendo evaluar la plataforma de inmediato.
- **Elevación de confianza**: Los hallazgos cuyas direcciones IP origen sean corroboradas como maliciosas elevan automáticamente su puntaje de confianza e incorporan evidencia de Threat Intel en los indicadores.

### 5. Módulo de Reportes & Exportación PDF
- **Tipos de informe**:
  - **Resumen Ejecutivo**: Dirigido a directivos y C-Level (narrativa clara no técnica, impacto comercial estimado en confidencialidad, continuidad operativa, cumplimiento y reputación, y plan de acción priorizado).
  - **Reporte Técnico**: Dirigido a equipos de respuesta a incidentes y SOC (mapeo MITRE ATT&CK, justificación técnica, lista de IoCs, bloque de Threat Intel VirusTotal/AbuseIPDB, tabla enriquecida de IPs origen y telemetría forense).
- **Selección granular por criticidad**: Filtros por severidad (Crítico, Alto, Medio, Bajo), preajustes rápidos y selección individual de alertas a incluir en el reporte.
- **Soporte Bilingüe Sincronizado**: Generación en **Inglés** o **Español**, sincronizado con el idioma activo de la aplicación.
- **Exportación en PDF**: Generado localmente con `jsPDF` y `jspdf-autotable`.

---

## 🛠️ Stack Tecnológico

- **Framework**: [Next.js](https://nextjs.org/) 15 (App Router, React 19)
- **Lenguaje**: TypeScript
- **Estilos**: Tailwind CSS (soporte nativo para Tema Oscuro y Claro)
- **Threat Intelligence**: VirusTotal v3 API & AbuseIPDB v2 API (Backend Proxy & HttpOnly Session Cookies)
- **Procesamiento de Hojas de Cálculo**: [SheetJS (xlsx)](https://docs.sheetjs.com/)
- **Visualización de Datos**: [Recharts](https://recharts.org/)
- **Generación de PDFs**: [jsPDF](https://github.com/parallax/jsPDF) & [jspdf-autotable](https://github.com/simonbengtsson/jsPDF-AutoTable)
- **Iconografía**: [Lucide React](https://lucide.dev/)

---

## 💻 Configuración de Claves de API & Ejecución

### Opción 1: Variables de Entorno del Servidor (Recomendado)
Cree un archivo `.env.local` en la raíz del proyecto (basado en `.env.example`):

```env
ABUSEIPDB_API_KEY=su_clave_abuseipdb_aqui
VIRUSTOTAL_API_KEY=su_clave_virustotal_aqui
```

### Opción 2: Sesión Dinámica desde la UI
Abra el modal de **Threat Intelligence** en la app. Las claves ingresadas se almacenan únicamente en una cookie de sesión con el atributo `HttpOnly`, inaccesible para JavaScript en el navegador.

### Iniciar el servidor:

```bash
# Servidor de desarrollo
npm run dev

# Servidor de producción
npm run build
npm run start
```
