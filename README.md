# SOC Sentinel — Security Log Analyzer & Forensic Reporting

Plataforma web de ciberseguridad para analistas de **SOC Nivel 2**, orientada al análisis forense de logs exportados de SIEMs y a la generación automatizada de informes técnicos y ejecutivos en PDF.

---

## 🚀 Características Principales

### 1. Pantalla de Carga & Visualización (.xlsx SIEM)
- **Importación universal de archivos Excel (.xlsx)**: Mapeo inteligente de cabeceras SIEM heterogéneas (`Timestamp`, `Source_IP`, `Destination_IP`, `User`, `Action`, `Event_Type`, `Severity`, `Message`, `Device`, etc.).
- **Vista previa interactiva**: Tabla de registros con filtrado en tiempo real por usuario, dirección IP o tipo de evento.
- **Escenario de prueba inmediato**: Botón integrado para cargar un dataset simulado de incidentes corporativos reales (fuerza bruta, escalamiento de privilegios, movimiento lateral y comandos anómalos).
- **Descarga de plantilla**: Permite generar y descargar una plantilla `.xlsx` directamente desde el navegador.

### 2. Dashboard de Ciberseguridad Interactivo
- **KPIs clave**: Total de registros analizados, hallazgos categorizados por criticidad (Crítico, Alto, Medio, Bajo), IPs origen únicas y cuentas de usuario activas.
- **Gráficos interactivos (Recharts)**:
  - Ratio de criticidad de eventos (Gráfico de pastel/dona).
  - Distribución de hallazgos por tácticas y técnicas de ataque (Gráfico de barras horizontal).
  - Línea de tiempo de eventos por severidad (Gráfico de área acumulada temporal).
  - Ranking de principales IPs origen y usuarios con mayor actividad volumétrica.
  - Clasificación de eventos según su acción o categoría SIEM.

### 3. Motor Analítico Forense con Rigor Cero-Alucinación
El motor correlaciona registros inmutables sin inventar datos, sustentando cada hallazgo con los IDs de log de origen:
1. **Fuerza Bruta (MITRE ATT&CK T1110)**: Detecta ráfagas de autenticaciones fallidas por IP y usuario en ventanas temporales estrechas, alertando con criticidad máxima si hubo un inicio de sesión exitoso posterior al ataque.
2. **Inicios de Sesión Sospechosos (MITRE ATT&CK T1078)**: Identifica "viajes imposibles" y alternancias rápidas de IP pública (< 5 minutos), además de accesos repetidos en horarios no laborales (22:00 a 06:00).
3. **Escalamiento de Privilegios (MITRE ATT&CK T1078.002)**: Detecta uso de privilegios sensibles (`SeDebugPrivilege`, `sudo`, `runas`) y modificaciones no autorizadas en grupos de administración (`Domain Admins`).
4. **Ejecución de Comandos Anómalos (MITRE ATT&CK T1059 / T1059.001)**: Identifica PowerShell ofuscado (`-EncodedCommand`, `-w hidden`, `downloadstring`), utilidades de reconocimiento (`whoami`, `systeminfo`), herramientas ofensivas (`mimikatz`, `psexec`) y utilidades de exfiltración.
5. **Movimiento Lateral (MITRE ATT&CK T1021 / T1550.002)**: Correlaciona accesos remotos entre múltiples estaciones de trabajo vía SMB/RDP/WinRM con indicadores de Pass-the-Hash y relay de credenciales.
- **Inspector de logs relacionados**: Modal para auditar y revisar línea por línea los registros exactos que justifican cada hallazgo.

### 4. Módulo de Reportes & Exportación PDF
- **Tipos de informe**:
  - **Resumen Ejecutivo**: Dirigido a directivos y C-Level (impacto en el negocio, métricas macro, riesgos prioritarios y recomendaciones estratégicas).
  - **Reporte Técnico**: Dirigido a equipos de respuesta a incidentes y SOC (mapeo MITRE ATT&CK, justificación técnica, lista de IoCs, activos comprometidos y telemetría forense).
- **Soporte Bilingüe**: Generación de reportes en **Inglés** o **Español**.
- **Personalización**: Título, autor/analista, organización y selección granular de hallazgos a incluir.
- **Vista previa en tiempo real**: Visualización del documento antes de exportar.
- **Exportación en PDF**: Generado localmente con `jsPDF` y `jspdf-autotable`.

---

## 🛠️ Stack Tecnológico

- **Framework**: [Next.js](https://nextjs.org/) (App Router, React 19)
- **Lenguaje**: TypeScript
- **Estilos**: Tailwind CSS (diseño moderno, minimalista, modo SOC)
- **Procesamiento de Hojas de Cálculo**: [SheetJS (xlsx)](https://docs.sheetjs.com/)
- **Visualización de Datos**: [Recharts](https://recharts.org/)
- **Generación de PDFs**: [jsPDF](https://github.com/parallax/jsPDF) & [jspdf-autotable](https://github.com/simonbengtsson/jsPDF-AutoTable)
- **Iconografía**: [Lucide React](https://lucide.dev/)

---

## 💻 Instrucciones de Ejecución

Para iniciar el servidor de desarrollo local:

```bash
# En el directorio del proyecto (g:\Projects\Final-Project-BDL2)
npm run dev
```

Abra su navegador en [http://localhost:3000](http://localhost:3000).

Para compilar la versión optimizada de producción:

```bash
npm run build
npm run start
```
