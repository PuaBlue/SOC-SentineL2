const fs = require('fs');
const path = require('path');
const { jsPDF } = require('jspdf');
require('jspdf-autotable');
const sharp = require('sharp');

// Paths to images
const IMG_DOJO_LOGO = 'C:/Users/angel/.gemini/antigravity/brain/e90af595-42e9-43eb-87d8-fd39c795df27/scratch/docx_extracted/word/media/image1.png';
const IMG_IMPORTER = 'C:/Users/angel/.gemini/antigravity/brain/e90af595-42e9-43eb-87d8-fd39c795df27/scratch/docx_extracted/word/media/image2.png';
const IMG_PS_ERROR = 'C:/Users/angel/.gemini/antigravity/brain/e90af595-42e9-43eb-87d8-fd39c795df27/scratch/docx_extracted/word/media/image3.png';
const IMG_DASHBOARD = 'C:/Users/angel/.gemini/antigravity/brain/e90af595-42e9-43eb-87d8-fd39c795df27/scratch/docx_extracted/word/media/image4.png';
const IMG_THREAT_INTEL = 'C:/Users/angel/.gemini/antigravity/brain/e90af595-42e9-43eb-87d8-fd39c795df27/.user_uploaded/media_1793982589456_8218c838.png';
const IMG_ANALYSIS_VIEW = 'C:/Users/angel/.gemini/antigravity/brain/e90af595-42e9-43eb-87d8-fd39c795df27/.user_uploaded/media_1794020162782_82d68cbb.jpg';

const GITHUB_REPO_URL = 'https://github.com/PuaBlue/SOC-SentineL2';

async function getImageBase64(filePath, maxW = 1200) {
  if (fs.existsSync(filePath)) {
    if (filePath.endsWith('image1.png')) {
      const buf = await sharp(filePath).resize({ width: 800, withoutEnlargement: true }).png().toBuffer();
      return `data:image/png;base64,${buf.toString('base64')}`;
    }
    const buf = await sharp(filePath)
      .resize({ width: maxW, withoutEnlargement: true })
      .jpeg({ quality: 82 })
      .toBuffer();
    return `data:image/jpeg;base64,${buf.toString('base64')}`;
  }
  return null;
}

async function generatePDF() {
  const logoBase64 = await getImageBase64(IMG_DOJO_LOGO);
  const importerBase64 = await getImageBase64(IMG_IMPORTER, 1200);
  const psErrorBase64 = await getImageBase64(IMG_PS_ERROR, 800);
  const dashboardBase64 = await getImageBase64(IMG_DASHBOARD, 1200);
  const threatIntelBase64 = await getImageBase64(IMG_THREAT_INTEL, 1200);
  const analysisViewBase64 = await getImageBase64(IMG_ANALYSIS_VIEW, 1200);

  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = 210;
  const pageHeight = 297;
  const margin = 14;
  const contentWidth = pageWidth - margin * 2; // 182 mm
  let currentY = 16;

  function ensureSpace(neededHeight) {
    if (currentY + neededHeight > pageHeight - 18) {
      doc.addPage();
      currentY = 22; // leaving space for running header
      return true;
    }
    return false;
  }

  function addSectionTitle(numberStr, titleStr) {
    ensureSpace(16);
    currentY += 4;
    doc.setFillColor(79, 70, 229); // Indigo #4f46e5
    doc.roundedRect(margin, currentY, 7, 7, 1.5, 1.5, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.text(numberStr, margin + 3.5, currentY + 4.8, { align: 'center' });

    doc.setTextColor(15, 23, 42); // Slate #0f172a
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.text(titleStr, margin + 10, currentY + 5.2);
    currentY += 10;
  }

  function addParagraph(text) {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(51, 65, 85);
    const lines = doc.splitTextToSize(text, contentWidth);
    ensureSpace(lines.length * 4.2 + 2);
    doc.text(lines, margin, currentY);
    currentY += lines.length * 4.2 + 2;
  }

  function addBullet(bulletTitle, bulletDesc) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(30, 41, 59);
    const titleText = `• ${bulletTitle}: `;
    
    doc.setFont('helvetica', 'normal');
    const fullText = titleText + bulletDesc;
    const lines = doc.splitTextToSize(fullText, contentWidth - 4);
    ensureSpace(lines.length * 4.2 + 2);

    doc.setFillColor(79, 70, 229);
    doc.circle(margin + 2, currentY - 1, 0.8, 'F');
    
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text(bulletTitle + ':', margin + 4, currentY);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    const titleW = doc.getTextWidth(bulletTitle + ': ');
    const remainingFirstLine = doc.splitTextToSize(bulletDesc, contentWidth - 4 - titleW)[0] || '';
    doc.text(remainingFirstLine, margin + 4 + titleW, currentY);

    if (lines.length > 1) {
      const restLines = lines.slice(1);
      doc.text(restLines, margin + 4, currentY + 4.2);
      currentY += lines.length * 4.2 + 2;
    } else {
      currentY += 5.5;
    }
  }

  function addCodeBox(codeLines, label) {
    doc.setFont('courier', 'normal');
    doc.setFontSize(7.5);
    const splitLines = [];
    codeLines.forEach(l => {
      const wrapped = doc.splitTextToSize(l, contentWidth - 8);
      wrapped.forEach(w => splitLines.push(w));
    });

    const boxHeight = splitLines.length * 3.8 + (label ? 8 : 5);
    ensureSpace(boxHeight + 3);

    doc.setFillColor(15, 23, 42); // Slate 900
    doc.roundedRect(margin, currentY, contentWidth, boxHeight, 2, 2, 'F');
    doc.setDrawColor(51, 65, 85);
    doc.roundedRect(margin, currentY, contentWidth, boxHeight, 2, 2, 'D');

    let textY = currentY + 4;
    if (label) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7);
      doc.setTextColor(148, 163, 184); // Slate 400
      doc.text(label.toUpperCase(), margin + 4, textY);
      textY += 4;
    }

    doc.setFont('courier', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(241, 245, 249); // Slate 100
    splitLines.forEach(l => {
      doc.text(l, margin + 4, textY);
      textY += 3.8;
    });

    currentY += boxHeight + 4;
  }

  function addImageCard(base64Data, widthMm, heightMm, caption) {
    if (!base64Data) return;
    ensureSpace(heightMm + 10);
    
    const x = margin + (contentWidth - widthMm) / 2;
    
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(x - 1, currentY - 1, widthMm + 2, heightMm + 7, 2, 2, 'FD');
    
    const format = base64Data.startsWith('data:image/jpeg') ? 'JPEG' : 'PNG';
    doc.addImage(base64Data, format, x, currentY, widthMm, heightMm);
    
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(7.2);
    doc.setTextColor(100, 116, 139);
    doc.text(caption, margin + contentWidth / 2, currentY + heightMm + 4, { align: 'center' });
    
    currentY += heightMm + 10;
  }

  function addCalloutBox(title, message, type = 'info', linkUrl = null) {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    const lines = doc.splitTextToSize(message, contentWidth - 14);
    const boxHeight = lines.length * 4 + 9;
    ensureSpace(boxHeight + 3);

    let bgColor = [238, 242, 255]; // Indigo 50
    let borderColor = [99, 102, 241]; // Indigo 500
    let titleColor = [67, 56, 202]; // Indigo 700

    if (type === 'danger') {
      bgColor = [255, 241, 242]; // Rose 50
      borderColor = [244, 63, 94]; // Rose 500
      titleColor = [190, 18, 60]; // Rose 700
    } else if (type === 'success') {
      bgColor = [236, 253, 245]; // Emerald 50
      borderColor = [16, 185, 129]; // Emerald 500
      titleColor = [4, 120, 87]; // Emerald 700
    }

    doc.setFillColor(...bgColor);
    doc.roundedRect(margin, currentY, contentWidth, boxHeight, 1.5, 1.5, 'F');
    
    doc.setFillColor(...borderColor);
    doc.rect(margin, currentY, 2.5, boxHeight, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(...titleColor);
    doc.text(title, margin + 6, currentY + 4.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(51, 65, 85);
    doc.text(lines, margin + 6, currentY + 9);

    if (linkUrl) {
      doc.link(margin, currentY, contentWidth, boxHeight, { url: linkUrl });
    }

    currentY += boxHeight + 3;
  }

  // ==========================================
  // 1. HEADER & COVER PAGE
  // ==========================================
  if (logoBase64) {
    const logoW = 60;
    const logoH = logoW / 4.75;
    doc.addImage(logoBase64, 'PNG', margin, currentY, logoW, logoH);
    currentY += logoH + 6;
  }

  doc.setFillColor(238, 242, 255);
  doc.setDrawColor(199, 210, 254);
  doc.roundedRect(margin, currentY, 78, 5.5, 1, 1, 'FD');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(67, 56, 202);
  doc.text('COMUNIDAD DOJO • BOOTCAMP ANALISTA SOC NIVEL 2', margin + 39, currentY + 3.8, { align: 'center' });
  currentY += 9;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(17);
  doc.setTextColor(15, 23, 42);
  doc.text('Desarrollo de Aplicación Web SOC Nivel 2', margin, currentY);
  currentY += 6;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(79, 70, 229);
  doc.text('Plataforma SOC Sentinel L2: Telemetría SIEM, Correlación Forense, CTI y Reportes DFIR', margin, currentY);
  currentY += 5;

  // Dedicated GitHub Repository Card on Header
  doc.setFillColor(15, 23, 42); // Slate 900
  doc.roundedRect(margin, currentY, contentWidth, 10, 2, 2, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(248, 250, 252);
  doc.text('Repositorio Oficial en GitHub:', margin + 4, currentY + 6.2);
  
  doc.setTextColor(129, 140, 248); // Indigo 300
  doc.setFont('courier', 'bold');
  doc.setFontSize(8.5);
  doc.text(GITHUB_REPO_URL, margin + 50, currentY + 6.2);
  const repoWidth = doc.getTextWidth(GITHUB_REPO_URL);
  // Add clickable hyperlink annotation
  doc.link(margin + 50, currentY + 1, repoWidth, 8, { url: GITHUB_REPO_URL });

  // Add a pill on the right
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(pageWidth - margin - 26, currentY + 2, 22, 6, 1, 1, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(6.5);
  doc.setTextColor(52, 211, 153); // Emerald 400
  doc.text('● REPO ACTIVO', pageWidth - margin - 15, currentY + 6, { align: 'center' });

  currentY += 13;

  // Metadata bar
  doc.setFillColor(241, 245, 249);
  doc.roundedRect(margin, currentY, contentWidth, 8, 1.5, 1.5, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.8);
  doc.setTextColor(30, 41, 59);
  doc.text('Autora: Paula Villegas (PuaBlue)', margin + 4, currentY + 5.2);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100, 116, 139);
  doc.text('Entorno: Windows 11 / PowerShell • Rama: main • Versión: v2.0 Consolidada', margin + 54, currentY + 5.2);
  currentY += 11;

  addParagraph('Esta documentación técnica consolida de manera exhaustiva todo el ciclo de vida del proyecto "SOC Sentinel L2", desde la concepción de requerimientos y solución de incidentes de entorno y control de versiones (Git), hasta la ingeniería de software avanzada: el motor de detección determinista sin alucinaciones, la integración de CTI externa (VirusTotal & AbuseIPDB), la resolución de problemas de redes privadas RFC 1918, la construcción de reportes forenses bajo estándares DFIR L2/L3 y la localización completa al español neutro.');

  // ==========================================
  // SECCIÓN 1: DEFINICIÓN DE REQUISITOS Y ARQUITECTURA
  // ==========================================
  addSectionTitle('1', 'Definición de Requisitos y Arquitectura');
  addParagraph('Para dar inicio al proyecto, se formularon los requerimientos funcionales y técnicos necesarios para emular una estación de trabajo de consultoría de ciberseguridad avanzada para un Analista SOC Nivel 2. La meta central consistió en procesar telemetría de logs heterogéneos y transformarla en inteligencia procesable y reportes de respuesta a incidentes.');

  addBullet('Módulo de Carga', 'Soporte para importar archivos Excel (.xlsx) exportados de herramientas SIEM.');
  addBullet('Dashboard Interactivo', 'Visualización de estadísticas y gráficos clasificados por criticidad (Crítico, Alto, Medio, Bajo).');
  addBullet('Motor de Correlación Forense', 'Reglas analíticas basadas en IA/heurísticas para detectar Fuerza Bruta, Inicios Sospechosos, Escalamiento de Privilegios, Comandos Anómalos y Movimiento Lateral con rigor estricto (cero alucinaciones).');
  addBullet('Módulo de Reportes Automatizados', 'Generación de informes ejecutivos (C-Level) y técnicos forenses (DFIR L2 a L3) descargables en PDF.');

  addParagraph('Stack técnico seleccionado: React 19, Next.js 15 (App Router), Tailwind CSS, SheetJS (xlsx), jsPDF / jsPDF-AutoTable, Recharts y Lucide Icons.');

  addCodeBox([
    'Actúa como un desarrollador web experto. Necesito crear una aplicación web de análisis de logs de seguridad y',
    'generación de informes automatizados para un escenario de consultoría de ciberseguridad (SOC Nivel 2).',
    'Los usuarios principales son analistas de seguridad. La aplicación debe tener 4 pantallas principales:',
    '1) Pantalla de carga para importar y visualizar archivos Excel (.xlsx) exportados de un SIEM.',
    '2) Dashboard con estadísticas y gráficos interactivos categorizados por criticidad.',
    '3) Vista de análisis de seguridad para inspeccionar y correlacionar eventos.',
    '4) Módulo de reportes para generar y visualizar informes ejecutivos y técnicos.',
    'A nivel de datos, debe detectar fuerza bruta, inicios de sesión sospechosos, escalamiento de privilegios,',
    'ejecución de comandos anómalos y movimiento lateral. Debe clasificar en riesgo Crítico, Alto, Medio o Bajo con su',
    'debida justificación. Es estrictamente obligatorio mantener el rigor analítico: no inventar hallazgos, todo debe',
    'sustentarse en los registros. Soporte bilingüe (EN/ES) y exportación PDF sin Microsoft Sentinel.'
  ], 'Prompt Inicial de Especificación de Requisitos');

  // ==========================================
  // SECCIÓN 2: CONFIGURACIÓN DEL ENTORNO Y POLÍTICAS POWERSHELL
  // ==========================================
  addSectionTitle('2', 'Configuración del Entorno y Solución de Políticas PowerShell');
  addParagraph('Durante la inicialización del proyecto en la terminal de Windows PowerShell dentro del directorio de trabajo G:\\Projects\\Final-Project-BDL2, se produjo un bloqueo de ejecución al invocar el comando npm run dev debido a las directivas de seguridad nativas del sistema operativo.');

  addCodeBox([
    'PS C:\\WINDOWS\\system32> cd g:\\Projects\\Final-Project-BDL2',
    'PS G:\\Projects\\Final-Project-BDL2> npm run dev',
    'npm : File C:\\Program Files\\nodejs\\npm.ps1 cannot be loaded because running scripts is disabled on this system.',
    'For more information, see about_Execution_Policies at https://go.microsoft.com/fwlink/?LinkID=135170.',
    'At line:1 char:1',
    '+ npm run dev',
    '+ ~~~',
    '    + CategoryInfo          : SecurityError: (:) [], PSSecurityException',
    '    + FullyQualifiedErrorId : UnauthorizedAccess'
  ], 'Error en Terminal de Windows PowerShell');

  if (psErrorBase64) {
    addImageCard(psErrorBase64, 110, 82.7, 'Figura 1: Captura del error de directivas de ejecución de scripts en PowerShell.');
  }

  addCalloutBox(
    'Solución Aplicada — Desbloqueo de Políticas',
    'Se ajustó la directiva de ejecución en PowerShell para autorizar scripts locales y firmados digitalmente mediante el comando: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser. Esto habilitó de inmediato la ejecución de herramientas de Node.js y paquetes npm.',
    'success'
  );

  // ==========================================
  // SECCIÓN 3: INICIALIZACIÓN DEL SERVIDOR LOCAL
  // ==========================================
  addSectionTitle('3', 'Inicialización del Servidor Local de Desarrollo');
  addParagraph('Con las políticas de ejecución debidamente habilitadas, se ejecutó con éxito el script de inicio local:');
  addCodeBox(['npm run dev'], 'Comando de Inicio');
  addParagraph('El servidor de desarrollo de Next.js se levantó en http://localhost:3000, habilitando el renderizado reactivo y la construcción modular de la interfaz gráfica y los estados globales de la aplicación.');

  // ==========================================
  // SECCIÓN 4: CONTROL DE VERSIONES Y VINCULACIÓN A GITHUB
  // ==========================================
  addSectionTitle('4', 'Solución de Errores en la Vinculación Remota con Git');
  addParagraph('Al sincronizar el repositorio local con GitHub se presentaron dos incidencias de protocolo y configuración de ramas:');
  addBullet('Error de Protocolo', 'En la URL del origen remoto (origin) se configuró accidentalmente hhttps:// en lugar de https://.');
  addBullet('Error de Rama', 'El cliente local se encontraba en la rama histórica master, mientras que el repositorio remoto esperaba main.');

  addCodeBox([
    'git remote set-url origin https://github.com/PuaBlue/SOC-SentineL2.git',
    'git branch -M main',
    'git push -u origin main'
  ], 'Comandos de Corrección de Origen y Rama');

  addCalloutBox(
    'Repositorio Remoto Conectado Exitosamente',
    `La URL fue actualizada al protocolo HTTPS estándar y la rama se unificó en main, completando la asociación con el repositorio oficial: ${GITHUB_REPO_URL}.`,
    'success',
    GITHUB_REPO_URL
  );

  // ==========================================
  // SECCIÓN 5: EXCLUSIÓN DE NODE_MODULES Y .GITIGNORE
  // ==========================================
  addSectionTitle('5', 'Gestión del Límite de Archivos en GitHub y Conflicto en .gitignore');
  addParagraph('Al ejecutar el push hacia el repositorio remoto, GitHub rechazó la subida (pre-receive hook declined) indicando que un binario compilado superaba el límite estricto de 100.00 MB:');

  addCodeBox([
    'remote: error: File node_modules/.../next-swc.win32-x64-msvc.node is 141.51 MB;',
    'remote: error: this exceeds GitHub\'s file size limit of 100.00 MB',
    'remote: error: GH001: Large files detected. See http://git.io/iEPt8g for details.'
  ], 'Rechazo de GitHub por Tamaño Excesivo');

  addCalloutBox(
    'Causa Raíz y Conflicto con "git add *"',
    'La carpeta node_modules contenía binarios compilados de Next.js SWC. El comando "git add *" intentaba incluir explícitamente todo el árbol ignorando las directivas del archivo .gitignore, lo que producía la advertencia "The following paths are ignored by one of your .gitignore files: node_modules".',
    'danger'
  );

  addParagraph('Solución aplicada: Se utilizó el comando git add . (con punto), el cual respeta escrupulosamente los patrones de exclusión definidos en .gitignore. Se purgó la carpeta node_modules del historial y se completó la sincronización:');

  addCodeBox([
    'git rm -r --cached node_modules',
    'git add .',
    'git commit -m "Fix: configurar .gitignore correctamente y excluir dependencias"',
    'git pull origin main --rebase',
    'git push -u origin main'
  ], 'Resolución y Subida Exitosa a GitHub');

  // ==========================================
  // SECCIÓN 6: MÓDULO DE INGESTA SIEM (UPLOAD VIEW)
  // ==========================================
  addSectionTitle('6', 'Módulo de Ingesta y Normalización de Telemetría SIEM');
  addParagraph('Se desarrolló el componente UploadView con capacidades drag-and-drop para ingerir archivos Excel (.xlsx) exportados de herramientas SIEM corporativas (Splunk, Elastic SIEM, Microsoft Sentinel, QRadar).');

  addBullet('Parser Inteligente (SheetJS)', 'Normaliza columnas heterogéneas (Timestamp, Event ID, User, Source IP, Destination IP, Process Name, CommandLine, Message).');
  addBullet('Dataset de Pruebas Multi-Incidente', 'Se incorporó el dataset SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx con 715 registros crudos que cubren escenarios de amenazas reales.');
  addBullet('Plantilla Descargable', 'Permite a los analistas descargar un archivo .xlsx plantilla con la estructura ideal requerida para la auditoría.');

  if (importerBase64) {
    addImageCard(importerBase64, 150, 79.6, 'Figura 2: Pantalla de carga e importación de telemetría SIEM (Upload View).');
  }

  // ==========================================
  // SECCIÓN 7: MOTOR DE CORRELACIÓN FORENSE DETERMINISTA
  // ==========================================
  addSectionTitle('7', 'Motor de Correlación Forense Determinista (Zero-Hallucination)');
  addParagraph('Uno de los mayores requerimientos del proyecto fue asegurar el rigor analítico: la plataforma no debía inventar hallazgos. Se diseñó el motor securityEngine.ts, el cual procesa los logs cronológicamente y aplica heurísticas forenses auditables y mapeadas a la matriz MITRE ATT&CK:');

  // Table of Threat Vectors
  doc.autoTable({
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'grid',
    head: [['Vector de Amenaza', 'Táctica MITRE', 'Técnica', 'Patrón Detectado en Telemetría', 'Criticidad']],
    body: [
      ['Fuerza Bruta (Brute Force)', 'Credential Access', 'T1110.001', 'Ráfagas de Event ID 4625 seguidas de Event ID 4624 (compromiso confirmado)', 'CRITICAL / HIGH'],
      ['Inicio Sospechoso / Viaje Imposible', 'Initial Access / Defense Evasion', 'T1078', 'Logins concurrentes desde IPs distantes en <5m o fuera de horario (22:00-06:00)', 'CRITICAL / MEDIUM'],
      ['Escalamiento de Privilegios', 'Privilege Escalation', 'T1068 / T1078.002', 'Uso de SeDebugPrivilege, SeImpersonatePrivilege, sudo/runas y alteración de Domain Admins', 'CRITICAL / HIGH'],
      ['Comandos Anómalos y Scripts', 'Execution / Defense Evasion', 'T1059.001', 'PowerShell con Base64 (-EncodedCommand), whoami /priv, net group, Mimikatz y volcado de LSASS', 'CRITICAL'],
      ['Movimiento Lateral', 'Lateral Movement', 'T1021.002', 'Propagación mediante PsExec, servicio PSEXESVC (Event 7045), SMB puerto 445 y Pass-the-Hash', 'CRITICAL / HIGH']
    ],
    headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontSize: 7.5, fontStyle: 'bold' },
    bodyStyles: { fontSize: 7, textColor: [51, 65, 85] },
    alternateRowStyles: { fillColor: [248, 250, 252] },
    columnStyles: {
      0: { cellWidth: 32, fontStyle: 'bold' },
      1: { cellWidth: 26 },
      2: { cellWidth: 20, fontStyle: 'bold' },
      3: { cellWidth: 78 },
      4: { cellWidth: 26, fontStyle: 'bold', textColor: [190, 18, 60] }
    }
  });
  currentY = doc.lastAutoTable.finalY + 4;

  addCalloutBox(
    'Cero Alucinaciones y Trazabilidad Inmutable',
    'Cada uno de los 38 hallazgos correlacionados incluye el listado exacto de los IDs de logs que lo fundamentan, timestamps con precisión de milisegundos y el cálculo matemático de su nivel de confianza (40% al 95%).',
    'info'
  );

  // ==========================================
  // SECCIÓN 8: INTEGRACIÓN Y DEPURACIÓN DE CTI (VIRUSTOTAL & ABUSEIPDB)
  // ==========================================
  addSectionTitle('8', 'Integración y Depuración de Inteligencia de Amenazas (CTI)');
  addParagraph('Se integró un módulo de Cyber Threat Intelligence (CTI) capaz de consultar las APIs v3 de VirusTotal y AbuseIPDB en tiempo real para enriquecer los IoCs (direcciones IP) detectados en las alertas.');

  addParagraph('Durante las pruebas operativas con el dataset del SOC, se identificaron y resolvieron dos problemas críticos de ciberseguridad y diseño:');

  addCalloutBox(
    'Problema 1: IPs Privadas Consultadas en Feeds Públicos',
    'Una dirección IP privada (ej. 10.10.2.15 o 198.51.100.77 de RFC 1918 / RFC 5737) pertenece al direccionamiento interno no enrutable de la corporación. No puede tener mala reputación pública en internet ni debe enviarse a APIs públicas para evitar fuga de información. Se implementó una función de validación previa que detecta subredes RFC 1918/5737 y las etiqueta inmediatamente como "RED PRIVADA / RFC 1918", omitiendo consultas erróneas a VirusTotal o AbuseIPDB.',
    'danger'
  );

  addCalloutBox(
    'Problema 2: Error 404 al Consultar Sockets con Puerto (ej. 203.0.113.88:443)',
    'Al hacer clic en los enlaces externos de enriquecimiento, los proveedores externos devolvían "404 Page Not Found" porque el sistema enviaba el socket completo "IP:PUERTO" (ej. www.abuseipdb.com/check/203.0.113.88:443). Se implementó la sanitización automática mediante extractIP(), separando la IP válida del puerto de destino para que los enlaces a VirusTotal Graph y AbuseIPDB Feed abran directamente el reporte del host sin errores.',
    'danger'
  );

  if (threatIntelBase64) {
    addImageCard(threatIntelBase64, 150, 72.1, 'Figura 3: Tarjetas de CTI con discriminación de IPs privadas RFC 1918 y scoring en tiempo real.');
  }

  // ==========================================
  // SECCIÓN 9: INTERFAZ INTERACTIVA (DASHBOARD & ANÁLISIS)
  // ==========================================
  addSectionTitle('9', 'Interfaz Interactiva de Monitoreo (Dashboard & Analysis View)');
  addParagraph('La plataforma se estructuró con un diseño minimalista de nivel profesional para centros de operaciones de seguridad (SOC):');

  addBullet('Dashboard Central', 'Resumen numérico de eventos (715 logs), hallazgos (38), fuentes IP y usuarios únicos. Gráfico de dona (Risk Ratio) con distribución de severidad, gráfico de barras horizontales por tipo de ataque, línea de tiempo de eventos y tablas interactivas de principales IPs y usuarios atacados.');
  addBullet('Vista de Análisis Forense', 'Buscador inteligente multi-parámetro, filtros rápidos por severidad (Crítico, Alto, Medio, Bajo) y categoría de ataque, selector de ordenamiento y tarjetas expandibles con desglose de justificación forense, enriquecimiento CTI, lista de IoCs y botón para desplegar el modal de inspección de logs SIEM crudos.');

  if (dashboardBase64) {
    addImageCard(dashboardBase64, 150, 83.3, 'Figura 4: Dashboard interactivo con telemetría de eventos y correlación de amenazas.');
  }

  if (analysisViewBase64) {
    addImageCard(analysisViewBase64, 150, 79.4, 'Figura 5: Vista de Análisis con tarjetas forenses, justificación técnica y corroboración CTI.');
  }

  // ==========================================
  // SECCIÓN 10: GENERADOR DE INFORMES DFIR (NIVEL 2 A NIVEL 3)
  // ==========================================
  addSectionTitle('10', 'Generador Automatizado de Informes DFIR (L2 a L3) y PDFs');
  addParagraph('Se rediseñó íntegramente el motor de generación de reportes en PDF (pdfGenerator.ts y dfirForensicReport.ts) para satisfacer los estándares más rigurosos de respuesta a incidentes forenses (DFIR):');

  addBullet('Reporte Ejecutivo (C-Level)', 'Eliminación de párrafos redundantes, prefacios teóricos sobre qué es ciberseguridad y avisos genéricos. El informe va directo al impacto financiero, riesgo operacional, activos comprometidos y acciones inmediatas.');
  addBullet('Reporte Técnico Forense (Escalamiento L3)', 'Diseñado específicamente para que un Analista Nivel 2 entregue un expediente completo y estructurado a un Analista Nivel 3. Se estructura estrictamente en 8 secciones temáticas:');

  // Syllabus Table
  doc.autoTable({
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'striped',
    head: [['Nº', 'Sección Oficial del Temario', 'Contenido y Aporte Forense']],
    body: [
      ['1', 'Resumen ejecutivo', 'Síntesis técnica del incidente, ventana de tiempo observada, vector inicial y nivel de compromiso.'],
      ['2', 'Hallazgos identificados', 'Matriz de alertas correlacionadas por categoría MITRE ATT&CK con severidad y confianza.'],
      ['3', 'Explicación técnica de cada hallazgo', 'Desglose detallado del comportamiento hostil, TTPs utilizadas y vector de explotación.'],
      ['4', 'Evidencias encontradas en los logs', 'Telemetría cruda, comandos CLI ejecutados, scripts Base64 decodificados (-EncodedCommand) y árboles de procesos (|__ ).'],
      ['5', 'Criticidad y justificación', 'Evaluación de severidad basada en el blast radius, privilegios alcanzados y activos críticos vulnerados.'],
      ['6', 'Posible impacto en la organización', 'Riesgo de despliegue de ransomware, exfiltración de propiedad intelectual y pérdida de continuidad operativa.'],
      ['7', 'Plan de acción: investigar, contener y remediar', 'Medidas inmediatas de contención (aislamiento perimetral, revocación de tokens) y erradicación.'],
      ['8', 'Recomendaciones generales de seguridad', 'Plan estratégico preventivo: endurecimiento de políticas AD, despliegue de EDR, MFA resistente a phishing.']
    ],
    headStyles: { fillColor: [79, 70, 229], textColor: [255, 255, 255], fontSize: 7.5, fontStyle: 'bold' },
    bodyStyles: { fontSize: 7, textColor: [51, 65, 85] },
    columnStyles: {
      0: { cellWidth: 10, fontStyle: 'bold', halign: 'center' },
      1: { cellWidth: 55, fontStyle: 'bold' },
      2: { cellWidth: 117 }
    }
  });
  currentY = doc.lastAutoTable.finalY + 4;

  addCalloutBox(
    'Ajustes Técnicos de Renderizado y Formato en jsPDF',
    '1. Índice interactivo: Se incorporó una tabla de contenido en la página 2 para navegar ágilmente a cualquier sección.\n2. Línea de tiempo estricta: Cada evento sigue el formato "[Timestamp exacto] | [Severidad] | [Nombre de la Alerta]".\n3. Corrección tipográfica: Se eliminaron solapamientos de texto ("Sele calertados"), cortes de palabras ("Confia nza") y caracteres Unicode incompatibles con WinAnsiEncoding ("➔", "└──") sustituyéndolos por conectores limpios ("->", "|__ ").\n4. Control de márgenes: Se calculó el ancho dinámico máximo en las tarjetas (contentWidth - 16) evitando desbordes.',
    'success'
  );

  // ==========================================
  // SECCIÓN 11: LOCALIZACIÓN COMPLETA AL ESPAÑOL NEUTRO
  // ==========================================
  addSectionTitle('11', 'Internacionalización y Localización Completa al Español Neutro');
  addParagraph('Para garantizar que la experiencia del analista hispanohablante sea impecable, se implementó una traducción dinámica y exhaustiva en toda la aplicación:');

  addBullet('Traducción de Alertas y Narrativas', 'Títulos, descripciones, evidencias, justificaciones y planes de acción se presentan 100% en español neutro cuando se selecciona el idioma español.');
  addBullet('Preservación Invariable de Artefactos Técnicos', 'Comandos crudos (ej. whoami /priv, net group), nombres de procesos (mimikatz.exe, lsass.exe), cuentas de usuario (CORP\\admin), direcciones IP y hashes se mantienen intactos sin sufrir alteraciones lingüísticas.');
  addBullet('Tácticas MITRE ATT&CK', 'Traducción de tácticas (Credential Access -> Acceso a Credenciales, Initial Access -> Acceso Inicial, Privilege Escalation -> Escalamiento de Privilegios).');
  addBullet('UI y Badges', 'Traducción de selectores ("Ordenar por:"), badges de CTI ("Inteligencia: Confiable / Sospechosa"), contadores de abuso ("% Nivel de Abuso (X reportes)") y el modal de inspección forense de logs.');

  // ==========================================
  // SECCIÓN 12: RESUMEN DE HITOS Y ESTADO DEL PROYECTO
  // ==========================================
  addSectionTitle('12', 'Resumen de Hitos y Estado Final del Sistema');
  addParagraph('El proyecto "SOC Sentinel L2" se encuentra completamente finalizado, probado y listo para su uso operativo en producción:');

  doc.autoTable({
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'grid',
    head: [['Hito del Proyecto', 'Componente / Módulo', 'Estado', 'Resultado Obtenido']],
    body: [
      ['1. Arquitectura y Entorno', 'Next.js 15 + PowerShell', 'Completado', 'Entorno local operativo sin bloqueos de directivas.'],
      ['2. Control de Versiones', 'Git + GitHub', 'Completado', 'Repositorio vinculado a rama main con exclusión de node_modules.'],
      ['3. Ingesta de Telemetría', 'UploadView (SheetJS)', 'Completado', 'Soporte drag-and-drop de archivos .xlsx y dataset de 715 logs.'],
      ['4. Motor de Detección', 'securityEngine.ts', 'Completado', '5 vectores MITRE correlacionados con cero alucinaciones.'],
      ['5. Enriquecimiento CTI', 'VirusTotal + AbuseIPDB', 'Completado', 'Validación RFC 1918 (redes privadas) y sockets sanitizados.'],
      ['6. Dashboard y Monitoreo', 'DashboardView + AnalysisView', 'Completado', 'Telemetría interactiva, gráficos Recharts y visor de logs crudos.'],
      ['7. Reportes DFIR (L2 -> L3)', 'pdfGenerator.ts', 'Completado', 'Reporte técnico en 8 secciones oficiales con timeline e índice.'],
      ['8. Localización al Español', 'i18n + dfirForensicReport', 'Completado', 'Traducción neutra 100% preservando entidades técnicas.'],
      ['9. Compilación de Producción', 'next build', 'Completado', '0 errores TypeScript, 0 advertencias de linting y 6 rutas compiladas.']
    ],
    headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontSize: 7.5, fontStyle: 'bold' },
    bodyStyles: { fontSize: 7, textColor: [51, 65, 85] },
    columnStyles: {
      0: { cellWidth: 40, fontStyle: 'bold' },
      1: { cellWidth: 42 },
      2: { cellWidth: 24, fontStyle: 'bold', textColor: [4, 120, 87] },
      3: { cellWidth: 76 }
    }
  });
  currentY = doc.lastAutoTable.finalY + 6;

  // Prominent GitHub Project Callout Box
  addCalloutBox(
    'Repositorio Oficial de Código Fuente en GitHub',
    `Todo el código fuente del proyecto, el motor heurístico determinista (securityEngine.ts), los módulos CTI, las plantillas de reportes forenses y la configuración de Next.js se encuentran publicados y bajo control de versiones en el repositorio público oficial de GitHub:\n\n${GITHUB_REPO_URL}\n\nRama activa: main • Commits sincronizados, trazables y auditados.`,
    'info',
    GITHUB_REPO_URL
  );

  addCalloutBox(
    'Conclusión y Valor Agregado',
    'La aplicación SOC Sentinel L2 proporciona a analistas SOC Nivel 2 y consultores de ciberseguridad una solución robusta, intuitiva y científicamente sustentada para acelerar la triada DFIR: detección inmediata, análisis de causa raíz y generación de informes forenses de alta fidelidad listos para escalamiento ejecutivo y técnico.',
    'success'
  );

  // ==========================================
  // RUNNING HEADERS & FOOTERS (All Pages)
  // ==========================================
  const totalPages = doc.internal.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);

    if (p > 1) {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(148, 163, 184); // Slate 400
      doc.text('COMUNIDAD DOJO • BOOTCAMP ANALISTA SOC NIVEL 2 | SOC SENTINEL L2', margin, 10);
      doc.text('DOCUMENTACIÓN TÉCNICA Y REPORTE DE DESARROLLO', pageWidth - margin, 10, { align: 'right' });
      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.3);
      doc.line(margin, 12, pageWidth - margin, 12);
    }

    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.3);
    doc.line(margin, pageHeight - 12, pageWidth - margin, pageHeight - 12);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.2);
    doc.setTextColor(100, 116, 139); // Slate 500
    doc.text('Paula Villegas — https://github.com/PuaBlue/SOC-SentineL2', margin, pageHeight - 7.5);
    doc.link(margin, pageHeight - 11, doc.getTextWidth('Paula Villegas — https://github.com/PuaBlue/SOC-SentineL2'), 6, { url: GITHUB_REPO_URL });
    doc.text(`Página ${p} de ${totalPages}`, pageWidth - margin, pageHeight - 7.5, { align: 'right' });
  }

  // Write PDF to workspace and scratch/artifacts
  const outWorkspacePath = path.resolve(process.cwd(), 'Desarrollo_Aplicacion_Web_SOC_Nivel_2_Paula_Villegas.pdf');
  const outArtifactPath = 'C:/Users/angel/.gemini/antigravity/brain/e90af595-42e9-43eb-87d8-fd39c795df27/Desarrollo_Aplicacion_Web_SOC_Nivel_2_Paula_Villegas.pdf';

  const pdfBytes = doc.output('arraybuffer');
  fs.writeFileSync(outWorkspacePath, Buffer.from(pdfBytes));
  fs.writeFileSync(outArtifactPath, Buffer.from(pdfBytes));

  console.log('PDF generated successfully with GitHub repository:', GITHUB_REPO_URL);
  console.log('Total pages:', totalPages);
  console.log('Output in workspace:', outWorkspacePath);
  console.log('Output in artifact dir:', outArtifactPath);
}

generatePDF().catch(err => {
  console.error('Error generating PDF:', err);
  process.exit(1);
});
