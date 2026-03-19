#  Análisis de la campaña de Remcos RAT - HACKCON_RD 2026

<div align="center">

![HACKCON_RD](https://img.shields.io/badge/HACKCON_RD-2026-red?style=for-the-badge)
![DFIR](https://img.shields.io/badge/DFIR-Analysis-blue?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange?style=for-the-badge)

**Repositorio de recursos y muestras de la charla sobre análisis de la campaña de Remcos RAT**

[![GitHub](https://img.shields.io/github/stars/Angel-Rojas-ING/HACKCON_RD_2026_REMCOS?style=social)](https://github.com/Angel-Rojas-ING/HACKCON_RD_2026_REMCOS)

</div>

---

##  Descripción

Este repositorio contiene el material completo del análisis de la campaña digital (DFIR) de una campaña de **Remcos RAT** distribuida mediante un dropper Delphi llamado **SyAlpha16.exe**. El análisis incluye la cadena de infección completa desde el vector inicial (HTA) hasta la persistencia del RAT, con mapeo completo a MITRE ATT&CK.

###  Sobre la Charla

**Evento:** HACKCON_RD 2026  
**Tema:** Análisis de la campaña de Remcos RAT  
**Enfoque:** Análisis práctico de malware, técnicas de evasión, y threat hunting

---

##  Resumen del Análisis

### Cadena de Infección

```
[ETAPA 0] Romulo.hta → Descarga y ejecuta SyAlpha16.exe
    ↓
[ETAPA 1] SyAlpha16.exe (PID 8884) - DROPPER
    ↓
[ETAPA 2] SyAlpha16.exe (PID 1176) - LOADER
    ↓
[ETAPA 3] FrameTrac32.exe (PID 8364) - REMCOS RAT
    ↓
[ETAPA 4] Chime.exe (PID 8392) - PERSISTENCE HELPER
```

### Características Principales

- **Vector Inicial:** HTA (HTML Application) con VBScript ofuscado
- **Dropper:** Delphi XE3 con múltiples técnicas de evasión
- **RAT:** Remcos v4.x con capacidades completas de control remoto
- **Técnicas MITRE:** 26 técnicas observadas en 10 tácticas
- **Persistencia:** Mecanismos redundantes (Task Scheduler 1.0 + 2.0)

---

##  Contenido del Repositorio

###  Documentación

| Archivo | Descripción |
|---------|-------------|
| **[IOC_TABLE_REMCOS_RAT.md](./IOC_TABLE_REMCOS_RAT.md)** | Tabla completa de Indicadores de Compromiso (IOC) para threat hunting |
| **[MITRE_ATTACK_MATRIX_REMCOS.md](./MITRE_ATTACK_MATRIX_REMCOS.md)** | Matriz MITRE ATT&CK con mapeo completo de técnicas observadas |
| **[REGLA_YARA.yar](./REGLA_YARA.yar)** | Reglas YARA para detección de variantes de Remcos RAT |

### Herramientas

| Archivo | Descripción |
|---------|-------------|
| **[remcosconfg-extract.py](./remcosconfg-extract.py)** | Extractor de configuración de Remcos RAT (v2.0) |

###  Muestras

| Archivo | Descripción |
|---------|-------------|
| **[CAMPAÑA_REMCOS_MUESTRAS.7z](./CAMPAÑA_REMCOS_MUESTRAS.7z)** | Archivo comprimido con muestras de la campaña ( **SOLO PARA ENTORNOS AISLADOS PASS (infected)**) |

>  **ADVERTENCIA:** Las muestras contenidas en este repositorio son **MALWARE REAL**. Solo deben ser analizadas en entornos de análisis aislados (sandbox, máquinas virtuales desconectadas, laboratorios de malware). El autor no se hace responsable del uso indebido de este material.

---

##  Indicadores Clave

### Hash Principal
```
SHA-256: 9f84bbd8179674ee35fd11e94435df0c49c81bb5ca44c2f5ad4b5bec53f0ab35
```

### Servidores C2
- **Descarga:** `192.159.99.10:80` (HTTP)
- **C2 RAT:** `192.159.99.19:1122` (TCP)

### Rutas Críticas
- `C:\ProgramData\store_adapter_x64\` - Dropper persistente
- `C:\Users\<USER>\AppData\Local\FrameTrac32.exe` - RAT principal
- `C:\ProgramData\dt\logs.dat` - Keylogger output
- `C:\Windows\Tasks\CLI.job` - Persistencia

---

##  Técnicas MITRE ATT&CK Observadas

### Distribución por Táctica

| Táctica | Técnicas | Porcentaje |
|---------|-----------|------------|
| **Defense Evasion** | 6 | 24% |
| **Command and Control** | 4 | 16% |
| **Collection** | 4 | 16% |
| **Execution** | 3 | 12% |
| **Persistence** | 3 | 12% |
| **Initial Access** | 2 | 8% |
| **Discovery** | 2 | 8% |
| **Credential Access** | 1 | 4% |
| **Privilege Escalation** | 1 | 4% |
| **TOTAL** | **26 técnicas** | **100%** |

### Técnicas Más Críticas

1. **T1055.012** - Process Hollowing (Early Bird Injection)
2. **T1056.001** - Keylogging (offline + online)
3. **T1053.005** - Scheduled Task (persistencia redundante)
4. **T1027.002** - Software Packing (DLL cifrada)
5. **T1573.001** - Encrypted Channel (RC4)

>  Ver la [matriz completa de MITRE ATT&CK](./MITRE_ATTACK_MATRIX_REMCOS.md) para detalles detallados.

---

##  Metodología de Análisis

### Herramientas Utilizadas

- **Process Monitor** - Monitoreo de actividad del sistema
- **Volatility** - Análisis de memoria
- **YARA** - Detección de patrones
- **Sysmon** - Logging avanzado
- **PowerShell** - Análisis de logs y eventos
- **remcosconfg-extract.py** - Extractor de configuración de Remcos RAT (desarrollado para esta charla)

### Fuentes de Evidencia

- `Logfile.CSV` - Captura de Process Monitor (8,165 eventos)
- `FrameTrac32.DMP` - Volcado de memoria del proceso RAT
- Análisis estático y dinámico del HTA y dropper


### Capacidades del RAT

-  Keylogging (offline y online)
-  Captura de pantalla
-  Captura de audio (micrófono)
-  Monitoreo de portapapeles
-  Control remoto completo
-  UAC Bypass preparado
-  Evasión de Windows Defender

---

## RemcosConfig Extractor v2.0

Herramienta CLI para extraer y descifrar la configuración embebida en muestras de Remcos RAT.

```
  ____                               ____             __ _
 |  _ \ ___ _ __ ___   ___ ___  ___ / ___|___  _ __  / _(_) __ _
 | |_) / _ \ '_ ` _ \ / __/ _ \/ __| |   / _ \| '_ \| |_| |/ _` |
 |  _ <  __/ | | | | | (_| (_) \__ \ |__| (_) | | | |  _| | (_| |
 |_| \_\___|_| |_| |_|\___\___/|___/\____\___/|_| |_|_| |_|\__, |
                                                             |___/
                          E X T R A C T O R   v2.0
```

### Capacidades

- Extrae y descifra configuración RC4 desde recursos RCDATA/SETTINGS del PE
- Parsea C2 en formato `host:port:password`
- Calcula hashes (SHA-256, MD5, SHA-1) de cada muestra
- Detecta packers (UPX, Themida, VMProtect, entropía alta)
- Detecta versión de Remcos (v1.x - v4.x)
- Mapea ~45 campos de configuración organizados por categoría
- Muestra flags como `[ON]`/`[OFF]` con colores
- Interfaz CLI con colores, marcos y banner ASCII Art
- Exporta a CSV y JSON
- Soporte batch con resumen consolidado y barra de progreso

### Requisitos

```bash
pip install pefile colorama
```

### Uso

```bash
# Extraer configuración de una muestra
python remcosconfg-extract.py muestra.exe

# Exportar a CSV y JSON
python remcosconfg-extract.py muestra.exe --csv iocs.csv --json config.json

# Batch (múltiples muestras)
python remcosconfg-extract.py *.exe --csv campana.csv

# Sin colores (para logs/pipelines)
python remcosconfg-extract.py muestra.exe --no-color --no-banner
```

### Ejemplo de Salida

```
  +========================================================================+
  | SAMPLE INFO                                                            |
  +------------------------------------------------------------------------+
  |  File      : FrameTrac32.exe                                           |
  |  SHA-256   : 9f84bbd8179674ee35fd...                                   |
  |  Packer    : None detected                                             |
  |  Remcos    : v4.x                                                      |
  +========================================================================+

  +------------------------------------------------------------------------+
  | NETWORK                                                                |
  +------------------------------------------------------------------------+
  |  [C2 #1]  192.159.99.19:1122  (password: (none))                      |
  |  Connect Interval (s) : 1                                              |
  |  TLS Enabled           [OFF]                                           |
  +------------------------------------------------------------------------+

  +------------------------------------------------------------------------+
  | SURVEILLANCE                                                           |
  +------------------------------------------------------------------------+
  |  Keylogger             [ON]                                            |
  |  Screenshots           [ON]                                            |
  |  Audio Capture         [ON]                                            |
  |  Clipboard Monitor     [OFF]                                           |
  +------------------------------------------------------------------------+
```

---

##  Uso de los Recursos

### Para Threat Hunters

1. Consulta la [tabla de IOC](./IOC_TABLE_REMCOS_RAT.md) para crear reglas de detección
2. Usa las [reglas YARA](./REGLA_YARA.yar) en tu infraestructura de detección
3. Implementa las queries de la matriz MITRE en tu SIEM/EDR
4. Usa el [extractor de configuración](./remcosconfg-extract.py) para analizar muestras y extraer IOCs automáticamente

### Para Analistas de Malware

1. Revisa la cadena de infección completa en la documentación
2. Analiza las técnicas de evasión documentadas
3. Estudia el mapeo MITRE ATT&CK para entender el TTP completo
4. Ejecuta `remcosconfg-extract.py` contra muestras para extraer C2, mutex, claves RC4 y capacidades activas

### Para Investigadores

1. Descarga las muestras ( **SOLO EN ENTORNO AISLADO**)
2. Reproduce el análisis usando la metodología documentada
3. Contribuye con mejoras a las reglas YARA o al extractor de configuración

---

##  Estadísticas del Análisis

- **Eventos analizados:** 8,165 (Process Monitor)
- **Procesos involucrados:** 4 etapas
- **Archivos creados:** 15+ artefactos
- **Técnicas MITRE:** 26 técnicas
- **Tácticas MITRE:** 10 tácticas
- **Duración del análisis:** ~3 minutos (captura)

---

##  Contribuciones

Este repositorio es parte del material de la charla **HACKCON_RD 2026**. Si encuentras errores, mejoras o quieres contribuir con reglas YARA adicionales, las contribuciones son bienvenidas.


##  Disclaimer Legal

Este repositorio contiene material educativo y de investigación sobre análisis de malware. El propósito es:

-  Educación y concienciación en seguridad
-  Investigación en ciberseguridad
-  Desarrollo de capacidades de detección y respuesta

**NO debe ser usado para:**
-  Actividades maliciosas
-  Compromiso no autorizado de sistemas
-  Cualquier actividad ilegal

El autor y los contribuyentes no se hacen responsables del uso indebido de este material.

---

##  Contacto

**Autores:** Angel Gil && Jorge Gonzalez
**Evento:** HACKCON_RD 2026  
**Repositorio:** [github.com/Angel-Rojas-ING/HACKCON_RD_2026_REMCOS](https://github.com/Angel-Rojas-ING/HACKCON_RD_2026_REMCOS)

---

##  Referencias

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Remcos RAT - MITRE ATT&CK](https://attack.mitre.org/software/S0332/)
- [YARA Rules Documentation](https://yara.readthedocs.io/)

---

##  Licencia

Este proyecto está bajo la licencia **MIT License**. Ver el archivo `LICENSE` para más detalles.

---

<div align="center">

**⭐ Si este repositorio te fue útil, considera darle una estrella ⭐**

"In code we trust, in shadows we operate" 
</div>
