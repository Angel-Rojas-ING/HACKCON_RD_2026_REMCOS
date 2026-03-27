import "pe"

rule MAL_Remcos_RAT_Artifacts_And_Indicators
{
    meta:
        description = "Detecta remcos en un sistema basado en artefactos conocidos y/o dumps de memoria"
        author = "Jorge Gonzalez y Angel Gil"
        date = "2026-03-10"
        version = 3
        malware_family = "Remcos"
        malware_type = "RAT"
        tags = "REMCOS"
        mitre_attack = "T1056.001, T1105, T1059"

    strings:
        // Artefactos PE asociados
        $pe_file_1 = "FrameTrac32.exe" wide ascii nocase
        $pe_file_2 = "SyAlpha16.exe" wide ascii nocase
        $pe_file_3 = "Chime.exe" wide ascii nocase

        // Artefacto log de keylogger
        $log_file = "logs.dat" wide ascii nocase

        // Indicadores de keylogger (para dump de proceso)
        $indicator_1 = "[Offline Keylogger Started]" ascii
        $indicator_2 = "Remcos restarted by watchdog!" ascii fullword
        $indicator_3 = "Remcos Agent initialized" ascii
        $indicator_4 = "[Cleared browsers logins and cookies.]" ascii

    condition:
        filesize < 10MB and
        (
            //  Archivo PE - nombres usados por Remcos
            (uint16(0) == 0x5A4D and 2 of ($pe_file_*)) or

            // Artefacto de log en disco
            ($log_file) or

            // Dump de memoria / regiones - indicadores runtime
            (uint16(0) != 0x5A4D and 1 of ($indicator_*))
        )
}
