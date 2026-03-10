import "pe"

rule MAL_Remcos_RAT_Artifacts_And_Indicators
{
    meta:
        description = "Detecta remcos en un sistema basado en artefactos conocidos y/o dumps de memoria"
        author = "Jorge Gonzalez y Angel Gil"
        date = "2026-03-10"
        version = 1
        malware_family = "Remcos"
        malware_type = "RAT"
        tags = "REMCOS"
        mitre_attack = "T1056.001, T1105, T1059"

    strings:
        // Artefactos asociados
        $file_1 = "FrameTrac32.exe" wide ascii nocase
        $file_2 = "SyAlpha16.exe" wide ascii nocase
        $file_3 = "Chime.exe" wide ascii nocase
        $file_4 = "logs.dat" wide ascii nocase

        // Indicadores de keylogger
        $indicator_1 = "[Offline Keylogger Started]" ascii
        $indicator_2 = "Remcos restarted by watchdog!" ascii fullword
        $indicator_3 = "Remcos Agent initialized" ascii
        $indicator_4 = "[Cleared browsers logins and cookies.]" ascii

    condition:
        // Esta regla aplica a binarios PE y dumps de memoria
        // Requiere de almenos un indicador de keylogging y dos artefactos
        // Esta combinacion reduce falsos positivos ya que como sabemos los binarios son legitimos
        filesize < 10MB and
        1 of ($indicator_*) and
        2 of ($file_*)
}
