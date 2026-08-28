/*
 * Example / starter YARA rules for the triage tool's IOC scanner (PART C).
 *
 * These are benign detection signatures for demonstration and testing. Drop
 * additional *.yar / *.yara files in this directory and they are compiled and
 * applied automatically by forensics/yara_scanner.py.
 */

rule EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test string (harmless standard test file)"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
        severity    = "informational"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_EncodedCommand
{
    meta:
        description = "PowerShell launched with an encoded/hidden command line"
        severity    = "medium"
    strings:
        $enc  = "-EncodedCommand" nocase
        $hid  = "-WindowStyle Hidden" nocase
        $ep   = "-ExecutionPolicy Bypass" nocase
    condition:
        any of them
}

rule Executable_Dropped_In_Temp
{
    meta:
        description = "Path reference to an executable inside a temp directory"
        severity    = "medium"
    strings:
        $t1 = /\\Temp\\[^\\]+\.exe/ nocase
        $t2 = "/tmp/" nocase
    condition:
        $t1 or ($t2 and $t1)
}
