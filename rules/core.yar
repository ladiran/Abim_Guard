/*
   Bimbo Guard bundled rules.

   Every rule carries a "severity" meta value:
     test        harmless antivirus test file (EICAR)
     malicious   strong evidence of malware; eligible for auto-quarantine
     suspicious  worth a human look; never auto-quarantined
     pua         potentially unwanted (miners, hacking tools)

   Add your own .yar files to the "rules" folder in the app data
   directory and press "Reload rules" in the app.
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR standard antivirus test file (harmless)"
        severity = "test"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar at 0 and filesize < 128
}

rule HackTool_Mimikatz
{
    meta:
        description = "Mimikatz credential theft tool strings"
        severity = "malicious"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "gentilkiwi" ascii wide
        $c = "kerberos::golden" ascii wide nocase
        $d = "lsadump::sam" ascii wide nocase
        $e = "mimikatz" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Beacon_CobaltStrike_Strings
{
    meta:
        description = "Strings typical of a Cobalt Strike beacon payload"
        severity = "malicious"
    strings:
        $a = "beacon.x64.dll" ascii
        $b = "beacon.dll" ascii
        $c = "ReflectiveLoader" ascii
        $d = "%s (admin)" ascii
        $e = "%02d/%02d/%02d %02d:%02d:%02d" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Webshell_PHP_Eval_Request
{
    meta:
        description = "PHP web shell that evaluates attacker supplied input"
        severity = "malicious"
    strings:
        $php = "<?php" nocase
        $e1 = /eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $e2 = /(assert|system|passthru|shell_exec)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase
    condition:
        $php and any of ($e*) and filesize < 2MB
}

rule Script_JS_Downloader
{
    meta:
        description = "JScript that downloads a file and saves it to disk (classic dropper)"
        severity = "malicious"
    strings:
        $x1 = "MSXML2.XMLHTTP" ascii wide nocase
        $x2 = "WinHttp.WinHttpRequest" ascii wide nocase
        $s1 = "ADODB.Stream" ascii wide nocase
        $s2 = "SaveToFile" ascii wide nocase
        $r1 = "WScript.Shell" ascii wide nocase
        $r2 = ".Run(" ascii wide nocase
    condition:
        filesize < 1MB and any of ($x*) and all of ($s*) and all of ($r*)
}

rule Script_PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell that downloads and immediately executes code"
        severity = "suspicious"
    strings:
        $c1 = /(IEX|Invoke-Expression)\s*\(?\s*\(?\s*New-Object\s+(System\.)?Net\.WebClient\s*\)?\s*\.\s*Download(String|Data)/ nocase
        $c2 = /(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\s+[^\n|]{1,200}\|\s*(iex|Invoke-Expression)/ nocase
        $c3 = /\[Convert\]::FromBase64String\([^\n]{0,200}\)[^\n]{0,200}(IEX|Invoke-Expression)/ nocase
        // "irm <url> | iex" is also how many honest installers are shown in
        // READMEs, so on its own it only counts alongside stealth options.
        $stealth = /-(w|windowstyle)\s+h(idden)?|-nop(rofile)?\s|-ep\s+bypass|-executionpolicy\s+bypass/ nocase
    condition:
        filesize < 5MB and ($c1 or $c3 or ($c2 and $stealth))
}

rule Script_PowerShell_Encoded_Hidden
{
    meta:
        description = "Hidden PowerShell launched with a long encoded command"
        severity = "suspicious"
    strings:
        $p = "powershell" ascii wide nocase
        $h = /-w(indowstyle)?\s+h(idden)?/ ascii wide nocase
        $e = /\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{120,}/ ascii wide nocase
    condition:
        filesize < 5MB and $p and $h and $e
}

rule Shortcut_LNK_Launches_Script
{
    meta:
        description = "Windows shortcut that launches hidden PowerShell, mshta or a download"
        severity = "malicious"
    strings:
        $ps = "powershell" ascii wide nocase
        $mshta = "mshta" ascii wide nocase
        $hid = "hidden" ascii wide nocase
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadFile" ascii wide nocase
        $dl3 = "http" ascii wide nocase
        $enc = "-enc" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and filesize < 1MB and
        ($ps or $mshta) and ($hid or $enc) and any of ($dl*)
}

rule HTA_Runs_Shell
{
    meta:
        description = "HTML application that runs shell commands"
        severity = "suspicious"
    strings:
        $hta = "<hta:application" ascii wide nocase
        $s1 = "WScript.Shell" ascii wide nocase
        $s2 = "powershell" ascii wide nocase
        $s3 = "cmd.exe" ascii wide nocase
    condition:
        $hta and 2 of ($s*) and filesize < 2MB
}

rule Office_OLE_AutoExec_Macro
{
    meta:
        description = "Legacy Office document with an auto-run macro"
        severity = "suspicious"
    strings:
        $vba = "VBA" ascii wide
        $a1 = "AutoOpen" ascii wide nocase
        $a2 = "Document_Open" ascii wide nocase
        $a3 = "Workbook_Open" ascii wide nocase
        $a4 = "Auto_Open" ascii wide nocase
        $x1 = "Shell" ascii wide
        $x2 = "CreateObject" ascii wide
        $x3 = "URLDownloadToFile" ascii wide nocase
    condition:
        uint32be(0) == 0xD0CF11E0 and $vba and any of ($a*) and any of ($x*)
}

rule Ransomware_Note_Indicators
{
    meta:
        description = "Text that reads like a ransomware ransom note"
        severity = "suspicious"
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "all your files are encrypted" ascii wide nocase
        $c = "bitcoin" ascii wide nocase
        $d = ".onion" ascii wide nocase
        $e = "decryption key" ascii wide nocase
        $f = "do not try to decrypt" ascii wide nocase
        $g = "tor browser" ascii wide nocase
    condition:
        filesize < 300KB and ($a or $b) and 2 of ($c, $d, $e, $f, $g)
}

rule Ransomware_Shadow_Copy_Wipe
{
    meta:
        description = "Program that deletes Windows backups and shadow copies (common ransomware step)"
        severity = "malicious"
    strings:
        $v1 = "vssadmin delete shadows" ascii wide nocase
        $v2 = "vssadmin.exe delete shadows" ascii wide nocase
        $w1 = "shadowcopy delete" ascii wide nocase
        $b1 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $b2 = "wbadmin delete catalog" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PUA_CoinMiner
{
    meta:
        description = "Cryptocurrency miner (often installed without consent)"
        severity = "pua"
    strings:
        $s1 = "stratum+tcp://" ascii wide nocase
        $s2 = "stratum+ssl://" ascii wide nocase
        $m1 = "xmrig" ascii wide nocase
        $m2 = "--donate-level" ascii wide
        $m3 = "cryptonight" ascii wide nocase
        $m4 = "randomx" ascii wide nocase
    condition:
        any of ($s*) and any of ($m*)
}
