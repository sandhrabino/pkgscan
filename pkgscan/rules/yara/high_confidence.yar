/*
  Signal 7 - High-confidence signatures.
  Every rule tagged `high_confidence` sets a deterministic verdict floor (see
  default_config.yaml -> verdict.high_confidence_floor). The LLM cannot lower it.
*/

rule HC_Invisible_Unicode_Run : high_confidence
{
    meta:
        category = "obfuscation"
        severity = "critical"
        signal = "7"
        description = "10+ consecutive invisible/zero-width/variation-selector characters (GlassWorm-style hidden code)"
    strings:
        // U+200B-U+200F, U+2060-U+2064, U+FEFF, U+3164, U+FE00-FE0F, U+E0100-E01EF (variation selectors supplement)
        $inv = /(\xE2\x80[\x8B-\x8F]|\xE2\x81[\xA0-\xA4]|\xEF\xBB\xBF|\xE3\x85\xA4|\xEF\xB8[\x80-\x8F]|\xF3\xA0[\x84-\x87][\x80-\xBF]){10}/
    condition:
        $inv
}

rule HC_Long_Hex_Blob : high_confidence
{
    meta:
        category = "obfuscation"
        severity = "high"
        signal = "7"
        description = "Hex string literal longer than 500 characters"
    strings:
        $hex = /["'`][0-9a-fA-F]{500}/
    condition:
        $hex
}

rule HC_JavaScript_Obfuscator_IO : high_confidence
{
    meta:
        category = "obfuscation"
        severity = "high"
        signal = "7"
        description = "obfuscator.io / javascript-obfuscator string-array rotation signature"
    strings:
        $rot1 = /\['push'\]\(\w+\['shift'\]\(\)\)/
        $rot2 = /\["push"\]\(\w+\["shift"\]\(\)\)/
        $rot3 = /while\s*\(\s*!!\[\]\s*\)/
        $arr  = /function\s+_0x[a-f0-9]{4,6}\s*\(\s*\)\s*\{\s*(var|const|let)\s+_0x[a-f0-9]{4,6}\s*=\s*\[/
        $id   = /_0x[a-f0-9]{4,6}/
        $site1 = "obfuscator.io"
        $site2 = "javascript-obfuscator"
    condition:
        (($rot1 or $rot2 or $rot3) and $arr and #id > 20) or (any of ($site*) and #id > 20)
}

rule HC_Reverse_Shell : high_confidence
{
    meta:
        category = "backdoor"
        severity = "critical"
        signal = "7"
        description = "Reverse / bind shell command"
    strings:
        $a = /(ba)?sh\s+-i\s+[>&]+\s*\/dev\/tcp\//
        $b = /\bnc(at)?(\.exe)?\s+(-[a-z]*\s+)*-e\s+(\/bin\/(ba)?sh|cmd(\.exe)?)/
        $c = /mkfifo\s+\/tmp\/\S+;\s*[^\n]{0,80}\|\s*\/bin\/(ba)?sh\s+-i/
        $d = /socat\s+[^\n]{0,80}exec:['"]?(\/bin\/)?(ba)?sh/ nocase
        $e = /pty\.spawn\(\s*["']\/bin\/(ba)?sh["']\s*\)/
        $f = /\bnc(at)?\s+-l[a-z]*p?\s+\d{2,5}\s+-e\b/
        $g = /spawn\(\s*["'](\/bin\/(ba)?sh|cmd\.exe)["'][^\n]{0,200}\.pipe\(/
        $h = /os\.dup2\(\s*\w+\.fileno\(\)\s*,\s*0\s*\)/
    condition:
        any of them
}

rule HC_Crypto_Miner : high_confidence
{
    meta:
        category = "cryptominer"
        severity = "critical"
        signal = "7"
        description = "Cryptocurrency miner (pool protocol / miner binary / pool host)"
    strings:
        $p1 = "stratum+tcp://" nocase
        $p2 = "stratum+ssl://" nocase
        $p3 = "stratum2+tcp://" nocase
        $m1 = "xmrig" nocase
        $m2 = "--donate-level" nocase
        $m3 = "cryptonight" nocase
        $m4 = "randomx" nocase fullword
        $h1 = "supportxmr.com" nocase
        $h2 = "nanopool.org" nocase
        $h3 = "moneroocean.stream" nocase
        $h4 = "2miners.com" nocase
        $h5 = "minexmr.com" nocase
        $h6 = "herominers.com" nocase
        $h7 = "c3pool.com" nocase
    condition:
        any of ($p*) or any of ($h*) or 2 of ($m*)
}

rule HC_Shai_Hulud_Worm : high_confidence
{
    meta:
        category = "worm"
        severity = "critical"
        signal = "7"
        description = "Shai-Hulud npm worm artefacts"
    strings:
        $a = "Shai-Hulud" nocase
        $b = "shai-hulud-workflow.yml"
        $c = "bun_environment.js"
        $d = "setup_bun.js"
        $e = /trufflehog[^\n]{0,80}filesystem/
        $f = "Sha1-Hulud" nocase
    condition:
        $a or $b or $f or ($c and $d) or ($e and ($c or $d))
}

rule HC_Webhook_Env_Exfil : high_confidence
{
    meta:
        category = "exfiltration"
        severity = "critical"
        signal = "7"
        description = "Environment/credentials posted to Discord/Telegram/webhook endpoints"
    strings:
        $w1 = /discord(app)?\.com\/api\/webhooks\/\d+\//
        $w2 = /api\.telegram\.org\/bot\d+:[A-Za-z0-9_-]{30,}/
        $w3 = /webhook\.site\/[0-9a-f-]{36}/
        $e1 = "process.env"
        $e2 = "os.environ"
        $e3 = ".npmrc"
        $e4 = ".ssh"
    condition:
        any of ($w*) and any of ($e*)
}

rule HC_Embedded_Executable_In_Script : high_confidence
{
    meta:
        category = "dropper"
        severity = "high"
        signal = "7"
        description = "Base64-encoded PE/ELF header embedded inside a script"
    strings:
        $pe_b64  = "TVqQAAMAAAAEAAAA"
        $elf_b64 = "f0VMRgIBAQ"
        $elf_b64b = "f0VMRgEBAQ"
    condition:
        any of them and filesize < 50MB
}

rule HC_CI_Runner_Secret_Harvest : high_confidence
{
    meta:
        category = "credential_access"
        severity = "high"
        signal = "7"
        description = "CI runner secret harvesting: runner memory dump piped to sudo python, or masked-secret scraping with token exfiltration"
    strings:
        $pipe_sudo_py = /curl[^\n]{0,300}\|\s*sudo\s+python3?/
        $memdump      = /memdump\.py/
        $is_secret    = /"?isSecret"?\s*:\s*(true|\\?"true)/
        $gh_token     = /Authorization:\s*Bearer\s+\$\{?(GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN)/
    condition:
        $pipe_sudo_py or $memdump or ($is_secret and $gh_token)
}
