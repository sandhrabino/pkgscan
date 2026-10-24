/*
  Signal 5.1 - Code obfuscation signatures (medium confidence).
  Counts/entropy/minification ratios are computed by the obfuscation_stats producer.
*/

rule Obf_Hex_Identifier_Names
{
    meta:
        category = "obfuscation"
        severity = "medium"
        signal = "5.1"
        description = "Many hex-like identifiers (_0x1a2b) typical of javascript-obfuscator"
    strings:
        $id = /_0x[a-f0-9]{4,6}\b/
    condition:
        #id > 25
}

rule Obf_Confusable_Identifier_Names
{
    meta:
        category = "obfuscation"
        severity = "medium"
        signal = "5.1"
        description = "Identifiers built only from l/I/1 (l1Il1I style obfuscation)"
    strings:
        $id = /\b[lI][lI1]{7,}\b/
    condition:
        #id > 15
}

rule Obf_Hex_Escape_Run
{
    meta:
        category = "obfuscation"
        severity = "medium"
        signal = "5.1"
        description = "Long run of \\xNN escapes"
    strings:
        $h = /(\\x[0-9a-fA-F]{2}){40}/
    condition:
        $h
}

rule Obf_Unicode_Escape_Run
{
    meta:
        category = "obfuscation"
        severity = "medium"
        signal = "5.1"
        description = "Long run of \\uNNNN escapes"
    strings:
        $u = /(\\u[0-9a-fA-F]{4}){30}/
    condition:
        $u
}

rule Obf_JSFuck
{
    meta:
        category = "obfuscation"
        severity = "high"
        signal = "5.1"
        description = "JSFuck-style encoding"
    strings:
        $a = "[][(![]+[])[+[]]"
        $b = "(![]+[])[!+[]+!+[]]"
        $c = /(\[\]\+\[\]|!\+\[\]){30}/
    condition:
        any of them
}

rule Obf_PyArmor
{
    meta:
        category = "obfuscation"
        severity = "high"
        signal = "5.1"
        description = "PyArmor protected Python code"
    strings:
        $a = "__pyarmor__"
        $b = "pyarmor_runtime"
        $c = "from pytransform import"
        $d = "__armor_enter__"
    condition:
        any of them
}

rule Obf_Python_Marshal_Exec
{
    meta:
        category = "obfuscation"
        severity = "high"
        signal = "5.1"
        description = "exec of marshalled / compressed code object"
    strings:
        $a = /exec\s*\(\s*marshal\.loads/
        $b = /exec\s*\(\s*zlib\.decompress/
        $c = /exec\s*\(\s*__import__\(\s*['"](base64|zlib|marshal|codecs)['"]\s*\)/
        $d = /exec\s*\(\s*base64\.b64decode/
    condition:
        any of them
}

rule Obf_Packer_Eval
{
    meta:
        category = "obfuscation"
        severity = "medium"
        signal = "5.1"
        description = "Dean Edwards packer / eval(function(p,a,c,k,e,d))"
    strings:
        $a = "eval(function(p,a,c,k,e,"
    condition:
        $a
}
