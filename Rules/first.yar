import "pe" // Optional: Imports the Portable Executable module for advanced Windows file checks

rule Detect_Generic_PHP_Webshell : Web_Tools Initial_Access {
    meta:
        description = "Detects basic patterns common in malicious PHP web shells"
        author = "Joshua Fishman"
        date = "2026-07-07"
        reference = "Static analysis study"

    strings:
        // 1. Text strings (modifiers: nocase handles capitalization, ascii/wide handles encoding)
        $text_cmd1 = "passthru(" ascii nocase
        $text_cmd2 = "shell_exec(" ascii nocase
        $text_cmd3 = "base64_decode(" ascii

        // 2. Hexadecimal byte patterns (supports wildcards ?? and jumps [X-Y])
        $hex_magic = { 3C 3F 70 68 70 } // This is "<?php" in hex

        // 3. Regular Expressions
        $regex_eval = /eval\(\s*\$_POST\[['"][a-zA-Z0-9_-]+['"]\]\s*\)/ ascii

    condition:
        // Condition logic determines if the file triggers an alert
        $hex_magic at 0 and // Must start with standard PHP tag
        (
            $regex_eval or 
            2 of ($text_cmd*) // Any two of the text strings must match
        ) and 
        filesize < 2MB // Performance guardrail: skips scanning massive files
}