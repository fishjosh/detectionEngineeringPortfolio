rule Detect_Generic_PHP_Webshell : PHP_Webshell {
    meta:
        description = "Detects basic patterns common in malicious PHP web shells"
        author = "Joshua Fishman"
        date = "2026-07-07"
        reference = "Static analysis study"

    strings:
        $exec1 = "exec(" ascii nocase 
        $exec2 = "shell_exec(" ascii nocase
        $exec3 = "passthru(" ascii nocase
        $exec4 = "system(" ascii nocase

        $input1 = "$_POST" ascii nocase
        $input2 = "$_GET" ascii nocase
        $input3 = "$_REQUEST" ascii nocase

        $php_tag = "<?php"
        $php_short_tag = "<?"
        $php_echo_tag = "<?="

    condition:
        ($php_tag or $php_short_tag or $php_echo_tag) and
        any of ($exec*) and any of ($input*) and
        filesize < 2MB 
}
