rule Detect_p0wny_Shell_Specific {
    meta:
        description = "Detects the p0wny-shell PHP webshell via unique author-specific string"
        author = "Joshua Fishman"
        date = "2026-07-07"
        reference = "https://github.com/flozz/p0wny-shell"

    strings:
        $unique_str = "p0wny" ascii nocase
        $php_tag = "<?php"

    condition:
        $php_tag and $unique_str and filesize < 500KB
}