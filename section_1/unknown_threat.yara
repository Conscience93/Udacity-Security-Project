rule Udacity_detector {
        meta:
                Author = "South Udan"
                Description = "This rule detects darklord url in this ubuntu server."
        strings:
                $url = "darkl0rd" nocase
        condition:
                $url

}
