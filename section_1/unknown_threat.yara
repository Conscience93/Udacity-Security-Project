rule suspicious_url_detector {
        meta:
                Author = "South Udan"
                Description = "This rule detects suspicious url in the ubuntu server."
        strings:
                $url = "darkl0rd" nocase
        condition:
                $url

}
