rule salaryIncreasePhish
{
    meta:
        description = "Yara rule that detects phishing e-mail by few simple repatable e-mail strings in subject and sender." 
        date = "18.01.2023"
        version = "1.00"
        author = "Mateusz Przybylko"
        weight = 100
    strings:
        $domain = /From: HR DEP [0-9]{0,7} <hrdep+[0-9]{0,7}@+[a-zA-Z]{0,99}.com>/
        // RegEx that detects repatable sender whose every time had diffrent domain name but, first strings was the same with diffrent numbers. Example for .eml extension: 
        // "From: HR DEP 1231231 <hrdep1231231@gmail.com>" or "From: HR DEP 3213213 <hrdep3213213@domains.com>"
       
        $stringInSubject = /B[0-9]{1}B[0-9]{1}B[0-9]{6}/
        // RegEx that detects reapatable value in .eml body. Example: "B1B2B313138" or "B3B9B123456"
       
        $fileType = {52 65 63 65 69 76 65 64 3A}
        // Hex value for .eml extension form: https://en.wikipedia.org/wiki/List_of_file_signatures 
    condition:
        $domain and $stringInSubjest and $filetype
}