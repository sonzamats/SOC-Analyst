rule GenericRansomwareDetection {
    meta:
        description = "Detects common ransomware behaviors and indicators"
        author = "SOC Analyst SIEM Project"
        date = "2023-05-15"
        version = "1.0"
        reference = "https://attack.mitre.org/techniques/T1486/"
        mitre_att = "T1486"
        severity = "HIGH"
    
    strings:
        // Common ransomware file extensions
        $ext1 = ".locked" nocase
        $ext2 = ".crypt" nocase
        $ext3 = ".encrypted" nocase
        $ext4 = ".crypto" nocase
        $ext5 = ".pay" nocase
        $ext6 = ".ransom" nocase
        $ext7 = ".wcry" nocase
        $ext8 = ".wncry" nocase
        
        // Common ransom note filenames
        $note1 = "HOW_TO_DECRYPT" nocase
        $note2 = "DECRYPT_INSTRUCTIONS" nocase
        $note3 = "YOUR_FILES" nocase
        $note4 = "RECOVER_FILES" nocase
        $note5 = "README_FOR_DECRYPT" nocase
        $note6 = "HELP_DECRYPT" nocase
        $note7 = "READ_TO_DECRYPT" nocase
        
        // Common ransomware strings
        $str1 = "Your files have been encrypted" nocase
        $str2 = "You have to pay for decryption" nocase
        $str3 = "bitcoin" nocase
        $str4 = "payment" nocase
        $str5 = "decrypt" nocase
        $str6 = "your personal files are encrypted" nocase
        $str7 = "your important files encryption produced" nocase
        
        // Common crypto functions
        $crypto1 = "CryptEncrypt" fullword
        $crypto2 = "CryptDecrypt" fullword
        $crypto3 = "CryptGenKey" fullword
        $crypto4 = "CryptDestroyKey" fullword
        
        // File enumeration
        $file1 = "FindFirstFile" fullword
        $file2 = "FindNextFile" fullword
        
        // Delete shadow copies
        $cmd1 = "vssadmin delete shadows" nocase
        $cmd2 = "wmic shadowcopy delete" nocase
        $cmd3 = "bcdedit /set" nocase
        
    condition:
        (2 of ($ext*) or 2 of ($note*)) and 
        (2 of ($str*)) and 
        (2 of ($crypto*) or 2 of ($file*) or 1 of ($cmd*))
}