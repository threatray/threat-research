rule FakeUpdater_Stage1 {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Hunting rule for the dropper stage of FakeUpdater"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-12-05"
        reference = "https://www.threatray.com/blog/fakeupdater-a-year-long-fake-application-campaign"
        hash = "5ae866358a4d24c8f3b81bf6790af2f90401bc07e0b07494f9867d95fb4b48f3"

    strings:
        $s1  = "placeSingleOne"
        $s2  = "placeSingleFile"
        $s3  = "placeInDir"
        $s4  = "placeFilesInFolder"
        $s5  = "putUpdates"
        $s6  = "RegisterUpdate"
        $s7  = "id.txt" wide
        $s8  = "userId.txt" wide
        $s9 = "-ep RemoteSigned -File"
        $s10  = "conmate_update.ps1" wide
        $s11 = "update_task_ad.ps1" wide

    condition:
        5 of ($s*)
}

rule FakeUpdater_Stage2 {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Hunting rule for the updater stage of FakeUpdater"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-12-05"
        reference = "https://www.threatray.com/blog/fakeupdater-a-year-long-fake-application-campaign"
        hash = "0edd3de73a63f65b68cff15ae32ea224c023d1339de9fb95046b0fbf17c8d1a5"

    strings:
        $x1 = "HandleUpdates"
        $x2 = "getInstallDate"
        $x3 = "GetSessionInfo"
        $x4 = "getUserID"
        $x5 = "createRequestMessage"
        $x6 = "GetUpdates"

        $y1 = "HitUrl"
        $y2 = "sendCrashReport"
        $y3 = "reportCrash"
        $y4 = "StartUpdate"
        $y5 = "getInstallationDate"
        $y6 = "getUserID"

        $z1 = "getSerializedTokenObj"
        $z2 = "deriveKeyFromString"
        $z3 = "decodeEncryptedContent"
        $z4  = "InstallDate"

    condition:
        filesize < 60KB and
        (5 of ($x*) or 5 of ($y*) or 4 of ($z*))
}
