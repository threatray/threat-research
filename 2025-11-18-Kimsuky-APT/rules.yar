rule Kimsuky_GoDropper {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Hunting rule for Kimsuky Go dropper"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-11-18"
        hash = "a4a8dc0f13ddacfad3e0ef8929aac9453759f5e77d9222412ca637bec32320d0"

    strings:
        $s1 = "main.SelfDel" ascii fullword
        $s2 = "main.RunCmd" ascii fullword
        $s3 = "main.RunProcess" ascii fullword
        $s4 = "main.RandomBytes" ascii fullword
        $s5 = "main.ChangeCurrentExe" ascii fullword

    condition:
        3 of them
}

rule Kimsuky_Memload {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Hunting rule for Kimsuky Memload"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-11-18"
        hash1 = "2a4c2aee3272fad79c70171ffd745375a6961ff27fa153f4bc5518d3aa79cbdc"
        hash2 = "0be26482a47e696774686dd19be90ee8220e17c739a85e6b114d4a81d32b3cfc"

    strings:
        $rc4_key = "#RsfsetraW#@EsfesgsgAJOPj4eml;"

        $rc4_simd = {
            8D 41 F8            // lea     eax, [rcx-8]
            66 0F 6E C0         // movd    xmm0, eax
            [0-10]
            66 0F 70 C0 00      // pshufd  xmm0, xmm0, 0
            [0-10]
            66 0F FE C2         // paddd   xmm0, xmm2
            [0-10]
            F3 0F 7F [1-2]      // movdqu  xmmword ptr [rdx-60h], xmm0
            [0-10]
            66 0F 70 C9 00      // pshufd  xmm1, xmm1, 0
            [0-10]
            66 0F FE CA         // paddd   xmm1, xmm2
            [0-10]
            F3 0F 7F [1-2]      // movdqu  xmmword ptr [rdx-50h], xmm1
            [10-80]
            3D 00 01 00 00      // cmp     eax, 100h
            7C ??               // jl      short loc_180001C40
        }

    condition:
        all of them
}
