import "pe"

rule ArtraDownloader : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects ArtraDownloader used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "ef0cb0a1a29bcdf2b36622f72734aec8d38326fc8f7270f78bd956e706a5fd57"
        hash = "0b2a794bac4bf650b6ba537137504162520b67266449be979679afbb14e8e5c0"
        hash = "f0ef4242cc6b8fa3728b61d2ce86ea934bd59f550de9167afbca0b0aaa3b2c22"

    strings:
        $v1_s1 = "BCDEF=%s&MNOPQ=%s&GHIJ=%s&UVWXYZ=%s&st=%d" ascii fullword
        $v1_s2 = "%s %s %s\r\n%s %s\r\n%s%s\r\n%s%s\r\nContent-length: %d\r\n\r\n%s" ascii fullword
        $v1_s3 = "DFCB=" ascii fullword
        $v1_s4 = "DWN" ascii fullword
        $v1_s5 = "<br>" ascii fullword

        $v2_s1 ="GET %s HTTP/1.0" ascii fullword
        $v2_s2 ="Host: %s" ascii fullword
        $v2_s3 ="?a=\x00&b=\x00&c=\x00&d=\x00&e=\x00" ascii fullword
        $v2_s4 ="%s%s%s%s%s%s%s%s" ascii fullword
        $v2_s5 ="Yes file" ascii fullword
        
        $v3_s1 = "AXE: #" ascii fullword
        $v3_s2 = "%s*%s*%s" ascii fullword
        $v3_s3 = "Bld: %s.%s.%s" ascii fullword
        $v3_s4 = "%s@%s %s" ascii fullword
        $v3_s5 = "%s%s\r\n\r\n" ascii fullword

    condition:
        pe.is_pe and
        filesize < 400KB and
        all of ($v1_*) or all of ($v2_*) or all of ($v3_*)
}

rule BitterKeylogger : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects the Keylogger module used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "f619eb9a6255f6adcb02d59ed20f69d801a7db1f481f88e14abca2df020c4d26"
        hash = "1f9363e640e9fe0d25ef15ed5d3517ec5b3fb16e3b1abb58049f5ad45415654d"

    strings:
        $code_get_key_state = {
            8B 07                  // mov     eax, [edi]
            3D A0 00 00 00         // cmp     eax, 0A0h
            74 ??                  // jz      short loc_401472
            3D A1 00 00 00         // cmp     eax, 0A1h
            75 ??                  // jnz     short loc_401486
        }
        $code_collect_clipboard = {
            FF 15 ?? ?? ?? ??      // call    ds:OpenClipboard
            85 ??                  // test    eax, eax
            74 ??                  // jz      short loc_40250A
            6A 01                  // push    1               ; format
            FF 15 ?? ?? ?? ??      // call    ds:IsClipboardFormatAvailable
            85 C0                  // test    eax, eax
            74 ??                  // jz      short loc_40250A
            6A 01                  // push    1               ; uFormat
            FF 15 ?? ?? ?? ??      // call    ds:GetClipboardData
            8B ??                  // mov     ecx, eax
            8D ?? 01               // lea     esi, [ecx+1]
        }
        $code_check_log_file_size = {
            6A 02                  // push    2
            8B ??                  // mov     esi, eax
            6A 00                  // push    0
            5?                     // push    esi
            E8 ?? ?? ?? ??         // call    _fseek
            5?                     // push    esi
            E8 ?? ?? ?? ??         // call    _ftell
            5?                     // push    esi
            8B ??                  // mov     edi, eax
            E8 ?? ?? ?? ??         // call    _fclose
            83 C4 1C               // add     esp, 1Ch
            81 ?? E8 03 00 00      // cmp     edi, 3E8h

        }

    condition:
        pe.is_pe and
        filesize < 400KB and
        all of them
}

rule WSCSPLBackdoor : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects WSCSPL backdoor used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "a241cfcd60942ea401d53d6e02ec3dfb5f92e8f4fda0aef032bee7bb5a344c35"
        hash = "096e6546b5ca43adbe34bbedc84b002bbf399d2ecf08e83966757b88c5c0d2a2"

    strings:
        $code_main = {
            6A 64                            // push    64h ; 'd'       ; cchBufferMax
            68 ?? ?? ?? ??                   // push    offset WindowName ; lpBuffer
            6A 67                            // push    67h ; 'g'       ; uID
            5?                               // push    esi             ; hInstance
            FF D?                            // call    edi ; LoadStringA
            6A 64                            // push    64h ; 'd'       ; cchBufferMax
            68 ?? ?? ?? ??                   // push    offset ClassName ; lpBuffer
            6A 6D                            // push    6Dh ; 'm'       ; uID
            5?                               // push    esi             ; hInstance
            FF D?                            // call    edi ; LoadStringA
        }
        $code_xor_c2_data = {
            8A 8? 17 ?? ?? ?? ??             // mov     al, byte_4520D8[edi+edx]
            32 8? ?? ?? ?? ??                // xor     al, byte_406078[ecx]
            4?                               // inc     ecx
            88 8? ?? ?? ?? ??                // mov     byte_4520D8[edx], al
            4?                               // inc     edx
            3? ??                            // cmp     ecx, esi
            75 ??                            // jnz     short loc_401C2B
            3? ??                            // xor     ecx, ecx
            3? ??                            // cmp     edx, ebp
            7C ??                            // jl      short loc_401C10
        }
        $code_handle_c2_commands = {
            8D ?? 24 10                      // lea     edx, [esp+10h]
            5?                               // push    edx             ; lpParameter
            68 ?? ?? ?? ??                   // push    offset mw_get_victim_info ; lpStartAddress
            6A 00                            // push    0               ; dwStackSize
            6A 00                            // push    0               ; lpThreadAttributes
            C7 05 ?? ?? ?? ?? A0 0F 00 00    // mov     dword_406090, 4000
            C7 05 ?? ?? ?? ?? ?? ?? 00 00    // mov     dword_45EA98, 3000
            FF 15 ?? ?? ?? ??                // call    ds:CreateThread
            A3 ?? ?? ?? ??                   // mov     dword_45EA64, eax
            E9 ?? ?? 00 00                   // jmp     def_401CEE
        }

    condition:
        pe.is_pe and
        filesize < 200KB and
        all of them
}

rule MuuyDownloader : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects MuuyDownloader used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "225d865d61178afafc33ef89f0a032ad0e17549552178a72e3182b48971821a8"
        hash = "3fdf291e39e93305ebc9df19ba480ebd60845053b0b606a620bf482d0f09f4d3"
        hash = "91ddbe011f1129c186849cd4c84cf7848f20f74bf512362b3283d1ad93be3e42"
        hash = "edb68223db3e583f9a4dd52fd91867fa3c1ce93a98b3c93df3832318fd0a3a56"

    strings:
    $x = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii wide fullword

    $code_main = {
        6A 64                    // push    64h ; 'd'       ; cchBufferMax
        68 ?? ?? ?? ??           // push    offset WindowName ; lpBuffer
        6A 67                    // push    67h ; 'g'       ; uID
        5?                       // push    esi             ; hInstance
        FF D?                    // call    edi ; LoadStringA
        6A 64                    // push    64h ; 'd'       ; cchBufferMax
        68 ?? ?? ?? ??           // push    offset ClassName ; lpBuffer
        6A 6D                    // push    6Dh ; 'm'       ; uID
        5?                       // push    esi             ; hInstance
        FF D?                    // call    edi ; LoadStringA
    }
    $code_write_mz = {
        8B 3D ?? ?? ?? ??      // mov     edi, ds:fwrite
        [0-2]
        56                     // push    esi             ; Stream
        6A 01                  // push    1               ; ElementCount
        6A 01                  // push    1               ; ElementSize
        68 ?? ?? ?? ??         // push    offset aM       ; Buffer
        FF D7                  // call    edi ; fwrite
    }
    $code_c2_conn = {
        C7 [2-3] 01 00 00 00     // mov     [esp+1E4h+pHints.ai_socktype], 1
        C7 [2-3] 06 00 00 00     // mov     [esp+1E4h+pHints.ai_protocol], 6
        FF 15 ?? ?? ?? ??        // call    ds:getaddrinfo
        85 C0                    // test    eax, eax
    }
    $code_check_running_procs = {
        6A 00                    // push    0               ; th32ProcessID
        6A 0F                    // push    0Fh             ; dwFlags
        E8 ?? ?? ?? ??           // call    CreateToolhelp32Snapshot
        68 ?? 01 00 00           // push    124h            ; Size
        8B ??                    // mov     esi, eax
        8D [3-5]                 // lea     eax, [ebp+pe.cntUsage]
        6A 00                    // push    0               ; Val
        50                       // push    eax             ; void *
        E8 ?? ?? ?? ??           // call    memset
        83 C4 0C                 // add     esp, 0Ch
    }

    condition:
        pe.is_pe and
        filesize < 100KB and
        ($x and 2 of ($code*) or (3 of ($code*))) and
        for any i in pe.import_details: ( for any f in i.functions: ( f.name == "fwrite" ) )
}

rule BDarkRAT : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects BDarkRAT used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "e07e8cbeeddc60697cc6fdb5314bd3abb748e3ac5347ff108fef9eab2f5c89b8"
        hash = "bf169e4dacda653c367b015a12ee8e379f07c5728322d9828b7d66f28ee7e07a"
        hash = "e599c55885a170c7ae5c7dfdb8be38516070747b642ac21194ad6d322f28c782"

    strings:
        $s1 = "Process started successfully" wide fullword
        $s2 = "No process to send input to" wide fullword

        $code_initialize_commands = {
            73 ?? 00 00 0A    // IL_0000: newobj    ::.ctor()
            80 ?? 00 00 04    // IL_0005: stsfld    ::packetList
            72 ?? ?? 00 70    // IL_000A: ldstr     "1"
            [1-2]             // IL_000F: ldc.i4.2
            D0 ?? ?? 00 02    // IL_0010: ldtoken   R_DeleteFile
            28 ?? ?? 00 0A    // IL_0015: call      ::GetTypeFromHandle
            73 ?? ?? 00 06    // IL_001A: newobj    ::.ctor
            28 ?? ?? 00 06    // IL_001F: call      ::RegisterPacket
            72 ?? ?? 00 70    // IL_0024: ldstr     "12"
            [1-2]             // IL_0029: ldc.i4.s  18
            D0 ?? ?? 00 02    // IL_002B: ldtoken   R_FileMgrGetDrives
            28 ?? ?? 00 0A    // IL_0030: call      ::GetTypeFromHandle
            73 ?? ?? 00 06    // IL_0035: newobj    ::.ctor
            28 ?? ?? 00 06    // IL_003A: call      ::RegisterPacket
            72 ?? ?? 00 70    // IL_003F: ldstr     "13"
        }
        $code_connect_ip = {
            26                // IL_0071: pop
            02                // IL_0072: ldarg.0
            7B ?? ?? 00 04    // IL_0073: ldfld     ::random
            17                // IL_0078: ldc.i4.1
            1?                // IL_0079: ldc.i4.4
            6F ?? ?? 00 0A    // IL_007A: callvirt  Random::Next
            20 E8 03 00 00    // IL_007F: ldc.i4    1000
            5A                // IL_0084: mul
            28 ?? ?? 00 0A    // IL_0085: call      Thread::Sleep
            DE ??             // IL_008A: leave.s   IL_00CE
            02                // IL_008C: ldarg.0
            7B ?? ?? 00 04    // IL_008D: ldfld     ::random
            17                // IL_0092: ldc.i4.1
            1?                // IL_0093: ldc.i4.2
            6F ?? ?? 00 0A    // IL_0094: callvirt  Random::Next
            20 E8 03 00 00    // IL_0099: ldc.i4    1000
            5A                // IL_009E: mul
            28 ?? ?? 00 0A    // IL_009F: call      Thread::Sleep
            7E ?? ?? 00 04    // IL_00A4: ldsfld    Settings::ConnectIP
            28 ?? ?? 00 0A    // IL_00A9: call      ::IsNullOrEmpty
            2D 19             // IL_00AE: brtrue.s  IL_00C9
            7E ?? ?? 00 04    // IL_00B0: ldsfld    ClientConnect::clientSocket
            7E ?? ?? 00 04    // IL_00B5: ldsfld    Settings::ConnectIP
            28 ?? ?? 00 0A    // IL_00BA: call      IPAddress::Parse
            7E ?? ?? 00 04    // IL_00BF: ldsfld    Settings::ConnectPort
            6F ?? ?? 00 0A    // IL_00C4: callvirt  Socket::Connect
            DE ??             // IL_01EE: leave.s   IL_01F3
        }
        $code_packet_crypt = {
            16                // IL_0000: ldc.i4.0
            0A                // IL_0001: stloc.0
            2B 16             // IL_0002: br.s      IL_001A
            02                // IL_0004: ldarg.0
            06                // IL_0005: ldloc.0
            8F ?? ?? 00 01    // IL_0006: ldelema   System.Byte
            25                // IL_000B: dup
            47                // IL_000C: ldind.u1
            7E ?? ?? 00 04    // IL_000D: ldsfld    CryptEngine::_key
            D2                // IL_0012: conv.u1
            61                // IL_0013: xor
            D2                // IL_0014: conv.u1
            52                // IL_0015: stind.i1
            06                // IL_0016: ldloc.0
            17                // IL_0017: ldc.i4.1
            58                // IL_0018: add
            0A                // IL_0019: stloc.0
            06                // IL_001A: ldloc.0
            02                // IL_001B: ldarg.0
            8E                // IL_001C: ldlen
            69                // IL_001D: conv.i4
            32 E4             // IL_001E: blt.s     IL_0004
            02                // IL_0020: ldarg.0
            2A                // IL_0021: ret
        }

    condition:
        pe.is_pe and
        filesize < 200KB and
        all of ($s*) and 2 of ($code*)
}

rule AlmondRAT : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects AlmondRAT used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"
        hash = "d83cb82be250604b2089a1198cedd553aaa5e8838b82011d6999bc6431935691"

    strings:
        $s1  = "GetMacid" ascii fullword
        $s2  = "GetOsName" ascii fullword
        $s3  = "GetallDrives" ascii fullword
        $s4  = "sendingSysInfo" ascii fullword
        $s5  = "fileAccessible" ascii fullword
        $s6  = "StartClient" ascii fullword
        $s7  = "StartCommWithServer" ascii fullword
        $s8  = "*|END|*" wide fullword
        $s9  = "PATH>" wide fullword
        $s10 = "FILE>" wide fullword
        $s11 = "NOTOK" wide fullword

    condition:
        pe.is_pe and
        filesize < 50KB and
        8 of ($s*)
}

rule ORPCBackdoor : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects ORPCBackdoor used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "8aeb7dd31c764b0cf08b38030a73ac1d22b29522fbcf512e0d24544b3d01d8b3"
        hash = "dd53768eb7d5724adeb58796f986ded3c9b469157a1a1757d80ccd7956a3dbda"

    strings:
        $rpc = "RPCRT4.dll"

        $s1  = "Host Name:\t\t\t" ascii
        $s2  = "OS Build Type :\t\t\t" ascii
        $s3  = "Registered Owner:\t\t" ascii
        $s4  = "Product ID:\t\t\t" ascii
        $s5  = "Install Date:\t\t\t" ascii
        $s6  = "System Manufacturer:\t\t" ascii
        $s7  = "Processor(s):\t\t\t" ascii
        $s8  = "BiosVersion:\t\t\t" ascii
        $s9  = "BIOSVENDOR:\t\t\t" ascii
        $s10 = "BIOS Date:\t\t\t" ascii
        $s11 = "Boot Device:\t\t\t" ascii
        $s12 = "Input Locale:\t\t\t" ascii
        $s13 = "Time zone:\t\t\t" ascii
        $s14 = "Total Physical Memory:\t\t" ascii
        $s15 = "Virtual Memory: In Use:\t\t" ascii
        $s16 = "Page File Location(s):\t\t" ascii
        $s17 = "Error! GetComputerName failed.\n" ascii
        $s18 = "Error! RegOpenKeyEx failed.\n" ascii
        $s19 = "IA64-based PC" wide
        $s20 = "AMD64-based PC" wide
        $s21 = "X86-based PC" wide
        $s22 = "%s\\oeminfo.ini" wide

    condition:
        pe.is_pe and
        $rpc and 15 of ($s*)
}

rule WmRAT : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf, Threatray)"
        description = "Detects WmRAT used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "4e3e4d476810c95c34b6f2aa9c735f8e57e85e3b7a97c709adc5d6ee4a5f6ccc"
        hash = "10cec5a84943f9b0c635640fad93fd2a2469cc46aae5e43a4604c903d139970f"

    strings:
        $s1  = "%s%ld M" ascii fullword
        $s2  = "%s%ld K" ascii fullword
        $s3  = "%s%ld MB" ascii fullword
        $s4  = "%s%ld KB" ascii fullword
        $s5  = "--,." ascii fullword
        $s6  = "RFOX" ascii fullword
        $s7  = "1llll" ascii fullword
        $s8  = "exit" ascii fullword
        $s9  = "Path=" ascii fullword
        $s10 = "  %d result(s)" ascii fullword
        $s11 = "%02d-%02d-%d %02d:%02d" ascii fullword

        $code_sleep = {
            6A 64                 // push    64h ; 'd'       ; dwMilliseconds
            FF ??                 // call    esi ; Sleep
            6A 01                 // push    1               ; unsigned int
            E8 ?? ?? ?? ??        // call    ??2@YAPAXI@Z    ; operator new(uint)
            83 C4 04              // add     esp, 4
            3B ??                 // cmp     eax, edi
            74 ??                 // jz      short loc_4019E5
        }
        $code_dec_str = {
            83 7C 24 ?? 10        // cmp     dword ptr [esp+44h], 10h
            8B 44 24 ??           // mov     eax, [esp+30h]
            73 ??                 // jnb     short loc_4086B2
            8D 44 24 ??           // lea     eax, [esp+30h]
            8A 0C 37              // mov     cl, [edi+esi]
            80 ?? ??              // sub     cl, 2Eh ; '.'
            88 0C 30              // mov     [eax+esi], cl
            46                    // inc     esi
            3B F5                 // cmp     esi, ebp
            7C ??                 // jl      short loc_408680
        }
        $code_fill_logs = {
            BD E8 03 00 00        // mov     ebp, 1000
            83 ?? FF              // or      edi, 0FFFFFFFFh
            E8 ?? ?? ?? ??        // call    Get_ComputerName_and_Username
            66 A1 ?? ?? ?? ??     // mov     ax, ds:word_40D82C
            8A 0D ?? ?? ?? ??     // mov     cl, ds:byte_40D82E
            66 89 44 24 ??        // mov     [esp+14h], ax
            88 4C 24 ??           // mov     [esp+16h], cl
            FF 15 ?? ?? ?? ??     // call    ds:GetLogicalDrives
            89 44 24 ??           // mov     [esp+18h], eax
            3B ??                 // cmp     eax, esi
            74 ??                 // jz      short loc_4091E1
            8D ?? 00 00 00 00     // lea     ebx, [ebx+0]
            A8 01                 // test    al, 1
            74 ??                 // jz      short loc_4091D5
        }

    condition:
        pe.is_pe and
        filesize < 300KB and
        10 of ($s*) or all of ($code*)
}

rule MiyaRAT : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects MiyaRAT used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "df5c0d787de9cc7dceeec3e34575220d831b5c8aeef2209bcd81f58c8b3c08ed"
        hash = "c7ab300df27ad41f8d9e52e2d732f95479f4212a3c3d62dbf0511b37b3e81317"
        hash = "0953d4cc6861082c079935918c63cd71df30e5e6854adf608a8b8f5254be8e99"
        hash = "c2c92f2238bc20a7b4d4c152861850b8e069c924231e2fa14ea09e9dcd1e9f0a"

    strings:
        $x1 = "] GB FREE\r\n" ascii fullword
        $x2 = "<||>\r\n" wide fullword

        $s1  = "<SZ>" wide
        $s2  = "<FIL>" wide
        $s3  = "UPL1" wide
        $s4  = "DWNL" wide
        $s5  = ",filesize==" wide
        $s6  = "[DIR]<||>" wide
        $s7  = "[FILE]<||>" wide
        $s8  = "[END]~!@" wide
        $s9  = "GDIR" wide
        $s10 = "DELz" wide
        $s11 = "GFS" wide
        $s12 = "SH1" wide
        $s13 = "SH2" wide
        $s14 = "SFS" wide
        $s15 = "GSS" wide
        $s16 = "SH1cmd" wide
        $s17 = "SH1start_cmd" wide
        $s18 = "SH1start_ps" wide
        $s19 = "SH1exit_client" wide

        $code_init_c2_conn = {
            68 00 00 00 80               // push    80000000h       ; esFlags
            FF 15 ?? ?? ?? ??            // call    ds:SetThreadExecutionState
            68 E9 FD 00 00               // push    0FDE9h          ; wCodePageID
            FF 15 ?? ?? ?? ??            // call    ds:SetConsoleOutputCP
            68 E9 FD 00 00               // push    0FDE9h          ; wCodePageID
            FF 15 ?? ?? ?? ??            // call    ds:SetConsoleCP
            [0-1]
            8D 85 ?? ?? ?? ??            // lea     eax, [ebp+WSAData]
            50                           // push    eax             ; lpWSAData
            68 02 02 00 00               // push    202h            ; wVersionRequested
            FF 15 ?? ?? ?? ??            // call    ds:WSAStartup
            85 C0                        // test    eax, eax
        }
        $code_collect_user_info = {
            68 00 20 00 00                       //  push    2000h           ; Size
            [0-6]
            6A 00                                //  push    0               ; Val
            [0-6]
            5?                                   //  push    eax             ; void *
            E8 ?? ?? ?? ??                       //  call    _memset         ; Connection successful. Start gathering system information.
            83 C4 0C                             //  add     esp, 0Ch
            C7 85 ?? ?? ?? ?? 10 00 00 00        //  mov     [ebp+pcbBuffer], 10h
            8D 8? ?? ?? ?? ??                    //  lea     eax, [ebp+pcbBuffer] ; Get username.
            5?                                   //  push    eax             ; pcbBuffer
            8D 4? ??                             //  lea     eax, [ebp+Buffer]
            5?                                   //  push    eax             ; lpBuffer
            FF 15 ?? ?? ?? ??                    //  call    ds:GetUserNameW
            [0-6]
            C7 85 ?? ?? ?? ?? 10 00 00 00        //   mov     [ebp+pcbBuffer], 10h
            [0-6]
            5?                                   //  push    eax             ; nSize
            8D 4? ??                             //  lea     eax, [ebp+var_34]
            5?                                   //  push    eax             ; lpBuffer
            FF 15 ?? ?? ?? ??                    //  call    ds:GetComputerNameW
            6A 00                                //  push    0               ; lpModuleName
            FF 15 ?? ?? ?? ??                    //  call    ds:GetModuleHandleW ; Get current module file path.
        }

    condition:
        pe.is_pe and
        all of ($x*) and
        (10 of ($s*) or 2 of ($code*))
}

rule KiwiStealer : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects KiwiStealer used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "4b62fc86273cdc424125a34d6142162000ab8b97190bf6af428d3599e4f4c175"

    strings:
        $code_main = {
            FF 15 ?? ?? ?? ??       // call    cs:CreateMutexA
            4C 8B F8                // mov     r15, rax
            FF 15 ?? ?? ?? ??       // call    cs:GetLastError
            3D B7 00 00 00          // cmp     eax, 0B7h
            0F 84 ?? ?? ?? ??       // jz      loc_14000B718
            FF 15 ?? ?? ?? ??       // call    cs:GetLastError
            83 F8 05                // cmp     eax, 5
            0F 84 ?? ?? ?? ??       // jz      loc_14000B718
        }
        $code_dec_str = {
            66 83 ?? 19             // cmp     ax, 19h
            77 ??                   // ja      short loc_140005CDF
            83 ?? 3F                // sub     ecx, 3Fh ; '?'
            B? 4F EC C4 4E          // mov     eax, 4EC4EC4Fh
            F7 ??                   // imul    ecx
            C1 ?? 03                // sar     edx, 3
            8B ??                   // mov     eax, edx
            C1 ?? 1F                // shr     eax, 1Fh
            03 ??                   // add     edx, eax
            6B ?? 1A                // imul    eax, edx, 1Ah
            2B ??                   // sub     ecx, eax
            66 83 ?? 41             // add     cx, 41h ; 'A'
        }

    condition:
        pe.is_pe and
        filesize < 300KB and
        all of them
}

rule KugelBlitz : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects KugelBlitz shellcode loader used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "a56b5e90a08822483805f9ab38debb028eb5eade8d796ebf0ff1695c3c379618"

    strings:
        $s1 = "run.bin" wide
        $s2 = "Failed to open the file." ascii
        $s3 = "Failed to allocate memory." ascii
        $s4 = "Failed to read the shellcode." ascii
        $s5 = "ShellCode_Loader" ascii

    condition:
        pe.is_pe and
        filesize < 100KB and
        4 of them
}
