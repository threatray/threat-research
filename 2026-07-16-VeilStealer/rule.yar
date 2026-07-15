rule VeilStealer
{
    meta:
        author       = "Threatray"
        description  = "VeilStealer - Go-based infostealer (Discord/browser/crypto-wallet/AI-key theft, based on the 'equilotl' Vencord-installer fork)."
        reference    = "https://reports.threatray.com/68ce7670-8dbc-4039-ae18-dc57b8886ada"
	license      = "Detection Rule License (DRL) 1.1"
        date         = "2026-07-16"
        family       = "VeilStealer"
        hash1        = "b545d32cea056346a19985cad082fe920f5114ae8eade2417e48ad3fae43e33b"
        hash2        = "cf07f33f8727b3dc4b1d956b2a5e24a487470a8d74d2558c37249eca53976ba5"
        hash3        = "37f9de776d211aead04a1e54f2a5d8b453a1a51d1e906f3f4306868ac31501e1"
        hash4        = "4b660a310fc1125a079f8154a86edd0d43501edbbc4bc759dd55f1d4fd0c6d40"
        hash5        = "ebc9d1abb69490462aa79e0fc4ac987ce5cfe19492832e32f36685859e635fba"
        hash6        = "d302ba5778fac5bb12d82810958c2136d2b86c0267499075e4d947c97b4940a0"
        hash7        = "0876c0228fea2b0f06b7ed4644b440ce40032adb7a40867e76d5274524a3058b"
        hash8        = "42dd676a77e7fdcf2da653c4150ed2b339ce062fb91e5ff7e7a1f2b1c5e32f44"
        hash9        = "7dcc113684fe5bd9355866a59f4a901929ff5d07fb47a05d6c186d1e7b3f444f"
        hash10       = "ff99e0fbf4bffe07738630833155fccb0775deb29cf8e0d02a5019362072a9f5"
        hash11       = "d93d3701b17598fdf244e0eec2a87a13902baadde7c2c9253d60566215ef6df2"

    strings:
        // --- Go-binary ---
        $go1 = "Go build ID:" ascii
        $go2 = "go:buildid" ascii
        $go3 = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A }   // "\xff Go buildinf:" magic

        // --- Family-unique markers ---
        $veil1  = "VEIL_RUN=1" ascii
        $veil2  = "veil_debug.txt" ascii
        $veil3  = "RunVeil started" ascii
        $veil4  = "RunVeil done" ascii
        // --- Go source file names ---
        $veil5  = "veil_bootstrap.go" ascii
        $veil6  = "veil_spawn_windows.go" ascii
        $veil7  = "veil_win.go" ascii
        // --- Go pclntab function symbols ---
        $veil8  = "main.RunVeil" ascii
        $veil9  = "main.StartVeil" ascii
        $veil10 = "main.spawnVeil" ascii
        $veil11 = "main.stealDiscordTokens" ascii
        $veil12 = "main.stealCryptoWallets" ascii
        $veil13 = "main.stealAIKeys" ascii
        // --- AI-key theft artefact ---
        $veil14 = "aikey_%d.txt" ascii

        // code1 = main.stealDiscordTokens
        $code1 = {
            89 94 24 10 01 00 00      // mov d:[rsp+0x110], edx
            48 89 84 24 18 01 00 00   // mov [rsp+0x118], rax
            31 c0                     // xor eax, eax
            48 8d 9c 24 e0 00 00 00   // lea rbx, [rsp+0xe0]
            b9 04 00 00 00            // mov ecx, 4
            48 89 cf                  // mov rdi, rcx
            e8 ?? ?? ?? ??            // call <rel32>
            31 c0                     // xor eax, eax
            48 8b 9c 24 80 00 00 00   // mov rbx, [rsp+0x80]
            48 8b 4c 24 48            // mov rcx, [rsp+0x48]
            48 8d 3d ?? ?? ?? ??      // lea rdi, [rip+<disp32>]
            be 09 00 00 00            // mov esi, 9
            e8 ?? ?? ?? ??            // call <rel32>
            48 89 84 24 b8 00         // mov [rsp+0xb8], rax
        }
        // code2 = main.uploadFiles
        $code2 = {
            ff                        // call <rel32>   ; <- tail of preceding instr
            48 8b b4 24 38 04 00 00   // mov rsi, [rsp+0x438]
            49 89 33                  // mov [r11], rsi
            49 89 53 08               // mov [r11+8], rdx
            48 89 30                  // mov [rax], rsi
            48 8b 94 24 a8 00 00 00   // mov rdx, [rsp+0xa8]
            48 89 94 24 98 01 00 00   // mov [rsp+0x198], rdx
            48 8b 94 24 40 01 00 00   // mov rdx, [rsp+0x140]
            48 89 94 24 90 01 00 00   // mov [rsp+0x190], rdx
        }
        // code3 = main.takeScreenshot
        $code3 = {
            ff                        // call <rel32>   ; <- tail of preceding instr
            48 8b 94 24 18 01 00 00   // mov rdx, [rsp+0x118]
            49 89 13                  // mov [r11], rdx
            48 8b b4 24 10 01 00 00   // mov rsi, [rsp+0x110]
            49 89 73 08               // mov [r11+8], rsi
            48 89 84 24 38 04 00 00   // mov [rsp+0x438], rax
            48 89 10                  // mov [rax], rdx
            48 8b 54 24 78            // mov rdx, [rsp+0x78]
            48 89 50 18               // mov [rax+0x18], rdx
            48 89 70 10               // mov [rax+0x10], rsi
            48 8d 05                  // lea rax, [rip+<disp32>]
        }
        // code4 = main.ReportUsage
        $code4 = {
            78 48                     // js 0x4a
            8b 94 24 80 00 00 00      // mov edx, d:[rsp+0x80]
            48 39 d1                  // cmp rcx, rdx
            72 0a                     // jb 0x18
            48 8b b4 24 a8 00 00 00   // mov rsi, [rsp+0xa8]
            eb 43                     // jmp 0x5b
            48 89 9c 24 80 00 00 00   // mov [rsp+0x80], rbx
            48 89 84 24 80 01 00 00   // mov [rsp+0x180], rax
            48 8b 84 24 a8 00 00 00   // mov rax, [rsp+0xa8]
            48 89 d3                  // mov rbx, rdx
            bf 03 00 00 00            // mov edi, 3
            48 8d 35 ?? ?? ?? ??      // lea rsi, [rip+<disp32>]
            90                        // nop
        }
        // code5 = main.PromptDiscord
        $code5 = {
            0c 00            // lea rcx, [rip+<disp32>]   ; <- tail of preceding instr
            48 89 4c 24 20   // mov [rsp+0x20], rcx
            48 89 44 24 28   // mov [rsp+0x28], rax
            b8 03 00 00 00   // mov eax, 3
            48 8d 5c 24 20   // lea rbx, [rsp+0x20]
            b9 01 00 00 00   // mov ecx, 1
            48 89 cf         // mov rdi, rcx
            e8 ?? ?? ?? ??   // call <rel32>
            e8 ?? ?? ?? ??   // call <rel32>
            48 83 c4 30      // add rsp, 0x30
            5d               // pop rbp
            c3               // ret
        }
        // code6 = main.sendFilesToWebhook
        $code6 = {
            ff                        // call <rel32>   ; <- tail of preceding instr
            48 8b 94 24 08 01 00 00   // mov rdx, [rsp+0x108]
            49 89 13                  // mov [r11], rdx
            48 89 84 24 30 04 00 00   // mov [rsp+0x430], rax
            48 89 10                  // mov [rax], rdx
            48 8d 05 ?? ?? ?? ??      // lea rax, [rip+<disp32>]
            48 8b 9c 24 70 01 00 00   // mov rbx, [rsp+0x170]
            48 8d 0d ?? ?? ?? ??      // lea rcx, [rip+<disp32>]
            bf                        // mov edi, 0xb
        }
        // code7 = main.stealDiscordTokens
        $code7 = {
            ff                        // call <rel32>   ; <- tail of preceding instr
            48 89 84 24 b8 00 00 00   // mov [rsp+0xb8], rax
            48 89 5c 24 68            // mov [rsp+0x68], rbx
            31 c0                     // xor eax, eax
            48 8b 9c 24 90 00 00 00   // mov rbx, [rsp+0x90]
            48 8b 4c 24 58            // mov rcx, [rsp+0x58]
            48 8d 3d ?? ?? ?? ??      // lea rdi, [rip+<disp32>]
            be 09 00 00 00            // mov esi, 9
            e8 ?? ?? ?? ??            // call <rel32>
            48 89 c1                  // mov rcx, rax
            48 89 df                  // mov rdi, rbx
        }
        // code8 = main.takeScreenshot
        $code8 = {
            00                        // adc eax, 0x158551   ; <- tail of preceding instr
            48 89 94 24 50 02 00 00   // mov [rsp+0x250], rdx
            48 8d 84 24 40 02 00 00   // lea rax, [rsp+0x240]
            bb 02 00 00 00            // mov ebx, 2
            48 89 d9                  // mov rcx, rbx
            e8 ?? ?? ?? ??            // call <rel32>
            48 89 84 24 10 01 00 00   // mov [rsp+0x110], rax
            48 89 5c 24 78            // mov [rsp+0x78], rbx
            48 8d 05                  // lea rax, [rip+<disp32>]
        }


    condition:
        uint16(0) == 0x5A4D and filesize < 30MB and
        any of ($go*) and                            
        (
            4 of ($veil*)                        
            or 6 of ($code*)
            or (2 of ($veil*) and 3 of ($code*))  
        )
}
