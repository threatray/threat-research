rule OceanLotusLoader {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Hunting rule for OceanLotus Loader"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-10-30"
        hash = "c829cfd6cc80f4583df4b54cfe4d42222a30ca4012e83dcdc3c7749b631f32e3"

    strings:
        $custom_djb2_api_hashing = {
            48 63 ?? 3C                     // movsxd  rax, dword ptr [rcx+3Ch]
            8B ?? ?? 88 00 00 00            // mov     edi, [rax+rcx+88h]
            48 01 ??                        // add     rdi, rcx
            44 8B ?? 20                     // mov     r9d, [rdi+20h]
            8B ?? 18                        // mov     ebx, [rdi+18h]
            49 01 ??                        // add     r9, rcx
            85 ??                           // test    ebx, ebx
            74 ??                           // jz      short loc_1800C011E
            49 89 ??                        // mov     r11, rcx
            48 89 ??                        // mov     rsi, rdx
            45 31 ??                        // xor     r10d, r10d
            0F 1F 84 00 00 00 00 00         // nop     dword ptr [rax+rax+00000000h]
            41 8B ??                        // mov     ecx, [r9]
            4C 01 ??                        // add     rcx, r11
            0F B6 ??                        // movzx   eax, byte ptr [rcx]
            84 ??                           // test    al, al
            74 ??                           // jz      short loc_1800C0124
            BA 0? 15 00 00                  // mov     edx, 1504h
            66 0F 1F 44 00 00               // nop     word ptr [rax+rax+00h]
            3C 60                           // cmp     al, 60h ; '`'
            44 8D ?? E0                     // lea     r8d, [rax-20h]
            41 0F 47 ??                     // cmova   eax, r8d
            41 89 ??                        // mov     r8d, edx
            48 83 ?? 01                     // add     rcx, 1
            41 C1 ?? 05                     // shl     r8d, 5
        }
    condition:
        $custom_djb2_api_hashing 
}
