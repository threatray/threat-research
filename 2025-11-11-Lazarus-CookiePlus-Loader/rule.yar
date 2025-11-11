rule CookiePlusLoader {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Hunting rule for CookiePlus Loader used by Lazarus"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-11-11"
        hash = "f9a9c1a13ed74aebca0652b102755833fc084e221d731b5e7ae76ff136f85864"

    strings:
        // NtAllocateVirtuaNtFreeVirtualMem
        $required_apis = {
            4E 74 41 6C 6C 6F 63 61 74 65 56 69 72 74 75 61 4E 74 46 72 65 65 56 69 72 74 75 61 6C 4D 65 6D
        }
        $reflective_loading = {
            C7 45 ?? 6C 4D 65 6D      // mov     dword ptr [rbp+57h+var_48], 6D654D6Ch
            C7 45 ?? 6F 72 79 00      // mov     dword ptr [rbp+57h+var_48+4], 79726Fh
            C7 45 ?? 6F 72 79 00      // mov     [rbp+57h+var_30], 79726Fh
            [10-25]
            FF 15 ?? ?? ?? ??         // call    cs:GetModuleHandleW
            48 8B C8                  // mov     rcx, rax        ; hModule
            48 8D 55 ??               // lea     rdx, [rbp+57h+ProcName] ; lpProcName
            48 8B D8                  // mov     rbx, rax
            FF 15 ?? ?? ?? ??         // call    cs:GetProcAddress
            48 8D 55 ??               // lea     rdx, [rbp+57h+var_40] ; lpProcName
            48 8B CB                  // mov     rcx, rbx        ; hModule
            48 8B F8                  // mov     rdi, rax
            FF 15 ?? ?? ?? ??         // call    cs:GetProcAddress
            49 63 4C 24 3C            // movsxd  rcx, dword ptr [r12+3Ch]
            48 89 45 ??               // mov     [rbp+57h+var_80], rax
            42 81 3C 21 50 45 00 00   // cmp     dword ptr [rcx+r12], 4550h
        }

    condition:
        all of them
}
