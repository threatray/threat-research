rule DotNet_Gulf_RedTeam_Loader {
    meta:
        author      = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects the .NET loader used across Gulf-targeting campaigns"
        license     = "Detection Rule License (DRL) 1.1"
        date        = "2026-04-23"
        reference   = "https://www.trellix.com/blogs/research/oneclik-a-clickonce-based-red-team-campaign-simulating-apt-tactics-in-energy-infrastructure/"
        reference   = "https://www.cyfirma.com/research/operation-phantomclr-stealth-execution-via-appdomain-hijacking-and-in-memory-net-abuse/"
        hash        = "048ffb71a1e5abfd6b905b7a4a5171eabe560948963a8c0d6aa14a40d0f6b255"
        hash        = "5d784d3ca02ab0015b028f34aa54bc8c50db39f9671dc787bc2a84f0987043b2"

    strings:
        $code_charswap = {
            02 07 08 93 06 08 93        // ldarg.0; ldloc.1; ldloc.2; ldelem.u2; ldloc.0; ldloc.2; ldelem.u2
            6F ?? ?? ?? 0A              // callvirt  String::Replace(char,char)
            10 00                       // starg.s   arg0
            08 17 58 0C                 // ldloc.2; ldc.i4.1; add; stloc.2
            08 6E 07 8E 69 6A 32 E6     // loop1 header: ldloc.2 conv.u8 ldloc.1 ldlen conv.i4 conv.i8 blt.s -26
            07                          // ldloc.1
            28 ?? ?? ?? 0A              // call      Array::Reverse
            16 0D 2B 12                 // ldc.i4.0; stloc.3; br.s +18
            02 06 09 93 07 09 93        // ldarg.0; ldloc.0; ldloc.3; ldelem.u2; ldloc.1; ldloc.3; ldelem.u2
            6F ?? ?? ?? 0A              // callvirt  String::Replace(char,char)
            10 00                       // starg.s   arg0
            09 17 58 0D                 // ldloc.3; ldc.i4.1; add; stloc.3
            09 6E 07 8E 69 6A 32 E6     // loop2 header: ldloc.3 conv.u8 ldloc.1 ldlen conv.i4 conv.i8 blt.s -26
            02 2A                       // ldarg.0; ret
        }

        $code_scratch200 = {
            20 C8 00 00 00              // ldc.i4    200
            28 ?? ?? ?? 0A              // call      Marshal::AllocHGlobal(int32)
            0B 16 0C 2B 20              // stloc.1; ldc.i4.0; stloc.2; br.s +32
            17                          // ldc.i4.1
            8D ?? ?? 00 01              // newarr    System.IntPtr
            25 16 02 9B                 // dup; ldc.i4.0; ldarg.0; stelem.i
            16 07 08                    // ldc.i4.0; ldloc.1; ldloc.2
            28 ?? ?? ?? 0A              // call      IntPtr::op_Addition
            17                          // ldc.i4.1
            28 ?? ?? ?? 0A              // call      Marshal::Copy(IntPtr[], i32, IntPtr, i32)
            08                          // ldloc.2
            28 ?? ?? ?? 0A              // call      IntPtr::get_Size
            58 0C 08                    // add; stloc.2; ldloc.2
            20 C8 00 00 00              // ldc.i4    200
            32 D8                       // blt.s     -40
        }

        $code_bruteforce_iv = {
            11 ?? 11 ??                 // ldloc.s V_aes; ldloc.s V_keybuf
            6F ?? ?? 00 06              // callvirt  <AES>::SetKey       (internal)
            11 ?? 11 ??                 // ldloc.s V_aes; ldloc.s V_ivbuf
            6F ?? ?? 00 06              // callvirt  <AES>::SetIV        (internal)
            11 ?? 11 ??                 // ldloc.s V_aes; ldloc.s V_ct
            6F ?? ?? 00 06              // callvirt  <AES>::Decrypt      (internal)
            13 ??                       // stloc.s   V_plain
            11 ?? 11 ??                 // ldloc.s V_plain; ldloc.s V_scratch
            [2-4]                       // 3rd Array.Copy arg: either 11 ?? (ldloc.s) or 11 ?? 8E 69 (ldloc.s; ldlen; conv.i4)
            28 ?? ?? ?? 0A              // call      Array::Copy(Array, Array, int32)
            11 ?? 11 ??                 // ldloc.s; ldloc.s  (the two enumerables)
            28 ?? 00 00 2B              // call      Enumerable::SequenceEqual<uint8>  (MethodSpec)
            2C                          // brfalse.s
        }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        2 of them
}
