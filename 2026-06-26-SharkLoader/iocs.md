| First Seen | SHA256 | Notes |
| --- | --- | --- |
| 2024-01-17 | `f87cb46cac1fa44c9f1430123fb23e179e3d653a0e4094e0c133fa48a924924f` | Sophos's Swedish case. Twofish at the loader stage, plaintext-PE payload. Signed with stolen Gala Lab Corp. certificate. |
| 2024-02-22 | `e534d9032141555d21be8b23f30d8f6dd156d61e986bbeed019d9316973b1ba9` | Twofish CBC loader, AES-128-CTR payload. Leaks PDB path `E:\2023\NewHookDll\Shark\` plus source filenames `EnTwoFish.cpp`, `LdrpLoaderLock.cpp`, `SharkData.cpp`. |
| 2024-09-25 | `c8d5ded9c78fa5cd8ea2ec956064e7aab3e04fab95e9b2c4611f9370c0b28323` | CryptoAPI MD5+AES loader, XTEA payload. C2 `bostik.cmsnet[.]se` (Sophos) + `ms-record[.]com` (Securelist). |
| 2025-11-04 | `6a5f9bd0e4a0c385b98cc7b528be53a95ff9c4ccffa8c1f65448ab792a46186c` | Securelist's published installer. Loader rewritten: Blowfish + xxHash + Vectored Exception Handler anti-analysis, payload back to standard AES-128. Dev username `28409` leaked via debug `WriteFile`. |
