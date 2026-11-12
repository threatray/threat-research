## Network

| C2              | Ports            |
| --------------- | ---------------- |
| 31.57.97[.]166  | 5559, 4455, 1234 |
| 82.47.102[.]67  | 2323             |
| 82.47.102[.]160 | 1417             |

## Host

| Type                                | Value                                                        |
| ----------------------------------- | ------------------------------------------------------------ |
| Mutex                               | `Global\Ky9_<id>`, `Global\Ky9_up_<id>`, `Ky9_bye_<id>`. `<id>` is 12 hex characters. |
| Config marker                       | JSON appended to the PE, followed by `KY9CFG01` + a 4-byte length |
| Config keys                         | `host, port, key, startup, startup_sched, delay, reconnect, spread, spread_usb, spread_usb_file, spread_lan, shell, rootkit, description, anti_vm, drop_size` |
| Install path                        | `%ProgramData%\Microsoft\svc_<id>.exe`, `%AppData%\Microsoft\svc_<id>.exe`, `…\Start Menu\Programs\Startup\svc_<id>.exe`, `%LocalAppData%\Microsoft\Windows\RuntimeHost.exe` |
| ID file                             | `svc.id` written to %ProgramData%, %ProgramData%\Microsoft, %AppData%\Microsoft, %LocalAppData%\Microsoft, Desktop and C:\Windows\Temp |
| Run keys                            | `HKCU` and `HKLM` `…\CurrentVersion\Run\WindowsDriverHost`, `…\RunOnce\WindowsDriverHost`, `HKCU\…\Policies\Explorer\Run\WindowsDriverHost`, `HKCU\…\Run\WindowsDriverHostHost` (→ RuntimeHost.exe) |
| Other autostarts                    | `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load`, `HKCU\Environment\UserInitMprLogonScript`, Startup folder `Windows Driver Host.lnk` |
| LAN worm                            | copies itself to `\\<host>\ADMIN$\Temp\win<hex>.exe`, then runs `schtasks /s <host> /tn winupdate<5hex> /ru system`, then `/run`, then `/delete` |
| USB worm file names                 | `RainbowUSB.exe`, `NovaUSB.exe`, `fivem.exe`                 |
| Defender tampering                  | `Set-MpPreference`; Defender path exclusions (`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\…\svc_<id>.exe`, `…\RuntimeHost.exe`) |
| Logs                                | `ky9_boot.log` (agent), `ky9_stub.log` / `ky9_stage.log` (stub) |
| Stub markers                        | `KY9_STUB_DEBUG`, `KY9DROP`, `KY9_WATCH`, `KY9CFG`           |
| Stolen-data files                   | `ky9_cookie_*`, `ky9_login_*`, `ky9_card_*`, `ky9_cc_*`, `ky9_wall_*`, `ky9_wifi_*`, `ky9_keys_*`, `ky9_cam_*` |
| Locker                              | `ky9-nova-locker-v1`, `.nova` extension, MBR text `master boot record owned by ky9` |
| Rootkit (r77 renamed `$77`→`Mason`) | `\\.\pipe\Masoncontrol_redirect64`, `\\.\pipe\Masonchildproc32/64`, `HKLM\SOFTWARE\Masonconfig` (in the sandbox it wrote `Masonconfig\pid\svc64`), `Masonstager`, `Masonsvc64`, `r77-x64.dll`, scheduled task `mason<sha256>.exe` that runs on logon with highest privileges |

## Files

| SHA256                                                       | First seen in VT | Type             | C2                                       |
| ------------------------------------------------------------ | ---------------- | ---------------- | ---------------------------------------- |
| e48605bd337407527bcc87def0ac355acf667bb1455ca41a740c874a68f729a7 | 2026-10-20       | Agent            | — (unconfigured, 127.0.0.1)              |
| 27c4b0c00a94ba4b9ffeb33e13a68def1dcc9a4643e2b2e9c4b86f932945c0b6 | 2026-10-21       | Crypter          | 31.57.97[.]166:5559                      |
| 400e651df84721213d31718b1a25c982dc7017e1b2bcd98176268851784fcaff | 2026-10-21       | Agent            | 31.57.97[.]166:5559                      |
| 68d14467867c5bad8d012df0ede7ed4b67dad5ab8c2745cba7d56d54cc349c63 | 2026-10-21       | Agent            | 31.57.97[.]166:5559                      |
| 6d5bea196a3d68b4cce14496685907db002ce9d1ac92671ef97a5d83e5c5c476 | 2026-10-21       | Agent            | 31.57.97[.]166:5559                      |
| d5cf8ec693a1126663b155052dc6e7bad3771da591d5527f858bf9d885528bb8 | 2026-10-21       | Crypter, Agent   | 31.57.97[.]166:5559                      |
| d9cbb80267a952285eb30d6c54e8dfce13ce6cff18cb9da0b832003f23f14be2 | 2026-10-21       | Crypter          | 31.57.97[.]166:5559                      |
| ef3983ea1b702ecb60c5b61e5a6e42fbe2be947f30f81ba293b28e3ec75a50bc | 2026-10-21       | Crypter          | 31.57.97[.]166:5559                      |
| 6c66522a8a7ba1e4e22072b9f43462c7c47b63e0ec8d85c828994c5b97502518 | 2026-10-22       | Crypter, Agent   | 31.57.97[.]166:5559                      |
| 71052fbd426deab850d1ee73f8afc6bffd5f707a7097a997aca4e1d720f00b0b | 2026-10-22       | Agent            | 31.57.97[.]166:5559                      |
| 7350b90fe81e93bc402b351000dd3d9592da72d1b0bea6240da05adf711cf430 | 2026-10-22       | Crypter, Agent   | 31.57.97[.]166:5559                      |
| b114d1cb8d312870f450f6c6a0537e9dbe9fb9324b1002f5d5220639f47e6ef5 | 2026-10-24       | Agent            | 31.57.97[.]166:3434                      |
| ec7056c7444b94e8033795483a95f03b4408e54de55a2df6fd162a560b1bd780 | 2026-10-24       | Crypter, Agent   | 31.57.97[.]166:3434                      |
| 6e164ae5ea13c182e1b915571b5691e010da9f656780e7a050b3e6b7e6597571 | 2026-10-25       | Agent            | 31.57.97[.]166:5559                      |
| 73abb0e39978910a9287ac7eca6dee0ff3b9e61dc304fbc9861a859f22ca6f89 | 2026-10-27       | Crypter, Agent   | 31.57.97[.]166:3434                      |
| 9750266017380fd1939fce8359f58e22d9bc8b4f5a9c06886cf460502912a031 | 2026-11-04       | Crypter, Agent   | 31.57.97[.]166:4455                      |
| f62344d9b0e8901ced60592bf88c0212bbe98ccaa88c12ea56cb45258a58a1e8 | 2026-11-04       | Agent            | 31.57.97[.]166:4455                      |
| b419f9b4d2e7aac2090ace5b110f3915bb3ed59018d2f6203760280f271c98bd | 2026-11-05       | Crypter, Agent   | 31.57.97[.]166:1234                      |
| cfc402e0695c975f915c67751f16348c0553a7a1ba3d11941d83e15d8dbc4f07 | 2026-11-05       | Agent            | 31.57.97[.]166:1234                      |
| fe29473acc64ce384efa0fa0c51df80f58e52d756fc913c0ea9c1d93b1e510a1 | 2026-11-05       | Agent            | 31.57.97[.]166:1234, 31.57.97[.]166:4455 |
| da46ac18b56b22f59219193edd2c04c91a5a791286926dfd768eda5109ff1c1b | 2026-11-06       | Crypter, Rootkit | 31.57.97[.]166:1234                      |
| e4397b9672f08de023e657abf77e9aa783ce8cad4a2de2c055f0502137003c99 | 2026-11-06       | Crypter, Agent   | 31.57.97[.]166:1234                      |
| ece8f22b59d0f86c7fc69a3f8f50a4b9405656f57f4faa34fa10154e928e7e83 | 2026-11-06       | Agent            | — (unconfigured, 127.0.0.1)              |
| eed25f9f0744389048d5a388dcf9e21e7b344745cd55b766c3730567174f3389 | 2026-11-06       | Agent            | 31.57.97[.]166:1234                      |
| 4ea13a47e3cccd9bfec4f15ec4b92ce500b997b29c3dceb949a3fa6ec5f7574b | 2026-11-07       | Crypter, Agent   | 82.47.102[.]160:1417                     |
| cd588e5bf0fb600666b12e8911126bda2504edb7892e194be757651426b5be8d | 2026-11-07       | Agent            | 82.47.102[.]160:1417                     |
| 48ca290fb86bfdf8a4fecfa0a75827e4037a3f274b9510b5a286e1f2addddb54 | 2026-11-08       | Crypter, Agent   | 82.47.102[.]67:2323                      |
| 6602a9646c6c0a2dfb2f12f917f1e1d358d3d7bbaa3a2bdd1152f92b5066cf8f | 2026-11-08       | Crypter, Agent   | 82.47.102[.]67:2323                      |
| 6b42a4e7a3105d748445281eb1a593f8eb3d8c2714af8fd7b3cbeba1c24a3b8c | 2026-11-08       | Agent            | 82.47.102[.]67:2323                      |
| 978e2d88691605d1eb0e164be37666aff303888f84cf4aab65829202e8a49fe9 | 2026-11-08       | Crypter, Agent   | 82.47.102[.]67:2323                      |
| dcf33df5bc2e6257c8a9c09b33665f61218617b7c2288228115af309135c8bfd | 2026-11-08       | Agent            | — (unconfigured, 127.0.0.1)              |
| ef3cae4959a7192672e2d3fafb444cf4ae03a21f4e84460d8414d99bf55ca268 | 2026-11-08       | Agent            | 82.47.102[.]67:2323                      |
| f463cbf1643144fd6dbe1e5d3f2fa1cb6b44c5a3da1dfec0aa0d82241ab88d70 | 2026-11-08       | Crypter          | 82.47.102[.]67:2323                      |
| 7405428549acc1ee26c1824f614040cdaf216ee1f742f28ecc0c5ed499eead45 | 2026-11-09       | Crypter, Agent   | 82.47.102[.]67:2323                      |
| b0a76ec7bb5def3d0aa5044d3676434b6a10a073abb05de10247c6706ee3bd46 | 2026-11-09       | Agent            | 82.47.102[.]67:2323                      |