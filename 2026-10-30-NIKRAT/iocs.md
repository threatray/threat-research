## SHA256

| SHA256                                                       | C2             | Threatray Analyses                                           |
| ------------------------------------------------------------ | -------------- | ------------------------------------------------------------ |
| `e7f51534b1106707a7e86b1531dfd4444639b824baec66c5e1ad8005b1f7da0a` | 2.26.49.181    | [Link](https://reports.threatray.com/4deec40a-1f6f-4ccf-bc4d-da471479745f) |
| `507436d5132cefeea7e35e3481c5726f00a90e041a6bbb55cfcf50b51e2b3b73` | 2.26.49.181    | [Link](https://reports.threatray.com/e3108d3e-c02f-4e47-b3e3-3bc8d61f13c9) |
| `626619e1a2ba0cfaf7809ad3fed0d8958762379bcdc549125699ce7e6a938500` | 2.26.49.181    | [Link](https://reports.threatray.com/1bcd4100-2726-4a04-a1be-fee0886214e8) |
| `46bea5c1ac50bbcb0fb700e6e8f46d5f09c8ea61c74f677bd19342bace670052` | 2.26.49.181    | [Link](https://reports.threatray.com/a8734e02-ddc9-48b1-bbd6-489076430b15) |
| `9b228bf578fee16d5ccd880ecafcc7159d3678ef09d7fa5c807d423f97d48a9e` | 2.26.49.181    | [Link](https://reports.threatray.com/f3afc3f2-2040-471b-81da-c4b391669d18) |
| `0008c95fb43bd97dec04c408b61a66a38f59a7912e4d4a058647ef14407463f2` | 191.44.109.125 | [Link](https://reports.threatray.com/c8755e3e-8cc8-47fe-ae22-77876d7385c9) |
| `876b1dbc4bcfc548d1fbf8ac8d4fe7dfa15df80e5085372397dffb814c5e5352` | 191.44.109.125 | [Link](https://reports.threatray.com/f064e4f3-80da-46eb-b8b5-ec3a9b4b9b92) |
| `9d9d9901b318cf30a8764f8b1a4d042e9c73bc22cfd39e159f81ba895a898920` | 191.44.109.125 | [Link](https://reports.threatray.com/cf7756ab-4263-438b-b6cb-1263bf1abaad) |
| `d0abbd4e13d026cea0f62d250080f721a37c3a033afb6b5ec368b31e07243f24` | 172.67.188.146 | [Link](https://reports.threatray.com/25eaf667-fa9d-4640-88b7-93f82caa753b) |
| `a7279f2425746deafef5c2ff6ebe612c7cc6062601be37d83e07ecdd1bb72ba2` | 87.120.196.120 | [Link](https://reports.threatray.com/c68ac7c1-7d6a-491f-9e0a-70a62619482f) |
| `5a39bd95d430a1093b3d179d100389ee2cf60226518b82e02572f3e25df2f803` | 2.26.51.12     | [Link](https://reports.threatray.com/b0bc03a7-dca3-4ce5-8b59-19f5215df650) |
| `0fb93dbb9525004f9e5b1ee4bcd6b6638700bee576413e955c8c96292fa964ee` | 2.26.51.12     | [Link](https://reports.threatray.com/6d26857f-8f8e-4c75-8cd2-c97696562b5c) |
| `ae38f1181c9dd0db7224d6023e335eb2cdabb0f441906d14ffba8602b7abca3c` | 87.120.196.120 | [Link](https://reports.threatray.com/f609d565-5582-47a5-a66c-2b0ee7d6069e) |

## Network indicators

| C2               | ASN                                    | Country | Certificate                                                  |
| ---------------- | -------------------------------------- | ------- | ------------------------------------------------------------ |
| `2.26.49.181`    | AS215439 Play2go International Limited | DE      | `CN=2.26.49.181` (SHA256 `750872a67ceb2adbe1e31340acabc6574aa9ebbcfe8acaad9ffe05301eca21dc`) |
| `191.44.109.125` | AS198550 Node Host Limited             | GB      | Same certificate                                             |

## Host indicators

| Indicator                                                    | Type             |
| ------------------------------------------------------------ | ---------------- |
| `Local\NIK_<16hex>_agent`, `Local\NIK_<16hex>_wd` (e.g. `NIK_000eb1adf56a5249`, `NIK_84a013bd0e11c6a1`) | Mutex            |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\NIKClient` | Registry Run key |
| Scheduled task `NikGuardian` → `C:\ProgramData\Microsoft\Windows\NetworkGuard.vbs` | Persistence      |
| `%APPDATA%\Microsoft\Windows\Network\svchost.exe` / `simvol.exe`, `C:\ProgramData\Microsoft\Windows\Network\svchost.exe`, `%LOCALAPPDATA%\Microsoft\Windows\svchost.exe`, `%TEMP%\svchost.exe` | Dropped copies   |
| `%TEMP%\nik_<16hex>.pid`, `%TEMP%\nik_<16hex>_wd.pid`, `%TEMP%\nik_dll.go`, `%TEMP%\nik_<timestamp>.vbs` / `.bat` | Artifacts        |
| `nik_panel/data/build_ba4f9757a37893c8`, `nik_panel/data/build_caf29f93fc0cd3e2` | Build paths      |