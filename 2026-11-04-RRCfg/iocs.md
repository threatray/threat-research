## SHA256

**2026-09-21 — arphaCrashReport.exe / arphaDump64.dll** — [Report](https://reports.threatray.com/331547c6-2557-4ae6-9ac1-bcc17afd4f00)

| File / Stage | SHA256 |
| --- | --- |
| `20260921163500-CC1DB4D9D1744A.exe (host)` | `e6318768cc146432534a11e842d1325ab2309a6587b05750b28bb6df33f02e24` |
| `arphaDump64.dll` | `76c854e5c2ec50f8da09c3bba7d292ed010587fc11d90996c2c8d5174e4748dc` |
| `27.124.41.111.bin (Donut)` | `3262e1248360d712d81f737b0b3db9c49deb1e12d800681af15bfc7507a36155` |
| RRCfg implant (memory dump) | `e0268accdbcb263d8ff4a4abf1d2d1cbaeb2018139a125d0cc178c58289cf9ad` |

**2026-09-23 — ClosePre.exe / kcommon64.dll**

| File / Stage | SHA256 |
| --- | --- |
| `2026095SDDE20.exe (host)` | `749050178a17ab5fab696ee8e1b51f5da50a8c5bfa6c592d0352020b79aa15d2` |
| `kcommon64.dll` | `d38217a317f23a1416bb335307ea744fc7783f1a0436aea4ee1585e16286ae4d` |

**2026-10-22 — BioEnrollmentHost.exe / wincorlib.dll** — [Report](https://reports.threatray.com/83d1ff51-17f0-45fe-bc0d-3be585a6d965)

| File / Stage | SHA256 |
| --- | --- |
| `20261022128205.BC6FBTAC08T.exe (host)` | `c9ca5797b92076943247208f2159ae169802b159555341b7adeee6f7dd387886` |
| `wincorlib.dll` | `bbbd33af2f25515c7fe4bbfb69cd490d417c54bcd4acfd91c274f83d1040b336` |
| `A03.bin (Donut)` | `2a3e56b17b3fa73fdc3c941e41654da8d5d48d81f1a884233d5b9eb8394df01f` |
| RRCfg implant (memory dump) | `230a7a2d6e5f23b57d02f5e62f69edc3a6b70f23607136d5ce9e5fe5de8e04a6` |

**2026-10-25 — RRCfg / ahfayui[.]eu[.]cc** — [Report](https://reports.threatray.com/4cd9fe89-e33d-4bec-963f-4a5158ced9d8)

| File / Stage | SHA256 |
| --- | --- |
| RRCfg implant — ahfayui[.]eu[.]cc | `0207194f5a4d277edc205895f7808bba04743c03f51717118e4d60151ab77b0e` |

**2026-10-28 — RRCfg / 27.124.41[.]111** — [Report](https://reports.threatray.com/97bed9fe-c1e8-493e-9142-9339b461467f)

| File / Stage | SHA256 |
| --- | --- |
| RRCfg implant — 27.124.41[.]111 | `c6385b4f23718d4e42bd72b0dcf62660f7de93b739e22f9ace5ce73d140ae71f` |

**2026-11-03 — Edge notification\_helper.exe / dbghelp.dll**

| File / Stage | SHA256 |
| --- | --- |
| `INV-No.20261102023748.exe (host)` | `57ee684afd82017ed2e90273c297c7142802657d09c9c732d35234c49b381dba` |
| `dbghelp.dll` | `a8199df9c157b3448065ef4c77968ba1abbdcef0acb134931deb0c80530e4782` |

## Network indicators

| Indicator | Role | Variant |
| --- | --- | --- |
| `27.124.41[.]111:8083` | C2 | 2026-09-21 — arphaDump64 |
| `27.124.41[.]111:7056` | C2 | 2026-10-28 — RRCfg |
| `192.252.178[.]174:8083` | C2 | 2026-10-22 — BioEnrollmentHost / wincorlib |
| `ahfayui[.]eu[.]cc` | C2 | 2026-10-25 — RRCfg |
| `61.18.208[.]171` | Resolved C2 address | 2026-10-25 — RRCfg |
| `hxxps://xiaxiazai.hkg.bcebos[.]com/kekehua/27.124.41.111.bin` | Payload staging | 2026-09-21 — arphaDump64 |
| `hxxps://aawwf.hkg.bcebos[.]com/shiade/A03.bin` | Payload staging | 2026-10-22 — BioEnrollmentHost / wincorlib |
| `hxxps://gdnkdl[.]eu[.]cc/files/ahfayui.eu.cc.bin` | Payload staging | 2026-09-23 — ClosePre / kcommon64 |
| `hxxps://bmafhahl[.]eu[.]cc/files/ahfayui.eu.cc.bin` | Payload staging | 2026-11-03 — Edge / dbghelp |
