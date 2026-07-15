**Samples (SHA256)**

| SHA256                                                       | First seen (VT, UTC) |
| ------------------------------------------------------------ | -------------------- |
| `d302ba5778fac5bb12d82810958c2136d2b86c0267499075e4d947c97b4940a0` | 2026-06-30 03:02     |
| `ebc9d1abb69490462aa79e0fc4ac987ce5cfe19492832e32f36685859e635fba` | 2026-06-30 03:31     |
| `0876c0228fea2b0f06b7ed4644b440ce40032adb7a40867e76d5274524a3058b` | 2026-06-30 03:37     |
| `37f9de776d211aead04a1e54f2a5d8b453a1a51d1e906f3f4306868ac31501e1` | 2026-06-30 04:41     |
| `d93d3701b17598fdf244e0eec2a87a13902baadde7c2c9253d60566215ef6df2` | 2026-06-30 04:59     |
| `4b660a310fc1125a079f8154a86edd0d43501edbbc4bc759dd55f1d4fd0c6d40` | 2026-06-30 05:20     |
| `42dd676a77e7fdcf2da653c4150ed2b339ce062fb91e5ff7e7a1f2b1c5e32f44` | 2026-06-30 05:41     |
| `cf07f33f8727b3dc4b1d956b2a5e24a487470a8d74d2558c37249eca53976ba5` | 2026-06-30 05:57     |
| `7dcc113684fe5bd9355866a59f4a901929ff5d07fb47a05d6c186d1e7b3f444f` | 2026-06-30 11:43     |
| `ff99e0fbf4bffe07738630833155fccb0775deb29cf8e0d02a5019362072a9f5` | 2026-06-30 12:45     |

**Host / Network**

| IOC                                                          | Type         | Context                                                      |
| ------------------------------------------------------------ | ------------ | ------------------------------------------------------------ |
| `%LOCALAPPDATA%\fontdrv\fontcachesvc.exe`                    | File path    | Persistence drop (masquerades as Windows Font Cache service) |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\FontCacheSvc` | Registry     | Autorun persistence                                          |
| `%LOCALAPPDATA%\Temp\veil_debug.txt`                         | File path    | Distinctive runtime marker file                              |
| `VEIL_RUN=1`                                                 | Env variable | Execution gate                                               |
| `taskkill /f /im discord.exe`                                | Command      | Kills Discord before app.asar patching                       |
| `taskkill /f /im discordptb.exe`                             | Command      | Kills Discord PTB before app.asar patching                   |
| `https://canary.discord.com/api/webhooks/1520964300800524308/cE5JLPnfpZWgawu818OCEcmOxZ4xblE0GXqMawHb28u2FXvPJzlcaNSky4CVJPBraDbI` | URL          | Discord webhook C2 (exfiltration)                            |