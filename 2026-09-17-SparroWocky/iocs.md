**Backdoors and containers**

| First seen | Compiled | Container | Backdoor | C&C | Variant | Analysis report |
| --- | --- | --- | --- | --- | --- | --- |
| 2025-11-29 | 2025-11-17 | `bf6c2595950aa3e389c5391d530e3a7381788d9c043e8aee426aaa187556fa22` | `e0b6f8535e19f0a4938e3317de0c4493ecea17aa906fd0454805ba2086cbf3a8` | `216[.]238.110.120:443` | TLS | [Link](https://reports.threatray.com/0e7952ba-8379-43d9-a607-7832b13726da) |
| 2025-12-24 | 2025-12-19 | `71408bc3a224e4a6f24020c53aea8468c46fd42dc56f87a41efca3feb03c3821` | `d08e09a17df22fb39838dcc9e99756830ef5175bc9e03d615adf979dc85ed052` | `38[.]54.45.155:443` | TLS | [Link](https://reports.threatray.com/f4af3184-84c9-4492-84c7-7b4f0add1a44) |
| 2026-02-05 | 2025-12-08 | `c957519cf7f77248dacc704fcf177b7c20524d4f57927c4219626b10224bea64` | `4e8a3ca7be64c7d546598483bcf0f16023c1cac5506f400ba736c6b42daf1d73` | `.files.seosnskorea[.]com` | DNS | [Link](https://reports.threatray.com/abf0f8c6-6270-49a5-8ab7-e9f1746c35a0) |
| 2026-04-01 | 2026-01-07 | `f2427ccec03c70952f41e7342eb76131dda20011238262cab76a9e29cc5cad77` (inside ZIP `5b3886c1a6a158c9b32ff190c2068a283a3337700a3b06e8cede8a8f5c0dd47c`) | `ef9e3e831b736b79561abeb4acf5acbb154b406ea245498a03f55715fc6bc73b` | `38[.]54.89.158:443` | TLS | [Link](https://reports.threatray.com/462675ab-392d-4b64-ac83-a4f860f88f62) |
| 2026-08-17 | 2026-05-25 | `5811e2d17a8fef495ab3e5fbc69204e25a16e1758cf558f78c44c52b07550a88` | `bb284f7977fc0251274f6188d6dd64d1bc95004a00b9ba7c8420a2c0f461ebf1` | `77[.]111.101.153:443` | TLS | [Link](https://reports.threatray.com/523ec7a5-03dc-43bf-8876-310d697fb223) |

**Loaders**

| First seen | SHA-256 | Filename (PE export name) | Entry point (RVA) |
| --- | --- | --- | --- |
| 2025-11-29 | `f01a73f651f8113bf9672dbe4c50c63ed365a41e4187aaf0a5ab34cd21154046` | winfsp-x64.dll | `0x3040` |
| 2026-02-10 | `17a6eb668445e7c5e66c4dc567b09c0361a0cfc3bb5bfc3cbf0ccd8ed4a66a73` | winfsp-x64.dll | `0x60F8` |
| 2026-04-01 | `40529ac470591b84adabe7cebdea8f67d8303d52c3cb4502590bae1e746cd360` | winfsp-x64.dll | `0x8AEE` |
| 2026-04-10 | `7ca7ffa9888720f77be9fbf321b60bffc03103f8fa4e8e69869903e5badeb00b` | winfsp-x64.dll | `0x7A1C` |
