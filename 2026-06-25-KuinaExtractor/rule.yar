rule KuinaExtractor {
  meta:
    author      = "Threatray"
    description = "Detects KuinaExtractor Rust infostealer"
    reference   = "https://www.threatray.com/blog/kuinaextractor-six-months-of-a-rust-infostealers-evolution"
    license     = "Detection Rule License (DRL) 1.1"
    date        = "2026-06-25"
    hash1       = "39b29a119f66e3466f93b427b2fd15c5830ae525730da733f43360c8a3f5bdd9"
    hash2       = "7a0901cae15154afaf190f8761d6f151bd3d84018e543b05896a8989d776193f"
    hash3       = "49b68ad8be0fbe219985de21d7010e52cc11e685be25a44d0077215f2d2b8901"
    hash4       = "cc933a50c4b195a7c043188496042d2a3566ee1589b48112050b552c948bb3d6"
    hash5       = "2ef927025cd95f5bacfb412b4cb1cc9dd35e858fb41cc3a224a6209b06d9ebae"
    hash6       = "929e498ec1dde698f0403e4d03329c8ba34689cd9267c0e09a91f78b7dfcf865"

  strings:
    $mutex = "Rust_Extractor_Mutex_V2" ascii
    $tg    = "t.me/kuina1999" ascii
    $tg2   = "@k0to4matsukami" ascii
    $brand = "Kuina Stealer" ascii
    $ua    = "Kuina-Bot/1.0" ascii

    $boot  = "src\\boot_collector.rs" ascii
    $fn1   = "discord_simple_steal" ascii
    $fn2   = "discord_safe_storage_steal" ascii
    $tdata = "Telegram tdata Extractor" ascii
    $wifi  = "src\\wifi.rs" ascii
    $pass  = "passwords_collected=" ascii
    $fake  = "FAKE_MSG_ENABLED" ascii

  condition:
    uint16(0) == 0x5A4D
    and filesize < 12MB
    and 1 of ($mutex, $tg, $tg2, $brand, $ua)
    and 2 of ($boot, $fn1, $fn2, $tdata, $wifi, $pass, $fake)
}
