fn main() {
    println!("cargo:rerun-if-changed=csrc/oslog.c");
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        cc::Build::new().file("csrc/oslog.c").compile("sbr_tunnel_oslog");
    }
}
