//! `.srs` compatibility with sing-box itself.
//!
//! The `*.singbox.srs` fixtures were produced by sing-box (rev a6952cc):
//!
//!     sing-box rule-set compile fixtures/route.json -o fixtures/route.singbox.srs
//!     sing-box rule-set convert --type adguard fixtures/adguard.txt -o fixtures/adguard.singbox.srs
//!
//! Set `SING_BOX_BIN` to also have sing-box decompile what sbr compiles.

use std::io::Read;
use std::path::PathBuf;

use sbr_config::srs::{self, HeadlessRule, PlainRuleSet};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn body(srs_file: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(&srs_file[4..])
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn compile(json: &str) -> PlainRuleSet {
    let mut set = PlainRuleSet::from_json(json).unwrap();
    set.downgrade_version();
    set
}

#[test]
fn sbr_encodes_exactly_what_sing_box_encodes() {
    for name in ["all-items", "route", "route-v1"] {
        let json = std::fs::read_to_string(fixture(&format!("{name}.json"))).unwrap();
        let theirs = std::fs::read(fixture(&format!("{name}.singbox.srs"))).unwrap();
        let ours = compile(&json);
        assert_eq!(theirs[3], ours.version, "{name}: version byte");
        // zlib streams differ between Go and Rust; the payload must not.
        assert_eq!(body(&theirs), ours.encode_body().unwrap(), "{name}: payload");
    }
}

#[test]
fn sbr_reads_sing_box_files() {
    for name in ["all-items", "route", "route-v1"] {
        let json = std::fs::read_to_string(fixture(&format!("{name}.json"))).unwrap();
        let theirs = srs::read(&std::fs::read(fixture(&format!("{name}.singbox.srs"))).unwrap()).unwrap();
        // Reading normalises (sorted domains, merged CIDRs); so does a round
        // trip of our own encoding, and the two must agree.
        let ours = srs::read(&compile(&json).write().unwrap()).unwrap();
        assert_eq!(theirs, ours, "{name}");
    }
    let r = srs::read(&std::fs::read(fixture("route.singbox.srs")).unwrap()).unwrap();
    let HeadlessRule::Default(d) = &r.rules[0] else {
        panic!()
    };
    assert_eq!(d.domain, ["exact.example"]);
    assert_eq!(d.domain_suffix, [".only-sub.net", "example.org"]);
    // Version 1 stores `domain_suffix: x` as `x` + `.x`; it reads back the same.
    let r = srs::read(&std::fs::read(fixture("route-v1.singbox.srs")).unwrap()).unwrap();
    assert_eq!(r.version, 1);
    let HeadlessRule::Default(d) = &r.rules[0] else {
        panic!()
    };
    assert_eq!(d.domain, ["exact.example"]);
    assert_eq!(d.domain_suffix, [".only-sub.net", "example.org"]);
}

#[test]
fn adguard_from_sing_box() {
    let theirs = std::fs::read(fixture("adguard.singbox.srs")).unwrap();
    let set = srs::read(&theirs).unwrap();
    let HeadlessRule::Default(d) = &set.rules[0] else {
        panic!()
    };
    let mut lines = d.adguard_domain.clone();
    lines.sort();
    let mut want: Vec<String> = std::fs::read_to_string(fixture("adguard.txt"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    want.sort();
    assert_eq!(lines, want);
    // Re-encoding gives the same bytes sing-box wrote.
    assert_eq!(body(&theirs), set.encode_body().unwrap());
    // And it routes: the AdGuard lines become plain matchers.
    let rules = set.into_rules().unwrap();
    assert_eq!(rules.len(), 1);
}

#[test]
fn sing_box_decompiles_sbr_files() {
    let Ok(bin) = std::env::var("SING_BOX_BIN") else {
        eprintln!("SING_BOX_BIN not set; skipping");
        return;
    };
    let dir = std::env::temp_dir().join(format!("sbr-srs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["all-items", "route", "route-v1"] {
        let json = std::fs::read_to_string(fixture(&format!("{name}.json"))).unwrap();
        let ours = compile(&json);
        let path = dir.join(format!("{name}.srs"));
        std::fs::write(&path, ours.write().unwrap()).unwrap();
        let out = dir.join(format!("{name}.out.json"));
        let st = std::process::Command::new(&bin)
            .args(["rule-set", "decompile"])
            .arg(&path)
            .arg("-o")
            .arg(&out)
            .status()
            .unwrap();
        assert!(st.success(), "{name}: sing-box failed to decompile");
        let theirs = std::fs::read_to_string(&out).unwrap();
        // sing-box's decompile output is byte-identical to ours.
        let mine = srs::read(&std::fs::read(&path).unwrap()).unwrap().to_json_pretty();
        assert_eq!(theirs, mine, "{name}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
