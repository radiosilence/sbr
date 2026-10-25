//! `sbr rule-set …` against files produced by sing-box (see
//! `crates/sbr-config/tests/fixtures`).

use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../sbr-config/tests/fixtures")
        .join(name)
}

fn sbr(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sbr")).args(args).output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn body(srs: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    flate2::read::ZlibDecoder::new(&srs[4..]).read_to_end(&mut v).unwrap();
    v
}

#[test]
fn compile_matches_sing_box_and_decompile_roundtrips() {
    let dir = std::env::temp_dir().join(format!("sbr-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["route", "all-items"] {
        let src = dir.join(format!("{name}.json"));
        std::fs::copy(fixture(&format!("{name}.json")), &src).unwrap();
        let (ok, _, err) = sbr(&["rule-set", "compile", src.to_str().unwrap()]);
        assert!(ok, "{err}");
        let ours = std::fs::read(dir.join(format!("{name}.srs"))).unwrap();
        let theirs = std::fs::read(fixture(&format!("{name}.singbox.srs"))).unwrap();
        assert_eq!(ours[..4], theirs[..4], "{name}: magic and version");
        assert_eq!(body(&ours), body(&theirs), "{name}: payload");

        // Decompiling sing-box's file and ours gives the same JSON.
        let a = dir.join(format!("{name}.a.json"));
        let b = dir.join(format!("{name}.b.json"));
        let theirs_path = fixture(&format!("{name}.singbox.srs"));
        assert!(
            sbr(&[
                "rule-set",
                "decompile",
                theirs_path.to_str().unwrap(),
                "-o",
                a.to_str().unwrap()
            ])
            .0
        );
        let ours_path = dir.join(format!("{name}.srs"));
        assert!(
            sbr(&[
                "rule-set",
                "decompile",
                ours_path.to_str().unwrap(),
                "-o",
                b.to_str().unwrap()
            ])
            .0
        );
        assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn match_and_format() {
    let srs = fixture("route.singbox.srs");
    let (ok, out, err) = sbr(&[
        "rule-set",
        "match",
        "-f",
        "binary",
        srs.to_str().unwrap(),
        "a.example.org",
    ]);
    assert!(ok, "{err}");
    assert_eq!(
        out.trim(),
        "match rules.[0]: domain=exact.example domain_suffix=[.only-sub.net example.org]"
    );
    let (_, out, _) = sbr(&[
        "rule-set",
        "match",
        "-f",
        "binary",
        srs.to_str().unwrap(),
        "203.0.113.7",
    ]);
    assert!(out.starts_with("match rules.[1]: ip_cidr="), "{out}");
    let (_, out, _) = sbr(&[
        "rule-set",
        "match",
        "-f",
        "binary",
        srs.to_str().unwrap(),
        "only-sub.net",
    ]);
    assert_eq!(out, "", "leading-dot suffix matches subdomains only");
    let src = fixture("route.json");
    let (ok, out, _) = sbr(&["rule-set", "match", src.to_str().unwrap(), "x.only-sub.net"]);
    assert!(ok && out.starts_with("match rules.[0]"), "{out}");

    let (ok, out, err) = sbr(&["rule-set", "format", src.to_str().unwrap()]);
    assert!(ok, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["version"], 2);
    assert_eq!(
        v["rules"][0]["domain"], "exact.example",
        "single items print bare, like sing-box"
    );
    // AdGuard binaries can't be decompiled (sing-box refuses too).
    let ad = fixture("adguard.singbox.srs");
    let (ok, _, err) = sbr(&["rule-set", "decompile", ad.to_str().unwrap(), "-o", "/dev/null"]);
    assert!(!ok && err.contains("AdGuard"), "{err}");
}
