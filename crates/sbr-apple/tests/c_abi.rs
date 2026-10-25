//! The C side of the ABI: `include/sbr.h` declares exactly the exported
//! symbols, and a C program compiled against it links the staticlib and runs.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

fn names(text: &str, pat: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|l| {
            let at = l.find(pat)? + pat.len();
            let rest = &l[at..];
            let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
            Some(format!("sbr_{}", &rest[..end]))
        })
        .collect()
}

#[test]
fn header_declares_every_export() {
    let src = std::fs::read_to_string(Path::new(MANIFEST).join("src/lib.rs")).unwrap();
    let header = std::fs::read_to_string(Path::new(MANIFEST).join("include/sbr.h")).unwrap();
    let exported = names(&src, "extern \"C\" fn sbr_");
    let declared: BTreeSet<String> = names(&header, " sbr_")
        .into_iter()
        .chain(names(&header, "*sbr_"))
        .filter(|n| header.contains(&format!("{n}(")))
        .collect();
    assert!(exported.len() >= 15, "{exported:?}");
    assert_eq!(exported, declared);
}

/// The staticlib cargo built alongside this test (same profile).
fn staticlib() -> Option<PathBuf> {
    let deps = std::env::current_exe().ok()?.parent()?.to_path_buf();
    std::fs::read_dir(&deps)
        .ok()?
        .flatten()
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.starts_with("libsbr_apple-") && n.ends_with(".a")
        })
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())
        .map(|e| e.path())
}

fn have(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

#[test]
fn c_program_links_and_runs() {
    if !have("cc") {
        eprintln!("skipping: no cc");
        return;
    }
    let lib = staticlib().expect("libsbr_apple.a next to the test binary");
    let include = Path::new(MANIFEST).join("include");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("sbr_abi_test");
    let mut cc = Command::new("cc");
    cc.args(["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-I"])
        .arg(&include)
        .arg(Path::new(MANIFEST).join("tests/c/abi_test.c"))
        .arg(&lib)
        .arg("-o")
        .arg(&out);
    if cfg!(target_os = "linux") {
        cc.args(["-lpthread", "-ldl", "-lm", "-lrt"]);
    }
    let st = cc.status().unwrap();
    assert!(st.success(), "cc failed");
    let run = Command::new(&out).output().unwrap();
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success(),
        "abi_test failed: {stdout}{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(stdout.contains("ok ("), "{stdout}");

    // The header also has to be valid C++ (Swift's ClangImporter and ObjC++).
    if have("c++") {
        let st = Command::new("c++")
            .args(["-x", "c++", "-std=c++17", "-Wall", "-Werror", "-fsyntax-only", "-I"])
            .arg(&include)
            .arg(include.join("sbr.h"))
            .status()
            .unwrap();
        assert!(st.success(), "sbr.h is not valid C++");
    }
}
