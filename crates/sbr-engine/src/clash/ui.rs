//! `external_ui`: serve a dashboard from a local directory. It is only ever
//! downloaded when `external_ui_download_url` is set explicitly (sing-box
//! falls back to a GitHub URL; sbr never contacts a third party on its own).

use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

/// Pick the content type the browser needs to run the dashboard.
pub fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=utf-8",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// Map a request path under `/ui/` to a file, refusing to leave `root`.
pub fn resolve(root: &Path, rel: &str) -> Option<PathBuf> {
    let rel = rel.split(['?', '#']).next().unwrap_or("");
    let mut p = root.to_path_buf();
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(s) => p.push(s),
            Component::CurDir => {}
            _ => return None,
        }
    }
    if p.is_dir() {
        p.push("index.html");
    }
    Some(p)
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("zip: {msg}"))
}

/// Extract a zip (stored or deflated entries) into `out`. When every file
/// sits under one top directory (GitHub archives), that directory is
/// dropped, like sing-box. Entries escaping `out` are rejected.
pub fn extract_zip(zip: &[u8], out: &Path) -> io::Result<usize> {
    // End of central directory: last occurrence of its signature.
    let eocd = (0..zip.len().saturating_sub(21))
        .rev()
        .take(65536 + 22)
        .find(|&i| u32_at(zip, i) == Some(0x0605_4b50))
        .ok_or_else(|| bad("no end of central directory"))?;
    let count = u16_at(zip, eocd + 10).ok_or_else(|| bad("truncated"))? as usize;
    let mut at = u32_at(zip, eocd + 16).ok_or_else(|| bad("truncated"))? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if u32_at(zip, at) != Some(0x0201_4b50) {
            return Err(bad("bad central directory"));
        }
        let field = |o| u16_at(zip, at + o).ok_or_else(|| bad("truncated"));
        let method = field(10)?;
        let csize = u32_at(zip, at + 20).ok_or_else(|| bad("truncated"))? as usize;
        let name_len = field(28)? as usize;
        let extra_len = field(30)? as usize;
        let comment_len = field(32)? as usize;
        let local = u32_at(zip, at + 42).ok_or_else(|| bad("truncated"))? as usize;
        let name = zip.get(at + 46..at + 46 + name_len).ok_or_else(|| bad("truncated"))?;
        let name = String::from_utf8_lossy(name).into_owned();
        at += 46 + name_len + extra_len + comment_len;
        if name.split(['/', '\\']).any(|c| c == "..") || name.starts_with('/') {
            return Err(bad("entry escapes the output directory"));
        }
        if !name.ends_with('/') {
            entries.push((name, method, csize, local));
        }
    }
    let first = |n: &str| n.split('/').next().unwrap_or("").to_owned();
    let trim = entries.first().is_some_and(|(n, ..)| {
        let top = first(n);
        n.contains('/') && entries.iter().all(|(m, ..)| first(m) == top && m.contains('/'))
    });
    let mut written = 0;
    for (name, method, csize, local) in entries {
        let rel = if trim {
            name.split_once('/').map(|x| x.1).unwrap_or(&name)
        } else {
            &name
        };
        let Some(dest) = resolve(out, rel) else {
            return Err(bad("entry escapes the output directory"));
        };
        if u32_at(zip, local) != Some(0x0403_4b50) {
            return Err(bad("bad local header"));
        }
        let data_at =
            local + 30 + u16_at(zip, local + 26).unwrap_or(0) as usize + u16_at(zip, local + 28).unwrap_or(0) as usize;
        let data = zip
            .get(data_at..data_at + csize)
            .ok_or_else(|| bad("truncated entry"))?;
        let content = match method {
            0 => data.to_vec(),
            8 => {
                let mut v = Vec::new();
                flate2::read::DeflateDecoder::new(data)
                    .take(256 << 20)
                    .read_to_end(&mut v)?;
                v
            }
            m => return Err(bad(&format!("unsupported compression method {m}"))),
        };
        if let Some(dir) = dest.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&dest, content)?;
        written += 1;
    }
    Ok(written)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// A minimal zip writer for tests (deflated entries).
    pub fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in files {
            let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            z.write_all(data).unwrap();
            let comp = z.finish().unwrap();
            let offset = out.len() as u32;
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&[20, 0, 0, 0, 8, 0, 0, 0, 0, 0]);
            out.extend_from_slice(&0u32.to_le_bytes()); // crc (not checked)
            out.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&comp);
            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 8, 0, 0, 0, 0, 0]);
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_at = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_at.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn extracts_and_trims_single_top_dir() {
        let dir = std::env::temp_dir().join(format!("sbr-zip-{}", std::process::id()));
        let zip = make_zip(&[("ui-main/index.html", b"<html>"), ("ui-main/assets/a.js", b"x()")]);
        assert_eq!(extract_zip(&zip, &dir).unwrap(), 2);
        assert_eq!(std::fs::read(dir.join("index.html")).unwrap(), b"<html>");
        assert_eq!(std::fs::read(dir.join("assets/a.js")).unwrap(), b"x()");
        let evil = make_zip(&[("../evil", b"x")]);
        assert!(extract_zip(&evil, &dir).is_err());
        assert!(resolve(&dir, "../etc/passwd").is_none());
        assert_eq!(resolve(&dir, "").unwrap(), dir.join("index.html"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
