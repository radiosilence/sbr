//! Request decoration Xray applies to every XHTTP request: browser-like
//! default headers (`common/utils/browser.go`, the `fetch` variant) and the
//! padding generators (`splithttp/xpadding.go`).

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use sbr_config::PaddingMethod;

fn days_since_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| (d.as_secs() / 86400) as i64)
}

fn days(y: i32, m: u32, d: u32) -> i64 {
    // Days from the civil date to 1970-01-01 (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y } as i64;
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// One random draw per process, like Xray's CPU-seeded generator: versions
/// stay coherent for the life of the process.
fn skew() -> f64 {
    static R: OnceLock<f64> = OnceLock::new();
    *R.get_or_init(fastrand::f64)
}

fn chrome_version() -> i64 {
    let diff = days_since_epoch() - days(2026, 1, 13) - 35 - (skew().powi(2) * 105.0).floor() as i64;
    144 + diff / 35
}

fn firefox_version() -> i64 {
    let diff = days_since_epoch() - days(2024, 7, 29) - 25 - (skew().powi(2) * 50.0).floor() as i64;
    diff / 30 + 128
}

fn curl_version() -> String {
    let diff = days_since_epoch() - days(2023, 3, 20) - 60 - (skew().powi(2) * 165.0).floor() as i64;
    format!("8.{}.0", diff / 57)
}

fn safari_version() -> String {
    const MINOR: [i64; 25] = [
        0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6,
    ];
    let now = days_since_epoch();
    let delay = (skew().powi(3) * 75.0).floor() as i64;
    let year_now = 1970 + (now as f64 / 365.2425) as i32;
    let mut year = year_now;
    let mut split = days(year, 9, 23) + delay;
    if now < split {
        year -= 1;
        split = days(year, 9, 23) + delay;
    }
    let idx = (((now - split) * 86400) / 1_296_000).clamp(0, 24) as usize;
    format!("{}.{}", year - 1999, MINOR[idx])
}

const GREASE_NA: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
const GREASE_V: [&str; 3] = ["8", "99", "24"];
const SHUFFLE3: [[usize; 3]; 6] = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];

fn ch_ua(major: i64, brand: &str) -> String {
    let m = major as usize;
    let brands = [
        format!(
            "\"Not{}A{}Brand\";v=\"{}\"",
            GREASE_NA[m % GREASE_NA.len()],
            GREASE_NA[(m + 1) % GREASE_NA.len()],
            GREASE_V[m % GREASE_V.len()]
        ),
        format!("\"Chromium\";v=\"{major}\""),
        format!("\"{brand}\";v=\"{major}\""),
    ];
    let order = SHUFFLE3[m % SHUFFLE3.len()];
    let mut out = [""; 3];
    for (i, &e) in order.iter().enumerate() {
        out[e] = &brands[i];
    }
    out.join(", ")
}

/// Ordered `(name, value)` request headers.
pub type Headers = Vec<(String, String)>;

fn get<'a>(h: &'a Headers, k: &str) -> Option<&'a str> {
    h.iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(k))
        .map(|(_, v)| v.as_str())
}

pub fn set(h: &mut Headers, k: &str, v: impl Into<String>) {
    h.retain(|(n, _)| !n.eq_ignore_ascii_case(k));
    h.push((k.to_owned(), v.into()));
}

fn set_default(h: &mut Headers, k: &str, v: &str) {
    if get(h, k).is_none_or(str::is_empty) {
        set(h, k, v);
    }
}

/// The configured headers with Xray's `TryDefaultHeadersWith(h, "fetch")`
/// applied: a browser identity unless `User-Agent` names something else.
pub fn request_headers(configured: &[(String, String)]) -> Headers {
    let mut h: Headers = Vec::with_capacity(configured.len() + 12);
    for (k, v) in configured {
        h.push((k.clone(), v.clone()));
    }
    let browser = match get(&h, "User-Agent") {
        None => "chrome",
        Some(b @ ("chrome" | "firefox" | "safari" | "edge" | "curl" | "golang")) => {
            let b: &'static str = match b {
                "chrome" => "chrome",
                "firefox" => "firefox",
                "safari" => "safari",
                "edge" => "edge",
                "curl" => "curl",
                _ => "golang",
            };
            b
        }
        Some(_) => return h,
    };
    match browser {
        "chrome" | "edge" => {
            let v = chrome_version();
            let (ua, brand) = if browser == "chrome" {
                (
                    format!(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36"
                    ),
                    "Google Chrome",
                )
            } else {
                (
                    format!(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36Edg/{v}.0.0.0"
                    ),
                    "Microsoft Edge",
                )
            };
            set(&mut h, "Sec-CH-UA", ch_ua(v, brand));
            set(&mut h, "Sec-CH-UA-Mobile", "?0");
            set(&mut h, "Sec-CH-UA-Platform", "\"Windows\"");
            set(&mut h, "DNT", "1");
            set(&mut h, "User-Agent", ua);
            set(&mut h, "Accept-Language", "en-US,en;q=0.9");
        }
        "firefox" => {
            let v = firefox_version();
            set(
                &mut h,
                "User-Agent",
                format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0"),
            );
            set(&mut h, "DNT", "1");
            set(&mut h, "Accept-Language", "en-US,en;q=0.5");
        }
        "safari" => {
            set(
                &mut h,
                "User-Agent",
                format!(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{} Safari/605.1.15",
                    safari_version()
                ),
            );
            set(&mut h, "Accept-Language", "en-US,en;q=0.9");
        }
        "golang" => {
            h.retain(|(n, _)| !n.eq_ignore_ascii_case("User-Agent"));
            return h;
        }
        _ => {
            set(&mut h, "User-Agent", format!("curl/{}", curl_version()));
            return h;
        }
    }
    set(&mut h, "Sec-Fetch-Mode", "cors");
    set(&mut h, "Sec-Fetch-Dest", "empty");
    set(&mut h, "Sec-Fetch-Site", "same-origin");
    let priority = match browser {
        "firefox" => "u=4",
        "safari" => "u=3, i",
        _ => "u=1, i",
    };
    set_default(&mut h, "Priority", priority);
    set_default(&mut h, "Cache-Control", "no-cache");
    set_default(&mut h, "Pragma", "no-cache");
    set_default(&mut h, "Accept", "*/*");
    h
}

/// HPACK Huffman code lengths (RFC 7541 Appendix B) for 0x20..=0x7e.
const HUFFMAN_LEN: [u8; 95] = [
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, // 0x20
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, // 0x30
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, // 0x40
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, // 0x50
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, // 0x60
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, // 0x70
];

/// `hpack.HuffmanEncodeLength` for printable ASCII.
fn huffman_len(s: &[u8]) -> usize {
    let bits: usize = s
        .iter()
        .map(|&b| HUFFMAN_LEN.get((b as usize).wrapping_sub(0x20)).copied().unwrap_or(30) as usize)
        .sum();
    bits.div_ceil(8)
}

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// `GenerateTokenishPaddingBase62`: random base62 whose HPACK Huffman length
/// is within 2 bytes of `target`.
fn tokenish(target: usize) -> String {
    let n = ((target as f64) / 0.8).ceil().max(1.0) as usize;
    let mut s: Vec<u8> = (0..n).map(|_| BASE62[(crate::tls::rand_u32() % 62) as usize]).collect();
    let mut adjust = b'X';
    for _ in 0..150 {
        let cur = huffman_len(&s) as i64;
        let diff = cur - target as i64;
        if diff.abs() <= 2 {
            break;
        }
        if diff < 0 {
            s.push(adjust);
            adjust = if adjust == b'X' { b'Z' } else { b'X' };
        } else {
            if s.len() <= 1 {
                break;
            }
            s.pop();
        }
    }
    String::from_utf8(s).unwrap_or_default()
}

/// `GeneratePadding`. 'X' has an 8-bit Huffman code, so the padding's size
/// on the wire is its length under HPACK and QPACK too.
pub fn padding(method: PaddingMethod, len: usize) -> String {
    if len == 0 {
        return String::new();
    }
    match method {
        PaddingMethod::RepeatX => "X".repeat(len),
        PaddingMethod::Tokenish => {
            let t = tokenish(len);
            if t.is_empty() { "X".repeat(len) } else { t }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_days() {
        assert_eq!(days(1970, 1, 1), 0);
        assert_eq!(days(2026, 1, 13), 20466);
    }

    #[test]
    fn default_identity_is_chrome() {
        let h = request_headers(&[]);
        let ua = get(&h, "User-Agent").unwrap();
        assert!(ua.contains("Chrome/"), "{ua}");
        assert_eq!(get(&h, "Sec-Fetch-Mode"), Some("cors"));
        assert_eq!(get(&h, "Priority"), Some("u=1, i"));
        let custom = request_headers(&[("User-Agent".into(), "x/1".into())]);
        assert_eq!(custom, vec![("User-Agent".to_string(), "x/1".to_string())]);
    }

    #[test]
    fn tokenish_length() {
        for target in [100usize, 333, 1000] {
            let p = padding(PaddingMethod::Tokenish, target);
            assert!(p.bytes().all(|b| b.is_ascii_alphanumeric()));
            assert!((huffman_len(p.as_bytes()) as i64 - target as i64).abs() <= 2);
        }
        assert_eq!(huffman_len(b"XXXX"), 4);
    }
}
