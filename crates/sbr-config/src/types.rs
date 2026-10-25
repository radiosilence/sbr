use std::time::Duration;

/// Parse a Go `time.ParseDuration` string ("1h30m", "250ms", "1.5s").
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let err = || format!("invalid duration {s:?}");
    let mut rest = s.trim();
    if rest == "0" {
        return Ok(Duration::ZERO);
    }
    if rest.starts_with('-') {
        return Err(format!("negative duration {s:?}"));
    }
    rest = rest.strip_prefix('+').unwrap_or(rest);
    if rest.is_empty() {
        return Err(err());
    }
    let mut total = 0f64;
    while !rest.is_empty() {
        let num_end = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).ok_or_else(err)?;
        if num_end == 0 {
            return Err(err());
        }
        let n: f64 = rest[..num_end].parse().map_err(|_| err())?;
        rest = &rest[num_end..];
        let unit_end = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let scale = match &rest[..unit_end] {
            "ns" => 1e-9,
            "us" | "µs" | "μs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return Err(err()),
        };
        total += n * scale;
        rest = &rest[unit_end..];
    }
    Ok(Duration::from_secs_f64(total))
}

/// Strip `//` and `/* */` comments outside of strings. sing-box's JSON
/// reader accepts commented configs and people rely on it.
pub fn strip_comments(input: &str) -> String {
    let b = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut start = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            match c {
                b'\\' => i += 1,
                b'"' => in_str = false,
                _ => {}
            }
            i += 1;
            continue;
        }
        match (c, b.get(i + 1)) {
            (b'"', _) => {
                in_str = true;
                i += 1;
            }
            (b'/', Some(b'/')) => {
                out.push_str(&input[start..i]);
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                start = i;
            }
            (b'/', Some(b'*')) => {
                out.push_str(&input[start..i]);
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(b.len());
                start = i;
                out.push(' ');
            }
            _ => i += 1,
        }
    }
    out.push_str(&input[start..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("1.5s").unwrap(), Duration::from_millis(1500));
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert!(parse_duration("5").is_err());
        assert!(parse_duration("5d").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn comments() {
        let s = r#"{ // hi
  "a": "http://x/*y*/", /* block */ "b": 1 }"#;
        let v: serde_json::Value = serde_json::from_str(&strip_comments(s)).unwrap();
        assert_eq!(v["a"], "http://x/*y*/");
        assert_eq!(v["b"], 1);
    }
}
