//! The binary rule-set decoder, which reads files downloaded from remote URLs.
//!
//! Inputs with an even first byte are compressed and given a valid header so
//! the fuzzer reaches the body parser; odd ones are fed raw.
#![no_main]

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use sbr_config::srs;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, body)) = data.split_first() else { return };
    let file = if mode & 1 == 0 {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(body).unwrap();
        let mut f = b"SRS".to_vec();
        f.push(1 + (mode >> 1) % srs::VERSION_CURRENT);
        f.extend_from_slice(&z.finish().unwrap());
        f
    } else {
        body.to_vec()
    };
    if let Ok(set) = srs::read(&file) {
        let _ = set.write();
        let _ = set.into_rules();
    }
});
