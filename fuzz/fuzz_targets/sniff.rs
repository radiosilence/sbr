//! Stream and datagram sniffers (TLS, HTTP, QUIC, DNS and the rest) on bytes
//! a local app controls.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sbr_core::sniff;

fuzz_target!(|data: &[u8]| {
    // Several prefixes, as the dispatcher re-sniffs while bytes arrive.
    let step = (data.len() / 8).max(1);
    let mut n = 0;
    while n < data.len() {
        let _ = sniff::stream(&data[..n], &[]);
        n += step;
    }
    let _ = sniff::stream(data, &[]);
    let _ = sniff::packet(data, &[]);
    let _ = sniff::client_hello_sni(data);
});
