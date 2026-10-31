//! sing-mux client sessions (smux, yamux, padding) and the stream response,
//! fed whatever a hostile server sends.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(sbr_engine::outbound::fuzz_mux_session(data));
});
