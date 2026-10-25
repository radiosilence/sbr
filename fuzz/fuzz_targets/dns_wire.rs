//! DNS wire decoding and the message helpers that run on server responses
//! and on queries from local apps.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sbr_dns::msg;

fuzz_target!(|data: &[u8]| {
    let Ok(mut m) = msg::decode(data) else { return };
    let _ = msg::rcode(&m);
    let _ = msg::answer_addrs(&m);
    let _ = msg::response_ttl(&m);
    let _ = msg::client_subnet(&m);
    let _ = msg::is_simple(&m);
    let _ = msg::udp_size(&m);
    if let Some(q) = m.queries.first() {
        let _ = msg::domain_of(q);
    }
    let _ = msg::status(&m, 2);
    let _ = msg::addresses(&m, &["192.0.2.1".parse().unwrap()], 60);
    msg::set_ttl(&mut m, 30);
    msg::remove_client_subnet(&mut m);
    msg::set_client_subnet(&mut m, "192.0.2.0/24".parse().unwrap());
    if let Ok(enc) = msg::encode(&m) {
        let _ = msg::decode(&enc);
    }
    let _ = msg::truncate_to(m, 512);
});
