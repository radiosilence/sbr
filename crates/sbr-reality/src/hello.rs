//! Browser ClientHello fingerprints.
//!
//! | name             | profile                                                       |
//! |------------------|---------------------------------------------------------------|
//! | `chrome`         | Chrome 155 (macOS), captured from the browser                  |
//! | `safari`, `ios`  | Apple Network.framework (macOS 27 URLSession), captured        |
//! | `firefox`        | Firefox 148, uTLS `HelloFirefox_148` as Xray-core 26.10 uses it |
//!
//! Chrome and Apple are transcribed from ClientHellos the real clients sent
//! (October 2026). uTLS (and so sing-box and Xray) still sends Chrome 133;
//! real Chrome has since added GREASE and ML-DSA signature algorithms and
//! the Trust Anchor IDs extension, and a frozen profile increasingly marks a
//! proxy client. The Apple capture matches uTLS `HelloSafari_26_3`. `ios`
//! is the same stack, not uTLS `HelloIOS_14`: an iOS 14 hello is six years
//! stale, and XTLS/REALITY servers since 2026-09-08 refuse a ClientHello
//! without an X25519MLKEM768 key share ahead of any X25519 one, which iOS 14
//! does not send.
//!
//! GREASE values follow BoringSSL (`0x?a?a`, one random value per role, the two
//! GREASE extensions never equal), Chrome's extension order is a fresh random
//! permutation per connection with the GREASE extensions pinned first and last.

use std::io;

use aws_lc_rs::{agreement, kem, rand};

pub(crate) const GREASE: u16 = 0x0a0a;

pub(crate) const GROUP_X25519: u16 = 0x001d;
pub(crate) const GROUP_P256: u16 = 0x0017;
pub(crate) const GROUP_P384: u16 = 0x0018;
pub(crate) const GROUP_P521: u16 = 0x0019;
pub(crate) const GROUP_X25519_MLKEM768: u16 = 0x11ec;
const GROUP_FFDHE2048: u16 = 0x0100;
const GROUP_FFDHE3072: u16 = 0x0101;

pub(crate) const MLKEM768_ENCAPS_LEN: usize = 1184;
pub(crate) const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

/// Offset of the 32-byte legacy_session_id inside the handshake message
/// (4-byte header + version + random + length byte), as Xray hardcodes it.
pub(crate) const SESSION_ID_OFFSET: usize = 39;

pub(crate) const CERT_COMPRESSION_ZLIB: u16 = 1;
pub(crate) const CERT_COMPRESSION_BROTLI: u16 = 2;
pub(crate) const CERT_COMPRESSION_ZSTD: u16 = 3;

/// The browser whose ClientHello is imitated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Fingerprint {
    /// Chrome 155.
    #[default]
    Chrome,
    /// Firefox 148 (uTLS `HelloFirefox_148`).
    Firefox,
    /// Safari on macOS 27: Apple's Network.framework TLS stack.
    Safari,
    /// iOS: the same Network.framework stack as [`Fingerprint::Safari`].
    Ios,
}

impl std::str::FromStr for Fingerprint {
    type Err = io::Error;

    /// sing-box `utls.fingerprint` names. Unsupported names are an error, never
    /// silently replaced by another browser. The `chrome_*` variants differ
    /// from `chrome` only in PSK resumption or in Chrome versions sbr does not
    /// imitate; sbr never resumes, so on the wire they are Chrome.
    fn from_str(s: &str) -> io::Result<Self> {
        match s {
            "" | "chrome" | "chrome_pq" | "chrome_psk" | "chrome_psk_shuffle" | "chrome_pq_psk" => Ok(Self::Chrome),
            "firefox" => Ok(Self::Firefox),
            "safari" => Ok(Self::Safari),
            "ios" => Ok(Self::Ios),
            // sing-box picks one browser per process for `random`.
            "random" => {
                let r: [u8; 1] = random_bytes()?;
                Ok([Self::Chrome, Self::Firefox, Self::Safari][r[0] as usize % 3])
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported uTLS fingerprint {s:?} (supported: chrome, firefox, safari, ios, random)"),
            )),
        }
    }
}

#[derive(Clone, Copy)]
enum Ext {
    /// First GREASE extension (empty body) / second (one zero byte).
    Grease1,
    Grease2,
    Sni,
    ExtendedMasterSecret,
    RenegotiationInfo,
    Groups(&'static [u16]),
    PointFormats,
    SessionTicket,
    Alpn,
    StatusRequest,
    SignatureAlgorithms(&'static [u16]),
    Sct,
    KeyShare(&'static [u16]),
    PskModes,
    Versions(&'static [u16]),
    CompressCertificate(&'static [u16]),
    /// ALPS, new code point (Chrome ≥ 131).
    ApplicationSettings,
    /// GREASE ECH with the candidate AEAD ids and inner payload lengths.
    EchGrease(&'static [u16], &'static [u16]),
    DelegatedCredentials(&'static [u16]),
    RecordSizeLimit(u16),
    /// draft-ietf-tls-trust-anchor-ids (Chrome's experimental 0xca34), body verbatim.
    TrustAnchors(&'static [u8]),
}

struct Spec {
    suites: &'static [u16],
    exts: &'static [Ext],
    /// Chrome-style extension permutation.
    shuffle: bool,
    /// The X25519 share repeats the X25519 half of the hybrid share
    /// (NSS; uTLS `ReuseHybridAndClassicalKeyShares`).
    reuse_x25519: bool,
}

// Cipher suites.
const CHROME_SUITES: &[u16] = &[
    GREASE, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
    0x002f, 0x0035,
];
const FIREFOX_SUITES: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];
const APPLE_SUITES: &[u16] = &[
    GREASE, 0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009, 0xc014, 0xc013,
    0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
];

// Signature algorithms. Chrome leads with a GREASE value, then ML-DSA-44/65/87.
const CHROME_SIGALGS: &[u16] = &[
    GREASE, 0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const FIREFOX_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const FIREFOX_DC_SIGALGS: &[u16] = &[0x0403, 0x0503, 0x0603, 0x0203];
// Apple really lists rsa_pss_rsae_sha384 twice.
const APPLE_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

const CHROME_GROUPS: &[u16] = &[GREASE, GROUP_X25519_MLKEM768, GROUP_X25519, GROUP_P256, GROUP_P384];
const CHROME_SHARES: &[u16] = &[GREASE, GROUP_X25519_MLKEM768, GROUP_X25519];
const BORINGSSL_VERSIONS: &[u16] = &[GREASE, 0x0304, 0x0303];
const FIREFOX_GROUPS: &[u16] = &[
    GROUP_X25519_MLKEM768,
    GROUP_X25519,
    GROUP_P256,
    GROUP_P384,
    GROUP_P521,
    GROUP_FFDHE2048,
    GROUP_FFDHE3072,
];
const FIREFOX_SHARES: &[u16] = &[GROUP_X25519_MLKEM768, GROUP_X25519, GROUP_P256];
const FIREFOX_VERSIONS: &[u16] = &[0x0304, 0x0303];
const APPLE_GROUPS: &[u16] = &[
    GREASE,
    GROUP_X25519_MLKEM768,
    GROUP_X25519,
    GROUP_P256,
    GROUP_P384,
    GROUP_P521,
];
const APPLE_SHARES: &[u16] = &[GREASE, GROUP_X25519_MLKEM768, GROUP_X25519];

/// Chrome 155's Trust Anchor IDs (Chrome Root Store entries), as sent.
const CHROME_TRUST_ANCHORS: &[u8] = &[
    0x00, 0xb8, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x01, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x06, 0x05, 0x82, 0xdf, 0x13, 0x02,
    0x0d, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x0e, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x0f, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x12,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x13, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x14, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d,
    0x01, 0x07, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01,
    0x09, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d, 0x08,
    0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13, 0x04, 0xd6,
    0x79, 0x09, 0x01, 0x04, 0xd6, 0x79, 0x09, 0x04, 0x04, 0xd6, 0x79, 0x09, 0x05, 0x04, 0xd6, 0x79, 0x09, 0x06, 0x04,
    0xd6, 0x79, 0x09, 0x07, 0x04, 0xd6, 0x79, 0x09, 0x08, 0x04, 0xd6, 0x79, 0x09, 0x0a, 0x04, 0xd6, 0x79, 0x09, 0x0b,
    0x04, 0xd6, 0x79, 0x09, 0x0c, 0x04, 0xd6, 0x79, 0x09, 0x0d, 0x04, 0xd6, 0x79, 0x09, 0x0f,
];

const AEAD_AES128GCM: u16 = 1;
const AEAD_CHACHA20POLY1305: u16 = 3;

const CHROME: Spec = Spec {
    suites: CHROME_SUITES,
    exts: &[
        Ext::Grease1,
        Ext::Sni,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::Groups(CHROME_GROUPS),
        Ext::PointFormats,
        Ext::SessionTicket,
        Ext::Alpn,
        Ext::StatusRequest,
        Ext::SignatureAlgorithms(CHROME_SIGALGS),
        Ext::Sct,
        Ext::KeyShare(CHROME_SHARES),
        Ext::PskModes,
        Ext::Versions(BORINGSSL_VERSIONS),
        Ext::CompressCertificate(&[CERT_COMPRESSION_BROTLI]),
        Ext::ApplicationSettings,
        Ext::TrustAnchors(CHROME_TRUST_ANCHORS),
        Ext::EchGrease(&[AEAD_AES128GCM], &[128, 160, 192, 224]),
        Ext::Grease2,
    ],
    shuffle: true,
    reuse_x25519: false,
};

const FIREFOX: Spec = Spec {
    suites: FIREFOX_SUITES,
    exts: &[
        Ext::Sni,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::Groups(FIREFOX_GROUPS),
        Ext::PointFormats,
        Ext::Alpn,
        Ext::StatusRequest,
        Ext::DelegatedCredentials(FIREFOX_DC_SIGALGS),
        Ext::Sct,
        Ext::KeyShare(FIREFOX_SHARES),
        Ext::Versions(FIREFOX_VERSIONS),
        Ext::SignatureAlgorithms(FIREFOX_SIGALGS),
        Ext::RecordSizeLimit(0x4001),
        Ext::CompressCertificate(&[CERT_COMPRESSION_ZLIB, CERT_COMPRESSION_BROTLI, CERT_COMPRESSION_ZSTD]),
        Ext::EchGrease(&[AEAD_AES128GCM, AEAD_CHACHA20POLY1305], &[223]),
    ],
    shuffle: false,
    reuse_x25519: true,
};

const APPLE: Spec = Spec {
    suites: APPLE_SUITES,
    exts: &[
        Ext::Grease1,
        Ext::Sni,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::Groups(APPLE_GROUPS),
        Ext::PointFormats,
        Ext::Alpn,
        Ext::StatusRequest,
        Ext::SignatureAlgorithms(APPLE_SIGALGS),
        Ext::Sct,
        Ext::KeyShare(APPLE_SHARES),
        Ext::PskModes,
        Ext::Versions(BORINGSSL_VERSIONS),
        Ext::CompressCertificate(&[CERT_COMPRESSION_ZLIB]),
        Ext::Grease2,
    ],
    shuffle: false,
    reuse_x25519: false,
};

fn spec(fp: Fingerprint) -> &'static Spec {
    match fp {
        Fingerprint::Chrome => &CHROME,
        Fingerprint::Firefox => &FIREFOX,
        Fingerprint::Safari | Fingerprint::Ios => &APPLE,
    }
}

/// Key material behind the offered key shares.
#[derive(Default)]
pub(crate) struct KeyShares {
    /// The standalone X25519 share. REALITY derives its auth key from it.
    pub(crate) x25519: Option<agreement::PrivateKey>,
    /// ML-KEM-768 decapsulation key and the X25519 half of the hybrid share.
    pub(crate) mlkem: Option<(kem::DecapsulationKey, agreement::PrivateKey)>,
    pub(crate) ecdh: Vec<(u16, agreement::PrivateKey)>,
    /// (group, key_exchange) in the order offered; GREASE included.
    pub(crate) public: Vec<(u16, Vec<u8>)>,
}

impl KeyShares {
    /// Generates one share per group (GREASE gets the one-byte placeholder).
    /// `reuse_x25519`: the X25519 share reuses the hybrid share's X25519 key.
    pub(crate) fn generate(groups: &[u16], grease: u16, reuse_x25519: bool) -> io::Result<Self> {
        let mut k = Self::default();
        let mut hybrid_x25519: Option<[u8; 32]> = None;
        for &g in groups {
            match g {
                GREASE => k.public.push((grease, vec![0])),
                GROUP_X25519 => {
                    let (sk, pk) = match &hybrid_x25519 {
                        Some(secret) if reuse_x25519 => x25519_from(secret)?,
                        _ => x25519_key()?,
                    };
                    k.x25519 = Some(sk);
                    k.public.push((g, pk));
                }
                GROUP_X25519_MLKEM768 => {
                    let dk = kem::DecapsulationKey::generate(&kem::ML_KEM_768).map_err(|_| crypto_err())?;
                    let ek = dk.encapsulation_key().map_err(|_| crypto_err())?;
                    let ek = ek.key_bytes().map_err(|_| crypto_err())?;
                    let secret: [u8; 32] = random_bytes()?;
                    let (xk, xp) = x25519_from(&secret)?;
                    hybrid_x25519 = Some(secret);
                    let mut data = Vec::with_capacity(MLKEM768_ENCAPS_LEN + 32);
                    data.extend_from_slice(ek.as_ref());
                    data.extend_from_slice(&xp);
                    k.mlkem = Some((dk, xk));
                    k.public.push((g, data));
                }
                GROUP_P256 | GROUP_P384 | GROUP_P521 => {
                    let alg = ecdh_alg(g).expect("NIST group");
                    let sk = agreement::PrivateKey::generate(alg).map_err(|_| crypto_err())?;
                    let pk = sk.compute_public_key().map_err(|_| crypto_err())?.as_ref().to_vec();
                    k.ecdh.push((g, sk));
                    k.public.push((g, pk));
                }
                _ => return Err(io::Error::other("key share group not implemented")),
            }
        }
        Ok(k)
    }
}

pub(crate) fn ecdh_alg(group: u16) -> Option<&'static agreement::Algorithm> {
    match group {
        GROUP_P256 => Some(&agreement::ECDH_P256),
        GROUP_P384 => Some(&agreement::ECDH_P384),
        GROUP_P521 => Some(&agreement::ECDH_P521),
        GROUP_X25519 => Some(&agreement::X25519),
        _ => None,
    }
}

pub(crate) struct HelloParams<'a> {
    pub(crate) fingerprint: Fingerprint,
    /// SNI; `None` (or an IP literal) sends no server_name extension.
    pub(crate) server_name: Option<&'a str>,
    /// Empty: the fingerprint's own ALPN list.
    pub(crate) alpn: &'a [String],
    pub(crate) post_quantum: bool,
}

fn crypto_err() -> io::Error {
    io::Error::other("crypto backend failure")
}

fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut b = [0u8; N];
    rand::fill(&mut b).map_err(|_| crypto_err())?;
    Ok(b)
}

/// BoringSSL's per-connection GREASE values.
struct Grease {
    cipher: u16,
    group: u16,
    ext1: u16,
    ext2: u16,
    version: u16,
    sigalg: u16,
}

impl Grease {
    fn new() -> io::Result<Self> {
        let seed: [u8; 6] = random_bytes()?;
        let v = |b: u8| {
            let x = u16::from(b & 0xf0) | 0x0a;
            x | (x << 8)
        };
        let ext1 = v(seed[2]);
        let mut ext2 = v(seed[3]);
        if ext1 == ext2 {
            ext2 ^= 0x1010;
        }
        Ok(Self {
            cipher: v(seed[0]),
            group: v(seed[1]),
            ext1,
            ext2,
            version: v(seed[4]),
            sigalg: v(seed[5]),
        })
    }
}

/// Appends a u16-length-prefixed block written by `f`.
fn with_u16_len(out: &mut Vec<u8>, f: impl FnOnce(&mut Vec<u8>)) {
    let at = out.len();
    out.extend_from_slice(&[0, 0]);
    f(out);
    let len = (out.len() - at - 2) as u16;
    out[at..at + 2].copy_from_slice(&len.to_be_bytes());
}

fn with_u8_len(out: &mut Vec<u8>, f: impl FnOnce(&mut Vec<u8>)) {
    let at = out.len();
    out.push(0);
    f(out);
    out[at] = (out.len() - at - 1) as u8;
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_ext(out: &mut Vec<u8>, ty: u16, body: impl FnOnce(&mut Vec<u8>)) {
    put_u16(out, ty);
    with_u16_len(out, body);
}

fn degrease(v: u16, grease: u16) -> u16 {
    if v == GREASE { grease } else { v }
}

fn x25519_key() -> io::Result<(agreement::PrivateKey, Vec<u8>)> {
    let k = agreement::PrivateKey::generate(&agreement::X25519).map_err(|_| crypto_err())?;
    let p = k.compute_public_key().map_err(|_| crypto_err())?.as_ref().to_vec();
    Ok((k, p))
}

fn x25519_from(secret: &[u8; 32]) -> io::Result<(agreement::PrivateKey, Vec<u8>)> {
    let k = agreement::PrivateKey::from_private_key(&agreement::X25519, secret).map_err(|_| crypto_err())?;
    let p = k.compute_public_key().map_err(|_| crypto_err())?.as_ref().to_vec();
    Ok((k, p))
}

const DEFAULT_ALPN: &[&str] = &["h2", "http/1.1"];

/// Everything a connection's ClientHellos share. A HelloRetryRequest is
/// answered with the same random, session id, GREASE values, extension order
/// and ECH payload, as BoringSSL does; only key_share and cookie change.
pub(crate) struct Hello {
    spec: &'static Spec,
    exts: Vec<Ext>,
    grease: Grease,
    pub(crate) random: [u8; 32],
    pub(crate) session_id: [u8; 32],
    server_name: Option<String>,
    alpn: Vec<String>,
    post_quantum: bool,
    ech: Option<Vec<u8>>,
}

impl Hello {
    pub(crate) fn new(p: &HelloParams<'_>) -> io::Result<Self> {
        let spec = spec(p.fingerprint);
        let server_name = p
            .server_name
            .filter(|n| !n.is_empty() && n.parse::<std::net::IpAddr>().is_err())
            .map(str::to_owned);
        let alpn: Vec<String> = if p.alpn.is_empty() {
            DEFAULT_ALPN.iter().map(|s| s.to_string()).collect()
        } else {
            p.alpn.to_vec()
        };
        let has_h2 = alpn.iter().any(|a| a == "h2");
        let mut exts: Vec<Ext> = spec
            .exts
            .iter()
            .copied()
            // Go (and therefore uTLS) never puts an IP literal in SNI.
            .filter(|e| !(matches!(e, Ext::Sni) && server_name.is_none()))
            // Chrome only configures ALPS for h2.
            .filter(|e| !(matches!(e, Ext::ApplicationSettings) && !has_h2))
            .collect();
        if spec.shuffle {
            shuffle_middle(&mut exts)?;
        }
        let ech = match exts.iter().find_map(|e| match e {
            Ext::EchGrease(a, l) => Some((*a, *l)),
            _ => None,
        }) {
            Some((aeads, lens)) => Some(grease_ech(aeads, lens)?),
            None => None,
        };
        Ok(Self {
            spec,
            exts,
            grease: Grease::new()?,
            random: random_bytes()?,
            session_id: random_bytes()?,
            server_name,
            alpn,
            post_quantum: p.post_quantum,
            ech,
        })
    }

    fn offers_group(&self, g: u16) -> bool {
        self.post_quantum || g != GROUP_X25519_MLKEM768
    }

    /// The groups the first ClientHello carries key shares for.
    pub(crate) fn initial_share_groups(&self) -> Vec<u16> {
        self.exts
            .iter()
            .find_map(|e| match e {
                Ext::KeyShare(g) => Some(g.iter().copied().filter(|&g| self.offers_group(g)).collect()),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// True if `group` is in supported_groups (GREASE excluded).
    pub(crate) fn supports_group(&self, group: u16) -> bool {
        group != GREASE
            && self.exts.iter().any(|e| match e {
                Ext::Groups(g) => g.contains(&group) && self.offers_group(group),
                _ => false,
            })
    }

    pub(crate) fn offers_suite(&self, suite: u16) -> bool {
        suite != GREASE && self.spec.suites.contains(&suite)
    }

    pub(crate) fn offers_alpn(&self, proto: &[u8]) -> bool {
        self.alpn.iter().any(|a| a.as_bytes() == proto)
    }

    pub(crate) fn offers_alps(&self) -> bool {
        self.exts.iter().any(|e| matches!(e, Ext::ApplicationSettings))
    }

    pub(crate) fn offers_compression(&self, alg: u16) -> bool {
        self.exts.iter().any(|e| match e {
            Ext::CompressCertificate(a) => a.contains(&alg),
            _ => false,
        })
    }

    pub(crate) fn grease_group(&self) -> u16 {
        self.grease.group
    }

    pub(crate) fn reuse_x25519(&self) -> bool {
        self.spec.reuse_x25519
    }

    /// The handshake message (4-byte header included) carrying `shares` and,
    /// after a HelloRetryRequest, the server's cookie.
    pub(crate) fn encode(&self, shares: &[(u16, Vec<u8>)], cookie: Option<&[u8]>) -> Vec<u8> {
        let g = &self.grease;
        let mut m = Vec::with_capacity(2048);
        m.extend_from_slice(&[1, 0, 0, 0]); // ClientHello, u24 length patched below
        put_u16(&mut m, 0x0303);
        m.extend_from_slice(&self.random);
        m.push(32);
        m.extend_from_slice(&self.session_id);
        with_u16_len(&mut m, |m| {
            for &s in self.spec.suites {
                put_u16(m, degrease(s, g.cipher));
            }
        });
        m.extend_from_slice(&[1, 0]);

        let ext_start = m.len();
        m.extend_from_slice(&[0, 0]);
        for e in &self.exts {
            match *e {
                Ext::Grease1 => put_ext(&mut m, g.ext1, |_| {}),
                Ext::Grease2 => put_ext(&mut m, g.ext2, |b| b.push(0)),
                Ext::Sni => {
                    let name = self.server_name.as_deref().unwrap_or_default();
                    put_ext(&mut m, 0x0000, |b| {
                        with_u16_len(b, |b| {
                            b.push(0);
                            with_u16_len(b, |b| b.extend_from_slice(name.as_bytes()));
                        })
                    })
                }
                Ext::ExtendedMasterSecret => put_ext(&mut m, 0x0017, |_| {}),
                Ext::RenegotiationInfo => put_ext(&mut m, 0xff01, |b| b.push(0)),
                Ext::Groups(groups) => put_ext(&mut m, 0x000a, |b| {
                    with_u16_len(b, |b| {
                        for &gr in groups.iter().filter(|&&gr| self.offers_group(gr)) {
                            put_u16(b, degrease(gr, g.group));
                        }
                    })
                }),
                Ext::PointFormats => put_ext(&mut m, 0x000b, |b| b.extend_from_slice(&[1, 0])),
                Ext::SessionTicket => put_ext(&mut m, 0x0023, |_| {}),
                Ext::Alpn => put_ext(&mut m, 0x0010, |b| {
                    with_u16_len(b, |b| {
                        for a in &self.alpn {
                            with_u8_len(b, |b| b.extend_from_slice(a.as_bytes()));
                        }
                    })
                }),
                Ext::StatusRequest => put_ext(&mut m, 0x0005, |b| b.extend_from_slice(&[1, 0, 0, 0, 0])),
                Ext::SignatureAlgorithms(algs) => put_ext(&mut m, 0x000d, |b| {
                    with_u16_len(b, |b| {
                        for &a in algs {
                            put_u16(b, degrease(a, g.sigalg));
                        }
                    })
                }),
                Ext::Sct => put_ext(&mut m, 0x0012, |_| {}),
                Ext::KeyShare(_) => put_ext(&mut m, 0x0033, |b| {
                    with_u16_len(b, |b| {
                        for (gr, data) in shares {
                            put_u16(b, *gr);
                            with_u16_len(b, |b| b.extend_from_slice(data));
                        }
                    })
                }),
                Ext::PskModes => {
                    put_ext(&mut m, 0x002d, |b| b.extend_from_slice(&[1, 1]));
                    // RFC 8446 §4.2.2: the cookie goes back in the retried hello.
                    if let Some(c) = cookie {
                        put_ext(&mut m, 0x002c, |b| with_u16_len(b, |b| b.extend_from_slice(c)));
                    }
                }
                Ext::Versions(vs) => put_ext(&mut m, 0x002b, |b| {
                    with_u8_len(b, |b| {
                        for &v in vs {
                            put_u16(b, degrease(v, g.version));
                        }
                    })
                }),
                Ext::CompressCertificate(algs) => put_ext(&mut m, 0x001b, |b| {
                    with_u8_len(b, |b| {
                        for &a in algs {
                            put_u16(b, a);
                        }
                    })
                }),
                Ext::ApplicationSettings => put_ext(&mut m, 0x44cd, |b| {
                    with_u16_len(b, |b| with_u8_len(b, |b| b.extend_from_slice(b"h2")))
                }),
                Ext::EchGrease(..) => {
                    // RFC 9849 §6.1: a retried hello repeats the extension verbatim.
                    let body = self.ech.as_deref().unwrap_or_default();
                    put_ext(&mut m, 0xfe0d, |b| b.extend_from_slice(body))
                }
                Ext::DelegatedCredentials(algs) => put_ext(&mut m, 0x0022, |b| {
                    with_u16_len(b, |b| {
                        for &a in algs {
                            put_u16(b, a);
                        }
                    })
                }),
                Ext::RecordSizeLimit(l) => put_ext(&mut m, 0x001c, |b| put_u16(b, l)),
                Ext::TrustAnchors(body) => put_ext(&mut m, 0xca34, |b| b.extend_from_slice(body)),
            }
        }
        let ext_len = (m.len() - ext_start - 2) as u16;
        m[ext_start..ext_start + 2].copy_from_slice(&ext_len.to_be_bytes());
        let body_len = (m.len() - 4) as u32;
        m[1..4].copy_from_slice(&body_len.to_be_bytes()[1..]);
        m
    }
}

/// A GREASE ECH extension body (RFC 9849 §6.2): random config id and
/// payload, and a real X25519 public key as the encapsulated key.
fn grease_ech(aeads: &[u16], lens: &[u16]) -> io::Result<Vec<u8>> {
    let r: [u8; 3] = random_bytes()?;
    let aead = aeads[r[0] as usize % aeads.len()];
    let inner_len = lens[r[1] as usize % lens.len()] as usize;
    let (_, enc) = x25519_key()?;
    let mut payload = vec![0u8; inner_len + 16];
    rand::fill(&mut payload).map_err(|_| crypto_err())?;
    let mut b = Vec::with_capacity(10 + enc.len() + payload.len());
    b.push(0); // outer
    put_u16(&mut b, 0x0001); // HKDF-SHA256
    put_u16(&mut b, aead);
    b.push(r[2]); // config_id
    with_u16_len(&mut b, |b| b.extend_from_slice(&enc));
    with_u16_len(&mut b, |b| b.extend_from_slice(&payload));
    Ok(b)
}

/// Uniform random permutation of everything between the pinned GREASE
/// extensions (Chrome ≥ 110 permutes its extensions per connection).
fn shuffle_middle(exts: &mut [Ext]) -> io::Result<()> {
    let pinned = |e: &Ext| matches!(e, Ext::Grease1 | Ext::Grease2);
    let idx: Vec<usize> = (0..exts.len()).filter(|&i| !pinned(&exts[i])).collect();
    let mut rnd = vec![0u8; idx.len() * 4];
    rand::fill(&mut rnd).map_err(|_| crypto_err())?;
    for i in (1..idx.len()).rev() {
        let r = u32::from_le_bytes(rnd[i * 4..i * 4 + 4].try_into().unwrap()) as usize;
        let j = r % (i + 1);
        exts.swap(idx[i], idx[j]);
    }
    Ok(())
}
