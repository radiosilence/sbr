//! Browser ClientHello fingerprints.
//!
//! Profiles are transcribed from uTLS (`github.com/metacubex/utls` v1.8.7,
//! `u_parrots.go`), which is what sing-box and Xray send for the same
//! `fingerprint` names:
//!
//! | name      | uTLS id            |
//! |-----------|--------------------|
//! | `chrome`  | `HelloChrome_133`  |
//! | `firefox` | `HelloFirefox_120` |
//! | `safari`  | `HelloSafari_16_0` |
//! | `ios`     | `HelloIOS_14`      |
//!
//! GREASE values follow BoringSSL (`0x?a?a`, one random value per role, the two
//! GREASE extensions never equal), Chrome's extension order is a fresh random
//! permutation per connection with the GREASE extensions pinned first and last,
//! and Safari/iOS use BoringSSL's padding rule.

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

/// The browser whose ClientHello is imitated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Fingerprint {
    /// Chrome 133 (uTLS `HelloChrome_133`, sing-box `chrome` / default).
    #[default]
    Chrome,
    /// Firefox 120 (uTLS `HelloFirefox_120`).
    Firefox,
    /// Safari 16.0 (uTLS `HelloSafari_16_0`).
    Safari,
    /// iOS 14 (uTLS `HelloIOS_14`).
    Ios,
}

impl std::str::FromStr for Fingerprint {
    type Err = io::Error;

    /// sing-box `utls.fingerprint` names. Unsupported names are an error, never
    /// silently replaced by another browser.
    fn from_str(s: &str) -> io::Result<Self> {
        match s {
            "" | "chrome" => Ok(Self::Chrome),
            "firefox" => Ok(Self::Firefox),
            "safari" => Ok(Self::Safari),
            "ios" => Ok(Self::Ios),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported uTLS fingerprint for REALITY: {s:?} (supported: chrome, firefox, safari, ios)"),
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
    /// BoringSSL padding to 512 bytes; must be last.
    Padding,
}

struct Spec {
    suites: &'static [u16],
    exts: &'static [Ext],
    /// Chrome-style extension permutation.
    shuffle: bool,
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
const SAFARI_SUITES: &[u16] = &[
    GREASE, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009, 0xc014, 0xc013,
    0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
];
const IOS_SUITES: &[u16] = &[
    GREASE, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc024, 0xc023, 0xc00a, 0xc009,
    0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
];

// Signature algorithms.
const CHROME_SIGALGS: &[u16] = &[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];
const FIREFOX_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const FIREFOX_DC_SIGALGS: &[u16] = &[0x0403, 0x0503, 0x0603, 0x0203];
// Apple really lists rsa_pss_rsae_sha384 twice.
const APPLE_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

const CHROME_GROUPS: &[u16] = &[GREASE, GROUP_X25519_MLKEM768, GROUP_X25519, GROUP_P256, GROUP_P384];
const CHROME_SHARES: &[u16] = &[GREASE, GROUP_X25519_MLKEM768, GROUP_X25519];
const CHROME_VERSIONS: &[u16] = &[GREASE, 0x0304, 0x0303];
const FIREFOX_GROUPS: &[u16] = &[
    GROUP_X25519,
    GROUP_P256,
    GROUP_P384,
    GROUP_P521,
    GROUP_FFDHE2048,
    GROUP_FFDHE3072,
];
const FIREFOX_SHARES: &[u16] = &[GROUP_X25519, GROUP_P256];
const FIREFOX_VERSIONS: &[u16] = &[0x0304, 0x0303];
const APPLE_GROUPS: &[u16] = &[GREASE, GROUP_X25519, GROUP_P256, GROUP_P384, GROUP_P521];
const APPLE_SHARES: &[u16] = &[GREASE, GROUP_X25519];
const APPLE_VERSIONS: &[u16] = &[GREASE, 0x0304, 0x0303, 0x0302, 0x0301];

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
        Ext::Versions(CHROME_VERSIONS),
        Ext::CompressCertificate(&[0x0002]),
        Ext::ApplicationSettings,
        Ext::EchGrease(&[AEAD_AES128GCM], &[128, 160, 192, 224]),
        Ext::Grease2,
    ],
    shuffle: true,
};

const FIREFOX: Spec = Spec {
    suites: FIREFOX_SUITES,
    exts: &[
        Ext::Sni,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::Groups(FIREFOX_GROUPS),
        Ext::PointFormats,
        Ext::SessionTicket,
        Ext::Alpn,
        Ext::StatusRequest,
        Ext::DelegatedCredentials(FIREFOX_DC_SIGALGS),
        Ext::KeyShare(FIREFOX_SHARES),
        Ext::Versions(FIREFOX_VERSIONS),
        Ext::SignatureAlgorithms(FIREFOX_SIGALGS),
        Ext::PskModes,
        Ext::RecordSizeLimit(0x4001),
        Ext::EchGrease(&[AEAD_AES128GCM, AEAD_CHACHA20POLY1305], &[223]),
    ],
    shuffle: false,
};

const SAFARI: Spec = Spec {
    suites: SAFARI_SUITES,
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
        Ext::Versions(APPLE_VERSIONS),
        Ext::CompressCertificate(&[0x0001]),
        Ext::Grease2,
        Ext::Padding,
    ],
    shuffle: false,
};

const IOS: Spec = Spec {
    suites: IOS_SUITES,
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
        Ext::Versions(APPLE_VERSIONS),
        Ext::Grease2,
        Ext::Padding,
    ],
    shuffle: false,
};

fn spec(fp: Fingerprint) -> &'static Spec {
    match fp {
        Fingerprint::Chrome => &CHROME,
        Fingerprint::Firefox => &FIREFOX,
        Fingerprint::Safari => &SAFARI,
        Fingerprint::Ios => &IOS,
    }
}

/// Key material behind the offered key shares.
pub(crate) struct KeyShares {
    /// The standalone X25519 share. REALITY derives its auth key from it.
    pub(crate) x25519: agreement::PrivateKey,
    /// ML-KEM-768 decapsulation key and the X25519 half of the hybrid share.
    pub(crate) mlkem: Option<(kem::DecapsulationKey, agreement::PrivateKey)>,
    pub(crate) p256: Option<agreement::PrivateKey>,
}

pub(crate) struct ClientHello {
    /// The handshake message (4-byte header included), session_id zeroed.
    pub(crate) msg: Vec<u8>,
    pub(crate) random: [u8; 32],
    pub(crate) keys: KeyShares,
}

pub(crate) struct HelloParams<'a> {
    pub(crate) fingerprint: Fingerprint,
    pub(crate) server_name: &'a str,
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
}

impl Grease {
    fn new() -> io::Result<Self> {
        let seed: [u8; 5] = random_bytes()?;
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

pub(crate) fn build(p: &HelloParams<'_>) -> io::Result<ClientHello> {
    let spec = spec(p.fingerprint);
    let grease = Grease::new()?;
    let random: [u8; 32] = random_bytes()?;
    let sni_is_ip = p.server_name.parse::<std::net::IpAddr>().is_ok();

    let mut exts: Vec<Ext> = spec
        .exts
        .iter()
        .copied()
        // Go (and therefore uTLS) never puts an IP literal in SNI.
        .filter(|e| !(matches!(e, Ext::Sni) && (sni_is_ip || p.server_name.is_empty())))
        .collect();
    if spec.shuffle {
        shuffle_middle(&mut exts)?;
    }
    let drop_pq = |g: &u16| p.post_quantum || *g != GROUP_X25519_MLKEM768;

    let mut x25519 = None;
    let mut mlkem = None;
    let mut p256 = None;

    let mut m = Vec::with_capacity(2048);
    m.extend_from_slice(&[1, 0, 0, 0]); // ClientHello, u24 length patched below
    put_u16(&mut m, 0x0303);
    m.extend_from_slice(&random);
    m.push(32);
    m.extend_from_slice(&[0; 32]);
    with_u16_len(&mut m, |m| {
        for &s in spec.suites {
            put_u16(m, degrease(s, grease.cipher));
        }
    });
    m.extend_from_slice(&[1, 0]);

    let ext_start = m.len();
    m.extend_from_slice(&[0, 0]);
    let mut pad = false;
    for e in &exts {
        match *e {
            Ext::Grease1 => put_ext(&mut m, grease.ext1, |_| {}),
            Ext::Grease2 => put_ext(&mut m, grease.ext2, |b| b.push(0)),
            Ext::Sni => put_ext(&mut m, 0x0000, |b| {
                with_u16_len(b, |b| {
                    b.push(0);
                    with_u16_len(b, |b| b.extend_from_slice(p.server_name.as_bytes()));
                })
            }),
            Ext::ExtendedMasterSecret => put_ext(&mut m, 0x0017, |_| {}),
            Ext::RenegotiationInfo => put_ext(&mut m, 0xff01, |b| b.push(0)),
            Ext::Groups(groups) => put_ext(&mut m, 0x000a, |b| {
                with_u16_len(b, |b| {
                    for g in groups.iter().filter(|g| drop_pq(g)) {
                        put_u16(b, degrease(*g, grease.group));
                    }
                })
            }),
            Ext::PointFormats => put_ext(&mut m, 0x000b, |b| b.extend_from_slice(&[1, 0])),
            Ext::SessionTicket => put_ext(&mut m, 0x0023, |_| {}),
            Ext::Alpn => {
                let default = ["h2", "http/1.1"];
                put_ext(&mut m, 0x0010, |b| {
                    with_u16_len(b, |b| {
                        if p.alpn.is_empty() {
                            for a in default {
                                with_u8_len(b, |b| b.extend_from_slice(a.as_bytes()));
                            }
                        } else {
                            for a in p.alpn {
                                with_u8_len(b, |b| b.extend_from_slice(a.as_bytes()));
                            }
                        }
                    })
                })
            }
            Ext::StatusRequest => put_ext(&mut m, 0x0005, |b| b.extend_from_slice(&[1, 0, 0, 0, 0])),
            Ext::SignatureAlgorithms(algs) => put_ext(&mut m, 0x000d, |b| {
                with_u16_len(b, |b| {
                    for &a in algs {
                        put_u16(b, a);
                    }
                })
            }),
            Ext::Sct => put_ext(&mut m, 0x0012, |_| {}),
            Ext::KeyShare(groups) => {
                // Generate first: the closures below cannot fail.
                let mut shares: Vec<(u16, Vec<u8>)> = Vec::with_capacity(groups.len());
                for &g in groups.iter().filter(|g| drop_pq(g)) {
                    match g {
                        GREASE => shares.push((grease.group, vec![0])),
                        GROUP_X25519 => {
                            let (k, pk) = x25519_key()?;
                            x25519 = Some(k);
                            shares.push((g, pk));
                        }
                        GROUP_X25519_MLKEM768 => {
                            let dk = kem::DecapsulationKey::generate(&kem::ML_KEM_768).map_err(|_| crypto_err())?;
                            let ek = dk.encapsulation_key().map_err(|_| crypto_err())?;
                            let ek = ek.key_bytes().map_err(|_| crypto_err())?;
                            let (xk, xp) = x25519_key()?;
                            let mut data = Vec::with_capacity(MLKEM768_ENCAPS_LEN + 32);
                            data.extend_from_slice(ek.as_ref());
                            data.extend_from_slice(&xp);
                            mlkem = Some((dk, xk));
                            shares.push((g, data));
                        }
                        GROUP_P256 => {
                            let k = agreement::PrivateKey::generate(&agreement::ECDH_P256).map_err(|_| crypto_err())?;
                            let pk = k.compute_public_key().map_err(|_| crypto_err())?.as_ref().to_vec();
                            p256 = Some(k);
                            shares.push((g, pk));
                        }
                        _ => return Err(io::Error::other("key share group not implemented")),
                    }
                }
                put_ext(&mut m, 0x0033, |b| {
                    with_u16_len(b, |b| {
                        for (g, data) in &shares {
                            put_u16(b, *g);
                            with_u16_len(b, |b| b.extend_from_slice(data));
                        }
                    })
                })
            }
            Ext::PskModes => put_ext(&mut m, 0x002d, |b| b.extend_from_slice(&[1, 1])),
            Ext::Versions(vs) => put_ext(&mut m, 0x002b, |b| {
                with_u8_len(b, |b| {
                    for &v in vs {
                        put_u16(b, degrease(v, grease.version));
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
            Ext::EchGrease(aeads, lens) => {
                let r: [u8; 3] = random_bytes()?;
                let aead = aeads[r[0] as usize % aeads.len()];
                let inner_len = lens[r[1] as usize % lens.len()] as usize;
                // The encapsulated key is a real X25519 public key, as from HPKE.
                let (_, enc) = x25519_key()?;
                let mut payload = vec![0u8; inner_len + 16];
                rand::fill(&mut payload).map_err(|_| crypto_err())?;
                put_ext(&mut m, 0xfe0d, |b| {
                    b.push(0); // outer
                    put_u16(b, 0x0001); // HKDF-SHA256
                    put_u16(b, aead);
                    b.push(r[2]); // config_id
                    with_u16_len(b, |b| b.extend_from_slice(&enc));
                    with_u16_len(b, |b| b.extend_from_slice(&payload));
                })
            }
            Ext::DelegatedCredentials(algs) => put_ext(&mut m, 0x0022, |b| {
                with_u16_len(b, |b| {
                    for &a in algs {
                        put_u16(b, a);
                    }
                })
            }),
            Ext::RecordSizeLimit(l) => put_ext(&mut m, 0x001c, |b| put_u16(b, l)),
            Ext::Padding => pad = true,
        }
    }
    if pad {
        // BoringSSL: pad hellos of 256..511 bytes up to 512.
        let unpadded = m.len();
        if unpadded > 0xff && unpadded < 0x200 {
            let mut n = 0x200 - unpadded;
            n = if n >= 5 { n - 4 } else { 1 };
            put_ext(&mut m, 0x0015, |b| b.resize(b.len() + n, 0));
        }
    }
    let ext_len = (m.len() - ext_start - 2) as u16;
    m[ext_start..ext_start + 2].copy_from_slice(&ext_len.to_be_bytes());
    let body_len = (m.len() - 4) as u32;
    m[1..4].copy_from_slice(&body_len.to_be_bytes()[1..]);
    // Every profile offers a plain X25519 share; REALITY needs it.
    let x25519 = x25519.ok_or_else(|| io::Error::other("fingerprint offers no X25519 key share"))?;
    Ok(ClientHello {
        msg: m,
        random,
        keys: KeyShares { x25519, mlkem, p256 },
    })
}

/// Uniform random permutation of everything between the pinned GREASE
/// extensions (Chrome ≥ 110 permutes its extensions per connection).
fn shuffle_middle(exts: &mut [Ext]) -> io::Result<()> {
    let pinned = |e: &Ext| matches!(e, Ext::Grease1 | Ext::Grease2 | Ext::Padding);
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
