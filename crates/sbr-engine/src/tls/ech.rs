//! Where a rustls client's ECHConfigList comes from (sing-box
//! `common/tls/ech.go`): `config` / `config_path`, else the `ech` SvcParam
//! of the HTTPS record for `query_server_name` (or the TLS server name),
//! asked of the DNS router so it follows the config's DNS servers and rules,
//! and kept for the record's TTL. `retry_configs` from a server that
//! rejected the offer replace the list.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::client::EchConfig;
use rustls::pki_types::EchConfigListBytes;
use sbr_core::dns::Dns;
use sbr_core::{Destination, Host, Metadata, Network};
use sbr_dns::msg;

use super::{inline_or_file, invalid};

pub struct EchSource {
    lookup: Option<Lookup>,
    current: Mutex<Option<Current>>,
    /// Serialises DNS lookups so concurrent handshakes share one.
    fetching: tokio::sync::Mutex<()>,
}

struct Lookup {
    name: String,
    dns: Arc<dyn Dns>,
}

#[derive(Clone)]
struct Current {
    list: Arc<[u8]>,
    /// `None` for a static config.
    expires: Option<Instant>,
}

impl EchSource {
    pub fn new(
        e: &sbr_config::Ech,
        server_name: &str,
        base: Option<&std::path::Path>,
        dns: &Arc<dyn Dns>,
    ) -> Result<Self, String> {
        let (lookup, current) = match inline_or_file(&e.config, &e.config_path, base)? {
            Some(pem) => {
                let list = config_list_pem(&pem)?;
                parse(&list).map_err(|e| format!("tls.ech.config: {e}"))?;
                let current = Current {
                    list: list.into(),
                    expires: None,
                };
                (None, Some(current))
            }
            None => {
                let name = e.query_server_name.as_deref().unwrap_or(server_name);
                if name.parse::<std::net::IpAddr>().is_ok() || name.is_empty() {
                    return Err(invalid(
                        "tls.ech: no config and no domain to look its HTTPS record up for; set config or query_server_name",
                    ));
                }
                let lookup = Lookup {
                    name: name.trim_end_matches('.').to_owned(),
                    dns: dns.clone(),
                };
                (Some(lookup), None)
            }
        };
        Ok(Self {
            lookup,
            current: Mutex::new(current),
            fetching: tokio::sync::Mutex::new(()),
        })
    }

    fn fresh(&self) -> Option<Arc<[u8]>> {
        let c = self.current.lock().unwrap();
        let c = c.as_ref()?;
        c.expires.is_none_or(|t| Instant::now() < t).then(|| c.list.clone())
    }

    /// The list to offer, looked up again once its TTL has passed.
    pub async fn list(&self) -> io::Result<Arc<[u8]>> {
        if let Some(l) = self.fresh() {
            return Ok(l);
        }
        let Some(lookup) = &self.lookup else {
            unreachable!("a static ECH config never expires")
        };
        let _guard = self.fetching.lock().await;
        if let Some(l) = self.fresh() {
            return Ok(l);
        }
        let (list, ttl) = lookup.fetch().await?;
        let list: Arc<[u8]> = list.into();
        *self.current.lock().unwrap() = Some(Current {
            list: list.clone(),
            expires: Some(Instant::now() + Duration::from_secs(ttl.into())),
        });
        Ok(list)
    }

    /// The server's `retry_configs`, in place of the list until it would
    /// have expired.
    pub fn retry_with(&self, list: Vec<u8>) {
        let mut c = self.current.lock().unwrap();
        let expires = c.as_ref().and_then(|c| c.expires);
        *c = Some(Current {
            list: list.into(),
            expires,
        });
    }
}

impl Lookup {
    async fn fetch(&self) -> io::Result<(Vec<u8>, u32)> {
        let fail = |why: String| io::Error::other(format!("tls.ech: HTTPS record for {}: {why}", self.name));
        let query = msg::encode(&msg::query(&self.name, msg::TYPE_HTTPS)?)?;
        let meta = Metadata::new(
            Arc::from(""),
            "",
            Network::Tcp,
            std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            Destination::new(Host::Domain(self.name.as_str().into()), 0),
        );
        let resp = self
            .dns
            .exchange(&query, &meta)
            .await
            .map_err(|e| fail(e.to_string()))?;
        let resp = msg::decode(&resp)?;
        match msg::rcode(&resp) {
            0 => msg::https_ech(&resp).ok_or_else(|| fail("no ech parameter".into())),
            rcode => Err(fail(format!("rcode {rcode}"))),
        }
    }
}

pub fn parse(list: &[u8]) -> Result<EchConfig, rustls::Error> {
    EchConfig::new(
        EchConfigListBytes::from(list.to_vec()),
        rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
    )
}

/// The `ECH CONFIGS` PEM block sing-box uses (`sing-box generate ech-keypair`).
pub fn config_list_pem(pem: &[u8]) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let bad = || invalid("tls.ech.config: invalid ECH configs pem");
    let text = std::str::from_utf8(pem).map_err(|_| bad())?;
    let body = text
        .split("-----BEGIN ECH CONFIGS-----")
        .nth(1)
        .and_then(|r| r.split("-----END ECH CONFIGS-----").next())
        .ok_or_else(bad)?;
    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(b64).map_err(|_| bad())
}

/// The `retry_configs` of a handshake error, encoded as an ECHConfigList.
pub fn retry_configs(e: &io::Error) -> Option<Vec<u8>> {
    use rustls::internal::msgs::codec::Codec as _;
    let rustls::Error::PeerIncompatible(rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(Some(configs))) =
        e.get_ref()?.downcast_ref::<rustls::Error>()?
    else {
        return None;
    };
    (!configs.is_empty()).then(|| configs.get_encoding())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_proto::rr::rdata::HTTPS;
    use hickory_proto::rr::rdata::svcb::{EchConfigList, SVCB, SvcParamKey, SvcParamValue};
    use hickory_proto::rr::{Name, RData, Record};
    use sbr_config::{DomainStrategy, Ech};
    use sbr_core::BoxFuture;

    use super::*;

    /// Answers HTTPS queries for one name with an ECH list and a TTL.
    struct Answer {
        name: &'static str,
        list: Vec<u8>,
        ttl: u32,
        queries: AtomicUsize,
    }

    impl Dns for Answer {
        fn lookup<'a>(
            &'a self,
            _: &'a str,
            _: Option<DomainStrategy>,
        ) -> BoxFuture<'a, io::Result<Vec<std::net::IpAddr>>> {
            Box::pin(async { Err(io::Error::other("lookup")) })
        }
        fn exchange<'a>(&'a self, query: &'a [u8], _: &'a Metadata) -> BoxFuture<'a, io::Result<Vec<u8>>> {
            Box::pin(async move {
                self.queries.fetch_add(1, Ordering::Relaxed);
                let q = msg::decode(query)?;
                assert_eq!(u16::from(q.queries[0].query_type()), msg::TYPE_HTTPS);
                if msg::domain_of(&q.queries[0]) != self.name {
                    return msg::encode(&msg::status(&q, 3));
                }
                let mut m = msg::status(&q, 0);
                let ech = (
                    SvcParamKey::EchConfigList,
                    SvcParamValue::EchConfigList(EchConfigList(self.list.clone())),
                );
                m.answers.push(Record::from_rdata(
                    q.queries[0].name().clone(),
                    self.ttl,
                    RData::HTTPS(HTTPS(SVCB::new(1, Name::root(), vec![ech]))),
                ));
                msg::encode(&m)
            })
        }
    }

    fn answer(name: &'static str, ttl: u32) -> Arc<Answer> {
        Arc::new(Answer {
            name,
            list: vec![0, 3, 1, 2, 3],
            ttl,
            queries: AtomicUsize::new(0),
        })
    }

    fn enabled() -> Ech {
        Ech {
            enabled: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn looked_up_through_the_router_and_kept_for_the_ttl() {
        let a = answer("front.test", 300);
        let dns: Arc<dyn Dns> = a.clone();
        let src = EchSource::new(&enabled(), "front.test", None, &dns).unwrap();
        assert_eq!(&*src.list().await.unwrap(), &a.list[..]);
        assert_eq!(&*src.list().await.unwrap(), &a.list[..]);
        assert_eq!(a.queries.load(Ordering::Relaxed), 1);

        src.retry_with(vec![0, 1, 9]);
        assert_eq!(&*src.list().await.unwrap(), &[0, 1, 9]);
        assert_eq!(a.queries.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn ttl_zero_asks_every_time() {
        let a = answer("front.test", 0);
        let dns: Arc<dyn Dns> = a.clone();
        let src = EchSource::new(&enabled(), "front.test", None, &dns).unwrap();
        src.list().await.unwrap();
        src.list().await.unwrap();
        assert_eq!(a.queries.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn query_server_name_overrides_the_server_name() {
        let a = answer("ech.test", 60);
        let dns: Arc<dyn Dns> = a.clone();
        let e = Ech {
            query_server_name: Some("ech.test".into()),
            ..enabled()
        };
        let src = EchSource::new(&e, "front.test", None, &dns).unwrap();
        assert_eq!(&*src.list().await.unwrap(), &a.list[..]);

        let src = EchSource::new(&enabled(), "front.test", None, &dns).unwrap();
        let err = src.list().await.unwrap_err().to_string();
        assert!(err.contains("front.test") && err.contains("rcode 3"), "{err}");

        let err = EchSource::new(&enabled(), "192.0.2.1", None, &dns).err().unwrap();
        assert!(err.starts_with("tls.ech"), "{err}");
    }

    #[tokio::test]
    async fn static_config_is_never_looked_up() {
        let a = answer("front.test", 60);
        let dns: Arc<dyn Dns> = a.clone();
        let bad = Ech {
            config: Some("-----BEGIN ECH CONFIGS-----\nAAA=\n-----END ECH CONFIGS-----".into()),
            ..enabled()
        };
        assert!(EchSource::new(&bad, "front.test", None, &dns).is_err());
        assert_eq!(a.queries.load(Ordering::Relaxed), 0);
    }
}
