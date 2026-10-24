use std::io;
use std::sync::Arc;

use sbr_core::{Metadata, Network};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::Context;
use crate::OpenError;
use crate::socks5::*;

pub async fn handle(ctx: &Context, mut s: TcpStream) -> io::Result<()> {
    let source = s.peer_addr()?;
    if s.read_u8().await? != VER {
        return Err(invalid("not SOCKS5"));
    }
    let n = s.read_u8().await? as usize;
    let mut methods = [0u8; 255];
    s.read_exact(&mut methods[..n]).await?;
    let methods = &methods[..n];

    let mut user: Option<Arc<str>> = None;
    if ctx.users.is_empty() {
        if !methods.contains(&NO_AUTH) {
            s.write_all(&[VER, NO_ACCEPTABLE]).await?;
            return Ok(());
        }
        s.write_all(&[VER, NO_AUTH]).await?;
    } else {
        if !methods.contains(&USER_PASS) {
            s.write_all(&[VER, NO_ACCEPTABLE]).await?;
            return Ok(());
        }
        s.write_all(&[VER, USER_PASS]).await?;
        let _ver = s.read_u8().await?;
        let ulen = s.read_u8().await? as usize;
        let mut u = vec![0; ulen];
        s.read_exact(&mut u).await?;
        let plen = s.read_u8().await? as usize;
        let mut p = vec![0; plen];
        s.read_exact(&mut p).await?;
        let (u, p) = (String::from_utf8_lossy(&u), String::from_utf8_lossy(&p));
        if !ctx.check_user(&u, &p) {
            s.write_all(&[1, 1]).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("socks auth failed for {u:?}"),
            ));
        }
        s.write_all(&[1, 0]).await?;
        user = Some(u.as_ref().into());
    }

    let mut head = [0u8; 3];
    s.read_exact(&mut head).await?;
    let destination = read_addr(&mut s).await?;
    match head[1] {
        CMD_CONNECT => {}
        CMD_UDP_ASSOCIATE => {
            write_reply(&mut s, REP_CMD_UNSUPPORTED).await?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SOCKS5 UDP not supported by sbr yet",
            ));
        }
        _ => {
            write_reply(&mut s, REP_CMD_UNSUPPORTED).await?;
            return Ok(());
        }
    }

    let meta = Metadata {
        inbound: ctx.tag.clone(),
        inbound_type: ctx.type_name(),
        network: Network::Tcp,
        source,
        destination,
        user,
    };
    match ctx.engine.open(&meta).await {
        Ok(remote) => {
            write_reply(&mut s, REP_OK).await?;
            ctx.engine.relay(&meta, s, remote).await
        }
        Err(OpenError::Rejected { drop: true }) => Ok(()),
        Err(OpenError::Rejected { drop: false }) => write_reply(&mut s, REP_NOT_ALLOWED).await,
        Err(OpenError::Io(e)) => {
            write_reply(&mut s, reply_code(&e)).await?;
            Err(e)
        }
    }
}
