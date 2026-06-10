use std::collections::BTreeMap;
use std::net::SocketAddr;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::cli::Endpoint;
use crate::error::{AppError, AppResult};
use crate::resp::{Frame, parse_frame, read_raw_frame};

#[derive(Clone, Debug)]
pub enum Topology {
    Standalone {
        target: ProxyTarget,
    },
    Cluster {
        targets: Vec<ProxyTarget>,
        slots: Vec<LocalSlotRange>,
    },
}

impl Topology {
    pub fn targets(&self) -> &[ProxyTarget] {
        match self {
            Topology::Standalone { target } => std::slice::from_ref(target),
            Topology::Cluster { targets, .. } => targets,
        }
    }

    pub fn local_slots_response(&self) -> Option<Frame> {
        match self {
            Topology::Standalone { .. } => None,
            Topology::Cluster { slots, .. } => Some(Frame::Array(Some(
                slots.iter().map(LocalSlotRange::to_resp_frame).collect(),
            ))),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProxyTarget {
    pub upstream: Endpoint,
    pub listen: SocketAddr,
}

#[derive(Clone, Debug)]
pub struct LocalSlotRange {
    pub start: u16,
    pub end: u16,
    pub upstream: Endpoint,
    pub local: SocketAddr,
    pub node_id: Option<Vec<u8>>,
}

impl LocalSlotRange {
    fn to_resp_frame(&self) -> Frame {
        let node_id = self.node_id.clone().unwrap_or_else(|| {
            format!("evilresp-{}", self.local.port()).into_bytes()
        });
        Frame::Array(Some(vec![
            Frame::Integer(i64::from(self.start)),
            Frame::Integer(i64::from(self.end)),
            Frame::Array(Some(vec![
                Frame::BulkString(Some(
                    self.local.ip().to_string().into_bytes(),
                )),
                Frame::Integer(i64::from(self.local.port())),
                Frame::BulkString(Some(node_id)),
            ])),
        ]))
    }
}

pub async fn discover(
    proxy: Endpoint,
    listen: SocketAddr,
) -> AppResult<Topology> {
    let slots = match fetch_cluster_slots(&proxy).await {
        Ok(slots) if slots.is_empty() => {
            debug!(
                "CLUSTER SLOTS returned an empty topology; using standalone proxy mode"
            );
            return Ok(Topology::Standalone {
                target: ProxyTarget {
                    upstream: proxy,
                    listen,
                },
            });
        }
        Ok(slots) => slots,
        Err(error) => {
            debug!(%error, "cluster probe failed; using standalone proxy mode");
            return Ok(Topology::Standalone {
                target: ProxyTarget {
                    upstream: proxy,
                    listen,
                },
            });
        }
    };

    if listen.port() == 0 {
        return Err(AppError::Proxy(
            "cluster proxy mode requires a non-zero --listen port".to_owned(),
        ));
    }

    let mut local_by_upstream = BTreeMap::<String, SocketAddr>::new();
    let mut targets = Vec::new();
    for slot in &slots {
        let key = slot.upstream.connect_addr();
        if local_by_upstream.contains_key(&key) {
            continue;
        }

        let offset = u16::try_from(local_by_upstream.len()).map_err(|_| {
            AppError::Proxy(
                "cluster has more local nodes than u16 ports".to_owned(),
            )
        })?;
        let port = listen.port().checked_add(offset).ok_or_else(|| {
            AppError::Proxy(format!(
                "cluster local port mapping from {} overflows u16",
                listen.port()
            ))
        })?;
        let mut local = listen;
        local.set_port(port);
        local_by_upstream.insert(key, local);
        targets.push(ProxyTarget {
            upstream: slot.upstream.clone(),
            listen: local,
        });
    }

    let local_slots = slots
        .into_iter()
        .map(|mut slot| {
            let key = slot.upstream.connect_addr();
            slot.local = local_by_upstream[&key];
            slot
        })
        .collect::<Vec<_>>();

    info!(
        nodes = targets.len(),
        "detected cluster topology and mapped local node listeners"
    );

    Ok(Topology::Cluster {
        targets,
        slots: local_slots,
    })
}

async fn fetch_cluster_slots(
    proxy: &Endpoint,
) -> AppResult<Vec<LocalSlotRange>> {
    let stream = TcpStream::connect(proxy.connect_addr()).await?;
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);

    write.write_all(&cluster_slots_command().encode()).await?;
    write.flush().await?;

    let raw = read_raw_frame(&mut read).await?;
    let frame = parse_frame(&raw)?;
    match frame {
        Frame::Array(Some(items)) => parse_cluster_slots(items, proxy),
        Frame::SimpleError(error) => {
            Err(AppError::Proxy(format!("CLUSTER SLOTS failed: {error}")))
        }
        other => Err(AppError::Proxy(format!(
            "CLUSTER SLOTS returned unexpected frame {other:?}"
        ))),
    }
}

fn cluster_slots_command() -> Frame {
    Frame::Array(Some(vec![
        Frame::BulkString(Some(b"CLUSTER".to_vec())),
        Frame::BulkString(Some(b"SLOTS".to_vec())),
    ]))
}

fn parse_cluster_slots(
    items: Vec<Frame>,
    bootstrap: &Endpoint,
) -> AppResult<Vec<LocalSlotRange>> {
    items
        .into_iter()
        .map(|item| parse_slot_range(item, bootstrap))
        .collect()
}

fn parse_slot_range(
    item: Frame,
    bootstrap: &Endpoint,
) -> AppResult<LocalSlotRange> {
    let Frame::Array(Some(parts)) = item else {
        return Err(AppError::Proxy(
            "cluster slot entry is not an array".to_owned(),
        ));
    };
    if parts.len() < 3 {
        return Err(AppError::Proxy(
            "cluster slot entry has fewer than three items".to_owned(),
        ));
    }

    let start = as_slot(parts.first(), "start slot")?;
    let end = as_slot(parts.get(1), "end slot")?;
    let (upstream, node_id) = parse_node(parts.get(2), bootstrap)?;

    Ok(LocalSlotRange {
        start,
        end,
        upstream,
        local: "127.0.0.1:0"
            .parse()
            .expect("static local placeholder must parse"),
        node_id,
    })
}

fn parse_node(
    node: Option<&Frame>,
    bootstrap: &Endpoint,
) -> AppResult<(Endpoint, Option<Vec<u8>>)> {
    let Some(Frame::Array(Some(parts))) = node else {
        return Err(AppError::Proxy(
            "cluster slot primary node is not an array".to_owned(),
        ));
    };
    if parts.len() < 2 {
        return Err(AppError::Proxy(
            "cluster slot primary node has fewer than two items".to_owned(),
        ));
    }

    let host = match &parts[0] {
        Frame::BulkString(Some(bytes)) | Frame::VerbatimString(bytes) => {
            let host = String::from_utf8_lossy(bytes);
            if host.is_empty() || host == "?" {
                bootstrap.host.clone()
            } else {
                host.into_owned()
            }
        }
        Frame::SimpleString(host) => host.clone(),
        _ => {
            return Err(AppError::Proxy(
                "cluster slot node host is not a string".to_owned(),
            ));
        }
    };

    let port = match parts.get(1) {
        Some(Frame::Integer(port)) => u16::try_from(*port).map_err(|_| {
            AppError::Proxy(format!("invalid cluster node port {port}"))
        })?,
        _ => {
            return Err(AppError::Proxy(
                "cluster slot node port is not an integer".to_owned(),
            ));
        }
    };

    let node_id = match parts.get(2) {
        Some(Frame::BulkString(Some(bytes)))
        | Some(Frame::VerbatimString(bytes)) => Some(bytes.clone()),
        Some(Frame::SimpleString(value)) => Some(value.as_bytes().to_vec()),
        _ => None,
    };

    Ok((Endpoint { host, port }, node_id))
}

fn as_slot(frame: Option<&Frame>, name: &str) -> AppResult<u16> {
    match frame {
        Some(Frame::Integer(value)) => u16::try_from(*value).map_err(|_| {
            AppError::Proxy(format!("{name} {value} is outside u16 range"))
        }),
        _ => Err(AppError::Proxy(format!("{name} is not an integer"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resp::parse_frame;

    #[test]
    fn parses_cluster_slots_response() {
        let frame = parse_frame(
            b"*1\r\n*3\r\n:0\r\n:16383\r\n*3\r\n$9\r\n127.0.0.1\r\n:7000\r\n$4\r\nnode\r\n",
        )
        .unwrap();
        let Frame::Array(Some(items)) = frame else {
            panic!("expected array");
        };

        let slots = parse_cluster_slots(
            items,
            &Endpoint {
                host: "127.0.0.1".to_owned(),
                port: 6379,
            },
        )
        .unwrap();

        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].start, 0);
        assert_eq!(slots[0].end, 16383);
        assert_eq!(slots[0].upstream.port, 7000);
    }
}
