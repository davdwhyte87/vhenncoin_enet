//! TCP peer-to-peer networking for node-to-node communication.
//!
//! On start-up the node listens for inbound peers and also dials every
//! configured bootnode. Each connection performs a [`Message::Hello`]
//! handshake, then the behind-the-tip side downloads and validates the chain
//! (see [`sync`]). Both directions of a connection can serve blocks, so a pair
//! of nodes converge regardless of who dialled whom.

mod framing;
mod message;
mod peer;
mod sync;

pub use message::{Message, PROTOCOL_VERSION};
pub use peer::{Peer, PeerId};

use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncRead, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::block::Transaction;
use crate::error::{Error, Result};
use crate::state::AppState;

use framing::{read_message, write_message};

/// How long to wait for the peer's Hello before giving up.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often to advertise our chain status on an idle connection.
const STATUS_INTERVAL: Duration = Duration::from_secs(15);
/// Delay between reconnection attempts to a dropped bootnode.
const RECONNECT_DELAY: Duration = Duration::from_secs(5);
/// Upper bound on messages buffered from a single peer.
const INBOUND_QUEUE: usize = 128;
/// Upper bound on entries served per header/block request.
const MAX_BATCH: u32 = 256;

/// Bind the P2P listener, start dialing bootnodes, and accept peers until the
/// process exits.
pub async fn run(state: AppState) -> Result<()> {
    let listener = TcpListener::bind(state.config.network.listen_addr).await?;
    serve(listener, state).await
}

/// Serve an already-bound listener. Split out from [`run`] so callers (and
/// tests) can bind to a specific port and observe it.
pub async fn serve(listener: TcpListener, state: AppState) -> Result<()> {
    let addr = listener.local_addr()?;
    tracing::info!(%addr, "P2P TCP listener bound");

    let dialer_state = state.clone();
    tokio::spawn(async move { dial_bootnodes(dialer_state).await });

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, peer_addr, state, false).await {
                tracing::debug!(%peer_addr, %err, "inbound peer connection ended");
            }
        });
    }
}

/// Repeatedly connect to each bootnode in turn, reconnecting when a connection
/// drops.
async fn dial_bootnodes(state: AppState) {
    let bootnodes = state.config.network.resolved_bootnodes();
    if bootnodes.is_empty() {
        tracing::debug!("no bootnodes configured; running as a listener only");
        return;
    }

    loop {
        for addr in &bootnodes {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    if let Err(err) =
                        handle_connection(stream, *addr, state.clone(), true).await
                    {
                        tracing::debug!(%addr, %err, "outbound peer connection ended");
                    }
                }
                Err(err) => {
                    tracing::debug!(%addr, %err, "bootnode dial failed");
                }
            }
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Handle one connection: split it, spawn a reader task, handshake, sync, then
/// serve messages until the peer goes away.
async fn handle_connection(
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    state: AppState,
    outbound: bool,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let (reader, writer) = stream.into_split();

    let (tx, mut rx) = mpsc::channel::<Result<Message>>(INBOUND_QUEUE);
    let reader_task = tokio::spawn(read_loop(reader, tx));

    let mut writer = BufWriter::new(writer);
    let result = run_peer(&state, &mut writer, &mut rx, peer_addr, outbound).await;

    reader_task.abort();
    result
}

/// Drive the handshake, initial sync and steady-state message loop.
async fn run_peer<W>(
    state: &AppState,
    writer: &mut W,
    rx: &mut sync::Inbound,
    peer_addr: std::net::SocketAddr,
    outbound: bool,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    write_message(writer, &local_hello(state)?).await?;

    let mut peer = match timeout(HANDSHAKE_TIMEOUT, read_hello(rx, state)).await {
        Ok(result) => result?,
        Err(_) => return Err(Error::Network("handshake timed out".to_string())),
    };
    peer.addr = peer_addr;

    state.peer_count.fetch_add(1, Ordering::AcqRel);
    let _guard = PeerGuard(state.clone());

    tracing::info!(
        peer = %peer_addr,
        outbound,
        height = peer.best_height,
        finalized = peer.finalized_height,
        "peer connected"
    );

    if let Err(err) = sync::sync_from_peer(state, writer, rx, &mut peer).await {
        tracing::warn!(peer = %peer_addr, %err, "initial sync rejected a peer block");
    }

    let mut gossip = state.subscribe_transactions();
    serve_peer(state, writer, rx, &mut peer, &mut gossip).await
}

/// Steady-state: answer requests, track status, relay gossiped transactions and
/// re-sync when the peer advances past the local finalised height.
async fn serve_peer<W>(
    state: &AppState,
    writer: &mut W,
    rx: &mut sync::Inbound,
    peer: &mut Peer,
    gossip: &mut tokio::sync::broadcast::Receiver<Transaction>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            inbound = timeout(STATUS_INTERVAL, rx.recv()) => {
                match inbound {
                    Ok(Some(Ok(message))) => handle_message(state, writer, peer, message).await?,
                    Ok(Some(Err(err))) => return Err(err),
                    Ok(None) => return Ok(()),
                    Err(_) => {
                        write_message(writer, &local_status(state)?).await?;
                        if peer.finalized_height > state.storage.head_height()? {
                            if let Err(err) = sync::sync_from_peer(state, writer, rx, peer).await {
                                tracing::warn!(%err, "background sync failed");
                            }
                        }
                    }
                }
            }
            relayed = gossip.recv() => {
                if let Ok(tx) = relayed {
                    write_message(writer, &Message::NewTransaction(tx)).await?;
                }
            }
        }
    }
}

/// Respond to a single peer request.
async fn handle_message<W>(
    state: &AppState,
    writer: &mut W,
    peer: &mut Peer,
    message: Message,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    match message {
        Message::Ping { nonce } => {
            write_message(writer, &Message::Pong { nonce }).await?;
        }
        Message::Status {
            height,
            finalized_height,
            ..
        } => {
            peer.best_height = height.max(peer.best_height);
            if finalized_height > peer.finalized_height {
                peer.finalized_height = finalized_height;
            }
        }
        Message::GetHeaders { from_height, max } => {
            let headers = state.storage.headers_from(from_height, clamp(max))?;
            write_message(writer, &Message::Headers { headers }).await?;
        }
        Message::GetBlock { hash } => match state.storage.get_block_by_hash(&hash)? {
            Some(block) => write_message(writer, &Message::Block(block)).await?,
            None => write_message(writer, &Message::NotFound { hash }).await?,
        },
        Message::GetBlocks { from_height, max } => {
            let blocks = state.storage.blocks_from(from_height, clamp(max))?;
            write_message(writer, &Message::Blocks { blocks }).await?;
        }
        Message::NewTransaction(tx) => {
            // A governance request broadcast by a node reaches us here. Accept
            // it (which re-validates the signature and, for a removal, checks
            // the override key) and relay it onward.
            if let Err(err) = crate::chain::accept_transaction(state, tx) {
                tracing::debug!(%err, "rejected gossiped transaction");
            }
        }
        // Duplicate handshakes are not handled yet.
        Message::Hello { .. } | Message::Pong { .. } => {}
        Message::Headers { .. }
        | Message::Block(_)
        | Message::Blocks { .. }
        | Message::NotFound { .. } => {}
    }
    Ok(())
}

/// Background task that turns a byte stream into a queue of decoded messages.
async fn read_loop<R>(mut reader: R, tx: mpsc::Sender<Result<Message>>)
where
    R: AsyncRead + Unpin,
{
    loop {
        match read_message(&mut reader).await {
            Ok(Some(message)) => {
                if tx.send(Ok(message)).await.is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(err) => {
                let _ = tx.send(Err(err)).await;
                break;
            }
        }
    }
}

/// Build the Hello we send to a peer from our committed head.
fn local_hello(state: &AppState) -> Result<Message> {
    Ok(Message::Hello {
        protocol_version: PROTOCOL_VERSION,
        chain_id: state.config.node.chain_id,
        best_height: state.storage.head_height()?,
        best_hash: state.storage.head_hash()?,
        finalized_height: state.storage.finalized_height()?,
    })
}

/// Build the periodic Status we advertise.
fn local_status(state: &AppState) -> Result<Message> {
    Ok(Message::Status {
        height: state.storage.head_height()?,
        best_hash: state.storage.head_hash()?,
        finalized_height: state.storage.finalized_height()?,
    })
}

/// Wait for the peer's Hello, rejecting incompatible protocol or chain ids.
async fn read_hello(rx: &mut sync::Inbound, state: &AppState) -> Result<Peer> {
    loop {
        match rx.recv().await {
            None => return Err(Error::Network("peer closed before handshake".to_string())),
            Some(Err(err)) => return Err(err),
            Some(Ok(Message::Hello {
                protocol_version,
                chain_id,
                best_height,
                best_hash,
                finalized_height,
            })) => {
                if protocol_version != PROTOCOL_VERSION {
                    return Err(Error::Network(format!(
                        "protocol version mismatch: peer {protocol_version}, local {PROTOCOL_VERSION}"
                    )));
                }
                if chain_id != state.config.node.chain_id {
                    return Err(Error::Network(format!(
                        "chain id mismatch: peer {chain_id}, local {}",
                        state.config.node.chain_id
                    )));
                }
                return Ok(Peer {
                    id: best_hash,
                    addr: "0.0.0.0:0".parse().expect("valid placeholder addr"),
                    best_height,
                    finalized_height,
                });
            }
            // Ignore any chatter that arrives before the handshake.
            Some(Ok(_)) => continue,
        }
    }
}

fn clamp(max: u32) -> u32 {
    max.clamp(1, MAX_BATCH)
}

/// Decrements the peer counter when a connection ends.
struct PeerGuard(AppState);

impl Drop for PeerGuard {
    fn drop(&mut self) {
        self.0.peer_count.fetch_sub(1, Ordering::AcqRel);
    }
}
