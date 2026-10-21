//! Chain download and catch-up.
//!
//! A node that is behind a peer downloads blocks, but it never trusts them:
//! each batch is stored first and then run through [`crate::chain`], which
//! validates the hash linkage, the transaction Merkle root, the consensus
//! proof, the individual transactions and the resulting state root before the
//! block is committed. Only blocks up to the peer's *finalised* height are
//! treated as the synchronization target, never merely the highest block the
//! peer claims to have.

use tokio::io::AsyncWrite;
use tokio::sync::mpsc::Receiver;

use crate::chain;
use crate::error::Result;
use crate::state::{AppState, NodePhase};

use super::framing::write_message;
use super::message::Message;
use super::peer::Peer;

/// Inbound messages read from a peer's connection.
pub type Inbound = Receiver<Result<Message>>;

/// Bring the local chain up to the peer's finalised height.
pub async fn sync_from_peer<W>(
    state: &AppState,
    writer: &mut W,
    rx: &mut Inbound,
    peer: &mut Peer,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    // Only one peer may drive chain download at a time.
    let _guard = state.sync_lock.lock().await;

    // First, replay anything already on disk (e.g. after a crash) so the head
    // reflects all downloaded blocks before we ask for more.
    chain::recover(&state.storage, state.consensus.as_ref())?;

    let mut local = state.storage.head_height()?;
    if local < peer.finalized_height {
        state.sync.set_phase(NodePhase::Syncing);
    }
    state.sync.set_target(peer.finalized_height);

    let batch = state.config.network.sync_batch_size.max(1);

    loop {
        // Re-read the target each round: the peer may have advanced.
        let target = peer.finalized_height;
        if local >= target {
            break;
        }

        let max = (target - local).min(batch as u64) as u32;
        write_message(
            writer,
            &Message::GetBlocks {
                from_height: local + 1,
                max,
            },
        )
        .await?;

        let received = loop {
            match next_relevant_message(writer, rx, peer).await? {
                Some(Message::Blocks { blocks }) => break Some(blocks),
                Some(Message::NotFound { .. }) => break None,
                None => return Ok(()),
                Some(_) => continue,
            }
        };

        let blocks = match received {
            Some(blocks) if !blocks.is_empty() => blocks,
            _ => break,
        };

        let mut progressed = false;
        for block in blocks {
            let height = block.header.height;
            if height <= local {
                continue;
            }
            if height != local + 1 {
                // Gap: ask again for the missing height.
                break;
            }

            // Store the untrusted block, then validate and apply it. Storing
            // first means a crash mid-sync can replay from the committed head.
            state.storage.put_block(&block)?;
            match chain::apply_next(state) {
                Ok(true) => {
                    progressed = true;
                    local = state.storage.head_height()?;
                }
                Ok(false) => break,
                Err(err) => {
                    // The peer sent a block that failed validation. Drop it so
                    // it cannot wedge the node, and disconnect from the peer.
                    let _ = state.storage.remove_block(height);
                    return Err(err);
                }
            }
        }

        if !progressed {
            break;
        }
    }

    let head = state.storage.head_height()?;
    if head >= peer.finalized_height {
        // Verify the reconstructed state is complete before declaring ready.
        chain::recover(&state.storage, state.consensus.as_ref())?;
        if state.storage.head_height()? >= peer.finalized_height {
            state.sync.set_target(peer.finalized_height);
            state.sync.set_phase(NodePhase::Ready);
            tracing::info!(
                height = state.storage.head_height()?,
                finalized = peer.finalized_height,
                "chain synchronised; node is consensus-ready"
            );
        }
    }

    Ok(())
}

/// Read messages until one the caller cares about arrives. Liveness and status
/// chatter is handled transparently, and a peer disconnect yields `None`.
async fn next_relevant_message<W>(
    writer: &mut W,
    rx: &mut Inbound,
    peer: &mut Peer,
) -> Result<Option<Message>>
where
    W: AsyncWrite + Unpin,
{
    loop {
        let message = match rx.recv().await {
            None => return Ok(None),
            Some(Err(err)) => return Err(err),
            Some(Ok(message)) => message,
        };

        match message {
            Message::Ping { nonce } => {
                write_message(writer, &Message::Pong { nonce }).await?;
            }
            Message::Pong { .. } => {}
            Message::Status {
                height,
                finalized_height,
                ..
            } => {
                peer.best_height = height;
                if finalized_height > peer.finalized_height {
                    peer.finalized_height = finalized_height;
                }
            }
            relevant => return Ok(Some(relevant)),
        }
    }
}
