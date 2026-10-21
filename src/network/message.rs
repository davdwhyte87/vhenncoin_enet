//! P2P wire messages exchanged between nodes.

use serde::{Deserialize, Serialize};

use crate::block::{Block, BlockHeader, Transaction};
use crate::crypto::Hash;

/// Protocol version advertised during the handshake.
pub const PROTOCOL_VERSION: u32 = 1;

/// Messages exchanged over the peer-to-peer TCP connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Opening handshake sent by each side.
    Hello {
        protocol_version: u32,
        chain_id: u64,
        /// Highest block the sender has, applied or not.
        best_height: u64,
        best_hash: Hash,
        /// Highest block the sender considers final under BFT rules.
        finalized_height: u64,
    },
    /// Liveness probe.
    Ping { nonce: u64 },
    /// Response to [`Message::Ping`].
    Pong { nonce: u64 },
    /// Request a batch of headers.
    GetHeaders { from_height: u64, max: u32 },
    /// Response carrying requested headers.
    Headers { headers: Vec<BlockHeader> },
    /// Request a full block by hash.
    GetBlock { hash: Hash },
    /// A full block.
    Block(Block),
    /// Request a contiguous batch of full blocks.
    GetBlocks { from_height: u64, max: u32 },
    /// Response carrying a batch of full blocks, starting at `from_height`.
    Blocks { blocks: Vec<Block> },
    /// A requested block or hash is unknown to the sender.
    NotFound { hash: Hash },
    /// An unconfirmed transaction to gossip.
    NewTransaction(Transaction),
    /// Periodic chain-status update.
    Status {
        height: u64,
        best_hash: Hash,
        finalized_height: u64,
    },
}
