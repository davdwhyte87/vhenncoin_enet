//! Peer identity and bookkeeping types.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::crypto::Hash;

/// Stable identifier for a peer (typically the peer's public key hash).
pub type PeerId = Hash;

/// Known information about a connected or discovered peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub id: PeerId,
    pub addr: SocketAddr,
    /// Highest block the peer advertises, applied or not.
    pub best_height: u64,
    /// Highest block the peer considers final.
    pub finalized_height: u64,
}
