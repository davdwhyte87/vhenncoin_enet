//! Shared application state passed to the HTTP and P2P servers.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;
use tokio::sync::Mutex as AsyncMutex;

use crate::block::Transaction;
use crate::config::Config;
use crate::consensus::ConsensusEngine;
use crate::crypto::Hash;
use crate::storage::Storage;

/// Lifecycle phase of a node with respect to the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NodePhase {
    /// Starting up; the local chain may not yet reflect the network tip.
    Bootstrapping = 0,
    /// Actively downloading and applying blocks from a peer.
    Syncing = 1,
    /// Caught up to the latest finalised block and safe to participate.
    Ready = 2,
}

impl NodePhase {
    fn from_u8(value: u8) -> Self {
        match value {
            2 => NodePhase::Ready,
            1 => NodePhase::Syncing,
            _ => NodePhase::Bootstrapping,
        }
    }

    /// Stable lowercase label for APIs and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            NodePhase::Bootstrapping => "bootstrapping",
            NodePhase::Syncing => "syncing",
            NodePhase::Ready => "ready",
        }
    }
}

/// Lock-free progress information shared across the node.
#[derive(Default)]
pub struct SyncState {
    phase: AtomicU8,
    /// Finalised height we are currently syncing towards.
    target: AtomicU64,
}

impl SyncState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn phase(&self) -> NodePhase {
        NodePhase::from_u8(self.phase.load(Ordering::Acquire))
    }

    pub fn set_phase(&self, phase: NodePhase) {
        self.phase.store(phase as u8, Ordering::Release);
    }

    pub fn target(&self) -> u64 {
        self.target.load(Ordering::Acquire)
    }

    pub fn set_target(&self, height: u64) {
        self.target.store(height, Ordering::Release);
    }

    /// Whether the node has finished syncing and may act on consensus.
    pub fn is_ready(&self) -> bool {
        self.phase() == NodePhase::Ready
    }
}

pub use crate::mempool::Mempool;

/// Shared, cheaply-cloneable node state.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub storage: Arc<Storage>,
    pub consensus: Arc<dyn ConsensusEngine>,
    pub sync: Arc<SyncState>,
    /// Serialises block application so `head + 1` can never be applied twice.
    pub apply_lock: Arc<Mutex<()>>,
    /// Ensures only one peer drives chain download at a time.
    pub sync_lock: Arc<AsyncMutex<()>>,
    /// Number of currently connected peers.
    pub peer_count: Arc<AtomicUsize>,
    /// Mempool of pending transactions.
    pub mempool: Arc<Mempool>,
    /// This node's identity key pair, loaded from (or generated into) its
    /// keystore file. `None` when no keystore is configured.
    pub identity: Option<Arc<crate::crypto::Keypair>>,
    /// Transactions accepted by this node, re-broadcast to every connected
    /// peer so a governance request reaches the validators that must seal it.
    gossip: Arc<broadcast::Sender<Transaction>>,
    /// Transaction ids already accepted or relayed, so gossip terminates.
    seen_transactions: Arc<Mutex<HashSet<Hash>>>,
}

impl AppState {
    pub fn new(config: Config, storage: Storage, consensus: Arc<dyn ConsensusEngine>) -> Self {
        let (gossip, _) = broadcast::channel(256);
        Self {
            config: Arc::new(config),
            storage: Arc::new(storage),
            consensus,
            sync: Arc::new(SyncState::new()),
            apply_lock: Arc::new(Mutex::new(())),
            sync_lock: Arc::new(AsyncMutex::new(())),
            peer_count: Arc::new(AtomicUsize::new(0)),
            mempool: Arc::new(Mempool::new()),
            identity: None,
            gossip: Arc::new(gossip),
            seen_transactions: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Subscribe to transactions accepted by this node.
    pub fn subscribe_transactions(&self) -> broadcast::Receiver<Transaction> {
        self.gossip.subscribe()
    }

    /// Re-broadcast a transaction to every connected peer.
    pub fn broadcast_transaction(&self, tx: Transaction) {
        let _ = self.gossip.send(tx);
    }

    /// Whether this transaction has already been accepted or relayed.
    pub fn has_seen_transaction(&self, txid: &Hash) -> bool {
        self.seen_transactions
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .contains(txid)
    }

    /// Remember a transaction id so gossip terminates.
    pub fn mark_transaction_seen(&self, txid: Hash) {
        self.seen_transactions
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(txid);
    }

    /// Attach this node's identity key pair.
    pub fn with_identity(mut self, identity: crate::crypto::Keypair) -> Self {
        self.identity = Some(Arc::new(identity));
        self
    }

    /// Current committed (applied) chain head height.
    pub fn head_height(&self) -> crate::error::Result<u64> {
        self.storage.head_height()
    }

    /// Latest finalised block height under the BFT rules.
    pub fn finalized_height(&self) -> crate::error::Result<u64> {
        self.storage.finalized_height()
    }

    pub fn peers(&self) -> usize {
        self.peer_count.load(Ordering::Acquire)
    }
}
