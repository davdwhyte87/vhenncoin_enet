//! Block data structures.
//!
//! Blocks are hash-linked: every [`BlockHeader`] carries the hash of its
//! parent, forming an append-only chain.

mod transaction;

pub use transaction::{
    OutPoint, RegistrationPayload, Transaction, TransactionType, TxInput, TxOutput, Txid,
};

use serde::{Deserialize, Serialize};

use crate::consensus::ConsensusProof;
use crate::crypto::{self, Hash};

/// The fixed-size header of a [`Block`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub previous_hash: [u8; 32],
    pub transactions_root: [u8; 32],
    pub state_root: [u8; 32],
    pub timestamp: u64,
    pub validator_set_version: u64,
}

impl BlockHeader {
    /// Deterministic hash of the header, used as the block identifier.
    pub fn hash(&self) -> Hash {
        let mut buf = Vec::with_capacity(8 + 32 + 32 + 32 + 8 + 8);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.previous_hash);
        buf.extend_from_slice(&self.transactions_root);
        buf.extend_from_slice(&self.state_root);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.validator_set_version.to_le_bytes());
        crypto::sha256(&buf)
    }
}

/// A full block: header, body and the proof that seals it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub consensus_proof: ConsensusProof,
}

impl Block {
    /// The hash that identifies this block.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// The hash of the parent block.
    pub fn previous_hash(&self) -> Hash {
        self.header.previous_hash
    }

    /// Recompute the Merkle root of the block's transactions.
    ///
    /// This is what a validator compares against `header.transactions_root`.
    pub fn compute_transactions_root(&self) -> Hash {
        let leaves: Vec<Hash> = self.transactions.iter().map(|tx| tx.txid()).collect();
        crypto::merkle_root(&leaves)
    }
}
