//! The hard-coded genesis block.
//!
//! Genesis is special: it has no parent (`previous_hash == [0; 32]`) and holds a
//! single, fee-less [`TransactionType::Coinbase`] transaction. That first
//! transaction has no inputs (nothing to spend yet) and exactly one output that
//! mints the entire initial supply of **80,000,000 VHN** to the genesis
//! recipient.

use crate::block::{Block, BlockHeader, Transaction, TransactionType, TxOutput};
use crate::consensus::ConsensusProof;
use crate::crypto::{self, PublicKeyHash};

/// Base units per whole VHN coin (8 decimal places).
pub const COIN: u128 = 100_000_000;

/// Total initial supply, in base units: 80,000,000 VHN.
pub const INITIAL_SUPPLY: u128 = 80_000_000 * COIN;

/// Fixed timestamp of the genesis block (2024-01-01T00:00:00Z).
pub const GENESIS_TIMESTAMP: u64 = 1_704_067_200;

/// The genesis block precedes every validator set.
pub const GENESIS_VALIDATOR_SET_VERSION: u64 = 0;

/// Fallback owner of the genesis output, used when no public key is configured
/// for genesis. Derived deterministically so every node agrees on the same
/// initial UTXO. Note: there is no private key for this recipient, so coins
/// minted here would be unspendable.
pub fn genesis_recipient() -> PublicKeyHash {
    crypto::sha256(b"vhenncoin-enet:genesis-treasury")
}

/// The very first transaction: mints [`INITIAL_SUPPLY`] in one output to
/// `recipient`.
pub fn genesis_transaction(recipient: PublicKeyHash) -> Transaction {
    Transaction {
        version: 1,
        tx_type: TransactionType::Coinbase,
        inputs: Vec::new(),
        outputs: vec![TxOutput {
            asset_id: crypto::native_asset_id(),
            amount: INITIAL_SUPPLY,
            recipient,
        }],
        lock_time: 0,
        registration: None,
        vote: None,
        removal: None,
    }
}

/// The genesis block containing exactly one transaction and one output paying
/// `recipient`.
pub fn genesis_block(recipient: PublicKeyHash) -> Block {
    let transaction = genesis_transaction(recipient);

    let header = BlockHeader {
        height: 0,
        previous_hash: [0u8; 32],
        transactions_root: crypto::merkle_root(&[transaction.txid()]),
        state_root: [0u8; 32],
        timestamp: GENESIS_TIMESTAMP,
        validator_set_version: GENESIS_VALIDATOR_SET_VERSION,
    };

    Block {
        header,
        transactions: vec![transaction],
        consensus_proof: ConsensusProof::default(),
    }
}
