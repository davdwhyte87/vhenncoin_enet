//! VhennCoin ENET - a hash-linked blockchain node.
//!
//! The crate is organised into small, focused modules:
//!
//! * [`config`]  - node configuration loading
//! * [`crypto`]  - hash / key primitives
//! * [`keystore`] - node identity seed phrases and local key files
//! * [`block`]   - block and UTXO transaction data structures
//! * [`genesis`] - the hard-coded genesis block and its first output
//! * [`consensus`] - consensus proof types and the validator-set engine
//! * [`registry`] - stake ledger and validator registry
//! * [`registration`] - automatic validator registration
//! * [`chain`]   - block validation, execution and crash-safe application
//! * [`storage`] - Redb-backed persistence
//! * [`api`]     - HTTP server for clients
//! * [`network`] - TCP peer-to-peer server and chain synchronisation

pub mod api;
pub mod block;
pub mod chain;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod error;
pub mod genesis;
pub mod keystore;
pub mod mempool;
pub mod mining;
pub mod network;
pub mod registration;
pub mod registry;
pub mod state;
pub mod storage;

pub use config::Config;
pub use error::{Error, Result};
pub use state::AppState;
pub use storage::Storage;
