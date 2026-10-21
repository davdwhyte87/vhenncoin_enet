//! Automatic validator registration.
//!
//! Once an administrator has funded this node's stake wallet (at least
//! [`MIN_STAKE`](crate::consensus::MIN_STAKE) paid into the system wallet and
//! confirmed in a block) and set `node.stake_address` in the node config, the
//! node registers itself: it builds a
//! [`ValidatorRegistration`](crate::block::TransactionType::ValidatorRegistration)
//! transaction carrying its identity public key and stake wallet address,
//! signs it with the identity key, and submits it to its own mempool. The
//! network re-checks the stake when the block is executed, so an unsigned,
//! unfunded or duplicate registration is rejected by every node.
//!
//! The config file is re-read on every tick so the administrator can add
//! `stake_address` while the node is running - no restart required.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::interval;

use crate::block::{RegistrationPayload, Transaction, TransactionType};
use crate::config::Config;
use crate::consensus::MIN_STAKE;
use crate::crypto::Keypair;
use crate::state::AppState;

/// How often the node checks whether it should (re-)register.
const CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Spawn the background registration task. No-op when the node has no
/// identity key pair.
pub fn start(state: Arc<AppState>) {
    if state.identity.is_none() {
        tracing::info!("no node identity configured; validator registration disabled");
        return;
    }
    tokio::spawn(async move {
        let mut ticker = interval(CHECK_INTERVAL);
        // The first tick completes immediately; give the chain a moment so the
        // first check happens against a real head.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if let Err(err) = check_once(&state).await {
                tracing::debug!("validator registration check: {err}");
            }
        }
    });
}

async fn check_once(state: &AppState) -> Result<(), String> {
    let identity = state
        .identity
        .as_ref()
        .ok_or("no identity key pair")?
        .clone();

    // The admin may add `stake_address` to the config at any time; re-read it.
    let stake_address = fresh_stake_address(&state.config)?;
    let Some(stake_address) = stake_address else {
        return Err("node.stake_address not set yet".to_string());
    };

    let node_public_key = identity
        .public_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let node_hex = hex::encode(&node_public_key);

    let chain_state = crate::chain::load_chain_state(&state.storage)
        .map_err(|err| format!("failed to load chain state: {err}"))?;

    if chain_state.registry.contains_key(&node_hex) {
        return Err(format!("node {node_hex} already registered"));
    }

    let staked = chain_state
        .stakes
        .get(&stake_address)
        .copied()
        .unwrap_or(0);
    if staked < MIN_STAKE {
        return Err(format!(
            "stake wallet {} has staked {} which is below the minimum {MIN_STAKE}",
            hex::encode(stake_address),
            staked
        ));
    }

    let tx = build_registration(&identity, stake_address);
    let txid = tx.txid();

    // Skip if an identical registration is already waiting in the mempool.
    let pending = state.mempool.get_pending_transactions(1000);
    if pending.iter().any(|candidate| candidate.txid() == txid) {
        return Err(format!(
            "registration {} already pending in the mempool",
            hex::encode(txid)
        ));
    }

    // Validate locally first so a bad request never enters the mempool.
    crate::chain::validate_transaction(&chain_state, &tx)
        .map_err(|err| format!("registration would be rejected: {err}"))?;

    state
        .mempool
        .add_transaction(tx)
        .map_err(|err| format!("failed to enqueue registration: {err}"))?;

    tracing::info!(
        node = %node_hex,
        stake_wallet = %hex::encode(stake_address),
        stake_amount = staked,
        txid = %hex::encode(txid),
        "validator registration submitted"
    );
    Ok(())
}

/// Re-read the config file (if it still exists) and return the configured
/// stake address, falling back to the in-memory config.
fn fresh_stake_address(config: &Config) -> Result<Option<[u8; 32]>, String> {
    let path = std::env::var("VHENNCOIN_CONFIG").unwrap_or_else(|_| "./config.toml".to_string());
    let reloaded = Config::load_from(&path).map_err(|err| err.to_string())?;
    let effective = if reloaded.node.stake_address.is_some() {
        &reloaded.node
    } else {
        &config.node
    };
    effective
        .stake_address_bytes()
        .map_err(|err| err.to_string())
}

/// Build and sign a validator-registration transaction.
fn build_registration(identity: &Keypair, stake_address: [u8; 32]) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        tx_type: TransactionType::ValidatorRegistration,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        registration: Some(RegistrationPayload {
            node_public_key: identity
                .public_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            stake_address,
            signature: Vec::new(),
        }),
    };
    let txid = tx.txid();
    tx.registration
        .as_mut()
        .expect("payload present")
        .signature = identity.sign(&txid);
    tx
}
