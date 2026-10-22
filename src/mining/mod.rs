//! Block production from mempool.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::interval;

use crate::block::{Block, BlockHeader, Transaction};
use crate::chain::{self, execute_block, state_root};
use crate::consensus::ConsensusProof;
use crate::crypto::{self, Keypair};
use crate::error::Result;
use crate::state::AppState;

pub fn load_keypairs(config: &crate::config::ConsensusConfig) -> Vec<Keypair> {
    let mut keypairs = Vec::new();
    for raw in &config.validator_private_keys {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if let Ok(bytes) = hex::decode(raw) {
            if let Ok(kp) = Keypair::from_bytes(&bytes) {
                keypairs.push(kp);
            }
        }
    }
    keypairs
}

pub async fn start_block_producer(state: Arc<AppState>) {
    let state = state;
    _start_block_producer_internal(state).await;
}

async fn _start_block_producer_internal(state: Arc<AppState>) {
    let block_time = state.config.consensus.block_time_secs;
    let mut ticker = interval(Duration::from_secs(block_time.max(1)));

    let state_clone = state.clone();
    tokio::spawn(async move {
        loop {
            ticker.tick().await;
            if let Err(e) = produce_block(state_clone.clone()).await {
                tracing::warn!("Failed to produce block: {}", e);
            }
        }
    });
}

async fn produce_block(state: Arc<AppState>) -> Result<()> {
    let keypairs = load_keypairs(&state.config.consensus);
    if keypairs.is_empty() {
        return Ok(());
    }

    let storage = &state.storage;
    let head = storage.head_height()?;
    let head_hash = storage.head_hash()?;
    let height = head + 1;

    // In a permissioned set only the designated proposer may seal the block.
    let Some(expected) = state.consensus.select_proposer(&head_hash, height) else {
        return Ok(());
    };
    let Some(keypair) = keypairs.iter().find(|kp| kp.address() == expected) else {
        return Ok(());
    };

    let set_version = storage.validator_set_version()?;

    let pending = state.mempool.drain_transactions(1000);
    if pending.is_empty() {
        return Ok(());
    }

    let mut state_final = chain::load_chain_state(storage)?;

    let mut block_txs: Vec<Transaction> = Vec::new();
    for tx in pending {
        let mut test_state = state_final.clone();
        if execute_block(&mut test_state, &Block {
            header: BlockHeader {
                height,
                previous_hash: head_hash,
                transactions_root: [0; 32],
                state_root: [0; 32],
                timestamp: 0,
                validator_set_version: set_version,
            },
            transactions: vec![tx.clone()],
            consensus_proof: ConsensusProof::default(),
        })
        .is_ok()
        {
            if execute_block(&mut state_final, &Block {
                header: BlockHeader {
                    height,
                    previous_hash: head_hash,
                    transactions_root: [0; 32],
                    state_root: [0; 32],
                    timestamp: 0,
                    validator_set_version: set_version,
                },
                transactions: vec![tx.clone()],
                consensus_proof: ConsensusProof::default(),
            })
            .is_ok()
            {
                block_txs.push(tx);
            }
        }
    }

    if block_txs.is_empty() {
        return Ok(());
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let header = BlockHeader {
        height,
        previous_hash: head_hash,
        transactions_root: crypto::merkle_root(
            &block_txs.iter().map(|t| t.txid()).collect::<Vec<_>>(),
        ),
        state_root: state_root(&state_final.utxos),
        timestamp,
        validator_set_version: set_version,
    };

    let hash = header.hash();
    let proof = ConsensusProof {
        height: header.height,
        round: 0,
        validator: keypair.address(),
        signature: keypair.sign(&hash),
        bitmap: Vec::new(),
        attestations: Vec::new(),
    };

    let block = Block {
        header,
        transactions: block_txs,
        consensus_proof: proof,
    };

    chain::apply_block(storage, state.consensus.as_ref(), &block)?;
    tracing::info!("Produced block at height {}", block.header.height);
    Ok(())
}