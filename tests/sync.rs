//! End-to-end test: a fresh node boots, dials a bootnode, downloads the chain,
//! validates every block and only then becomes consensus-ready.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use vhenncoin_enet::block::{
    Block, BlockHeader, OutPoint, Transaction, TransactionType, TxInput, TxOutput,
};
use vhenncoin_enet::chain;
use vhenncoin_enet::config::Config;
use vhenncoin_enet::consensus::{ConsensusProof, ValidatorSetEngine};
use vhenncoin_enet::crypto::{self, Hash, Keypair};
use vhenncoin_enet::{network, AppState, Storage};

fn unique() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn base_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("vhn-sync-{}-{}-{}", std::process::id(), tag, unique()))
}

fn node_config(tag: &str, public_key_hex: &str, bootnodes: Vec<String>) -> Config {
    let dir = base_dir(tag);
    let mut config = Config::default();
    config.node.name = format!("test-{tag}");
    config.node.chain_id = 4242;
    config.node.data_dir = dir.clone();
    config.storage.path = dir.join(format!("{tag}.redb"));
    config.network.listen_addr = "127.0.0.1:0".parse().unwrap();
    config.network.bootnodes = bootnodes;
    config.consensus.validator_set_version = 1;
    config.consensus.validators = vec![public_key_hex.to_string()];
    config.genesis.public_key = Some(public_key_hex.to_string());
    std::fs::create_dir_all(&config.node.data_dir).unwrap();
    config
}

fn spawn_node(config: Config) -> AppState {
    let storage = Storage::open(&config.storage.path).unwrap();
    let governance = config.governance.to_governance().unwrap();
    let validators: Vec<_> =
        vhenncoin_enet::consensus::parse_validator_keys(&config.consensus.validators)
            .unwrap()
            .into_values()
            .collect();
    storage
        .bootstrap_genesis(
            config.genesis_recipient().unwrap(),
            &governance,
            &validators,
            config.consensus.validator_set_version,
        )
        .unwrap();
    let engine = Arc::new(ValidatorSetEngine::from_config(&config.consensus).unwrap());
    AppState::new(config, storage, engine)
}

fn transfer(keypair: &Keypair, outpoint: OutPoint, amount: u128, recipient: [u8; 32]) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        tx_type: TransactionType::Transfer,
        inputs: vec![TxInput {
            previous_output: outpoint,
            signature: Vec::new(),
            public_key: keypair
                .public_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        }],
        outputs: vec![TxOutput {
            asset_id: crypto::native_asset_id(),
            amount,
            recipient,
        }],
        lock_time: 0,
        registration: None,
        vote: None,
        removal: None,
    };
    let message = tx.signing_message(0);
    tx.inputs[0].signature = keypair.sign(&message);
    tx
}

/// Build, seal and apply one block onto `state`, returning its output out-point.
fn extend_chain(state: &AppState, keypair: &Keypair, spend: OutPoint) -> OutPoint {
    let amount = vhenncoin_enet::genesis::INITIAL_SUPPLY;
    let tx = transfer(keypair, spend, amount, keypair.address());
    let txid = tx.txid();

    let storage = &state.storage;
    let head = storage.head_height().unwrap();
    let head_hash = storage.head_hash().unwrap();
    let mut chain_state = chain::load_chain_state(storage).unwrap();

    let leaves: Vec<Hash> = vec![tx.txid()];
    let header = BlockHeader {
        height: head + 1,
        previous_hash: head_hash,
        transactions_root: crypto::merkle_root(&leaves),
        state_root: [0u8; 32],
        timestamp: 1_700_000_000 + head,
        validator_set_version: state.config.consensus.validator_set_version,
    };
    let mut block = Block {
        header,
        transactions: vec![tx],
        consensus_proof: ConsensusProof::default(),
    };
    chain::execute_block(&mut chain_state, &block).unwrap();
    block.header.state_root = chain::state_root(&chain_state.utxos);

    let hash = block.header.hash();
    block.consensus_proof = ConsensusProof {
        height: block.header.height,
        round: 0,
        validator: keypair.address(),
        signature: keypair.sign(&hash),
        bitmap: vec![0b1],
        attestations: Vec::new(),
    };

    chain::apply_block(storage, state.consensus.as_ref(), &block).unwrap();
    OutPoint {
        txid,
        output_index: 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_node_syncs_validates_and_becomes_ready() {
    let keypair = Keypair::generate();
    let public_key_hex = hex::encode(keypair.public_key().to_encoded_point(true).as_bytes());

    // Node A holds a chain of three blocks.
    let state_a = spawn_node(node_config("a", &public_key_hex, Vec::new()));

    let genesis_tx = vhenncoin_enet::genesis::genesis_transaction(keypair.address());
    let mut outpoint = OutPoint {
        txid: genesis_tx.txid(),
        output_index: 0,
    };
    for _ in 0..3 {
        outpoint = extend_chain(&state_a, &keypair, outpoint);
    }
    let target = state_a.storage.head_height().unwrap();
    assert_eq!(target, 3);

    let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = listener_a.local_addr().unwrap();
    tokio::spawn(network::serve(listener_a, state_a.clone()));

    // Node B starts empty and only knows A as a bootnode.
    let state_b = spawn_node(node_config("b", &public_key_hex, vec![addr_a.to_string()]));
    assert_eq!(state_b.storage.head_height().unwrap(), 0);

    let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    tokio::spawn(network::serve(listener_b, state_b.clone()));

    // Wait for B to download, validate and apply every block.
    let mut synced = false;
    for _ in 0..300 {
        if state_b.storage.head_height().unwrap() >= target {
            synced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(synced, "node B failed to sync within the timeout");
    assert_eq!(state_b.storage.head_height().unwrap(), target);
    assert_eq!(state_b.storage.finalized_height().unwrap(), target);
    assert!(state_b.sync.is_ready(), "node B never became consensus-ready");

    // B independently reconstructed the same UTXO state as A.
    assert_eq!(
        state_b.storage.utxo_count().unwrap(),
        state_a.storage.utxo_count().unwrap()
    );
    assert_eq!(
        state_b.storage.head_hash().unwrap(),
        state_a.storage.head_hash().unwrap()
    );
}
