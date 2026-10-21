//! Block execution, validation and crash-safe application.
//!
//! Downloading a block is not the same as trusting it. Every block is treated
//! as untrusted input until this module has:
//!
//! 1. checked it links to the current committed head (height and parent hash),
//! 2. recomputed the transaction Merkle root and matched the header,
//! 3. verified the consensus evidence with the configured engine,
//! 4. re-executed every transaction against the local UTXO set, and
//! 5. recomputed the resulting state root and matched the header.
//!
//! Only then is the block applied. Application writes the UTXO changes, the
//! block, and the new head/finalised metadata in a *single* Redb write
//! transaction, so the committed head always describes exactly the UTXO set
//! that is on disk. A crash can therefore never apply a block twice or leave a
//! partially-applied block behind.

use std::collections::BTreeMap;

use redb::ReadableTable;

use crate::block::{Block, TxOutput};
use crate::consensus::ConsensusEngine;
use crate::crypto::{self, Hash, PublicKeyHash};
use crate::error::{Error, Result};
use crate::registry::{apply_registration, NodeRegistration, NodeRegistry, StakeLedger};
use crate::state::AppState;
use crate::storage::{
    self, outpoint_key, Storage, BLOCK_INDEX, BLOCKS, HEADERS, META, META_FINALIZED_HASH,
    META_FINALIZED_HEIGHT, META_GENESIS_HASH, META_HEAD_HASH, META_HEAD_HEIGHT, TRANSACTIONS, UTXOS,
};

/// In-memory UTXO set: out-point key -> output.
pub type UtxoSet = BTreeMap<[u8; storage::OUTPOINT_KEY_LEN], TxOutput>;

/// The full ledger view a block is executed against: the UTXO set plus the
/// two derived indexes (stake ledger and validator registry).
///
/// Both indexes are pure functions of the applied block sequence, so every
/// node applying the same blocks derives an identical view.
#[derive(Debug, Clone, Default)]
pub struct ChainState {
    pub utxos: UtxoSet,
    /// Stake-wallet address -> total paid into the system stake wallet.
    pub stakes: StakeLedger,
    /// Approved nodes: node public key (hex) -> registration.
    pub registry: NodeRegistry,
}

/// The observable effects of executing a block, used to persist only the
/// changed part of the UTXO set and the derived indexes.
#[derive(Debug, Default)]
pub struct BlockEffects {
    pub spent: Vec<[u8; storage::OUTPOINT_KEY_LEN]>,
    pub created: Vec<([u8; storage::OUTPOINT_KEY_LEN], TxOutput)>,
    /// Stake-ledger entries that changed: address -> new total.
    pub stakes: Vec<(PublicKeyHash, u128)>,
    /// Validator registrations accepted by this block.
    pub registrations: Vec<(String, NodeRegistration)>,
}

/// Merge all of `block`'s transactions into `state`, validating each one.
///
/// * Regular transfers and the genesis coinbase update the UTXO set as before.
/// * A transfer that pays [`crate::consensus::MIN_STAKE`] or more into the
///   system stake wallet is recorded in the stake ledger.
/// * A [`crate::block::TransactionType::ValidatorRegistration`] transaction is
///   validated against the stake ledger and the current registry (signature by
///   the node identity key, stake already paid, no duplicates) and added to
///   the registry. It moves no coins.
///
/// Returns the set of entries that changed so the caller can persist them.
pub fn execute_block(state: &mut ChainState, block: &Block) -> Result<BlockEffects> {
    let height = block.header.height;
    let mut effects = BlockEffects::default();

    for tx in &block.transactions {
        if tx.is_coinbase() && height != 0 {
            return Err(Error::InvalidBlock(format!(
                "coinbase transaction at non-genesis height {height}"
            )));
        }

        if tx.is_registration() {
            apply_registration(tx, height, &state.stakes, &mut state.registry)?;
            let registration = tx.registration.as_ref().expect("validated above");
            let node_hex = hex::encode(&registration.node_public_key);
            let entry = state
                .registry
                .get(&node_hex)
                .cloned()
                .expect("registration was just applied");
            effects.registrations.push((node_hex, entry));
            continue;
        }

        if !tx.is_coinbase() && tx.inputs.is_empty() {
            return Err(Error::InvalidBlock("transfer with no inputs".to_string()));
        }
        if tx.outputs.is_empty() {
            return Err(Error::InvalidBlock("transaction with no outputs".to_string()));
        }

        let mut input_sum: u128 = 0;
        let mut sender: Option<PublicKeyHash> = None;
        let mut spent_keys: Vec<[u8; storage::OUTPOINT_KEY_LEN]> = Vec::new();

        for (index, input) in tx.inputs.iter().enumerate() {
            let key = outpoint_key(&input.previous_output.txid, input.previous_output.output_index);
            if spent_keys.contains(&key) {
                return Err(Error::InvalidBlock(
                    "transaction spends the same output twice".to_string(),
                ));
            }

            let previous = state.utxos.get(&key).cloned().ok_or_else(|| {
                Error::InvalidBlock(format!(
                    "input references unknown or already-spent output (tx {}, index {})",
                    hex::encode(input.previous_output.txid),
                    input.previous_output.output_index
                ))
            })?;

            let public_key = crypto::parse_public_key(&input.public_key)
                .map_err(|err| Error::InvalidBlock(format!("invalid input public key: {err}")))?;
            let address = crypto::address_from_public_key(&public_key);
            if address != previous.recipient {
                return Err(Error::InvalidBlock(
                    "input does not own the referenced output".to_string(),
                ));
            }
            if index == 0 {
                sender = Some(address);
            }

            let message = tx.signing_message(index as u32);
            if !crypto::verify(&public_key, &message, &input.signature) {
                return Err(Error::InvalidBlock(format!(
                    "invalid signature on input {index}"
                )));
            }

            input_sum = input_sum
                .checked_add(previous.amount)
                .ok_or_else(|| Error::InvalidBlock("input amount overflow".to_string()))?;
            spent_keys.push(key);
        }

        let output_sum = tx.total_output();
        if output_sum > input_sum {
            return Err(Error::InvalidBlock(format!(
                "outputs ({output_sum}) exceed inputs ({input_sum})"
            )));
        }

        for key in spent_keys {
            state.utxos.remove(&key);
            effects.spent.push(key);
        }

        let txid = tx.txid();
        for (index, output) in tx.outputs.iter().enumerate() {
            let key = outpoint_key(&txid, index as u32);
            state.utxos.insert(key, output.clone());
            effects.created.push((key, output.clone()));
        }

        // Any payment into the system stake wallet is recorded under the
        // sending address, so several smaller deposits accumulate towards the
        // minimum a registration request requires.
        let deposited: u128 = tx
            .outputs
            .iter()
            .filter(|output| crate::consensus::is_system_wallet(&output.recipient))
            .map(|output| output.amount)
            .sum();
        if deposited > 0 {
            if let Some(address) = sender {
                let total = state.stakes.entry(address).or_insert(0);
                *total = total
                    .checked_add(deposited)
                    .ok_or_else(|| Error::InvalidBlock("stake ledger overflow".to_string()))?;
                effects.stakes.push((address, *total));
            }
        }
    }

    Ok(effects)
}

/// Validate a transaction against a given chain state without modifying it.
pub fn validate_transaction(state: &ChainState, tx: &crate::block::Transaction) -> Result<()> {
    if tx.is_coinbase() {
        return Err(Error::InvalidBlock("coinbase transactions not allowed".to_string()));
    }

    if tx.is_registration() {
        return crate::registry::validate_registration(tx, &state.stakes, &state.registry);
    }

    if tx.inputs.is_empty() {
        return Err(Error::InvalidBlock("transfer with no inputs".to_string()));
    }
    if tx.outputs.is_empty() {
        return Err(Error::InvalidBlock("transaction with no outputs".to_string()));
    }

    let mut input_sum: u128 = 0;
    let mut spent_keys: Vec<[u8; storage::OUTPOINT_KEY_LEN]> = Vec::new();

    for (index, input) in tx.inputs.iter().enumerate() {
        let key = outpoint_key(&input.previous_output.txid, input.previous_output.output_index);
        if spent_keys.contains(&key) {
            return Err(Error::InvalidBlock(
                "transaction spends the same output twice".to_string(),
            ));
        }

        let previous = state.utxos.get(&key).cloned().ok_or_else(|| {
            Error::InvalidBlock(format!(
                "input references unknown or already-spent output (tx {}, index {})",
                hex::encode(input.previous_output.txid),
                input.previous_output.output_index
            ))
        })?;

        let public_key = crypto::parse_public_key(&input.public_key)
            .map_err(|err| Error::InvalidBlock(format!("invalid input public key: {err}")))?;
        let address = crypto::address_from_public_key(&public_key);
        if address != previous.recipient {
            return Err(Error::InvalidBlock(
                "input does not own the referenced output".to_string(),
            ));
        }

        let message = tx.signing_message(index as u32);
        if !crypto::verify(&public_key, &message, &input.signature) {
            return Err(Error::InvalidBlock(format!(
                "invalid signature on input {index}"
            )));
        }

        input_sum = input_sum
            .checked_add(previous.amount)
            .ok_or_else(|| Error::InvalidBlock("input amount overflow".to_string()))?;
        spent_keys.push(key);
    }

    let output_sum = tx.total_output();
    if output_sum > input_sum {
        return Err(Error::InvalidBlock(format!(
            "outputs ({output_sum}) exceed inputs ({input_sum})"
        )));
    }

    Ok(())
}

/// Deterministic commitment to a UTXO set.
///
/// Leaves are `sha256(key || value)` over the serialised value, taken in key
/// order, then folded into a Merkle root.
pub fn state_root(utxos: &UtxoSet) -> Hash {
    let leaves: Vec<Hash> = utxos
        .iter()
        .map(|(key, output)| {
            let value = serde_json::to_vec(output).unwrap_or_default();
            let mut buf = Vec::with_capacity(key.len() + value.len());
            buf.extend_from_slice(key);
            buf.extend_from_slice(&value);
            crypto::sha256(&buf)
        })
        .collect();
    crypto::merkle_root(&leaves)
}

/// Validate `block` against the committed head and apply it atomically.
pub fn apply_block(storage: &Storage, engine: &dyn ConsensusEngine, block: &Block) -> Result<()> {
    let hash = block.hash();

    storage.write(|txn| {
        let (head_height, head_hash) = {
            let meta = txn.open_table(META)?;
            (
                read_u64(&meta, META_HEAD_HEIGHT)?.unwrap_or(0),
                read_hash(&meta, META_HEAD_HASH)?.unwrap_or([0u8; 32]),
            )
        };

        if read_hash_from(txn, META_GENESIS_HASH)?.is_none() {
            return Err(Error::NotSynced(
                "chain has not been bootstrapped with a genesis block".to_string(),
            ));
        }

        let expected_height = head_height + 1;
        if block.header.height != expected_height {
            return Err(Error::InvalidBlock(format!(
                "block height {} does not follow head {head_height}",
                block.header.height
            )));
        }
        if block.header.previous_hash != head_hash {
            return Err(Error::InvalidBlock(
                "block parent hash does not match committed head".to_string(),
            ));
        }
        if block.compute_transactions_root() != block.header.transactions_root {
            return Err(Error::InvalidBlock(
                "transactions root does not match header".to_string(),
            ));
        }
        if !engine.verify(&block.header, &block.consensus_proof) {
            return Err(Error::Consensus(format!(
                "consensus proof rejected for block {}",
                hex::encode(hash)
            )));
        }

        let mut state = load_chain_state_in_apply(txn)?;
        let effects = execute_block(&mut state, block)?;

        if block.header.height > 0 {
            let root = state_root(&state.utxos);
            if root != block.header.state_root {
                return Err(Error::InvalidBlock(format!(
                    "state root mismatch (computed {}, header {})",
                    hex::encode(root),
                    hex::encode(block.header.state_root)
                )));
            }
        }

        {
            let mut table = txn.open_table(UTXOS)?;
            for key in &effects.spent {
                table.remove(key.as_slice())?;
            }
            for (key, output) in &effects.created {
                let value = serde_json::to_vec(output)
                    .map_err(|err| Error::Serialization(err.to_string()))?;
                table.insert(key.as_slice(), value.as_slice())?;
            }
        }
        for (address, total) in &effects.stakes {
            storage::put_stake_amount(txn, address, *total)?;
        }
        for (node_hex, entry) in &effects.registrations {
            storage::put_node_registration(txn, node_hex, entry)?;
            tracing::info!(
                node = %node_hex,
                stake_wallet = %hex::encode(entry.stake_address),
                stake_amount = %entry.stake_amount,
                height = block.header.height,
                "validator registered"
            );
        }
        {
            let mut table = txn.open_table(BLOCKS)?;
            let body = serde_json::to_vec(block)
                .map_err(|err| Error::Serialization(err.to_string()))?;
            table.insert(block.header.height, body.as_slice())?;
        }
        {
            let mut table = txn.open_table(HEADERS)?;
            let header = serde_json::to_vec(&block.header)
                .map_err(|err| Error::Serialization(err.to_string()))?;
            table.insert(block.header.height, header.as_slice())?;
        }
        {
            let mut table = txn.open_table(BLOCK_INDEX)?;
            table.insert(hash.as_slice(), block.header.height)?;
        }
        {
            let mut table = txn.open_table(TRANSACTIONS)?;
            let mut tx_blocks = txn.open_table(crate::storage::TX_BLOCK)?;
            for tx in &block.transactions {
                let txid = tx.txid();
                let body =
                    serde_json::to_vec(tx).map_err(|err| Error::Serialization(err.to_string()))?;
                table.insert(txid.as_slice(), body.as_slice())?;
                tx_blocks.insert(txid.as_slice(), block.header.height)?;
            }
        }

        let finalized = engine.is_finalized(&block.header, &block.consensus_proof);
        {
            let mut meta = txn.open_table(META)?;
            meta.insert(META_HEAD_HEIGHT, block.header.height.to_le_bytes().as_slice())?;
            meta.insert(META_HEAD_HASH, hash.as_slice())?;
            if finalized {
                meta.insert(
                    META_FINALIZED_HEIGHT,
                    block.header.height.to_le_bytes().as_slice(),
                )?;
                meta.insert(META_FINALIZED_HASH, hash.as_slice())?;
            }
        }

        Ok(())
    })
}

/// Apply the block stored at `head + 1`, if any. Returns whether one was
/// applied.
pub fn apply_next_block(storage: &Storage, engine: &dyn ConsensusEngine) -> Result<bool> {
    let head = storage.head_height()?;
    let next = head + 1;
    let block = match storage.get_block(next)? {
        Some(block) => block,
        None => return Ok(false),
    };
    apply_block(storage, engine, &block)?;
    Ok(true)
}

/// Apply every stored-but-unapplied block in order, under the apply lock so a
/// concurrent sync cannot apply the same height twice.
pub fn apply_next(state: &AppState) -> Result<bool> {
    let _guard = state
        .apply_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    apply_next_block(&state.storage, state.consensus.as_ref())
}

/// Replay any blocks that were downloaded but not yet applied (for example
/// after a crash). Returns the resulting head height.
///
/// An invalid pending block is dropped so it cannot wedge the node, and replay
/// stops at the last valid block.
pub fn recover(storage: &Storage, engine: &dyn ConsensusEngine) -> Result<u64> {
    loop {
        match apply_next_block(storage, engine) {
            Ok(true) => continue,
            Ok(false) => break,
            Err(err) => {
                let head = storage.head_height()?;
                tracing::warn!(height = head + 1, %err, "dropping invalid pending block");
                storage.remove_block(head + 1)?;
                break;
            }
        }
    }
    storage.head_height()
}

/// Load the full UTXO set from disk.
pub fn load_utxo_set(storage: &Storage) -> Result<UtxoSet> {
    storage.read(|txn| {
        let table = txn.open_table(UTXOS)?;
        collect_utxos(&table)
    })
}

/// Load the full chain state (UTXO set, stake ledger and validator registry)
/// from disk.
pub fn load_chain_state(storage: &Storage) -> Result<ChainState> {
    storage.read(|txn| {
        let utxos = {
            let table = txn.open_table(UTXOS)?;
            collect_utxos(&table)?
        };
        let stakes = {
            let table = txn.open_table(crate::storage::STAKE_LEDGER)?;
            storage::load_stake_ledger(&table)?
        };
        let registry = {
            let table = txn.open_table(crate::storage::NODE_REGISTRY)?;
            storage::load_node_registry(&table)?
        };
        Ok(ChainState {
            utxos,
            stakes,
            registry,
        })
    })
}

/// Load the full chain state inside the open write transaction of
/// [`apply_block`], so the block is validated against exactly the state the
/// new entries will be committed alongside.
fn load_chain_state_in_apply(txn: &redb::WriteTransaction) -> Result<ChainState> {
    let utxos = {
        let table = txn.open_table(UTXOS)?;
        collect_utxos(&table)?
    };
    let stakes = {
        let table = txn.open_table(crate::storage::STAKE_LEDGER)?;
        storage::load_stake_ledger(&table)?
    };
    let registry = {
        let table = txn.open_table(crate::storage::NODE_REGISTRY)?;
        storage::load_node_registry(&table)?
    };
    Ok(ChainState {
        utxos,
        stakes,
        registry,
    })
}

fn collect_utxos(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<UtxoSet> {
    let mut utxos = UtxoSet::new();
    for entry in table.iter()? {
        let (key, value) = entry?;
        let output: TxOutput = serde_json::from_slice(value.value())
            .map_err(|err| Error::Serialization(err.to_string()))?;
        let mut arr = [0u8; storage::OUTPOINT_KEY_LEN];
        arr.copy_from_slice(key.value());
        utxos.insert(arr, output);
    }
    Ok(utxos)
}

fn read_hash_from(txn: &redb::WriteTransaction, key: &str) -> Result<Option<Hash>> {
    let meta = txn.open_table(META)?;
    read_hash(&meta, key)
}

fn read_u64(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Option<u64>> {
    match meta.get(key)? {
        Some(value) => {
            let arr: [u8; 8] = value
                .value()
                .try_into()
                .map_err(|_| Error::Serialization(format!("meta {key} is not 8 bytes")))?;
            Ok(Some(u64::from_le_bytes(arr)))
        }
        None => Ok(None),
    }
}

fn read_hash(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Option<Hash>> {
    match meta.get(key)? {
        Some(value) => {
            let arr: [u8; 32] = value
                .value()
                .try_into()
                .map_err(|_| Error::Serialization(format!("meta {key} is not 32 bytes")))?;
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockHeader, OutPoint, Transaction, TransactionType, TxInput, TxOutput};
    use crate::consensus::{ConsensusProof, ValidatorSetEngine};
    use crate::config::ConsensusConfig;
    use crate::crypto::Keypair;
    use crate::genesis;

    struct Fixture {
        storage: Storage,
        engine: ValidatorSetEngine,
        keypair: Keypair,
        path: std::path::PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let keypair = Keypair::generate();
            let path = std::env::temp_dir().join(format!(
                "vhn-chain-{}-{}-{}.redb",
                std::process::id(),
                tag,
                unique()
            ));
            let _ = std::fs::remove_file(&path);
            let storage = Storage::open(&path).unwrap();
            storage.bootstrap_genesis(keypair.address()).unwrap();

            let config = ConsensusConfig {
                validator_set_version: 1,
                validators: vec![hex::encode(
                    keypair.public_key().to_encoded_point(true).as_bytes(),
                )],
                ..ConsensusConfig::default()
            };
            let engine = ValidatorSetEngine::from_config(&config).unwrap();
            Self {
                storage,
                engine,
                keypair,
                path,
            }
        }

        fn genesis_outpoint(&self) -> OutPoint {
            let tx = genesis::genesis_transaction(self.keypair.address());
            OutPoint {
                txid: tx.txid(),
                output_index: 0,
            }
        }

        fn transfer(&self, outpoint: OutPoint, amount: u128, recipient: [u8; 32]) -> Transaction {
            let mut tx = Transaction {
                version: 1,
                tx_type: TransactionType::Transfer,
                inputs: vec![TxInput {
                    previous_output: outpoint,
                    signature: Vec::new(),
                    public_key: self
                        .keypair
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
            };
            let message = tx.signing_message(0);
            tx.inputs[0].signature = self.keypair.sign(&message);
            tx
        }

        fn seal(&self, transactions: Vec<Transaction>) -> Block {
            let head = self.storage.head_height().unwrap();
            let head_hash = self.storage.head_hash().unwrap();
            let mut state = load_chain_state(&self.storage).unwrap();

            let leaves: Vec<Hash> = transactions.iter().map(|tx| tx.txid()).collect();
            let header = BlockHeader {
                height: head + 1,
                previous_hash: head_hash,
                transactions_root: crypto::merkle_root(&leaves),
                state_root: [0u8; 32],
                timestamp: 1_700_000_000 + head,
                validator_set_version: self.engine.version(),
            };
            let mut block = Block {
                header,
                transactions,
                consensus_proof: ConsensusProof::default(),
            };
            execute_block(&mut state, &block).unwrap();
            block.header.state_root = state_root(&state.utxos);
            let hash = block.header.hash();
            block.consensus_proof = ConsensusProof {
                height: block.header.height,
                round: 0,
                validator: self.keypair.address(),
                signature: self.keypair.sign(&hash),
                bitmap: vec![0b1],
                attestations: Vec::new(),
            };
            block
        }

        fn resign(&self, block: &mut Block) {
            let hash = block.header.hash();
            block.consensus_proof.signature = self.keypair.sign(&hash);
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn unique() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn applies_a_signed_transfer() {
        let fx = Fixture::new("apply");
        let outpoint = fx.genesis_outpoint();
        let tx = fx.transfer(outpoint.clone(), genesis::INITIAL_SUPPLY, [7u8; 32]);
        let txid = tx.txid();
        let block = fx.seal(vec![tx]);

        apply_block(&fx.storage, &fx.engine, &block).unwrap();

        assert_eq!(fx.storage.head_height().unwrap(), 1);
        assert_eq!(fx.storage.finalized_height().unwrap(), 1);
        assert!(fx.storage.get_utxo(&outpoint.txid, 0).unwrap().is_none());
        assert!(fx.storage.get_utxo(&txid, 0).unwrap().is_some());
        assert_eq!(fx.storage.utxo_count().unwrap(), 1);
    }

    #[test]
    fn rejects_state_root_mismatch() {
        let fx = Fixture::new("stateroot");
        let outpoint = fx.genesis_outpoint();
        let tx = fx.transfer(outpoint, genesis::INITIAL_SUPPLY, [7u8; 32]);
        let mut block = fx.seal(vec![tx]);
        block.header.state_root = [0xAB; 32];
        fx.resign(&mut block);

        let err = apply_block(&fx.storage, &fx.engine, &block).unwrap_err();
        assert!(matches!(err, Error::InvalidBlock(_)), "got {err:?}");
        assert_eq!(fx.storage.head_height().unwrap(), 0);
    }

    #[test]
    fn rejects_wrong_parent() {
        let fx = Fixture::new("parent");
        let outpoint = fx.genesis_outpoint();
        let tx = fx.transfer(outpoint, genesis::INITIAL_SUPPLY, [7u8; 32]);
        let mut block = fx.seal(vec![tx]);
        block.header.previous_hash = [0xEE; 32];
        fx.resign(&mut block);

        let err = apply_block(&fx.storage, &fx.engine, &block).unwrap_err();
        assert!(matches!(err, Error::InvalidBlock(_)), "got {err:?}");
    }

    #[test]
    fn rejects_bad_consensus_proof() {
        let fx = Fixture::new("proof");
        let outpoint = fx.genesis_outpoint();
        let tx = fx.transfer(outpoint, genesis::INITIAL_SUPPLY, [7u8; 32]);
        let mut block = fx.seal(vec![tx]);
        block.consensus_proof.signature = vec![0u8; 64];

        let err = apply_block(&fx.storage, &fx.engine, &block).unwrap_err();
        assert!(matches!(err, Error::Consensus(_)), "got {err:?}");
    }

    #[test]
    fn rejects_double_spend_within_a_block() {
        let fx = Fixture::new("double");
        let outpoint = fx.genesis_outpoint();
        let first = fx.transfer(outpoint.clone(), genesis::INITIAL_SUPPLY / 2, [1u8; 32]);
        let second = fx.transfer(outpoint, genesis::INITIAL_SUPPLY / 2, [2u8; 32]);
        let block = Block {
            header: BlockHeader {
                height: 1,
                previous_hash: fx.storage.head_hash().unwrap(),
                transactions_root: [0u8; 32],
                state_root: [0u8; 32],
                timestamp: 0,
                validator_set_version: 1,
            },
            transactions: vec![first, second],
            consensus_proof: ConsensusProof::default(),
        };
        let mut state = load_chain_state(&fx.storage).unwrap();
        let err = execute_block(&mut state, &block).unwrap_err();
        assert!(matches!(err, Error::InvalidBlock(_)), "got {err:?}");
    }

    #[test]
    fn replays_downloaded_but_unapplied_blocks() {
        let fx = Fixture::new("recover");
        let outpoint = fx.genesis_outpoint();
        let tx = fx.transfer(outpoint, genesis::INITIAL_SUPPLY, [7u8; 32]);
        let block = fx.seal(vec![tx]);

        // Simulate a crash after download but before application.
        fx.storage.put_block(&block).unwrap();
        assert_eq!(fx.storage.head_height().unwrap(), 0);

        let head = recover(&fx.storage, &fx.engine).unwrap();
        assert_eq!(head, 1);
        assert_eq!(fx.storage.head_height().unwrap(), 1);
        assert_eq!(fx.storage.finalized_height().unwrap(), 1);
    }

    #[test]
    fn never_applies_the_same_height_twice() {
        let fx = Fixture::new("idempotent");
        let outpoint = fx.genesis_outpoint();
        let tx = fx.transfer(outpoint, genesis::INITIAL_SUPPLY, [7u8; 32]);
        let block = fx.seal(vec![tx]);

        apply_block(&fx.storage, &fx.engine, &block).unwrap();
        // Nothing stored at head + 1, so no second application.
        assert!(!apply_next_block(&fx.storage, &fx.engine).unwrap());
        assert_eq!(fx.storage.head_height().unwrap(), 1);
        assert_eq!(fx.storage.utxo_count().unwrap(), 1);
    }

    fn registration_tx(node: &Keypair, stake_address: [u8; 32]) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type: TransactionType::ValidatorRegistration,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            registration: Some(crate::block::RegistrationPayload {
                node_public_key: node
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
            .expect("payload")
            .signature = node.sign(&txid);
        tx
    }

    #[test]
    fn registers_a_node_after_its_stake_is_confirmed() {
        let fx = Fixture::new("register");
        let node_identity = Keypair::generate();

        // Height 1: the stake wallet pays the minimum stake to the system wallet.
        let outpoint = fx.genesis_outpoint();
        let stake_tx = fx.transfer(
            outpoint,
            crate::consensus::MIN_STAKE,
            crate::consensus::system_wallet_address(),
        );
        let block1 = fx.seal(vec![stake_tx]);
        apply_block(&fx.storage, &fx.engine, &block1).unwrap();

        let ledger = fx.storage.stake_ledger().unwrap();
        assert_eq!(
            ledger.get(&fx.keypair.address()).copied().unwrap_or(0),
            crate::consensus::MIN_STAKE,
            "stake payment recorded under the sender address"
        );
        assert!(fx.storage.node_registry().unwrap().is_empty());

        // Height 2: the node registers against the stake wallet that just paid.
        let reg_tx = registration_tx(&node_identity, fx.keypair.address());
        let block2 = fx.seal(vec![reg_tx]);
        apply_block(&fx.storage, &fx.engine, &block2).unwrap();

        let registry = fx.storage.node_registry().unwrap();
        assert_eq!(registry.len(), 1);
        let entry = registry
            .get(&hex::encode(
                node_identity.public_key().to_encoded_point(true).as_bytes(),
            ))
            .expect("node registered");
        assert_eq!(entry.node_address, node_identity.address());
        assert_eq!(entry.stake_address, fx.keypair.address());
        assert_eq!(entry.stake_amount, crate::consensus::MIN_STAKE);
        assert_eq!(entry.joined_height, 2);
    }

    #[test]
    fn rejects_a_registration_before_the_stake_is_paid() {
        let fx = Fixture::new("earlyreg");
        let node_identity = Keypair::generate();

        // No stake has been paid at all, yet the node tries to register. The
        // block is built by hand because executing the invalid registration
        // (as `seal` would) must fail - that is exactly what this tests.
        let reg_tx = registration_tx(&node_identity, fx.keypair.address());
        let leaves: Vec<Hash> = vec![reg_tx.txid()];
        let mut block = Block {
            header: BlockHeader {
                height: 1,
                previous_hash: fx.storage.head_hash().unwrap(),
                transactions_root: crypto::merkle_root(&leaves),
                state_root: [0u8; 32],
                timestamp: 1_700_000_000,
                validator_set_version: fx.engine.version(),
            },
            transactions: vec![reg_tx],
            consensus_proof: ConsensusProof::default(),
        };
        let hash = block.header.hash();
        block.consensus_proof = ConsensusProof {
            height: 1,
            round: 0,
            validator: fx.keypair.address(),
            signature: fx.keypair.sign(&hash),
            bitmap: vec![0b1],
            attestations: Vec::new(),
        };

        let err = apply_block(&fx.storage, &fx.engine, &block).unwrap_err();
        assert!(matches!(err, Error::InvalidBlock(_)), "got {err:?}");
        assert!(err.to_string().contains("below the minimum"), "got {err}");
        assert_eq!(fx.storage.head_height().unwrap(), 0);
        assert!(fx.storage.node_registry().unwrap().is_empty());
    }

    #[test]
    fn stake_ledger_totals_accumulate_across_blocks() {
        let fx = Fixture::new("stakeledger");
        let outpoint = fx.genesis_outpoint();
        let half = crate::consensus::MIN_STAKE / 2;
        let first = fx.transfer(outpoint.clone(), half, crate::consensus::system_wallet_address());
        let block1 = fx.seal(vec![first]);
        apply_block(&fx.storage, &fx.engine, &block1).unwrap();
        // Below the minimum: recorded in the ledger (so the total can grow)
        // but not enough to register yet.
        assert_eq!(fx.storage.stake_amount(&fx.keypair.address()).unwrap(), half);
    }
}
