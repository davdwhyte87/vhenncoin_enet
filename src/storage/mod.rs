//! Redb-backed persistent storage.
//!
//! The database is the single source of truth for the applied chain: the
//! committed head, the finalised height, every stored block and the UTXO set.
//! A block is only ever "applied" (i.e. its transactions are executed and the
//! head advances) inside one write transaction, which makes application
//! crash-safe: after a crash the head always matches the UTXO set.

use std::path::Path;

use redb::{Database, ReadableTable, TableDefinition, WriteTransaction};

use crate::block::{Block, BlockHeader, OutPoint, TxOutput};
use crate::crypto::Hash;
use crate::error::{Error, Result};

/// height -> encoded [`crate::block::Block`]
pub const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");
/// block hash -> height
pub const BLOCK_INDEX: TableDefinition<&[u8], u64> = TableDefinition::new("block_index");
/// height -> encoded [`crate::block::BlockHeader`]
pub const HEADERS: TableDefinition<u64, &[u8]> = TableDefinition::new("headers");
/// transaction id -> encoded [`crate::block::Transaction`]
pub const TRANSACTIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("transactions");
/// out-point (`txid || index_le`) -> encoded [`crate::block::TxOutput`]
pub const UTXOS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("utxos");
/// state key -> state value
pub const STATE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("state");
/// validator-set version -> encoded validator set
pub const VALIDATORS: TableDefinition<u64, &[u8]> = TableDefinition::new("validators");
/// peer id -> encoded [`crate::network::Peer`]
pub const PEERS: TableDefinition<&str, &[u8]> = TableDefinition::new("peers");
/// transaction id -> block height
pub const TX_BLOCK: TableDefinition<&[u8], u64> = TableDefinition::new("tx_block");
/// metadata key -> value (chain head, schema version, ...)
pub const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
/// stake-wallet address -> total amount paid into the system wallet (u128 LE)
pub const STAKE_LEDGER: TableDefinition<&[u8], &[u8]> = TableDefinition::new("stake_ledger");
/// node identity public key (hex) -> encoded [`crate::registry::NodeRegistration`]
pub const NODE_REGISTRY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("node_registry");

/// META key holding the genesis block hash.
pub const META_GENESIS_HASH: &str = "genesis_hash";
/// META key holding the last applied (committed) block height.
pub const META_HEAD_HEIGHT: &str = "head_height";
/// META key holding the last applied (committed) block hash.
pub const META_HEAD_HASH: &str = "head_hash";
/// META key holding the latest finalised block height.
pub const META_FINALIZED_HEIGHT: &str = "finalized_height";
/// META key holding the latest finalised block hash.
pub const META_FINALIZED_HASH: &str = "finalized_hash";

/// Byte length of an [`OutPoint`] key: 32-byte txid + 4-byte little-endian index.
pub const OUTPOINT_KEY_LEN: usize = 36;

/// Encode `(txid, index)` as the UTXO table key.
pub fn outpoint_key(txid: &Hash, index: u32) -> [u8; OUTPOINT_KEY_LEN] {
    let mut key = [0u8; OUTPOINT_KEY_LEN];
    key[..32].copy_from_slice(txid);
    key[32..].copy_from_slice(&index.to_le_bytes());
    key
}

/// Decode a UTXO table key back into an [`OutPoint`].
pub fn decode_outpoint(key: &[u8]) -> Result<OutPoint> {
    if key.len() != OUTPOINT_KEY_LEN {
        return Err(Error::Serialization(
            "invalid outpoint key length".to_string(),
        ));
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&key[..32]);
    let mut idx = [0u8; 4];
    idx.copy_from_slice(&key[32..]);
    Ok(OutPoint {
        txid,
        output_index: u32::from_le_bytes(idx),
    })
}

/// Handle to the on-disk node database.
pub struct Storage {
    db: Database,
}

impl Storage {
    /// Open (creating if necessary) the database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path)?;
        init_tables(&db)?;
        Ok(Self { db })
    }

    /// Borrow the underlying Redb database.
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Run `f` inside a single read transaction.
    pub fn read<T>(&self, f: impl FnOnce(&redb::ReadTransaction) -> Result<T>) -> Result<T> {
        let txn = self.db.begin_read()?;
        f(&txn)
    }

    /// Run `f` inside a single write transaction, committing only on success.
    pub fn write<T>(&self, f: impl FnOnce(&WriteTransaction) -> Result<T>) -> Result<T> {
        let txn = self.db.begin_write()?;
        let out = f(&txn)?;
        txn.commit()?;
        Ok(out)
    }

    /// Persist the genesis block at height 0 if the chain has not been
    /// bootstrapped yet. No-op on subsequent starts.
    ///
    /// Besides storing the block itself, this seeds the UTXO set with the
    /// genesis output and marks height 0 as both the head and finalised.
    pub fn bootstrap_genesis(&self, recipient: crate::crypto::PublicKeyHash) -> Result<bool> {
        let genesis = crate::genesis::genesis_block(recipient);
        let genesis_hash = genesis.hash();

        let created = self.write(|txn| {
            let already = {
                let meta = txn.open_table(META)?;
                let present = meta.get(META_GENESIS_HASH)?.is_some();
                present
            };
            if already {
                return Ok(false);
            }

            let body = encode(&genesis)?;
            {
                let mut blocks = txn.open_table(BLOCKS)?;
                blocks.insert(0u64, body.as_slice())?;
            }
            {
                let mut headers = txn.open_table(HEADERS)?;
                let header = encode(&genesis.header)?;
                headers.insert(0u64, header.as_slice())?;
            }
            {
                let mut index = txn.open_table(BLOCK_INDEX)?;
                index.insert(genesis_hash.as_slice(), 0u64)?;
            }
            {
                let mut txs = txn.open_table(TRANSACTIONS)?;
                for tx in &genesis.transactions {
                    let txid = tx.txid();
                    let encoded = encode(tx)?;
                    txs.insert(txid.as_slice(), encoded.as_slice())?;
                }
            }
            {
                let mut utxos = txn.open_table(UTXOS)?;
                for tx in &genesis.transactions {
                    let txid = tx.txid();
                    for (index, output) in tx.outputs.iter().enumerate() {
                        let key = outpoint_key(&txid, index as u32);
                        let value = encode(output)?;
                        utxos.insert(key.as_slice(), value.as_slice())?;
                    }
                }
            }
            {
                let mut meta = txn.open_table(META)?;
                meta.insert(META_GENESIS_HASH, genesis_hash.as_slice())?;
                meta.insert(META_HEAD_HEIGHT, 0u64.to_le_bytes().as_slice())?;
                meta.insert(META_HEAD_HASH, genesis_hash.as_slice())?;
                meta.insert(META_FINALIZED_HEIGHT, 0u64.to_le_bytes().as_slice())?;
                meta.insert(META_FINALIZED_HASH, genesis_hash.as_slice())?;
            }
            Ok(true)
        })?;

        if created {
            tracing::info!(
                hash = %hex::encode(genesis_hash),
                supply = crate::genesis::INITIAL_SUPPLY,
                "genesis block created"
            );
        } else {
            tracing::info!("genesis already present; skipping creation");
        }
        Ok(created)
    }

    /// Height of the last applied block. Returns 0 when nothing is stored.
    pub fn head_height(&self) -> Result<u64> {
        self.read(|txn| {
            let meta = txn.open_table(META)?;
            Ok(read_u64(&meta, META_HEAD_HEIGHT)?.unwrap_or(0))
        })
    }

    /// Hash of the last applied block. Returns the zero hash when nothing is
    /// stored.
    pub fn head_hash(&self) -> Result<Hash> {
        self.read(|txn| {
            let meta = txn.open_table(META)?;
            Ok(read_hash(&meta, META_HEAD_HASH)?.unwrap_or([0u8; 32]))
        })
    }

    /// Height of the latest finalised block. Returns 0 when unset.
    pub fn finalized_height(&self) -> Result<u64> {
        self.read(|txn| {
            let meta = txn.open_table(META)?;
            Ok(read_u64(&meta, META_FINALIZED_HEIGHT)?.unwrap_or(0))
        })
    }

    /// The stored genesis block, if the chain has been bootstrapped.
    pub fn genesis_block(&self) -> Result<Option<Block>> {
        self.get_block(0)
    }

    /// Read a block by height.
    pub fn get_block(&self, height: u64) -> Result<Option<Block>> {
        self.read(|txn| {
            let blocks = txn.open_table(BLOCKS)?;
            match blocks.get(height)? {
                Some(raw) => Ok(Some(decode(raw.value())?)),
                None => Ok(None),
            }
        })
    }

    /// Read a block by its hash.
    pub fn get_block_by_hash(&self, hash: &Hash) -> Result<Option<Block>> {
        self.read(|txn| {
            let index = txn.open_table(BLOCK_INDEX)?;
            let height = match index.get(hash.as_slice())? {
                Some(value) => value.value(),
                None => return Ok(None),
            };
            let blocks = txn.open_table(BLOCKS)?;
            match blocks.get(height)? {
                Some(raw) => Ok(Some(decode(raw.value())?)),
                None => Ok(None),
            }
        })
    }

    /// Whether a block is stored at `height`.
    pub fn has_block(&self, height: u64) -> Result<bool> {
        self.read(|txn| {
            let blocks = txn.open_table(BLOCKS)?;
            Ok(blocks.get(height)?.is_some())
        })
    }

    /// Store a downloaded (not yet applied) block. Ignored when an identical
    /// block already exists; refuses to replace a block at or below the
    /// committed head.
    pub fn put_block(&self, block: &Block) -> Result<()> {
        let height = block.header.height;
        let hash = block.hash();
        let head = self.head_height()?;

        self.write(|txn| {
            let mut blocks = txn.open_table(BLOCKS)?;
            if let Some(raw) = blocks.get(height)? {
                let existing: Block = decode(raw.value())?;
                if existing.hash() == hash {
                    return Ok(());
                }
                if height <= head {
                    return Err(Error::InvalidBlock(format!(
                        "refusing to replace applied block at height {height}"
                    )));
                }
            }

            let body = encode(block)?;
            blocks.insert(height, body.as_slice())?;
            drop(blocks);

            let mut index = txn.open_table(BLOCK_INDEX)?;
            index.insert(hash.as_slice(), height)?;
            Ok(())
        })
    }

    /// Remove a stored block and its index entry (used to drop a rejected
    /// block near the head).
    pub fn remove_block(&self, height: u64) -> Result<()> {
        self.write(|txn| {
            let removed = {
                let mut blocks = txn.open_table(BLOCKS)?;
                let value = blocks.remove(height)?.map(|raw| raw.value().to_vec());
                value
            };
            let Some(removed) = removed else {
                return Ok(());
            };
            let block: Block = decode(&removed)?;
            let mut index = txn.open_table(BLOCK_INDEX)?;
            index.remove(block.hash().as_slice())?;
            Ok(())
        })
    }

    /// Highest height for which a block is stored (applied or not).
    pub fn highest_stored_height(&self) -> Result<Option<u64>> {
        self.read(|txn| {
            let blocks = txn.open_table(BLOCKS)?;
            let mut highest = None;
            for entry in blocks.iter()? {
                let (key, _) = entry?;
                highest = Some(key.value());
            }
            Ok(highest)
        })
    }

    /// Read up to `max` headers starting at `from_height` (inclusive).
    pub fn headers_from(&self, from_height: u64, max: u32) -> Result<Vec<BlockHeader>> {
        self.read(|txn| {
            let headers = txn.open_table(HEADERS)?;
            let mut out = Vec::new();
            for entry in headers.range(from_height..)? {
                if out.len() >= max as usize {
                    break;
                }
                let (_, value) = entry?;
                out.push(decode(value.value())?);
            }
            Ok(out)
        })
    }

    /// Read up to `max` full blocks starting at `from_height` (inclusive).
    pub fn blocks_from(&self, from_height: u64, max: u32) -> Result<Vec<Block>> {
        self.read(|txn| {
            let blocks = txn.open_table(BLOCKS)?;
            let mut out = Vec::new();
            for entry in blocks.range(from_height..)? {
                if out.len() >= max as usize {
                    break;
                }
                let (_, value) = entry?;
                out.push(decode(value.value())?);
            }
            Ok(out)
        })
    }

    /// Number of unspent outputs currently tracked.
    pub fn utxo_count(&self) -> Result<usize> {
        self.read(|txn| {
            let utxos = txn.open_table(UTXOS)?;
            Ok(utxos.iter()?.count())
        })
    }

    /// Look up a single UTXO by its out-point.
    pub fn get_utxo(&self, txid: &Hash, index: u32) -> Result<Option<TxOutput>> {
        self.read(|txn| {
            let utxos = txn.open_table(UTXOS)?;
            let key = outpoint_key(txid, index);
            match utxos.get(key.as_slice())? {
                Some(raw) => Ok(Some(decode(raw.value())?)),
                None => Ok(None),
            }
        })
    }

    /// Get a transaction by its ID.
    pub fn get_transaction(&self, txid: &Hash) -> Result<Option<crate::block::Transaction>> {
        self.read(|txn| {
            let txs = txn.open_table(TRANSACTIONS)?;
            match txs.get(txid.as_slice())? {
                Some(raw) => Ok(Some(decode(raw.value())?)),
                None => Ok(None),
            }
        })
    }

    /// Get the block height where a transaction was included.
    pub fn get_tx_block(&self, txid: &Hash) -> Result<Option<u64>> {
        self.read(|txn| {
            let tx_blocks = txn.open_table(TX_BLOCK)?;
            match tx_blocks.get(txid.as_slice())? {
                Some(raw) => Ok(Some(raw.value())),
                None => Ok(None),
            }
        })
    }

    /// The full stake ledger: stake-wallet address -> total paid into the
    /// system wallet.
    pub fn stake_ledger(&self) -> Result<crate::registry::StakeLedger> {
        self.read(|txn| {
            let table = txn.open_table(STAKE_LEDGER)?;
            load_stake_ledger(&table)
        })
    }

    /// Total amount `address` has paid into the system stake wallet.
    pub fn stake_amount(&self, address: &crate::crypto::PublicKeyHash) -> Result<u128> {
        self.read(|txn| {
            let ledger = txn.open_table(STAKE_LEDGER)?;
            Ok(match ledger.get(address.as_slice())? {
                Some(raw) => decode_u128(raw.value())?,
                None => 0,
            })
        })
    }

    /// The full validator registry: node public key (hex) -> registration.
    pub fn node_registry(&self) -> Result<crate::registry::NodeRegistry> {
        self.read(|txn| {
            let table = txn.open_table(NODE_REGISTRY)?;
            load_node_registry(&table)
        })
    }
}

/// Read the stake ledger from an open stake-ledger table.
pub fn load_stake_ledger(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<crate::registry::StakeLedger> {
    let mut ledger = crate::registry::StakeLedger::new();
    for entry in table.iter()? {
        let (key, value) = entry?;
        let mut address = [0u8; 32];
        if key.value().len() != 32 {
            continue;
        }
        address.copy_from_slice(key.value());
        ledger.insert(address, decode_u128(value.value())?);
    }
    Ok(ledger)
}

/// Read the validator registry from an open node-registry table.
pub fn load_node_registry(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<crate::registry::NodeRegistry> {
    let mut registry = crate::registry::NodeRegistry::new();
    for entry in table.iter()? {
        let (key, value) = entry?;
        let node: crate::registry::NodeRegistration = decode(value.value())?;
        let key = String::from_utf8(key.value().to_vec())
            .map_err(|_| Error::Serialization("registry key is not utf-8".to_string()))?;
        registry.insert(key, node);
    }
    Ok(registry)
}

/// Persist one stake-ledger total inside an open write transaction.
pub fn put_stake_amount(
    txn: &WriteTransaction,
    address: &crate::crypto::PublicKeyHash,
    amount: u128,
) -> Result<()> {
    let mut table = txn.open_table(STAKE_LEDGER)?;
    table.insert(address.as_slice(), amount.to_le_bytes().as_slice())?;
    Ok(())
}

/// Persist one registry entry inside an open write transaction.
pub fn put_node_registration(
    txn: &WriteTransaction,
    node_public_key_hex: &str,
    entry: &crate::registry::NodeRegistration,
) -> Result<()> {
    let mut table = txn.open_table(NODE_REGISTRY)?;
    let encoded = encode(entry)?;
    table.insert(node_public_key_hex.as_bytes(), encoded.as_slice())?;
    Ok(())
}

fn decode_u128(bytes: &[u8]) -> Result<u128> {
    let arr: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::Serialization("u128 value is not 16 bytes".to_string()))?;
    Ok(u128::from_le_bytes(arr))
}

/// Create every table so the rest of the node can assume they exist.
fn init_tables(db: &Database) -> Result<()> {
    let txn = db.begin_write()?;
    {
        let _ = txn.open_table(BLOCKS)?;
        let _ = txn.open_table(BLOCK_INDEX)?;
        let _ = txn.open_table(HEADERS)?;
        let _ = txn.open_table(TRANSACTIONS)?;
        let _ = txn.open_table(UTXOS)?;
        let _ = txn.open_table(STATE)?;
        let _ = txn.open_table(VALIDATORS)?;
        let _ = txn.open_table(PEERS)?;
        let _ = txn.open_table(META)?;
        let _ = txn.open_table(STAKE_LEDGER)?;
        let _ = txn.open_table(NODE_REGISTRY)?;
    }
    txn.commit()?;
    Ok(())
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|err| Error::Serialization(err.to_string()))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|err| Error::Serialization(err.to_string()))
}

fn read_u64(meta: &impl ReadableTable<&'static str, &'static [u8]>, key: &str) -> Result<Option<u64>> {
    match meta.get(key)? {
        Some(value) => {
            let bytes = value.value();
            let arr: [u8; 8] = bytes
                .try_into()
                .map_err(|_| Error::Serialization(format!("meta {key} is not 8 bytes")))?;
            Ok(Some(u64::from_le_bytes(arr)))
        }
        None => Ok(None),
    }
}

fn read_hash(meta: &impl ReadableTable<&'static str, &'static [u8]>, key: &str) -> Result<Option<Hash>> {
    match meta.get(key)? {
        Some(value) => {
            let bytes = value.value();
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| Error::Serialization(format!("meta {key} is not 32 bytes")))?;
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}
