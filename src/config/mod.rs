//! Node configuration.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::crypto::{self, PublicKeyHash};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub node: NodeConfig,
    pub api: ApiConfig,
    pub network: NetworkConfig,
    pub storage: StorageConfig,
    pub consensus: ConsensusConfig,
    pub governance: GovernanceConfig,
    pub crypto: CryptoConfig,
    pub genesis: GenesisConfig,
}

impl Config {
    /// Load configuration from `path`, falling back to defaults when the file
    /// does not exist.
    pub fn load_from(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }

        let raw = std::fs::read_to_string(path)?;
        toml::from_str(&raw).map_err(|err| Error::Config(err.to_string()))
    }

    /// Load configuration from `$VHENNCOIN_CONFIG` or `./config.toml`.
    pub fn load() -> Result<Self> {
        let path = std::env::var("VHENNCOIN_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
        Self::load_from(path)
    }

    /// Resolve the genesis recipient from `genesis.public_key`.
    ///
    /// The configured key is expected as hex-encoded SEC1 bytes (compressed or
    /// uncompressed). When it is absent or empty, the deterministic treasury
    /// recipient is used instead.
    ///
    /// This only matters when the genesis block is first created; once the
    /// chain is bootstrapped the stored genesis is authoritative.
    pub fn genesis_recipient(&self) -> Result<PublicKeyHash> {
        let raw = match self.genesis.public_key.as_deref() {
            Some(value) if !value.trim().is_empty() => value.trim(),
            _ => {
                tracing::warn!(
                    "genesis.public_key is not set; using the deterministic treasury recipient"
                );
                return Ok(crate::genesis::genesis_recipient());
            }
        };

        let bytes = hex::decode(raw)
            .map_err(|err| Error::Config(format!("invalid genesis.public_key hex: {err}")))?;
        let public_key = crypto::parse_public_key(&bytes)
            .map_err(|err| Error::Config(format!("invalid genesis.public_key: {err}")))?;

        Ok(crypto::address_from_public_key(&public_key))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    pub name: String,
    pub chain_id: u64,
    pub data_dir: PathBuf,
    /// Path to this node's identity keystore text file (seed phrase + keys).
    /// When the file does not exist yet the node generates a fresh identity
    /// and writes it there, so the first node mints its own keys on first
    /// boot.
    pub keystore_path: Option<PathBuf>,
    /// Hex-encoded SEC1 public key of this node's identity. Must match the
    /// keystore when both are set; when the keystore is missing it is used to
    /// verify a freshly generated identity.
    pub public_key: Option<String>,
    /// Hex-encoded address of the admin wallet that paid the stake into the
    /// system wallet. Once the stake is confirmed on chain the node
    /// automatically submits its validator registration request.
    pub stake_address: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            name: "vhenncoin-enet-node".to_string(),
            chain_id: 4242,
            data_dir: PathBuf::from("./data"),
            keystore_path: None,
            public_key: None,
            stake_address: None,
        }
    }
}

impl NodeConfig {
    /// Parsed `stake_address`, if set. Accepts a 32-byte address in hex; a
    /// 33-byte SEC1 public key is accepted too and hashed to its address.
    pub fn stake_address_bytes(&self) -> Result<Option<PublicKeyHash>> {
        let raw = match self.stake_address.as_deref() {
            Some(value) if !value.trim().is_empty() => value.trim(),
            _ => return Ok(None),
        };
        let bytes = hex::decode(raw)
            .map_err(|err| Error::Config(format!("invalid node.stake_address hex: {err}")))?;
        match bytes.len() {
            32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            33 | 65 => {
                let key = crypto::parse_public_key(&bytes)
                    .map_err(|err| Error::Config(format!("invalid node.stake_address key: {err}")))?;
                Ok(Some(crypto::address_from_public_key(&key)))
            }
            _ => Err(Error::Config(
                "node.stake_address must be a 32-byte address or SEC1 public key".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    pub listen_addr: SocketAddr,
    pub enable_cors: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8545".parse().expect("valid default addr"),
            enable_cors: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub listen_addr: SocketAddr,
    pub bootnodes: Vec<String>,
    pub max_peers: usize,
    /// Number of blocks requested per batch while syncing.
    pub sync_batch_size: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:7000".parse().expect("valid default addr"),
            bootnodes: Vec::new(),
            max_peers: 32,
            sync_batch_size: 32,
        }
    }
}

impl NetworkConfig {
    /// Resolve every bootnode entry (`host:port` or `ip:port`) to a socket
    /// address, skipping entries that cannot be parsed.
    pub fn resolved_bootnodes(&self) -> Vec<SocketAddr> {
        let mut addrs = Vec::new();
        for entry in &self.bootnodes {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            match entry.to_socket_addrs() {
                Ok(iter) => addrs.extend(iter),
                Err(err) => {
                    tracing::warn!(bootnode = entry, %err, "ignoring unresolvable bootnode");
                }
            }
        }
        addrs
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub path: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("./data/vhenncoin.redb"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ConsensusConfig {
    pub kind: String,
    pub block_time_secs: u64,
    /// Validator-set version carried by blocks produced under this set.
    pub validator_set_version: u64,
    /// Hex-encoded SEC1 public keys (compressed or uncompressed) of the
    /// validators authorised to seal blocks. An empty set means no block above
    /// genesis can be verified, so the node can never leave the genesis state
    /// until validators are configured.
    pub validators: Vec<String>,
    /// Hex-encoded private keys for validators (for block production). Used only locally.
    pub validator_private_keys: Vec<String>,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            kind: "validator-set".to_string(),
            block_time_secs: 10,
            validator_set_version: 1,
            validators: Vec::new(),
            validator_private_keys: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CryptoConfig {
    pub signature_scheme: String,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            signature_scheme: "secp256k1".to_string(),
        }
    }
}

/// Governance rules applied when deciding whether a node may join or leave the
/// validator set.
///
/// These parameters are consensus-critical: every node must agree on them, so
/// the values are captured into the chain state the first time the chain is
/// bootstrapped and are read from storage afterwards.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GovernanceConfig {
    /// Fraction of eligible validators that must approve a node, in basis
    /// points. `9000` = 90%.
    pub approval_threshold_bps: u32,
    /// Fraction of eligible validators that must reject a node, in basis
    /// points. `9000` = 90%.
    pub rejection_threshold_bps: u32,
    /// Blocks a pending proposal stays open before it is rejected and its stake
    /// refunded. `0` disables automatic expiry.
    pub voting_period_blocks: u64,
    /// Hex-encoded SEC1 public keys allowed to remove a node unilaterally.
    /// Any single one of these keys is sufficient.
    pub override_keys: Vec<String>,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            approval_threshold_bps: 9_000,
            rejection_threshold_bps: 9_000,
            voting_period_blocks: 0,
            override_keys: Vec::new(),
        }
    }
}

impl GovernanceConfig {
    /// Resolve the configuration into the consensus-critical form.
    pub fn to_governance(&self) -> Result<crate::registry::Governance> {
        if self.approval_threshold_bps == 0 || self.approval_threshold_bps > 10_000 {
            return Err(Error::Config(
                "governance.approval_threshold_bps must be between 1 and 10000".to_string(),
            ));
        }
        if self.rejection_threshold_bps == 0 || self.rejection_threshold_bps > 10_000 {
            return Err(Error::Config(
                "governance.rejection_threshold_bps must be between 1 and 10000".to_string(),
            ));
        }
        Ok(crate::registry::Governance {
            approval_threshold_bps: self.approval_threshold_bps,
            rejection_threshold_bps: self.rejection_threshold_bps,
            voting_period_blocks: self.voting_period_blocks,
            override_keys: crate::registry::parse_override_keys(&self.override_keys)?,
        })
    }
}

/// Genesis creation settings. Only used the first time the chain is
/// bootstrapped.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GenesisConfig {
    /// Hex-encoded SEC1 public key that receives the initial supply. When
    /// empty, a deterministic treasury recipient is used.
    pub public_key: Option<String>,
}
