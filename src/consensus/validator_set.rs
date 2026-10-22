//! A permissioned validator-set consensus engine.
//!
//! Blocks are sealed by the members of a versioned validator set. Every block
//! above genesis must carry a [`ConsensusProof`] that is:
//!
//! * produced for the same height as the header,
//! * signed by the validator whose turn it is to propose at that height, and
//! * signed over the block header hash.
//!
//! # Proposer rotation
//!
//! The proposer for a height is `addresses[height % len]` over the set in
//! canonical (lexicographic address) order. This is deterministic, needs no
//! extra consensus round, and cannot be forged: a block signed by anyone other
//! than the expected proposer is rejected.
//!
//! An earlier revision accepted an unverified attestation bitmap supplied by
//! the producer, which let a single validator claim a full quorum. The set is
//! permissioned and small, so a signed proposer rotation is both simpler and
//! sound: there is no bitmap to lie about.
//!
//! # Versioning
//!
//! The registry changes as nodes are approved or removed. Each distinct
//! validator set is stored under a version and every block records the version
//! it was produced under ([`BlockHeader::validator_set_version`]). Nodes
//! therefore verify an old block against the set that existed when it was made,
//! and the set used to verify block `H` is the one agreed at `H - 1`.

use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;

use k256::ecdsa::VerifyingKey;

use crate::block::BlockHeader;
use crate::config::ConsensusConfig;
use crate::consensus::{ConsensusEngine, ConsensusProof, ValidatorView};
use crate::crypto::{self, Address, Hash};
use crate::error::{Error, Result};

/// One validator set, addressing-ordered.
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    pub version: u64,
    /// Validator addresses in canonical (sorted) order.
    pub addresses: Vec<Address>,
    /// Address -> public key, used to verify the proposer signature.
    keys: HashMap<Address, VerifyingKey>,
}

impl ValidatorSet {
    fn new(version: u64, keys: HashMap<Address, VerifyingKey>) -> Self {
        let mut addresses: Vec<Address> = keys.keys().copied().collect();
        addresses.sort_unstable();
        Self {
            version,
            addresses,
            keys,
        }
    }

    fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// The validator that must propose `height`.
    pub fn proposer_for(&self, height: u64) -> Option<Address> {
        if self.addresses.is_empty() {
            return None;
        }
        Some(self.addresses[(height as usize) % self.addresses.len()])
    }

    fn key_for(&self, address: &Address) -> Option<&VerifyingKey> {
        self.keys.get(address)
    }
}

/// Engine that verifies proofs against one or more versioned validator sets.
pub struct ValidatorSetEngine {
    sets: RwLock<BTreeMap<u64, ValidatorSet>>,
}

impl ValidatorSetEngine {
    /// Build an engine from the configured bootstrap validator public keys.
    ///
    /// An empty validator list yields an engine that can only accept the
    /// (locally trusted) genesis block; no block above genesis will verify.
    pub fn from_config(config: &ConsensusConfig) -> Result<Self> {
        let keys = parse_validator_keys(&config.validators)?;
        let set = ValidatorSet::new(config.validator_set_version, keys);
        let mut sets = BTreeMap::new();
        sets.insert(set.version, set);
        Ok(Self {
            sets: RwLock::new(sets),
        })
    }

    /// Build an engine from an explicit set (used by tests and bootstrapping).
    pub fn from_keys(version: u64, public_keys: &[Vec<u8>]) -> Result<Self> {
        let keys = parse_public_keys(public_keys)?;
        let mut sets = BTreeMap::new();
        sets.insert(version, ValidatorSet::new(version, keys));
        Ok(Self {
            sets: RwLock::new(sets),
        })
    }

    /// Register (or replace) the validator set for `version`.
    pub fn register_set(&self, version: u64, public_keys: &[Vec<u8>]) -> Result<()> {
        let keys = parse_public_keys(public_keys)?;
        let mut sets = self
            .sets
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        sets.insert(version, ValidatorSet::new(version, keys));
        Ok(())
    }

    /// Load every persisted validator set from storage.
    ///
    /// Called at start-up so that a restarted node can verify historical blocks
    /// against the set each one was produced under.
    pub fn load_stored_sets(&self, storage: &crate::storage::Storage) -> Result<()> {
        for (version, public_keys) in storage.validator_sets()? {
            self.register_set(version, &public_keys)?;
        }
        Ok(())
    }

    /// The latest known set version.
    pub fn current_version(&self) -> Option<u64> {
        let sets = self
            .sets
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        sets.keys().next_back().copied()
    }

    /// The latest known set version, or `0` when no set is loaded.
    pub fn version(&self) -> u64 {
        self.current_version().unwrap_or(0)
    }

    /// Snapshot of the set for `version`.
    pub fn set(&self, version: u64) -> Option<ValidatorSet> {
        let sets = self
            .sets
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        sets.get(&version).cloned()
    }

    /// The latest set.
    pub fn active_set(&self) -> Option<ValidatorSet> {
        let version = self.current_version()?;
        self.set(version)
    }

    fn check(&self, header: &BlockHeader, proof: &ConsensusProof) -> bool {
        // Genesis is trusted locally and never carries a real proof.
        if header.height == 0 {
            return true;
        }
        if proof.height != header.height {
            return false;
        }

        let set = match self.set(header.validator_set_version) {
            Some(set) => set,
            None => return false,
        };
        if set.is_empty() {
            return false;
        }

        let expected = match set.proposer_for(header.height) {
            Some(address) => address,
            None => return false,
        };
        if proof.validator != expected {
            return false;
        }

        let key = match set.key_for(&proof.validator) {
            Some(key) => key,
            None => return false,
        };

        crypto::verify(key, &header.hash(), &proof.signature)
    }
}

impl ConsensusEngine for ValidatorSetEngine {
    fn name(&self) -> &'static str {
        "validator-set"
    }

    fn verify(&self, header: &BlockHeader, proof: &ConsensusProof) -> bool {
        self.check(header, proof)
    }

    fn is_finalized(&self, header: &BlockHeader, proof: &ConsensusProof) -> bool {
        // A correctly sealed block is final in this permissioned model: the
        // proposer is fixed by the set and cannot be raced.
        self.check(header, proof)
    }

    fn register_validator_set(&self, version: u64, public_keys: &[Vec<u8>]) {
        if let Err(err) = self.register_set(version, public_keys) {
            tracing::error!(version, %err, "failed to register validator set");
        }
    }

    fn has_validators(&self) -> bool {
        self.active_set()
            .map(|set| !set.is_empty())
            .unwrap_or(false)
    }

    fn select_proposer(&self, _previous_hash: &Hash, height: u64) -> Option<Address> {
        self.active_set().and_then(|set| set.proposer_for(height))
    }

    fn validators(&self) -> Vec<ValidatorView> {
        let Some(set) = self.active_set() else {
            return Vec::new();
        };
        set.addresses
            .iter()
            .map(|address| ValidatorView {
                address: *address,
                public_key: set
                    .key_for(address)
                    .map(|key| hex::encode(key.to_encoded_point(true).as_bytes()))
                    .unwrap_or_default(),
                stake: 0,
                joined_height: 0,
            })
            .collect()
    }
}

/// Parse hex-encoded SEC1 validator public keys into an address-keyed map.
pub fn parse_validator_keys(raw_keys: &[String]) -> Result<HashMap<Address, VerifyingKey>> {
    let mut keys = HashMap::new();
    for raw in raw_keys {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let bytes = hex::decode(raw)
            .map_err(|err| Error::Config(format!("invalid validator public key hex: {err}")))?;
        let key = crypto::parse_public_key(&bytes)
            .map_err(|err| Error::Config(format!("invalid validator public key: {err}")))?;
        keys.insert(crypto::address_from_public_key(&key), key);
    }
    Ok(keys)
}

fn parse_public_keys(raw_keys: &[Vec<u8>]) -> Result<HashMap<Address, VerifyingKey>> {
    let mut keys = HashMap::new();
    for raw in raw_keys {
        let key = crypto::parse_public_key(raw)
            .map_err(|err| Error::Config(format!("invalid validator public key: {err}")))?;
        keys.insert(crypto::address_from_public_key(&key), key);
    }
    Ok(keys)
}

/// Strict two-thirds quorum: `floor(2n/3) + 1`.
///
/// Retained for callers that reason about quorum sizes; proposer rotation does
/// not require a quorum to seal a block.
pub fn quorum_size(validators: usize) -> usize {
    (2 * validators) / 3 + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ConsensusProof;
    use crate::crypto::Keypair;

    fn header(height: u64, version: u64) -> BlockHeader {
        BlockHeader {
            height,
            previous_hash: [0u8; 32],
            transactions_root: [1u8; 32],
            state_root: [2u8; 32],
            timestamp: 0,
            validator_set_version: version,
        }
    }

    fn engine_for(keypairs: &[&Keypair], version: u64) -> ValidatorSetEngine {
        let keys: Vec<Vec<u8>> = keypairs
            .iter()
            .map(|kp| kp.public_key().to_encoded_point(true).as_bytes().to_vec())
            .collect();
        ValidatorSetEngine::from_keys(version, &keys).unwrap()
    }

    fn proof(keypair: &Keypair, header: &BlockHeader) -> ConsensusProof {
        ConsensusProof {
            height: header.height,
            round: 0,
            validator: keypair.address(),
            signature: keypair.sign(&header.hash()),
            bitmap: Vec::new(),
            attestations: Vec::new(),
        }
    }

    #[test]
    fn quorum_grows_with_set_size() {
        assert_eq!(quorum_size(0), 1);
        assert_eq!(quorum_size(1), 1);
        assert_eq!(quorum_size(2), 2);
        assert_eq!(quorum_size(3), 3);
        assert_eq!(quorum_size(4), 3);
    }

    #[test]
    fn single_validator_signs_and_finalises() {
        let keypair = Keypair::generate();
        let engine = engine_for(&[&keypair], 3);
        let header = header(1, 3);
        let proof = proof(&keypair, &header);

        assert!(engine.verify(&header, &proof));
        assert!(engine.is_finalized(&header, &proof));
    }

    #[test]
    fn proposer_rotates_by_height() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let mut addresses = vec![a.address(), b.address()];
        addresses.sort_unstable();
        let engine = engine_for(&[&a, &b], 1);

        // Height 0 is genesis; the proposer for height 1 is addresses[1 % 2].
        assert_eq!(
            engine.select_proposer(&[0u8; 32], 1),
            Some(addresses[1])
        );
        assert_eq!(
            engine.select_proposer(&[0u8; 32], 2),
            Some(addresses[0])
        );
    }

    #[test]
    fn only_the_expected_proposer_can_seal() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let mut addresses = vec![a.address(), b.address()];
        addresses.sort_unstable();
        let (expected, other) = if addresses[1] == a.address() {
            (&a, &b)
        } else {
            (&b, &a)
        };
        let engine = engine_for(&[&a, &b], 1);

        let header = header(1, 1);
        assert!(engine.verify(&header, &proof(expected, &header)));
        // The other validator signs the same header: rejected.
        assert!(!engine.verify(&header, &proof(other, &header)));
    }

    #[test]
    fn a_forged_bitmap_no_longer_buys_a_quorum() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let c = Keypair::generate();
        let mut addresses = vec![a.address(), b.address(), c.address()];
        addresses.sort_unstable();
        let expected = [&a, &b, &c]
            .into_iter()
            .find(|kp| kp.address() == addresses[1])
            .expect("proposer for height 1");
        let engine = engine_for(&[&a, &b, &c], 1);

        let mut header = header(1, 1);
        // The proposer signs, but claims every validator attested.
        let mut signed = proof(expected, &header);
        signed.bitmap = vec![0b0000_0111];
        assert!(engine.verify(&header, &signed));

        // A non-proposer claims the same bitmap: still rejected.
        let impostor = [&a, &b, &c]
            .into_iter()
            .find(|kp| kp.address() != addresses[1])
            .expect("non-proposer");
        let mut forged = proof(impostor, &header);
        forged.bitmap = vec![0b0000_0111];
        assert!(!engine.verify(&header, &forged));

        header.height = 2;
        let _ = header.hash();
    }

    #[test]
    fn wrong_version_or_height_is_rejected() {
        let keypair = Keypair::generate();
        let engine = engine_for(&[&keypair], 3);

        let block_header = header(1, 3);
        let mut proof = proof(&keypair, &block_header);
        assert!(engine.verify(&block_header, &proof));

        proof.height = 0;
        assert!(!engine.verify(&block_header, &proof));

        proof.height = 1;
        let other = header(1, 9);
        assert!(!engine.verify(&other, &proof));
    }

    #[test]
    fn empty_set_accepts_only_genesis() {
        let engine = ValidatorSetEngine::from_config(&ConsensusConfig::default()).unwrap();
        assert!(engine.verify(&header(0, 0), &ConsensusProof::default()));
        assert!(!engine.verify(&header(1, 1), &ConsensusProof::default()));
    }
}
