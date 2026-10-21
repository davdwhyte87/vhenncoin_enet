//! A validator-set consensus engine.
//!
//! Blocks are sealed by a fixed set of validators. Every block above genesis
//! must carry a [`ConsensusProof`] that is:
//!
//! * produced for the same height as the header,
//! * signed by a validator that belongs to the active set, over the block
//!   header hash, and
//! * backed by an attestation bitmap covering a strict two-thirds quorum of
//!   the set.
//!
//! The validator order used by the attestation bitmap is the lexicographic
//! order of the validator addresses, so every node agrees on which bit belongs
//! to which validator.

use std::collections::HashMap;

use k256::ecdsa::VerifyingKey;

use crate::block::BlockHeader;
use crate::config::ConsensusConfig;
use crate::consensus::{ConsensusEngine, ConsensusProof};
use crate::crypto::{self, Address};
use crate::error::{Error, Result};

/// Engine that verifies proofs against a fixed validator set.
pub struct ValidatorSetEngine {
    /// The version this set is valid for.
    version: u64,
    /// Validator addresses in the canonical (sorted) order used by bitmaps.
    addresses: Vec<Address>,
    /// Address -> public key, used to verify the proposer signature.
    keys: HashMap<Address, VerifyingKey>,
    /// Minimum number of attestations that constitutes a quorum.
    quorum: usize,
}

impl ValidatorSetEngine {
    /// Build an engine from the configured validator public keys.
    ///
    /// An empty validator list yields an engine that can only accept the
    /// (locally trusted) genesis block; no block above genesis will verify.
    pub fn from_config(config: &ConsensusConfig) -> Result<Self> {
        let mut keys = HashMap::new();
        let mut addresses = Vec::new();

        for raw in &config.validators {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let bytes = hex::decode(raw)
                .map_err(|err| Error::Config(format!("invalid validator public key hex: {err}")))?;
            let key = crypto::parse_public_key(&bytes)
                .map_err(|err| Error::Config(format!("invalid validator public key: {err}")))?;
            let address = crypto::address_from_public_key(&key);
            if keys.insert(address, key).is_none() {
                addresses.push(address);
            }
        }

        addresses.sort_unstable();

        Ok(Self::new(config.validator_set_version, addresses, keys))
    }

    /// Construct an engine directly from an address list (already unique).
    fn new(version: u64, addresses: Vec<Address>, keys: HashMap<Address, VerifyingKey>) -> Self {
        let quorum = quorum_size(addresses.len());
        Self {
            version,
            addresses,
            keys,
            quorum,
        }
    }

    /// The validator-set version this engine governs.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Whether any validator is configured at all.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Count how many validators attested, according to the proof bitmap.
    fn attestation_count(bitmap: &[u8]) -> usize {
        bitmap.iter().map(|byte| byte.count_ones() as usize).sum()
    }

    fn check(&self, header: &BlockHeader, proof: &ConsensusProof) -> bool {
        // Genesis is trusted locally and never carries a real proof.
        if header.height == 0 {
            return true;
        }
        if proof.height != header.height {
            return false;
        }
        if header.validator_set_version != self.version {
            return false;
        }
        if self.addresses.is_empty() {
            return false;
        }

        let key = match self.keys.get(&proof.validator) {
            Some(key) => key,
            None => return false,
        };

        if !crypto::verify(key, &header.hash(), &proof.signature) {
            return false;
        }

        Self::attestation_count(&proof.bitmap) >= self.quorum
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
        // A quorum attestation is exactly what makes a block final in this
        // simple BFT model.
        self.check(header, proof)
    }
}

/// Strict two-thirds quorum: `floor(2n/3) + 1`.
///
/// Yields `1` for a single validator (a lone producer can finalise) and grows
/// monotonically with the set size.
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
        let pubkey_hex = hex::encode(keypair.public_key().to_encoded_point(true).as_bytes());
        let config = ConsensusConfig {
            validator_set_version: 3,
            validators: vec![pubkey_hex],
            ..ConsensusConfig::default()
        };

        let engine = ValidatorSetEngine::from_config(&config).unwrap();
        let header = header(1, 3);
        let proof = ConsensusProof {
            height: 1,
            round: 0,
            validator: keypair.address(),
            signature: keypair.sign(&header.hash()),
            bitmap: vec![0b0000_0001],
            attestations: Vec::new(),
        };

        assert!(engine.verify(&header, &proof));
        assert!(engine.is_finalized(&header, &proof));
    }

    #[test]
    fn wrong_version_or_height_is_rejected() {
        let keypair = Keypair::generate();
        let config = ConsensusConfig {
            validator_set_version: 3,
            validators: vec![hex::encode(keypair.public_key().to_encoded_point(true).as_bytes())],
            ..ConsensusConfig::default()
        };
        let engine = ValidatorSetEngine::from_config(&config).unwrap();

        let block_header = header(5, 3);
        let mut proof = ConsensusProof {
            height: 5,
            round: 0,
            validator: keypair.address(),
            signature: keypair.sign(&block_header.hash()),
            bitmap: vec![0b1],
            attestations: Vec::new(),
        };
        assert!(engine.verify(&block_header, &proof));

        proof.height = 4;
        assert!(!engine.verify(&block_header, &proof));

        proof.height = 5;
        let other = header(5, 9);
        assert!(!engine.verify(&other, &proof));
    }

    #[test]
    fn empty_set_accepts_only_genesis() {
        let engine = ValidatorSetEngine::from_config(&ConsensusConfig::default()).unwrap();
        assert!(engine.verify(&header(0, 0), &ConsensusProof::default()));
        assert!(!engine.verify(&header(1, 1), &ConsensusProof::default()));
    }
}
