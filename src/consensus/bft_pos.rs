//! Proof-of-stake BFT consensus engine.

use std::sync::RwLock;

use crate::block::{Block, BlockHeader};
use crate::config::ConsensusConfig;
use crate::consensus::{Attestation, ConsensusEngine, ConsensusProof, ValidatorView};
use crate::crypto::{self, Address, Hash};
use crate::error::{Error, Result};

use super::staking::{select_proposer, StakeRegistry};

/// A simple BFT + PoS consensus engine.
///
/// * Validators join by staking to the system wallet (at least MIN_STAKE).
/// * The proposer is chosen deterministically from stake weight (on the parent
///   hash).
/// * A block is finalised when attestations sum to > two-thirds of total stake.
///   In the minimal single-proposer mode used here, we treat a valid proposer
///   signature as the primary attestation; additional attestations can be
///   provided in the proof.
#[derive(Clone)]
pub struct BftPosEngine {
    registry: std::sync::Arc<RwLock<StakeRegistry>>,
    version: u64,
    requires_atleast_one_proposer_key: bool,
    proposer_keys: Vec<Address>,
}

impl BftPosEngine {
    pub fn new(version: u64) -> Self {
        Self {
            registry: std::sync::Arc::new(RwLock::new(StakeRegistry::new())),
            version,
            requires_atleast_one_proposer_key: false,
            proposer_keys: Vec::new(),
        }
    }

    pub fn from_config(config: &ConsensusConfig) -> Result<Self> {
        let mut engine = Self::new(config.validator_set_version);
        // We don't load private keys here; block production handles them.
        Ok(engine)
    }

    pub fn registry(&self) -> std::sync::Arc<RwLock<StakeRegistry>> {
        self.registry.clone()
    }

    pub fn rebuild(&self, block: &Block) {
        let mut reg = self.registry.write().unwrap_or_else(|poison| poison.into_inner());
        reg.apply_block(block, block.header.height);
    }

    fn attested_stake(&self, header: &BlockHeader, proof: &ConsensusProof) -> u128 {
        let reg = self.registry.read().unwrap_or_else(|poison| poison.into_inner());
        let mut stake: u128 = 0;
        let proposer = proof.validator;

        // Proposer's signature counts as their attestation.
        if reg.get(&proposer).is_some() {
            stake += reg.stake_of(&proposer);
        }

        for att in &proof.attestations {
            if att.validator == proposer {
                continue;
            }
            if crypto::verify(
                &match crypto::parse_public_key(&self.pubkey_for(&att.validator, &reg)) {
                    Ok(k) => k,
                    Err(_) => continue,
                },
                &header.hash(),
                &att.signature,
            ) {
                stake += reg.stake_of(&att.validator);
            }
        }
        stake
    }

    fn pubkey_for(&self, _address: &Address, reg: &StakeRegistry) -> Vec<u8> {
        for info in reg.iter() {
            if &info.address == _address {
                return info.public_key.clone();
            }
        }
        Vec::new()
    }
}

impl ConsensusEngine for BftPosEngine {
    fn name(&self) -> &'static str {
        "bft-pos"
    }

    fn verify(&self, header: &BlockHeader, proof: &ConsensusProof) -> bool {
        if header.height == 0 {
            return true;
        }
        if header.validator_set_version != self.version {
            return false;
        }
        let reg = self.registry.read().unwrap_or_else(|poison| poison.into_inner());
        if !reg.is_empty() {
            let proposer = match select_proposer(&reg, &header.previous_hash, header.height) {
                Some(p) => p,
                None => return false,
            };
            if proposer != proof.validator {
                return false;
            }
        }

        let key_bytes = self.pubkey_for(&proof.validator, &reg);
        if key_bytes.is_empty() {
            return false;
        }
        let key = match crypto::parse_public_key(&key_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        crypto::verify(&key, &header.hash(), &proof.signature)
    }

    fn is_finalized(&self, header: &BlockHeader, proof: &ConsensusProof) -> bool {
        if header.height == 0 {
            return true;
        }
        if !self.verify(header, proof) {
            return false;
        }
        let reg = self.registry.read().unwrap_or_else(|poison| poison.into_inner());
        let quorum = reg.quorum_stake();
        let attested = self.attested_stake(header, proof);
        attested >= quorum
    }

    fn on_block_applied(&self, block: &Block) {
        let mut reg = self.registry.write().unwrap_or_else(|poison| poison.into_inner());
        reg.apply_block(block, block.header.height);
    }

    fn has_validators(&self) -> bool {
        let reg = self.registry.read().unwrap_or_else(|poison| poison.into_inner());
        !reg.is_empty()
    }

    fn select_proposer(&self, previous_hash: &Hash, height: u64) -> Option<Address> {
        let reg = self.registry.read().unwrap_or_else(|poison| poison.into_inner());
        select_proposer(&reg, previous_hash, height)
    }

    fn validators(&self) -> Vec<ValidatorView> {
        let reg = self.registry.read().unwrap_or_else(|poison| poison.into_inner());
        let mut out = Vec::new();
        for info in reg.iter() {
            out.push(ValidatorView {
                address: info.address,
                public_key: hex::encode(&info.public_key),
                stake: info.stake,
                joined_height: info.joined_height,
            });
        }
        out
    }

    fn total_stake(&self) -> u128 {
        let reg = self.registry.read().unwrap_or_else(|poison| poison.into_inner());
        reg.total_stake()
    }

    fn quorum_stake(&self) -> u128 {
        let reg = self.registry.read().unwrap_or_else(|poison| poison.into_inner());
        reg.quorum_stake()
    }
}
