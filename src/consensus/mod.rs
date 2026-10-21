//! Consensus proof types and engines.
//!
//! Two engines ship with the node:
//!
//! * [`ValidatorSetEngine`] - a fixed, permissioned validator set where a
//!   strict two-thirds quorum of validators attested a block.
//! * [`BftPosEngine`] - a proof-of-stake engine where validators join by
//!   locking a minimum stake into the system wallet. The next proposer is
//!   chosen at random with probability proportional to stake, and a block is
//!   final once more than two-thirds of the total stake has attested it.
//!
//! Both engines implement [`ConsensusEngine`], so [`crate::chain`] and the
//! block producer are agnostic to which one is active.

mod bft_pos;
mod staking;
mod validator_set;

pub use bft_pos::BftPosEngine;
pub use staking::{
    is_system_wallet, select_proposer, stake_deposit, system_wallet_address, StakeRegistry,
    ValidatorInfo, MIN_STAKE,
};
pub use validator_set::ValidatorSetEngine;

use serde::{Deserialize, Serialize};

use crate::block::{Block, BlockHeader};
use crate::crypto::{Address, Hash};

/// Proof that a block was sealed by the expected validator set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusProof {
    /// Height the proof was produced for.
    pub height: u64,
    /// Consensus round in which the block was finalised.
    pub round: u64,
    /// Validator that produced / signed the block.
    pub validator: Address,
    /// The proposer's signature over the block header.
    pub signature: Vec<u8>,
    /// Bitmap of the validators that attested the block (validator-set engine).
    pub bitmap: Vec<u8>,
    /// Individual stake-weighted attestations (proof-of-stake engine).
    ///
    /// Each attestation is a validator's signature over the block header. The
    /// stake behind the valid signatures is summed to decide finality.
    #[serde(default)]
    pub attestations: Vec<Attestation>,
}

/// A single validator's signature over a block header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// Address of the attesting validator.
    pub validator: Address,
    /// Signature over the block header hash.
    pub signature: Vec<u8>,
}

/// Read-only description of a validator, returned by [`ConsensusEngine`] for
/// the API layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorView {
    pub address: Address,
    pub public_key: String,
    pub stake: u128,
    pub joined_height: u64,
}

/// Interface implemented by a concrete consensus engine.
pub trait ConsensusEngine: Send + Sync {
    /// Human-readable engine name.
    fn name(&self) -> &'static str;

    /// Verify the proof attached to a block header.
    ///
    /// A `true` result means the required consensus evidence is present and
    /// valid for `header`, but it does *not* imply the block is final.
    fn verify(&self, header: &BlockHeader, proof: &ConsensusProof) -> bool;

    /// Whether `header` is finalised under this engine's BFT rules.
    ///
    /// Finality is stronger than validity: a node must not treat a block as
    /// irreversible, nor serve it as the chain head, until this returns `true`.
    fn is_finalized(&self, header: &BlockHeader, proof: &ConsensusProof) -> bool;

    /// Hook invoked once a block has been committed. Engines that track
    /// stake/validator membership update their state here.
    fn on_block_applied(&self, _block: &Block) {}

    /// Whether any validator is currently known. Chains with no validators
    /// cannot finalise a block above genesis.
    fn has_validators(&self) -> bool {
        true
    }

    /// Deterministically select the validator that should propose block
    /// `height` on top of `previous_hash`. Engines without proposer rotation
    /// return `None` (any quorum member may propose).
    fn select_proposer(&self, _previous_hash: &Hash, _height: u64) -> Option<Address> {
        None
    }

    /// Snapshot of the current validator set.
    fn validators(&self) -> Vec<ValidatorView> {
        Vec::new()
    }

    /// Total staked amount across all validators (base units).
    fn total_stake(&self) -> u128 {
        0
    }

    /// Stake required to finalise a block (strict two-thirds quorum).
    fn quorum_stake(&self) -> u128 {
        0
    }
}
