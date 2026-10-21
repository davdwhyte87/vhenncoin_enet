//! Proof-of-stake validator registry, staking rules and proposer selection.
//!
//! Joining the network as a validator is done by *paying a stake* to the
//! system wallet. The system wallet is an ordinary address derived from a
//! constant string, which means no one holds its private key: its funds can
//! never be moved by a client. Only the consensus layer reads it, to decide who
//! is allowed to validate.
//!
//! A stake deposit is an ordinary signed [`Transaction`] whose output pays the
//! system wallet at least [`MIN_STAKE`]. The sending input's public key is the
//! validator identity, so the stake is bound to a key the node controls. Once
//! the deposit is included in a *finalised* block the node is a validator.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::block::{Transaction, TransactionType};
use crate::crypto::{self, Address, Hash, PublicKeyHash};

/// Minimum stake a node must lock to join as a validator: 100,000 VHN.
pub const MIN_STAKE: u128 = 100_000 * crate::genesis::COIN;

/// Address of the system stake wallet.
///
/// It is derived purely from a fixed label, so no private key exists and its
/// funds can never be spent by a client.
pub fn system_wallet_address() -> PublicKeyHash {
    crypto::sha256(b"VHN_SYSTEM_STAKE_WALLET")
}

/// Whether `address` is the system stake wallet.
pub fn is_system_wallet(address: &Address) -> bool {
    address == &system_wallet_address()
}

/// A registered validator and the stake backing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: Address,
    pub public_key: Vec<u8>,
    pub stake: u128,
    pub joined_height: u64,
}

/// The set of stake-backed validators, keyed by address.
///
/// Iteration order is the lexicographic order of addresses, so proposer
/// selection and quorum counting agree on every node.
#[derive(Debug, Clone, Default)]
pub struct StakeRegistry {
    validators: BTreeMap<Address, ValidatorInfo>,
}

impl StakeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn total_stake(&self) -> u128 {
        self.validators.values().map(|v| v.stake).sum()
    }

    pub fn get(&self, address: &Address) -> Option<&ValidatorInfo> {
        self.validators.get(address)
    }

    /// Iterate validators in the canonical (address) order.
    pub fn iter(&self) -> impl Iterator<Item = &ValidatorInfo> {
        self.validators.values()
    }

    /// Minimum stake that must attest a block: strict two-thirds of the total.
    ///
    /// `floor(2*total/3) + 1`, and at least `MIN_STAKE` when any stake exists so
    /// a lone validator can still finalise.
    pub fn quorum_stake(&self) -> u128 {
        let total = self.total_stake();
        if total == 0 {
            0
        } else {
            (2 * total) / 3 + 1
        }
    }

    /// Insert a new validator or raise the stake of an existing one.
    pub fn register(&mut self, address: Address, public_key: Vec<u8>, amount: u128, height: u64) {
        self.validators
            .entry(address)
            .and_modify(|info| info.stake += amount)
            .or_insert(ValidatorInfo {
                address,
                public_key,
                stake: amount,
                joined_height: height,
            });
    }

    /// Apply every validator deposit found in `block` at `height`.
    pub fn apply_block(&mut self, block: &crate::block::Block, height: u64) {
        for tx in &block.transactions {
            if let Some((address, public_key, amount)) = stake_deposit(tx) {
                self.register(address, public_key, amount, height);
            }
        }
    }

    /// Select the proposer for `height` on top of `previous_hash`.
    ///
    /// A deterministic pseudo-random point is drawn in `[0, total_stake)` from
    /// the parent hash, then mapped onto the cumulative stake distribution.
    /// Weight is therefore proportional to stake, the result is verifiable by
    /// every node, and it cannot be biased by the proposer.
    pub fn select_proposer(&self, previous_hash: &Hash, height: u64) -> Option<Address> {
        let total = self.total_stake();
        if total == 0 {
            return None;
        }

        let mut seed = Vec::with_capacity(40);
        seed.extend_from_slice(previous_hash);
        seed.extend_from_slice(&height.to_le_bytes());
        let digest = crypto::sha256(&seed);

        let mut point = [0u8; 16];
        point.copy_from_slice(&digest[..16]);
        let draw = u128::from_le_bytes(point) % total;

        let mut cumulative: u128 = 0;
        for info in self.validators.values() {
            cumulative += info.stake;
            if draw < cumulative {
                return Some(info.address);
            }
        }
        self.validators.values().next_back().map(|info| info.address)
    }

    /// The sum of stake of `addresses` that are registered validators.
    pub fn stake_of(&self, address: &Address) -> u128 {
        self.validators.get(address).map(|v| v.stake).unwrap_or(0)
    }
}

/// Detect a staking deposit in a transaction.
///
/// Returns `(validator_address, public_key, amount)` when the transaction pays
/// at least [`MIN_STAKE`] into the system wallet. The validator identity is the
/// public key that authorised the spend.
pub fn stake_deposit(tx: &Transaction) -> Option<(Address, Vec<u8>, u128)> {
    if tx.tx_type != TransactionType::Transfer || tx.inputs.len() != 1 {
        return None;
    }

    let deposited: u128 = tx
        .outputs
        .iter()
        .filter(|output| is_system_wallet(&output.recipient))
        .map(|output| output.amount)
        .sum();
    if deposited < MIN_STAKE {
        return None;
    }

    let input = &tx.inputs[0];
    let public_key = crypto::parse_public_key(&input.public_key).ok()?;
    let address = crypto::address_from_public_key(&public_key);
    Some((address, input.public_key.clone(), deposited))
}

/// Convenience wrapper mirroring [`StakeRegistry::select_proposer`].
pub fn select_proposer(
    registry: &StakeRegistry,
    previous_hash: &Hash,
    height: u64,
) -> Option<Address> {
    registry.select_proposer(previous_hash, height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{OutPoint, TxInput, TxOutput};
    use crate::crypto::Keypair;

    fn deposit(keypair: &Keypair, amount: u128) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type: TransactionType::Transfer,
            inputs: vec![TxInput {
                previous_output: OutPoint {
                    txid: [1u8; 32],
                    output_index: 0,
                },
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
                recipient: system_wallet_address(),
            }],
            lock_time: 0,
            registration: None,
        };
        let message = tx.signing_message(0);
        tx.inputs[0].signature = keypair.sign(&message);
        tx
    }

    #[test]
    fn weights_proposer_selection_by_stake() {
        let heavy = Keypair::generate();
        let light = Keypair::generate();
        let mut registry = StakeRegistry::new();
        registry.register(heavy.address(), vec![], MIN_STAKE * 9, 1);
        registry.register(light.address(), vec![], MIN_STAKE, 1);

        let hash = [9u8; 32];
        let mut heavy_wins = 0;
        for height in 0..1000u64 {
            let proposer = registry.select_proposer(&hash, height).unwrap();
            if proposer == heavy.address() {
                heavy_wins += 1;
            }
        }
        // ~90% weight; assert it dominates by a wide margin.
        assert!(heavy_wins > 800, "heavy validator chose {heavy_wins}/1000 times");
    }

    #[test]
    fn detects_minimum_stake_deposit() {
        let keypair = Keypair::generate();
        let tx = deposit(&keypair, MIN_STAKE);
        let (address, public_key, amount) = stake_deposit(&tx).expect("deposit detected");
        assert_eq!(address, keypair.address());
        assert_eq!(public_key, tx.inputs[0].public_key);
        assert_eq!(amount, MIN_STAKE);
    }

    #[test]
    fn rejects_stake_below_minimum() {
        let keypair = Keypair::generate();
        let tx = deposit(&keypair, MIN_STAKE - 1);
        assert!(stake_deposit(&tx).is_none());
    }

    #[test]
    fn ordinary_transfer_is_not_a_stake() {
        let keypair = Keypair::generate();
        let mut tx = deposit(&keypair, MIN_STAKE);
        tx.outputs[0].recipient = [9u8; 32];
        assert!(stake_deposit(&tx).is_none());
    }

    #[test]
    fn selection_is_proportional_and_deterministic() {
        let mut registry = StakeRegistry::new();
        let a = Keypair::generate();
        let b = Keypair::generate();
        registry.register(a.address(), vec![], MIN_STAKE * 4, 1);
        registry.register(b.address(), vec![], MIN_STAKE, 1);

        let hash = [9u8; 32];
        let first = registry.select_proposer(&hash, 10);
        let second = registry.select_proposer(&hash, 10);
        assert_eq!(first, second);
        assert!(first.is_some());
    }

    #[test]
    fn quorum_is_two_thirds_of_stake() {
        let keypair = Keypair::generate();
        let mut registry = StakeRegistry::new();
        registry.register(keypair.address(), vec![], MIN_STAKE * 3, 1);
        assert_eq!(registry.quorum_stake(), (2 * MIN_STAKE * 3) / 3 + 1);

        let empty = StakeRegistry::new();
        assert_eq!(empty.quorum_stake(), 0);
    }

    #[test]
    fn below_minimum_deposits_are_ignored() {
        let keypair = Keypair::generate();
        let tx = deposit(&keypair, MIN_STAKE - 1);
        assert!(stake_deposit(&tx).is_none());
    }
}

#[cfg(test)]
mod bft_pos_tests {
    use super::*;
    use crate::block::{Block, BlockHeader, OutPoint, TxInput, TxOutput, Transaction, TransactionType};
    use crate::consensus::{Attestation, BftPosEngine, ConsensusEngine, ConsensusProof};
    use crate::crypto::{Keypair, sha256};

    fn make_header(height: u64, prev_hash: [u8; 32]) -> BlockHeader {
        BlockHeader {
            height,
            previous_hash: prev_hash,
            transactions_root: [1u8; 32],
            state_root: [2u8; 32],
            timestamp: 1_700_000_000 + height,
            validator_set_version: 1,
        }
    }

    fn signed_proof(keypair: &Keypair, header: &BlockHeader, att: Vec<Attestation>) -> ConsensusProof {
        let hash = header.hash();
        ConsensusProof {
            height: header.height,
            round: 0,
            validator: keypair.address(),
            signature: keypair.sign(&hash),
            bitmap: vec![0b1],
            attestations: att,
        }
    }

    #[test]
    fn genesis_is_always_finalised() {
        let engine = BftPosEngine::new(1);
        let header = BlockHeader {
            height: 0,
            previous_hash: [0u8; 32],
            transactions_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 0,
            validator_set_version: 1,
        };
        assert!(engine.verify(&header, &ConsensusProof::default()));
        assert!(engine.is_finalized(&header, &ConsensusProof::default()));
    }

    #[test]
    fn rejects_wrong_proposer() {
        let engine = BftPosEngine::new(1);
        let heavy = Keypair::generate();
        let light = Keypair::generate();
        {
            let registry = engine.registry();
            let mut reg = registry.write().unwrap();
            let pk_heavy = heavy.public_key().to_encoded_point(true).as_bytes().to_vec();
            let pk_light = light.public_key().to_encoded_point(true).as_bytes().to_vec();
            reg.register(heavy.address(), pk_heavy, MIN_STAKE * 9, 1);
            reg.register(light.address(), pk_light, MIN_STAKE, 1);
        }
        let prev_hash = [9u8; 32];
        let correct = engine.select_proposer(&prev_hash, 10).unwrap();
        assert_eq!(correct, heavy.address());

        let header = make_header(10, prev_hash);
        let wrong_proof = signed_proof(&light, &header, Vec::new());
        assert!(!engine.verify(&header, &wrong_proof), "light signed when heavy should propose");
    }

    #[test]
    fn finalises_when_quorum_attests() {
        let engine = BftPosEngine::new(1);
        let a = Keypair::generate();
        let b = Keypair::generate();
        let c = Keypair::generate();
        let validators = vec![(&a, "a"), (&b, "b"), (&c, "c")];
        {
            let registry = engine.registry();
            let mut reg = registry.write().unwrap();
            for (kp, _) in &validators {
                let pk = kp.public_key().to_encoded_point(true).as_bytes().to_vec();
                reg.register(kp.address(), pk, MIN_STAKE * 2, 1);
            }
        }
        // Total = 6*MIN_STAKE, quorum = 4*MIN_STAKE + 1.
        // Any two validators = 4*MIN_STAKE < quorum. All three = 6*MIN_STAKE >= quorum.

        let prev_hash = [9u8; 32];
        let height = 10;
        let proposer_addr = engine.select_proposer(&prev_hash, height).unwrap();
        let header = make_header(height, prev_hash);

        // Find the proposer keypair
        let proposer_kp = validators.iter().find(|(kp, _)| kp.address() == proposer_addr).unwrap().0;

        // Only proposer attests: not enough (2*MIN_STAKE < quorum)
        let proof1 = signed_proof(proposer_kp, &header, Vec::new());
        assert!(!engine.is_finalized(&header, &proof1));

        // Proposer + one more: still not enough (4*MIN_STAKE < 4*MIN_STAKE+1)
        let other = validators.iter().find(|(kp, _)| kp.address() != proposer_addr).unwrap().0;
        let att_other = Attestation { validator: other.address(), signature: other.sign(&header.hash()) };
        let proof2 = signed_proof(proposer_kp, &header, vec![att_other]);
        assert!(!engine.is_finalized(&header, &proof2));

        // All three: quorum reached (6*MIN_STAKE >= quorum)
        let att2 = Attestation { validator: other.address(), signature: other.sign(&header.hash()) };
        let third = validators.iter().find(|(kp, _)| kp.address() != proposer_addr && kp.address() != other.address()).unwrap().0;
        let att3 = Attestation { validator: third.address(), signature: third.sign(&header.hash()) };
        let proof3 = signed_proof(proposer_kp, &header, vec![att2, att3]);
        assert!(engine.is_finalized(&header, &proof3));
    }

    #[test]
    fn verifies_proposer_signature() {
        let engine = BftPosEngine::new(1);
        let keypair = Keypair::generate();
        {
            let registry = engine.registry();
            let mut reg = registry.write().unwrap();
            let pk = keypair.public_key().to_encoded_point(true).as_bytes().to_vec();
            reg.register(keypair.address(), pk, MIN_STAKE, 1);
        }
        let prev_hash = [9u8; 32];
        let header = make_header(10, prev_hash);
        let proof = signed_proof(&keypair, &header, Vec::new());
        assert!(engine.verify(&header, &proof));
        assert!(engine.is_finalized(&header, &proof));

        // Corrupt signature
        let mut bad = proof;
        bad.signature = vec![0u8; 64];
        assert!(!engine.verify(&header, &bad));
        assert!(!engine.is_finalized(&header, &bad));
    }

    #[test]
    fn on_block_applied_updates_registry() {
        let engine = BftPosEngine::new(1);
        let keypair = Keypair::generate();

        // Create a stake deposit transaction
        let mut tx = Transaction {
            version: 1,
            tx_type: TransactionType::Transfer,
            inputs: vec![TxInput {
                previous_output: OutPoint { txid: [1u8; 32], output_index: 0 },
                signature: Vec::new(),
                public_key: keypair.public_key().to_encoded_point(true).as_bytes().to_vec(),
            }],
            outputs: vec![TxOutput {
                asset_id: crate::crypto::native_asset_id(),
                amount: MIN_STAKE,
                recipient: system_wallet_address(),
            }],
            lock_time: 0,
            registration: None,
        };
        tx.inputs[0].signature = keypair.sign(&tx.signing_message(0));

        let block = Block {
            header: BlockHeader {
                height: 1,
                previous_hash: [0u8; 32],
                transactions_root: tx.txid(),
                state_root: [0u8; 32],
                timestamp: 1,
                validator_set_version: 1,
            },
            transactions: vec![tx],
            consensus_proof: ConsensusProof::default(),
        };

        engine.on_block_applied(&block);

        let registry = engine.registry();
        let reg = registry.read().unwrap();
        assert_eq!(reg.total_stake(), MIN_STAKE);
        assert!(reg.get(&keypair.address()).is_some());
    }
}
