//! On-chain validator registry and stake ledger.
//!
//! Two derived indexes are maintained alongside the UTXO set:
//!
//! * the **stake ledger** records, per wallet address, how much that wallet
//!   has paid into the system stake wallet in confirmed transfers;
//! * the **validator registry** records every approved node: its identity
//!   public key (and derived address), the stake wallet that paid for it, the
//!   stake amount at registration time and the height it joined.
//!
//! Both are pure functions of the applied block sequence, so every node that
//! applies the same blocks derives an identical view. Registration requests
//! travel as ordinary transactions ([`crate::block::TransactionType::
//! ValidatorRegistration`]) signed by the node's identity key; any block
//! containing an invalid request is rejected by every node, and because
//! blocks propagate through the existing sync path the registry converges
//! network-wide without extra messaging.
//!
//! Note: the registry is *not* yet wired into block signing - the consensus
//! validator set still comes from the node configuration. Feeding registered
//! node keys into proposer selection and quorum is the natural next step.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::block::Transaction;
use crate::crypto::{self, PublicKeyHash};
use crate::error::{Error, Result};

/// Total staked amount per stake-wallet address.
pub type StakeLedger = BTreeMap<PublicKeyHash, u128>;

/// Approved nodes, keyed by hex-encoded identity public key.
pub type NodeRegistry = BTreeMap<String, NodeRegistration>;

/// One approved node in the registry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeRegistration {
    /// SEC1 bytes of the node identity public key.
    pub node_public_key: Vec<u8>,
    /// Address derived from `node_public_key`.
    pub node_address: PublicKeyHash,
    /// The stake wallet that paid the minimum stake.
    pub stake_address: PublicKeyHash,
    /// Total stake paid by `stake_address` when the node registered.
    pub stake_amount: u128,
    /// Height of the block that contained the registration request.
    pub joined_height: u64,
}

/// Validate a validator-registration transaction against the current indexes.
///
/// A valid request:
/// * carries a registration payload and moves no coins,
/// * is signed by the node identity key it registers,
/// * names a stake wallet that has already paid at least [`crate::consensus::MIN_STAKE`]
///   into the system wallet (per the stake ledger), and
/// * is not a duplicate - neither the node key nor the stake wallet is
///   already registered.
pub fn validate_registration(
    tx: &Transaction,
    stakes: &StakeLedger,
    registry: &NodeRegistry,
) -> Result<()> {
    let registration = tx.registration.as_ref().ok_or_else(|| {
        Error::InvalidBlock("registration transaction without payload".to_string())
    })?;

    if !tx.inputs.is_empty() || !tx.outputs.is_empty() {
        return Err(Error::InvalidBlock(
            "registration transaction must not spend or create outputs".to_string(),
        ));
    }

    let key = crypto::parse_public_key(&registration.node_public_key)
        .map_err(|err| Error::InvalidBlock(format!("invalid node public key: {err}")))?;

    let txid = tx.txid();
    if registration.signature.is_empty()
        || !crypto::verify(&key, &txid, &registration.signature)
    {
        return Err(Error::InvalidBlock(
            "registration is not signed by the node identity key".to_string(),
        ));
    }

    let node_hex = hex::encode(&registration.node_public_key);
    if registry.contains_key(&node_hex) {
        return Err(Error::InvalidBlock(format!(
            "node {node_hex} is already registered"
        )));
    }
    if registry
        .values()
        .any(|entry| entry.stake_address == registration.stake_address)
    {
        return Err(Error::InvalidBlock(
            "stake wallet is already bound to another node".to_string(),
        ));
    }

    let staked = stakes
        .get(&registration.stake_address)
        .copied()
        .unwrap_or(0);
    if staked < crate::consensus::MIN_STAKE {
        return Err(Error::InvalidBlock(format!(
            "stake wallet has staked {} which is below the minimum {}",
            staked,
            crate::consensus::MIN_STAKE
        )));
    }

    Ok(())
}

/// Validate and apply a registration request to `registry`.
pub fn apply_registration(
    tx: &Transaction,
    height: u64,
    stakes: &StakeLedger,
    registry: &mut NodeRegistry,
) -> Result<()> {
    validate_registration(tx, stakes, registry)?;

    let registration = tx.registration.as_ref().expect("validated above");
    let key = crypto::parse_public_key(&registration.node_public_key)
        .map_err(|err| Error::InvalidBlock(format!("invalid node public key: {err}")))?;

    let entry = NodeRegistration {
        node_public_key: registration.node_public_key.clone(),
        node_address: crypto::address_from_public_key(&key),
        stake_address: registration.stake_address,
        stake_amount: stakes
            .get(&registration.stake_address)
            .copied()
            .unwrap_or(0),
        joined_height: height,
    };
    registry.insert(hex::encode(&registration.node_public_key), entry);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{OutPoint, RegistrationPayload, TransactionType, TxInput};
    use crate::consensus::MIN_STAKE;
    use crate::crypto::Keypair;
    use crate::genesis::COIN;

    fn stake(stakes: &mut StakeLedger, address: PublicKeyHash, amount: u128) {
        *stakes.entry(address).or_insert(0) += amount;
    }

    fn registration_tx(
        node: &Keypair,
        stake_address: PublicKeyHash,
    ) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type: TransactionType::ValidatorRegistration,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            registration: Some(RegistrationPayload {
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

    fn funded_stakes(stake_wallet: &Keypair) -> StakeLedger {
        let mut stakes = StakeLedger::new();
        stake(&mut stakes, stake_wallet.address(), MIN_STAKE);
        stakes
    }

    #[test]
    fn accepts_a_signed_registration_with_a_paid_stake() {
        let node = Keypair::generate();
        let wallet = Keypair::generate();
        let stakes = funded_stakes(&wallet);
        let mut registry = NodeRegistry::new();

        let tx = registration_tx(&node, wallet.address());
        apply_registration(&tx, 7, &stakes, &mut registry).unwrap();

        let entry = registry.get(&hex::encode(
            node.public_key().to_encoded_point(true).as_bytes(),
        ));
        let entry = entry.expect("registered");
        assert_eq!(entry.node_address, node.address());
        assert_eq!(entry.stake_address, wallet.address());
        assert_eq!(entry.stake_amount, MIN_STAKE);
        assert_eq!(entry.joined_height, 7);
    }

    #[test]
    fn rejects_an_unpaid_stake_wallet() {
        let node = Keypair::generate();
        let wallet = Keypair::generate();
        let stakes = StakeLedger::new();
        let mut registry = NodeRegistry::new();

        let tx = registration_tx(&node, wallet.address());
        let err = apply_registration(&tx, 1, &stakes, &mut registry).unwrap_err();
        assert!(matches!(err, Error::InvalidBlock(_)), "got {err:?}");
        assert!(registry.is_empty());
    }

    #[test]
    fn rejects_a_short_stake() {
        let node = Keypair::generate();
        let wallet = Keypair::generate();
        let mut stakes = StakeLedger::new();
        stake(&mut stakes, wallet.address(), MIN_STAKE - 1);
        let mut registry = NodeRegistry::new();

        let tx = registration_tx(&node, wallet.address());
        assert!(apply_registration(&tx, 1, &stakes, &mut registry).is_err());
    }

    #[test]
    fn rejects_a_bad_signature() {
        let node = Keypair::generate();
        let imposter = Keypair::generate();
        let wallet = Keypair::generate();
        let stakes = funded_stakes(&wallet);
        let mut registry = NodeRegistry::new();

        // Signed by a different key than the one being registered.
        let mut tx = registration_tx(&node, wallet.address());
        let txid = tx.txid();
        tx.registration.as_mut().expect("payload").signature = imposter.sign(&txid);
        assert!(apply_registration(&tx, 1, &stakes, &mut registry).is_err());
        assert!(registry.is_empty());
    }

    #[test]
    fn rejects_duplicates() {
        let node = Keypair::generate();
        let wallet = Keypair::generate();
        let stakes = funded_stakes(&wallet);
        let mut registry = NodeRegistry::new();

        let tx = registration_tx(&node, wallet.address());
        apply_registration(&tx, 1, &stakes, &mut registry).unwrap();

        // Same node key again.
        let err = apply_registration(&tx, 2, &stakes, &mut registry).unwrap_err();
        assert!(err.to_string().contains("already registered"), "got {err}");

        // Same stake wallet backing a different node key.
        let other_node = Keypair::generate();
        let other = registration_tx(&other_node, wallet.address());
        let err = apply_registration(&other, 2, &stakes, &mut registry).unwrap_err();
        assert!(err.to_string().contains("already bound"), "got {err}");
    }

    #[test]
    fn rejects_coin_moving_registrations() {
        let node = Keypair::generate();
        let wallet = Keypair::generate();
        let stakes = funded_stakes(&wallet);
        let mut registry = NodeRegistry::new();

        let mut tx = registration_tx(&node, wallet.address());
        tx.inputs.push(TxInput {
            previous_output: OutPoint {
                txid: [0u8; 32],
                output_index: 0,
            },
            signature: Vec::new(),
            public_key: Vec::new(),
        });
        assert!(apply_registration(&tx, 1, &stakes, &mut registry).is_err());
    }
}
