//! On-chain validator registry, stake ledger and governance.
//!
//! Three derived indexes live alongside the UTXO set:
//!
//! * the **stake ledger** records, per wallet address, which outputs were paid
//!   into the system stake wallet. Keeping the individual outputs (rather than
//!   only a total) is what makes a refund possible: the chain can release
//!   exactly the coins a node deposited;
//! * the **validator registry** records every node that asked to join, its
//!   lifecycle status and the votes cast on it;
//! * the **governance parameters** (approval/rejection thresholds, voting
//!   window and the override keys) are consensus-critical and are stored in the
//!   chain state, not in local configuration.
//!
//! # Lifecycle
//!
//! ```text
//! registration ──► Pending ──(≥ threshold approve)──► Approved
//!                     │
//!                     ├──(≥ threshold reject)──────► Rejected  (stake refunded)
//!                     └──(voting window elapsed)───► Rejected  (stake refunded)
//!
//! Approved ──(override key signs NodeRemoval)──────► Removed   (stake refunded)
//! ```
//!
//! All of these transitions are driven by ordinary transactions
//! ([`TransactionType::ValidatorRegistration`], [`TransactionType::ValidatorVote`]
//! and [`TransactionType::NodeRemoval`]) that are executed while applying a
//! block. Because every node executes the same block sequence, every node
//! derives the same registry - no separate consensus channel is needed for
//! membership.
//!
//! # Why the removal is a transaction, not a side effect of a broadcast
//!
//! An override key broadcasts a signed removal request, but the request only
//! takes effect once it is included in a block. Applying it immediately on
//! receipt would let a node that saw the message diverge from one that did not,
//! forking the chain. The broadcast is therefore the transport, and the block is
//! the decision.

use std::collections::BTreeMap;

use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::block::Transaction;
use crate::crypto::{self, Address, PublicKeyHash};
use crate::error::{Error, Result};

/// Hex-encoded node identity public key used as the registry key.
pub type NodeKey = String;

/// Lifecycle status of a registered node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    /// Registration accepted, waiting for the validators to vote.
    Pending,
    /// Active validator: may vote and produce/verify blocks.
    Approved,
    /// Rejected by the validators or by the voting window; stake refunded.
    Rejected,
    /// Removed by an override key; stake refunded.
    Removed,
}

impl NodeStatus {
    /// Stable lowercase label for APIs and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            NodeStatus::Pending => "pending",
            NodeStatus::Approved => "approved",
            NodeStatus::Rejected => "rejected",
            NodeStatus::Removed => "removed",
        }
    }

    /// Whether the node is part of the active validator set.
    pub fn is_active(self) -> bool {
        matches!(self, NodeStatus::Approved)
    }

    /// Whether the node is still awaiting a decision.
    pub fn is_pending(self) -> bool {
        matches!(self, NodeStatus::Pending)
    }
}

/// One node known to the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRegistration {
    /// SEC1 bytes of the node identity public key.
    pub node_public_key: Vec<u8>,
    /// Address derived from `node_public_key`.
    pub node_address: Address,
    /// The stake wallet that paid the minimum stake. `[0; 32]` for nodes seeded
    /// from the genesis validator set, which carry no on-chain stake.
    pub stake_address: PublicKeyHash,
    /// Total stake paid by `stake_address` when the node registered.
    pub stake_amount: u128,
    /// Height of the block that contained the registration request.
    pub joined_height: u64,
    /// Current lifecycle status.
    pub status: NodeStatus,
    /// Validator addresses eligible to vote on this proposal, snapshotted when
    /// the registration was applied so the threshold cannot move mid-vote.
    pub eligible_voters: Vec<Address>,
    /// Validators that voted to approve.
    #[serde(default)]
    pub approve_votes: Vec<Address>,
    /// Validators that voted to reject.
    #[serde(default)]
    pub reject_votes: Vec<Address>,
    /// Height at which the final status was decided.
    #[serde(default)]
    pub decided_height: Option<u64>,
}

impl NodeRegistration {
    /// Whether this entry was seeded from the genesis validator set.
    pub fn is_genesis(&self) -> bool {
        self.stake_address == [0u8; 32]
    }

    /// Whether `voter` already cast a vote on this proposal.
    pub fn has_voted(&self, voter: &Address) -> bool {
        self.approve_votes.contains(voter) || self.reject_votes.contains(voter)
    }
}

/// Approved and pending nodes, keyed by hex-encoded identity public key.
pub type NodeRegistry = BTreeMap<NodeKey, NodeRegistration>;

/// A single output paying the system stake wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeDeposit {
    pub txid: [u8; 32],
    pub output_index: u32,
    pub amount: u128,
}

/// Everything a stake wallet has paid into the system wallet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeAccount {
    pub total: u128,
    /// The individual system-wallet outputs backing `total`, in deposit order.
    pub deposits: Vec<StakeDeposit>,
}

impl StakeAccount {
    /// Record a new deposit.
    pub fn deposit(&mut self, txid: [u8; 32], output_index: u32, amount: u128) -> Result<()> {
        self.total = self
            .total
            .checked_add(amount)
            .ok_or_else(|| Error::InvalidBlock("stake ledger overflow".to_string()))?;
        self.deposits.push(StakeDeposit {
            txid,
            output_index,
            amount,
        });
        Ok(())
    }
}

/// Total staked amount per stake-wallet address.
pub type StakeLedger = BTreeMap<PublicKeyHash, StakeAccount>;

/// Consensus-critical governance parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Governance {
    /// Fraction of eligible validators that must approve, in basis points.
    pub approval_threshold_bps: u32,
    /// Fraction of eligible validators that must reject, in basis points.
    pub rejection_threshold_bps: u32,
    /// Blocks a pending proposal stays open. `0` disables automatic expiry.
    pub voting_period_blocks: u64,
    /// Addresses allowed to unilaterally remove a node.
    pub override_keys: Vec<Address>,
}

impl Default for Governance {
    fn default() -> Self {
        Self {
            approval_threshold_bps: 9_000,
            rejection_threshold_bps: 9_000,
            voting_period_blocks: 0,
            override_keys: Vec::new(),
        }
    }
}

impl Governance {
    fn threshold_reached(&self, votes: usize, eligible: usize, bps: u32) -> bool {
        if eligible == 0 {
            return false;
        }
        (votes as u128) * 10_000 >= (eligible as u128) * (bps as u128)
    }

    fn approved(&self, votes: usize, eligible: usize) -> bool {
        self.threshold_reached(votes, eligible, self.approval_threshold_bps)
    }

    fn rejected(&self, votes: usize, eligible: usize) -> bool {
        self.threshold_reached(votes, eligible, self.rejection_threshold_bps)
    }
}

/// Coins the chain must release from the system wallet back to a stake wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refund {
    pub stake_address: PublicKeyHash,
    /// System-wallet outputs to spend.
    pub deposits: Vec<StakeDeposit>,
    /// Sum of `deposits`.
    pub amount: u128,
}

/// Resolve the configured hex public keys of the override set into addresses.
pub fn parse_override_keys(entries: &[String]) -> Result<Vec<Address>> {
    let mut keys = Vec::new();
    for raw in entries {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let bytes = hex::decode(raw)
            .map_err(|err| Error::Config(format!("invalid override key hex: {err}")))?;
        let key = crypto::parse_public_key(&bytes)
            .map_err(|err| Error::Config(format!("invalid override public key: {err}")))?;
        keys.push(crypto::address_from_public_key(&key));
    }
    keys.sort_unstable();
    keys.dedup();
    Ok(keys)
}

/// Seed the registry with the genesis validator set, marked `Approved`.
///
/// These nodes are the root of trust: they are the only validators that can
/// vote on the first admission.
pub fn seed_genesis_validators(
    registry: &mut NodeRegistry,
    validators: &[VerifyingKey],
    height: u64,
) {
    for key in validators {
        let public_key = key.to_encoded_point(true).as_bytes().to_vec();
        let node_hex = hex::encode(&public_key);
        registry.entry(node_hex).or_insert_with(|| NodeRegistration {
            node_address: crypto::address_from_public_key(key),
            node_public_key: public_key,
            stake_address: [0u8; 32],
            stake_amount: 0,
            joined_height: height,
            status: NodeStatus::Approved,
            eligible_voters: Vec::new(),
            approve_votes: Vec::new(),
            reject_votes: Vec::new(),
            decided_height: Some(height),
        });
    }
}

/// Addresses of every currently approved node, in deterministic order.
pub fn approved_voters(registry: &NodeRegistry) -> Vec<Address> {
    let mut voters: Vec<Address> = registry
        .values()
        .filter(|entry| entry.status.is_active())
        .map(|entry| entry.node_address)
        .collect();
    voters.sort_unstable();
    voters.dedup();
    voters
}

/// Public keys of every currently approved node, sorted by address.
pub fn approved_public_keys(registry: &NodeRegistry) -> Vec<Vec<u8>> {
    let mut approved: Vec<&NodeRegistration> =
        registry.values().filter(|e| e.status.is_active()).collect();
    approved.sort_by_key(|entry| entry.node_address);
    approved
        .into_iter()
        .map(|entry| entry.node_public_key.clone())
        .collect()
}

/// Validate a validator-registration transaction.
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
    if registration.signature.is_empty() || !crypto::verify(&key, &txid, &registration.signature) {
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
    if registry.values().any(|entry| {
        !entry.is_genesis() && entry.stake_address == registration.stake_address
    }) {
        return Err(Error::InvalidBlock(
            "stake wallet is already bound to another node".to_string(),
        ));
    }

    let staked = stake_total(stakes, &registration.stake_address);
    if staked < crate::consensus::MIN_STAKE {
        return Err(Error::InvalidBlock(format!(
            "stake wallet has staked {} which is below the minimum {}",
            staked,
            crate::consensus::MIN_STAKE
        )));
    }

    Ok(())
}

/// Validate and apply a registration request. The node starts `Pending`.
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
        stake_amount: stake_total(stakes, &registration.stake_address),
        joined_height: height,
        status: NodeStatus::Pending,
        eligible_voters: approved_voters(registry),
        approve_votes: Vec::new(),
        reject_votes: Vec::new(),
        decided_height: None,
    };
    registry.insert(hex::encode(&registration.node_public_key), entry);
    Ok(())
}

/// Validate a vote on a pending proposal.
pub fn validate_vote(
    tx: &Transaction,
    height: u64,
    registry: &NodeRegistry,
    governance: &Governance,
) -> Result<()> {
    let vote = tx
        .vote
        .as_ref()
        .ok_or_else(|| Error::InvalidBlock("vote transaction without payload".to_string()))?;

    if !tx.inputs.is_empty() || !tx.outputs.is_empty() {
        return Err(Error::InvalidBlock(
            "vote transaction must not spend or create outputs".to_string(),
        ));
    }

    let voter_key = crypto::parse_public_key(&vote.voter_public_key)
        .map_err(|err| Error::InvalidBlock(format!("invalid voter public key: {err}")))?;
    let voter_address = crypto::address_from_public_key(&voter_key);

    let txid = tx.txid();
    if vote.signature.is_empty() || !crypto::verify(&voter_key, &txid, &vote.signature) {
        return Err(Error::InvalidBlock(
            "vote is not signed by the voter identity key".to_string(),
        ));
    }

    let voter_hex = hex::encode(&vote.voter_public_key);
    match registry.get(&voter_hex) {
        Some(entry) if entry.status.is_active() => {}
        _ => {
            return Err(Error::InvalidBlock(
                "vote is not cast by an approved validator".to_string(),
            ))
        }
    }

    let target_hex = hex::encode(&vote.target_node_public_key);
    let target = registry.get(&target_hex).ok_or_else(|| {
        Error::InvalidBlock(format!("vote targets unknown node {target_hex}"))
    })?;

    if !target.status.is_pending() {
        return Err(Error::InvalidBlock(format!(
            "node {target_hex} is no longer pending"
        )));
    }
    if !target.eligible_voters.contains(&voter_address) {
        return Err(Error::InvalidBlock(
            "voter was not eligible for this proposal".to_string(),
        ));
    }
    if target.has_voted(&voter_address) {
        return Err(Error::InvalidBlock(
            "validator has already voted on this node".to_string(),
        ));
    }

    if let Some(expiry) = proposal_expiry(target, governance) {
        if height > expiry {
            return Err(Error::InvalidBlock(
                "the voting window for this proposal has closed".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validate and apply a vote, returning a refund when the vote decides the
/// proposal as rejected.
pub fn apply_vote(
    tx: &Transaction,
    height: u64,
    registry: &mut NodeRegistry,
    stakes: &mut StakeLedger,
    governance: &Governance,
) -> Result<Option<Refund>> {
    validate_vote(tx, height, registry, governance)?;
    let vote = tx.vote.as_ref().expect("validated above");
    let voter_address = crypto::address_from_public_key(
        &crypto::parse_public_key(&vote.voter_public_key)
            .map_err(|err| Error::InvalidBlock(format!("invalid voter public key: {err}")))?,
    );

    let target_hex = hex::encode(&vote.target_node_public_key);
    let target = registry
        .get_mut(&target_hex)
        .expect("validated above");

    if vote.approve {
        target.approve_votes.push(voter_address);
        target.approve_votes.sort_unstable();
    } else {
        target.reject_votes.push(voter_address);
        target.reject_votes.sort_unstable();
    }

    let eligible = target.eligible_voters.len();
    if governance.approved(target.approve_votes.len(), eligible) {
        target.status = NodeStatus::Approved;
        target.decided_height = Some(height);
        return Ok(None);
    }
    if governance.rejected(target.reject_votes.len(), eligible) {
        target.status = NodeStatus::Rejected;
        target.decided_height = Some(height);
        let stake_address = target.stake_address;
        return Ok(take_refund(stake_address, stakes));
    }

    Ok(None)
}

/// Validate an override removal request.
pub fn validate_removal(
    tx: &Transaction,
    registry: &NodeRegistry,
    governance: &Governance,
) -> Result<()> {
    let removal = tx
        .removal
        .as_ref()
        .ok_or_else(|| Error::InvalidBlock("removal transaction without payload".to_string()))?;

    if !tx.inputs.is_empty() || !tx.outputs.is_empty() {
        return Err(Error::InvalidBlock(
            "removal transaction must not spend or create outputs".to_string(),
        ));
    }

    let override_key = crypto::parse_public_key(&removal.override_public_key)
        .map_err(|err| Error::InvalidBlock(format!("invalid override public key: {err}")))?;
    let override_address = crypto::address_from_public_key(&override_key);

    if !governance.override_keys.contains(&override_address) {
        return Err(Error::InvalidBlock(
            "removal is not signed by a configured override key".to_string(),
        ));
    }

    let txid = tx.txid();
    if removal.signature.is_empty() || !crypto::verify(&override_key, &txid, &removal.signature) {
        return Err(Error::InvalidBlock(
            "removal proof is not valid for the override key".to_string(),
        ));
    }

    let target_hex = hex::encode(&removal.target_node_public_key);
    let target = registry.get(&target_hex).ok_or_else(|| {
        Error::InvalidBlock(format!("removal targets unknown node {target_hex}"))
    })?;

    if target.is_genesis() {
        return Err(Error::InvalidBlock(
            "genesis validators cannot be removed by an override key".to_string(),
        ));
    }
    if !matches!(target.status, NodeStatus::Pending | NodeStatus::Approved) {
        return Err(Error::InvalidBlock(format!(
            "node {target_hex} is already {}",
            target.status.as_str()
        )));
    }

    Ok(())
}

/// Validate and apply an override removal, returning the stake refund.
pub fn apply_removal(
    tx: &Transaction,
    height: u64,
    registry: &mut NodeRegistry,
    stakes: &mut StakeLedger,
    governance: &Governance,
) -> Result<Option<Refund>> {
    validate_removal(tx, registry, governance)?;
    let removal = tx.removal.as_ref().expect("validated above");
    let target_hex = hex::encode(&removal.target_node_public_key);
    let target = registry.get_mut(&target_hex).expect("validated above");

    target.status = NodeStatus::Removed;
    target.decided_height = Some(height);
    let stake_address = target.stake_address;
    Ok(take_refund(stake_address, stakes))
}

/// Reject proposals whose voting window closed before `height`.
///
/// Returns the nodes that were rejected and the refunds they are owed.
pub fn expire_pending(
    height: u64,
    registry: &mut NodeRegistry,
    stakes: &mut StakeLedger,
    governance: &Governance,
) -> Vec<(NodeKey, Refund)> {
    let expired: Vec<NodeKey> = registry
        .values()
        .filter(|entry| entry.status.is_pending())
        .filter(|entry| match proposal_expiry(entry, governance) {
            Some(expiry) => height > expiry,
            None => false,
        })
        .map(|entry| hex::encode(&entry.node_public_key))
        .collect();

    let mut refunds = Vec::new();
    for node_hex in expired {
        if let Some(entry) = registry.get_mut(&node_hex) {
            entry.status = NodeStatus::Rejected;
            entry.decided_height = Some(height);
            let stake_address = entry.stake_address;
            if let Some(refund) = take_refund(stake_address, stakes) {
                refunds.push((node_hex, refund));
            }
        }
    }
    refunds
}

/// The height after which a pending proposal can no longer be voted on.
///
/// `None` means the proposal never expires.
fn proposal_expiry(entry: &NodeRegistration, governance: &Governance) -> Option<u64> {
    if governance.voting_period_blocks == 0 || !entry.status.is_pending() {
        return None;
    }
    Some(entry.joined_height + governance.voting_period_blocks)
}

/// Total staked by `address`.
pub fn stake_total(stakes: &StakeLedger, address: &PublicKeyHash) -> u128 {
    stakes.get(address).map(|account| account.total).unwrap_or(0)
}

/// Remove and return everything `address` paid into the system wallet.
///
/// The stake account is cleared so the refund can never be paid twice.
pub fn take_refund(
    stake_address: PublicKeyHash,
    stakes: &mut StakeLedger,
) -> Option<Refund> {
    let account = stakes.remove(&stake_address)?;
    if account.total == 0 || account.deposits.is_empty() {
        return None;
    }
    Some(Refund {
        stake_address,
        deposits: account.deposits,
        amount: account.total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{RegistrationPayload, TransactionType, VotePayload};
    use crate::consensus::MIN_STAKE;
    use crate::crypto::Keypair;

    fn stake(stakes: &mut StakeLedger, address: PublicKeyHash, amount: u128) {
        let account = stakes.entry(address).or_default();
        account.deposit([7u8; 32], 0, amount).unwrap();
    }

    fn registration_tx(node: &Keypair, stake_address: PublicKeyHash) -> Transaction {
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
            vote: None,
            removal: None,
        };
        let txid = tx.txid();
        tx.registration
            .as_mut()
            .expect("payload")
            .signature = node.sign(&txid);
        tx
    }

    fn vote_tx(voter: &Keypair, target: &Keypair, approve: bool) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type: TransactionType::ValidatorVote,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            registration: None,
            vote: Some(VotePayload {
                voter_public_key: voter
                    .public_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec(),
                target_node_public_key: target
                    .public_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec(),
                approve,
                signature: Vec::new(),
            }),
            removal: None,
        };
        let txid = tx.txid();
        tx.vote.as_mut().expect("payload").signature = voter.sign(&txid);
        tx
    }

    fn funded_stakes(stake_wallet: &Keypair) -> StakeLedger {
        let mut stakes = StakeLedger::new();
        stake(&mut stakes, stake_wallet.address(), MIN_STAKE);
        stakes
    }

    fn key_hex(key: &Keypair) -> String {
        hex::encode(key.public_key().to_encoded_point(true).as_bytes())
    }

    /// Build a registry containing `validators` as approved genesis nodes.
    fn genesis_registry(validators: &[&Keypair]) -> NodeRegistry {
        let mut registry = NodeRegistry::new();
        for validator in validators {
            let public_key = validator.public_key().to_encoded_point(true).as_bytes().to_vec();
            registry.insert(
                hex::encode(&public_key),
                NodeRegistration {
                    node_address: validator.address(),
                    node_public_key: public_key,
                    stake_address: [0u8; 32],
                    stake_amount: 0,
                    joined_height: 0,
                    status: NodeStatus::Approved,
                    eligible_voters: Vec::new(),
                    approve_votes: Vec::new(),
                    reject_votes: Vec::new(),
                    decided_height: Some(0),
                },
            );
        }
        registry
    }

    #[test]
    fn registration_starts_pending_and_snapshots_voters() {
        let voter = Keypair::generate();
        let node = Keypair::generate();
        let wallet = Keypair::generate();
        let stakes = funded_stakes(&wallet);
        let mut registry = genesis_registry(&[&voter]);

        let tx = registration_tx(&node, wallet.address());
        apply_registration(&tx, 5, &stakes, &mut registry).unwrap();

        let entry = registry.get(&key_hex(&node)).expect("registered");
        assert_eq!(entry.status, NodeStatus::Pending);
        assert_eq!(entry.eligible_voters, vec![voter.address()]);
        assert_eq!(entry.stake_amount, MIN_STAKE);
        assert_eq!(entry.decided_height, None);
    }

    #[test]
    fn eighty_nine_percent_is_not_enough_but_ninety_is() {
        let voters: Vec<Keypair> = (0..10).map(|_| Keypair::generate()).collect();
        let voter_refs: Vec<&Keypair> = voters.iter().collect();
        let node = Keypair::generate();
        let wallet = Keypair::generate();
        let mut stakes = funded_stakes(&wallet);
        let mut registry = genesis_registry(&voter_refs);
        let governance = Governance::default();

        apply_registration(&registration_tx(&node, wallet.address()), 1, &stakes, &mut registry)
            .unwrap();

        // 8 approvals out of 10 is 80% - still pending.
        for voter in voters.iter().take(8) {
            let refund =
                apply_vote(&vote_tx(voter, &node, true), 2, &mut registry, &mut stakes, &governance)
                    .unwrap();
            assert!(refund.is_none());
        }
        assert_eq!(registry[&key_hex(&node)].status, NodeStatus::Pending);

        // The ninth approval crosses 90%.
        apply_vote(&vote_tx(&voters[8], &node, true), 3, &mut registry, &mut stakes, &governance)
            .unwrap();
        assert_eq!(registry[&key_hex(&node)].status, NodeStatus::Approved);
        assert_eq!(registry[&key_hex(&node)].decided_height, Some(3));
    }

    #[test]
    fn rejection_refunds_the_stake() {
        let voter = Keypair::generate();
        let node = Keypair::generate();
        let wallet = Keypair::generate();
        let mut stakes = funded_stakes(&wallet);
        let mut registry = genesis_registry(&[&voter]);
        let governance = Governance::default();

        apply_registration(&registration_tx(&node, wallet.address()), 1, &stakes, &mut registry)
            .unwrap();

        // One of one eligible voters rejects: 100% >= 90%.
        let refund =
            apply_vote(&vote_tx(&voter, &node, false), 2, &mut registry, &mut stakes, &governance)
                .unwrap();

        let refund = refund.expect("stake refund");
        assert_eq!(refund.stake_address, wallet.address());
        assert_eq!(refund.amount, MIN_STAKE);
        assert_eq!(registry[&key_hex(&node)].status, NodeStatus::Rejected);
        assert!(stakes.get(&wallet.address()).is_none(), "account cleared");
    }

    #[test]
    fn a_validator_cannot_vote_twice() {
        let voters: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();
        let voter_refs: Vec<&Keypair> = voters.iter().collect();
        let node = Keypair::generate();
        let wallet = Keypair::generate();
        let mut stakes = funded_stakes(&wallet);
        let mut registry = genesis_registry(&voter_refs);
        let governance = Governance::default();

        apply_registration(&registration_tx(&node, wallet.address()), 1, &stakes, &mut registry)
            .unwrap();
        // One of three is not enough to decide either way.
        apply_vote(&vote_tx(&voters[0], &node, true), 2, &mut registry, &mut stakes, &governance)
            .unwrap();
        assert_eq!(registry[&key_hex(&node)].status, NodeStatus::Pending);

        let err = apply_vote(
            &vote_tx(&voters[0], &node, false),
            3,
            &mut registry,
            &mut stakes,
            &governance,
        )
        .unwrap_err();
        assert!(err.to_string().contains("already voted"), "got {err}");
    }

    #[test]
    fn a_non_validator_cannot_vote() {
        let voter = Keypair::generate();
        let outsider = Keypair::generate();
        let node = Keypair::generate();
        let wallet = Keypair::generate();
        let mut stakes = funded_stakes(&wallet);
        let mut registry = genesis_registry(&[&voter]);
        let governance = Governance::default();

        apply_registration(&registration_tx(&node, wallet.address()), 1, &stakes, &mut registry)
            .unwrap();

        let err = apply_vote(
            &vote_tx(&outsider, &node, true),
            2,
            &mut registry,
            &mut stakes,
            &governance,
        )
        .unwrap_err();
        assert!(err.to_string().contains("approved validator"), "got {err}");
    }

    #[test]
    fn expiry_rejects_a_stalled_proposal_and_refunds() {
        let voter = Keypair::generate();
        let node = Keypair::generate();
        let wallet = Keypair::generate();
        let mut stakes = funded_stakes(&wallet);
        let mut registry = genesis_registry(&[&voter]);
        let governance = Governance {
            voting_period_blocks: 1,
            ..Governance::default()
        };

        apply_registration(&registration_tx(&node, wallet.address()), 1, &stakes, &mut registry)
            .unwrap();

        // Expiry is joined_height + period = 2, so it is still open at height 1.
        assert!(expire_pending(1, &mut registry, &mut stakes, &governance).is_empty());

        let refunds = expire_pending(3, &mut registry, &mut stakes, &governance);
        assert_eq!(refunds.len(), 1);
        assert_eq!(refunds[0].1.amount, MIN_STAKE);
        assert_eq!(registry[&key_hex(&node)].status, NodeStatus::Rejected);
        assert!(stakes.get(&wallet.address()).is_none());
    }

    #[test]
    fn rejects_duplicates_and_unfunded_stakes() {
        let voter = Keypair::generate();
        let node = Keypair::generate();
        let wallet = Keypair::generate();
        let stakes = funded_stakes(&wallet);
        let mut registry = genesis_registry(&[&voter]);

        let tx = registration_tx(&node, wallet.address());
        apply_registration(&tx, 1, &stakes, &mut registry).unwrap();

        let err = apply_registration(&tx, 2, &stakes, &mut registry).unwrap_err();
        assert!(err.to_string().contains("already registered"), "got {err}");

        let poor_node = Keypair::generate();
        let poor_wallet = Keypair::generate();
        let err =
            apply_registration(&registration_tx(&poor_node, poor_wallet.address()), 2, &stakes, &mut registry)
                .unwrap_err();
        assert!(err.to_string().contains("below the minimum"), "got {err}");
    }

    #[test]
    fn duplicate_stake_wallets_are_rejected() {
        let voter = Keypair::generate();
        let first = Keypair::generate();
        let second = Keypair::generate();
        let wallet = Keypair::generate();
        let stakes = funded_stakes(&wallet);
        let mut registry = genesis_registry(&[&voter]);

        apply_registration(&registration_tx(&first, wallet.address()), 1, &stakes, &mut registry)
            .unwrap();

        let err = apply_registration(
            &registration_tx(&second, wallet.address()),
            2,
            &stakes,
            &mut registry,
        )
        .unwrap_err();
        assert!(err.to_string().contains("already bound"), "got {err}");
    }

    #[test]
    fn threshold_rounds_up() {
        let governance = Governance::default();
        // 1 of 1, 9 of 10, 10 of 10.
        assert!(governance.approved(1, 1));
        assert!(governance.approved(9, 10));
        assert!(!governance.approved(8, 10));
        // 2 of 2, 3 of 3.
        assert!(governance.approved(2, 2));
        assert!(governance.approved(3, 3));
        // 2 of 3 is 66% - not enough.
        assert!(!governance.approved(2, 3));
    }
}
