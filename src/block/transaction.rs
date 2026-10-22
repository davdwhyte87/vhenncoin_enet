//! UTXO transaction model.
//!
//! Coins are never moved between accounts. Instead a transaction *spends*
//! existing unspent outputs (UTXOs) and *creates* new ones:
//!
//! * [`TxInput`] references an existing output and carries the proof that the
//!   spender is allowed to consume it.
//! * [`TxOutput`] creates new spendable funds for a recipient.
//! * [`OutPoint`] identifies one specific output by `(txid, output_index)`.
//! * [`Transaction`] groups inputs and outputs into a single transfer.
//!
//! There are intentionally no gas fees and no transaction fees.
//!
//! Besides transfers, three governance transaction kinds travel as ordinary
//! transactions and are therefore applied deterministically by every node when
//! their block is executed: validator registration, validator votes and
//! override removals.

use serde::{Deserialize, Serialize};

use crate::crypto::{self, AssetId, Hash, PublicKeyHash};

/// Identifier of a transaction: the SHA-256 of its canonical encoding.
pub type Txid = Hash;

/// Kind of transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionType {
    /// Spends existing outputs and creates new ones.
    Transfer,
    /// The fee-less mint transaction. Only valid as the first transaction of
    /// the genesis block.
    Coinbase,
    /// Requests admission to the validator set: binds a node identity public
    /// key to a stake wallet that has already paid the minimum stake into the
    /// system wallet. The node starts in `Pending` and only becomes a
    /// validator once the current validators approve it. Moves no coins.
    ValidatorRegistration,
    /// Casts an approval or rejection vote for a pending node.
    ValidatorVote,
    /// Removes an approved (or pending) node using one of the configured
    /// override keys. Moves no coins itself; the refund is applied by the
    /// chain.
    NodeRemoval,
}

impl TransactionType {
    /// Stable byte used in the canonical encoding.
    pub fn code(self) -> u8 {
        match self {
            TransactionType::Transfer => 0,
            TransactionType::Coinbase => 1,
            TransactionType::ValidatorRegistration => 2,
            TransactionType::ValidatorVote => 3,
            TransactionType::NodeRemoval => 4,
        }
    }
}

/// Points at a specific output of a specific transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Txid,
    pub output_index: u32,
}

/// Consumes a previously created output, proving ownership of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInput {
    pub previous_output: OutPoint,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Creates new spendable funds for a recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    pub asset_id: AssetId,
    pub amount: u128,
    pub recipient: PublicKeyHash,
}

/// Payload carried by a [`TransactionType::ValidatorRegistration`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationPayload {
    /// SEC1 bytes of the registering node's identity public key.
    pub node_public_key: Vec<u8>,
    /// Address of the admin wallet that paid the stake.
    pub stake_address: PublicKeyHash,
    /// Signature by the node identity key over the transaction id, proving
    /// control of `node_public_key`. Excluded from the canonical encoding so
    /// it cannot mutate the txid.
    #[serde(default)]
    pub signature: Vec<u8>,
}

/// Payload carried by a [`TransactionType::ValidatorVote`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VotePayload {
    /// SEC1 bytes of the voting validator's identity public key.
    pub voter_public_key: Vec<u8>,
    /// SEC1 bytes of the node being voted on.
    pub target_node_public_key: Vec<u8>,
    /// `true` approves the node, `false` rejects it.
    pub approve: bool,
    /// Signature by the voter's identity key over the transaction id.
    #[serde(default)]
    pub signature: Vec<u8>,
}

/// Payload carried by a [`TransactionType::NodeRemoval`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovalPayload {
    /// SEC1 bytes of the override public key authorising the removal.
    pub override_public_key: Vec<u8>,
    /// SEC1 bytes of the node being removed.
    pub target_node_public_key: Vec<u8>,
    /// Signature by the override key over the transaction id.
    #[serde(default)]
    pub signature: Vec<u8>,
}

/// A transfer: a set of outputs being spent and a set of outputs being created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u16,
    pub tx_type: TransactionType,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u64,
    /// Present only for [`TransactionType::ValidatorRegistration`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<RegistrationPayload>,
    /// Present only for [`TransactionType::ValidatorVote`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vote: Option<VotePayload>,
    /// Present only for [`TransactionType::NodeRemoval`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removal: Option<RemovalPayload>,
}

impl Transaction {
    /// Whether this is the fee-less mint transaction.
    pub fn is_coinbase(&self) -> bool {
        matches!(self.tx_type, TransactionType::Coinbase)
    }

    /// Whether this is a validator-registration request.
    pub fn is_registration(&self) -> bool {
        matches!(self.tx_type, TransactionType::ValidatorRegistration)
    }

    /// Whether this is a validator vote.
    pub fn is_vote(&self) -> bool {
        matches!(self.tx_type, TransactionType::ValidatorVote)
    }

    /// Whether this is an override removal.
    pub fn is_removal(&self) -> bool {
        matches!(self.tx_type, TransactionType::NodeRemoval)
    }

    /// Whether this transaction participates in governance rather than moving
    /// coins.
    pub fn is_governance(&self) -> bool {
        self.is_registration() || self.is_vote() || self.is_removal()
    }

    /// Total value created across all outputs.
    pub fn total_output(&self) -> u128 {
        self.outputs.iter().map(|output| output.amount).sum()
    }

    /// Canonical byte encoding used for hashing and signing.
    ///
    /// Signatures are deliberately excluded so the transaction id cannot be
    /// mutated by re-encoding a valid signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.push(self.tx_type.code());

        buf.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            buf.extend_from_slice(&input.previous_output.txid);
            buf.extend_from_slice(&input.previous_output.output_index.to_le_bytes());
            write_bytes(&mut buf, &input.public_key);
        }

        buf.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for output in &self.outputs {
            buf.extend_from_slice(&output.asset_id);
            buf.extend_from_slice(&output.amount.to_le_bytes());
            buf.extend_from_slice(&output.recipient);
        }

        // Governance requests commit their identifying fields to the txid; the
        // signatures stay outside the encoding, like input signatures.
        if let Some(registration) = &self.registration {
            write_bytes(&mut buf, &registration.node_public_key);
            buf.extend_from_slice(&registration.stake_address);
        }
        if let Some(vote) = &self.vote {
            write_bytes(&mut buf, &vote.voter_public_key);
            write_bytes(&mut buf, &vote.target_node_public_key);
            buf.push(u8::from(vote.approve));
        }
        if let Some(removal) = &self.removal {
            write_bytes(&mut buf, &removal.override_public_key);
            write_bytes(&mut buf, &removal.target_node_public_key);
        }

        buf.extend_from_slice(&self.lock_time.to_le_bytes());
        buf
    }

    /// The transaction id (hash of the canonical encoding).
    pub fn txid(&self) -> Txid {
        crypto::sha256(&self.encode())
    }

    /// Message an input signs to authorise spending.
    ///
    /// The txid commits to every field except the signatures, and the input
    /// index binds the signature to the specific output being consumed so one
    /// input's signature cannot be replayed for another.
    pub fn signing_message(&self, input_index: u32) -> Vec<u8> {
        let mut msg = Vec::with_capacity(36);
        msg.extend_from_slice(&self.txid());
        msg.extend_from_slice(&input_index.to_le_bytes());
        msg
    }
}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}
