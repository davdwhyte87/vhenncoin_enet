//! Cryptographic primitives: hashing, addresses and key pairs.
//!
//! Only the building blocks live here for now; signing/verification is kept
//! intentionally small and will be wired into transactions and blocks later.

use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// A 32-byte hash digest.
pub type Hash = [u8; 32];

/// A 32-byte account / validator address.
pub type Address = [u8; 32];

/// Hash of a public key, used as the UTXO recipient identity.
pub type PublicKeyHash = [u8; 32];

/// Identifier of an asset tracked by the UTXO set.
pub type AssetId = [u8; 32];

/// Length of a hash or address in bytes.
pub const HASH_LEN: usize = 32;

/// SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();

    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Hash of two child hashes, used while building a Merkle tree.
pub fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; HASH_LEN * 2];
    buf[..HASH_LEN].copy_from_slice(left);
    buf[HASH_LEN..].copy_from_slice(right);
    sha256(&buf)
}

/// Merkle root of a list of leaf hashes.
///
/// An empty list yields the all-zero hash. Odd nodes are promoted unchanged to
/// the next level until a single root remains.
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return [0u8; HASH_LEN];
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [left, right] => next.push(hash_pair(left, right)),
                [only] => next.push(*only),
                _ => unreachable!("chunks(2) yields 1 or 2 items"),
            }
        }
        level = next;
    }

    level[0]
}

/// The asset id of the native VHN coin.
pub fn native_asset_id() -> AssetId {
    sha256(b"VHN")
}

/// Derive an [`Address`] from a verifying (public) key.
pub fn address_from_public_key(key: &VerifyingKey) -> Address {
    let encoded = key.to_encoded_point(false);
    sha256(encoded.as_bytes())
}

/// Parse a verifying (public) key from SEC1 bytes (compressed or
/// uncompressed).
pub fn parse_public_key(bytes: &[u8]) -> Result<VerifyingKey> {
    VerifyingKey::from_sec1_bytes(bytes).map_err(|err| Error::Crypto(err.to_string()))
}

/// Verify an ECDSA signature over `message` with `key`.
pub fn verify(key: &VerifyingKey, message: &[u8], signature: &[u8]) -> bool {
    match EcdsaSignature::from_slice(signature) {
        Ok(sig) => key.verify(message, &sig).is_ok(),
        Err(_) => false,
    }
}

/// A secp256k1 key pair used to sign transactions and consensus messages.
#[derive(Clone)]
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a fresh random key pair.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::random(&mut OsRng),
        }
    }

    /// Reconstruct a key pair from raw secret-key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let signing_key =
            SigningKey::from_slice(bytes).map_err(|err| Error::Crypto(err.to_string()))?;
        Ok(Self { signing_key })
    }

    /// The public key matching this key pair.
    pub fn public_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
    }

    /// The address derived from the public key.
    pub fn address(&self) -> Address {
        address_from_public_key(&self.public_key())
    }

    /// Raw secret-key bytes, for wallet persistence.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Sign `message`, returning the DER-encoded signature bytes.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: EcdsaSignature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }
}
