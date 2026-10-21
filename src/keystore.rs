//! Node identity keystore: seed phrases and local key files.
//!
//! Every node has an *identity*: a secp256k1 key pair generated from a
//! human-readable **seed phrase**. The phrase is 16 random bytes rendered as
//! 16 words from a fixed 256-word list, plus one checksum word (the first
//! byte of the SHA-256 of the entropy). The private key is derived
//! deterministically from the entropy, so the same phrase always yields the
//! same key pair.
//!
//! The full identity - seed phrase, private key, public key and address - is
//! stored in a local text file so an administrator can back it up:
//!
//! ```text
//! # VhennCoin ENET node keystore - keep this file private!
//! seed phrase: apple anchor arrow ... tiger
//! private key: <64 hex chars>
//! public key:  <66 hex chars, SEC1 compressed>
//! address:     <64 hex chars>
//! ```

use std::collections::HashMap;
use std::path::Path;

use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::crypto::Keypair;
use crate::error::{Error, Result};

/// Domain-separated derivation tag for seed phrases.
const KEY_DERIVATION_TAG: &[u8] = b"vhenncoin-enet:keystore:";

/// 256 short words; one word encodes one byte of entropy.
pub const WORDLIST: [&str; 256] = [
    "apple", "anchor", "arrow", "aspen", "badge", "bamboo", "banner", "basin",
    "beacon", "beaver", "bison", "bonnet", "border", "bottle", "boulder", "branch",
    "brass", "bread", "breeze", "bridge", "broom", "bubble", "bucket", "buffer",
    "bundle", "bunker", "butter", "cabin", "cable", "cactus", "camera", "canvas",
    "canyon", "carbon", "cargo", "carpet", "carrot", "castle", "cedar", "cellar",
    "chalk", "chapel", "cherry", "chest", "chimney", "circle", "citrus", "cloak",
    "clover", "cobalt", "cocoa", "coffee", "comet", "compass", "copper", "coral",
    "cotton", "cowboy", "crater", "crimson", "crystal", "cumulus", "daisy", "dawn",
    "delta", "denim", "depot", "desert", "device", "dial", "dolphin", "donkey",
    "drawer", "dream", "drift", "drum", "eagle", "ember", "emerald", "engine",
    "falcon", "farm", "fennel", "fern", "flute", "forest", "fossil", "founder",
    "fox", "frost", "garden", "garlic", "gecko", "ginger", "glacier", "globe",
    "glove", "grain", "granite", "grape", "gravel", "grove", "guitar", "hammock",
    "harbor", "harvest", "hazel", "helmet", "heron", "hollow", "honey", "horizon",
    "hornet", "horse", "hostel", "husky", "igloo", "indigo", "iris", "island",
    "ivory", "jasper", "jungle", "juniper", "kayak", "kernel", "kettle", "kingdom",
    "kitten", "koala", "ladder", "lantern", "lark", "laurel", "lava", "ledger",
    "lemon", "lily", "linen", "lion", "lobby", "lotus", "lumber", "lynx",
    "magnet", "mango", "maple", "marble", "meadow", "melon", "meteor", "mirror",
    "monkey", "monsoon", "moss", "moth", "mountain", "muffin", "mustard", "napkin",
    "navy", "nectar", "nickel", "night", "noodle", "north", "nutmeg", "oak",
    "oasis", "ocean", "olive", "onyx", "orange", "orbit", "orchid", "otter",
    "owl", "oxygen", "oyster", "paddle", "palm", "panda", "paper", "parade",
    "pasta", "pebble", "pelican", "pepper", "petal", "pigeon", "pillar", "pilot",
    "pine", "pirate", "planet", "plum", "pocket", "pollen", "pond", "poplar",
    "prism", "pumpkin", "quarry", "quartz", "rabbit", "radar", "raft", "rain",
    "ranger", "raven", "reef", "ribbon", "ridge", "river", "robin", "rocket",
    "rose", "ruby", "sage", "salmon", "sandal", "sapling", "sapphire", "savanna",
    "seal", "seed", "sequoia", "shale", "shark", "shelter", "shovel", "shrimp",
    "silk", "silver", "skillet", "solar", "sparrow", "spiral", "spring", "sprite",
    "squid", "stadium", "starling", "stone", "storm", "strawberry", "summit", "sunset",
    "tablet", "talent", "teapot", "temple", "thunder", "timber", "tide", "tiger",
];

/// A node identity: seed phrase plus the derived key pair.
#[derive(Clone)]
pub struct Keystore {
    /// The human-readable seed phrase (17 words).
    pub seed_phrase: String,
    /// The key pair derived from the phrase's entropy.
    pub keypair: Keypair,
}

impl Keystore {
    /// Generate a fresh identity from random entropy.
    pub fn generate() -> Result<Self> {
        let mut entropy = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        Self::from_entropy(&entropy)
    }

    /// Build an identity from exactly 16 bytes of entropy.
    pub fn from_entropy(entropy: &[u8; 16]) -> Result<Self> {
        let checksum = Sha256::digest(entropy)[0];
        let mut words = Vec::with_capacity(17);
        for byte in entropy {
            words.push(WORDLIST[*byte as usize]);
        }
        words.push(WORDLIST[checksum as usize]);
        Self::from_seed_phrase(&words.join(" "))
    }

    /// Restore an identity from its seed phrase (validating the checksum).
    pub fn from_seed_phrase(phrase: &str) -> Result<Self> {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        if words.len() != 17 {
            return Err(Error::Crypto(format!(
                "seed phrase must have 17 words, got {}",
                words.len()
            )));
        }

        let mut index = HashMap::with_capacity(WORDLIST.len());
        for (i, word) in WORDLIST.iter().enumerate() {
            index.insert(*word, i);
        }

        let mut entropy = [0u8; 16];
        for (position, word) in words[..16].iter().enumerate() {
            let byte = index.get(word).copied().ok_or_else(|| {
                Error::Crypto(format!("unknown seed phrase word {:?}", word))
            })?;
            entropy[position] = byte as u8;
        }

        let expected = WORDLIST[Sha256::digest(entropy)[0] as usize];
        if words[16] != expected {
            return Err(Error::Crypto(
                "seed phrase checksum does not match".to_string(),
            ));
        }

        let mut material = Vec::with_capacity(KEY_DERIVATION_TAG.len() + 16);
        material.extend_from_slice(KEY_DERIVATION_TAG);
        material.extend_from_slice(&entropy);
        let digest = Sha256::digest(&material);
        let keypair = Keypair::from_bytes(&digest)
            .map_err(|err| Error::Crypto(format!("derived key is invalid: {err}")))?;

        Ok(Self {
            seed_phrase: words.join(" "),
            keypair,
        })
    }

    /// Hex-encoded private key.
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.keypair.to_bytes())
    }

    /// Hex-encoded SEC1 compressed public key.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.keypair.public_key().to_encoded_point(true).as_bytes())
    }

    /// Hex-encoded address.
    pub fn address_hex(&self) -> String {
        hex::encode(self.keypair.address())
    }

    /// Render the keystore text-file contents.
    pub fn to_text(&self) -> String {
        format!(
            "# VhennCoin ENET node keystore - keep this file private!\n\
             # Anyone holding the seed phrase or private key controls this node's identity.\n\
             seed phrase: {}\n\
             private key: {}\n\
             public key:  {}\n\
             address:     {}\n",
            self.seed_phrase,
            self.private_key_hex(),
            self.public_key_hex(),
            self.address_hex(),
        )
    }

    /// Write the keystore to `path` (creating parent directories).
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(path, self.to_text())?;
        Ok(())
    }

    /// Load a keystore from `path`, verifying it is internally consistent.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())?;
        let mut phrase = None;
        let mut private = None;
        for line in text.lines() {
            let line = line.trim();
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "seed phrase" => phrase = Some(value.to_string()),
                "private key" => private = Some(value.to_string()),
                _ => {}
            }
        }

        let phrase = phrase.ok_or_else(|| {
            Error::Crypto("keystore file has no 'seed phrase' line".to_string())
        })?;
        let restored = Self::from_seed_phrase(&phrase)?;

        if let Some(private) = private {
            if !private.eq_ignore_ascii_case(&restored.private_key_hex()) {
                return Err(Error::Crypto(
                    "keystore private key does not match its seed phrase".to_string(),
                ));
            }
        }
        Ok(restored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_has_256_unique_words() {
        let unique: std::collections::HashSet<&str> = WORDLIST.iter().copied().collect();
        assert_eq!(unique.len(), 256);
    }

    #[test]
    fn phrase_round_trips_and_restores_the_same_key() {
        let original = Keystore::generate().unwrap();
        let words: Vec<&str> = original.seed_phrase.split_whitespace().collect();
        assert_eq!(words.len(), 17);

        let restored = Keystore::from_seed_phrase(&original.seed_phrase).unwrap();
        assert_eq!(restored.private_key_hex(), original.private_key_hex());
        assert_eq!(restored.public_key_hex(), original.public_key_hex());
        assert_eq!(restored.address_hex(), original.address_hex());
    }

    #[test]
    fn entropy_is_deterministic() {
        let entropy = [7u8; 16];
        let a = Keystore::from_entropy(&entropy).unwrap();
        let b = Keystore::from_entropy(&entropy).unwrap();
        assert_eq!(a.seed_phrase, b.seed_phrase);
        assert_eq!(a.private_key_hex(), b.private_key_hex());
    }

    #[test]
    fn rejects_tampered_phrases() {
        let original = Keystore::generate().unwrap();
        let mut words: Vec<String> =
            original.seed_phrase.split_whitespace().map(str::to_string).collect();

        // Wrong word count.
        assert!(Keystore::from_seed_phrase("apple anchor").is_err());

        // Unknown word.
        let bad_word = words.clone();
        words[0] = "notaword".to_string();
        assert!(Keystore::from_seed_phrase(&words.join(" ")).is_err());

        // Broken checksum (valid word, wrong last word).
        words = bad_word;
        words[16] = if words[16] == "apple" { "anchor" } else { "apple" }.to_string();
        assert!(Keystore::from_seed_phrase(&words.join(" ")).is_err());
    }

    #[test]
    fn file_save_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "vhn-keystore-{}-{}.txt",
            std::process::id(),
            unique()
        ));
        let original = Keystore::generate().unwrap();
        original.save(&dir).unwrap();

        let loaded = Keystore::load(&dir).unwrap();
        assert_eq!(loaded.seed_phrase, original.seed_phrase);
        assert_eq!(loaded.private_key_hex(), original.private_key_hex());
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn load_rejects_inconsistent_private_key() {
        let path = std::env::temp_dir().join(format!(
            "vhn-keystore-bad-{}-{}.txt",
            std::process::id(),
            unique()
        ));
        let original = Keystore::generate().unwrap();
        let mut text = original.to_text();
        let other = Keystore::generate().unwrap();
        text = text.replace(&original.private_key_hex(), &other.private_key_hex());
        std::fs::write(&path, text).unwrap();
        assert!(Keystore::load(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    fn unique() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}
