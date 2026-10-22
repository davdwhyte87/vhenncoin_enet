//! VhennCoin ENET node entry point.

use std::sync::Arc;

use anyhow::Context;
use tracing_subscriber::{fmt, EnvFilter};

use vhenncoin_enet::consensus::ValidatorSetEngine;
use vhenncoin_enet::keystore::Keystore;
use vhenncoin_enet::{api, chain, config::Config, network, registration, AppState, Storage};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = Config::load().context("failed to load configuration")?;

    std::fs::create_dir_all(&config.node.data_dir).context("failed to create data dir")?;
    if let Some(parent) = config.storage.path.parent() {
        std::fs::create_dir_all(parent).context("failed to create storage dir")?;
    }

    let storage = Storage::open(&config.storage.path).context("failed to open database")?;

    let genesis_recipient = config
        .genesis_recipient()
        .context("invalid genesis configuration")?;

    let governance = config
        .governance
        .to_governance()
        .context("invalid governance configuration")?;

    // The genesis validator set is the root of trust: it is the only body that
    // can approve the first new node.
    let mut validator_keys: Vec<k256::ecdsa::VerifyingKey> =
        vhenncoin_enet::consensus::parse_validator_keys(&config.consensus.validators)
            .context("invalid consensus configuration")?
            .into_values()
            .collect();
    validator_keys.sort_by_key(vhenncoin_enet::crypto::address_from_public_key);
    if validator_keys.is_empty() {
        tracing::warn!(
            "consensus.validators is empty: no block above genesis can be produced or verified"
        );
    }

    storage
        .bootstrap_genesis(
            genesis_recipient,
            &governance,
            &validator_keys,
            config.consensus.validator_set_version,
        )
        .context("failed to bootstrap genesis")?;

    let consensus = ValidatorSetEngine::from_config(&config.consensus)
        .context("invalid consensus configuration")?;
    // Replay every persisted validator set so historical blocks can still be
    // verified against the set that existed when they were produced.
    consensus
        .load_stored_sets(&storage)
        .context("failed to load validator sets")?;

    // Load (or generate on first boot) this node's identity key pair.
    let identity = match load_identity(&config) {
        Ok(identity) => identity,
        Err(err) => {
            anyhow::bail!("node identity error: {err}");
        }
    };

    let mut state = AppState::new(config, storage, Arc::new(consensus));
    if let Some(identity) = identity {
        state = state.with_identity(identity);
    }

    // Apply any blocks that were downloaded but not committed before the last
    // shutdown, so the UTXO set is reconstructed before we talk to peers.
    let recovered = chain::recover(&state.storage, state.consensus.as_ref())
        .context("failed to recover pending blocks")?;

    tracing::info!(
        node = %state.config.node.name,
        chain_id = state.config.node.chain_id,
        height = recovered,
        "starting vhenncoin_enet"
    );

    // Start block producer
    let _ = vhenncoin_enet::mining::start_block_producer(Arc::new(state.clone())).await;

    // Once the configured stake wallet has paid the minimum stake, register
    // this node as a validator automatically.
    registration::start(Arc::new(state.clone()));

    // The actix-web HTTP server runs on its own runtime/thread; the tokio P2P
    // listener runs here on the main runtime.
    let api_state = state.clone();
    let api_thread = std::thread::Builder::new()
        .name("http-api".to_string())
        .spawn(move || -> anyhow::Result<()> {
            actix_web::rt::System::new().block_on(async move { api::run(api_state).await })?;
            Ok(())
        })
        .context("failed to spawn HTTP API thread")?;

    if let Err(err) = network::run(state).await {
        tracing::error!(%err, "P2P network stopped");
    }

    let _ = api_thread.join();
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}

/// Load this node's identity from its keystore file, generating a fresh one
/// (and writing it to disk) when the file does not exist yet.
///
/// When `node.public_key` is also configured, the loaded/generate key must
/// match it - a mismatch is a hard error so a node can never silently run
/// under the wrong identity.
fn load_identity(config: &Config) -> anyhow::Result<Option<vhenncoin_enet::crypto::Keypair>> {
    let Some(path) = config.node.keystore_path.clone() else {
        if config.node.public_key.is_some() {
            tracing::warn!(
                "node.public_key is configured but node.keystore_path is not; \
                 the node will run without an identity key pair"
            );
        }
        return Ok(None);
    };

    let keystore = if path.exists() {
        Keystore::load(&path).with_context(|| {
            format!("failed to load node keystore from {}", path.display())
        })?
    } else {
        let generated = Keystore::generate().context("failed to generate node identity")?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create keystore directory {}", parent.display())
                })?;
            }
        }
        generated
            .save(&path)
            .with_context(|| format!("failed to write node keystore to {}", path.display()))?;
        tracing::warn!(
            path = %path.display(),
            seed_phrase = %generated.seed_phrase,
            "generated a new node identity; back up the seed phrase"
        );
        generated
    };

    let public_key_hex = keystore.public_key_hex();
    if let Some(expected) = config.node.public_key.as_deref() {
        let expected = expected.trim();
        if !expected.is_empty()
            && !expected.eq_ignore_ascii_case(&public_key_hex)
        {
            anyhow::bail!(
                "node keystore at {} holds public key {} but node.public_key is {}",
                path.display(),
                public_key_hex,
                expected
            );
        }
    }

    tracing::info!(
        path = %path.display(),
        public_key = %public_key_hex,
        address = %keystore.address_hex(),
        "node identity loaded"
    );
    Ok(Some(keystore.keypair))
}
