//! HTTP route definitions.

use actix_web::{get, post, web, HttpResponse, Responder};
use serde_json::json;

use crate::block::Transaction;
use crate::state::AppState;

/// Register every API route on the application.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(health)
        .service(status)
        .service(genesis)
        .service(latest_block)
        .service(get_block)
        .service(submit_transaction)
        .service(get_transaction)
        .service(get_validators);
}

#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().json(json!({ "status": "ok" }))
}

#[get("/status")]
async fn status(state: web::Data<AppState>) -> impl Responder {
    let height = state.storage.head_height().unwrap_or(0);
    let finalized = state.storage.finalized_height().unwrap_or(0);
    HttpResponse::Ok().json(json!({
        "node": state.config.node.name,
        "chain_id": state.config.node.chain_id,
        "height": height,
        "finalized_height": finalized,
        "phase": state.sync.phase().as_str(),
        "consensus_ready": state.sync.is_ready(),
        "peers": state.peers(),
        "node_public_key": state
            .identity
            .as_ref()
            .map(|keypair| hex::encode(keypair.public_key().to_encoded_point(true).as_bytes())),
        "node_address": state.identity.as_ref().map(|keypair| hex::encode(keypair.address())),
        "stake_address": state.config.node.stake_address.clone(),
    }))
}

#[get("/genesis")]
async fn genesis(state: web::Data<AppState>) -> impl Responder {
    match state.storage.genesis_block() {
        Ok(Some(block)) => HttpResponse::Ok().json(json!({
            "hash": hex::encode(block.hash()),
            "initial_supply": crate::genesis::INITIAL_SUPPLY.to_string(),
            "block": block,
        })),
        Ok(None) => HttpResponse::NotFound().json(json!({ "error": "genesis_not_initialized" })),
        Err(err) => {
            HttpResponse::InternalServerError().json(json!({ "error": err.to_string() }))
        }
    }
}

#[get("/blocks/latest")]
async fn latest_block(state: web::Data<AppState>) -> impl Responder {
    let height = match state.storage.head_height() {
        Ok(height) => height,
        Err(err) => return HttpResponse::InternalServerError().json(json!({ "error": err.to_string() })),
    };
    match state.storage.get_block(height) {
        Ok(Some(block)) => HttpResponse::Ok().json(json!({
            "height": height,
            "hash": hex::encode(block.hash()),
            "block": block,
        })),
        Ok(None) => HttpResponse::NotFound().json(json!({ "error": "no_blocks" })),
        Err(err) => HttpResponse::InternalServerError().json(json!({ "error": err.to_string() })),
    }
}

#[get("/blocks/{height}")]
async fn get_block(state: web::Data<AppState>, height: web::Path<u64>) -> impl Responder {
    let height = height.into_inner();
    match state.storage.get_block(height) {
        Ok(Some(block)) => HttpResponse::Ok().json(json!({
            "height": height,
            "hash": hex::encode(block.hash()),
            "block": block,
        })),
        Ok(None) => HttpResponse::NotFound().json(json!({ "error": "block_not_found", "height": height })),
        Err(err) => HttpResponse::InternalServerError().json(json!({ "error": err.to_string() })),
    }
}

#[get("/transactions/{txid}")]
async fn get_transaction(state: web::Data<AppState>, txid: web::Path<String>) -> impl Responder {
    let txid_str = txid.into_inner();
    let bytes = match hex::decode(&txid_str) {
        Ok(b) => b,
        Err(_) => return HttpResponse::BadRequest().json(json!({ "error": "invalid_txid" })),
    };
    if bytes.len() != 32 {
        return HttpResponse::BadRequest().json(json!({ "error": "invalid_txid" }));
    }
    let mut txid_arr = [0u8; 32];
    txid_arr.copy_from_slice(&bytes);

    match state.storage.get_transaction(&txid_arr) {
        Ok(Some(tx)) => {
            // Try to find block height
            let block_height = state.storage.get_tx_block(&txid_arr).unwrap_or(None);
            let finalized = state.storage.finalized_height().unwrap_or(0);
            let confirmed = block_height.is_some();
            let finalized_in_chain = if let Some(h) = block_height {
                h <= finalized
            } else {
                false
            };
            HttpResponse::Ok().json(json!({
                "txid": txid_str,
                "transaction": tx,
                "block_height": block_height,
                "confirmed": confirmed,
                "finalized": finalized_in_chain,
                "consensus_reached": finalized_in_chain,
                "status": if finalized_in_chain { "finalized" } else if confirmed { "confirmed" } else { "pending" },
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(json!({ "error": "transaction_not_found" })),
        Err(err) => HttpResponse::InternalServerError().json(json!({ "error": err.to_string() })),
    }
}

#[post("/transactions")]
async fn submit_transaction(state: web::Data<AppState>, body: web::Json<Transaction>) -> impl Responder {
    let tx = body.into_inner();
    let txid = tx.txid();
    
    // Load current chain state (UTXOs + stake ledger + registry) and validate.
    match crate::chain::load_chain_state(&state.storage) {
        Ok(chain_state) => {
            match crate::chain::validate_transaction(&chain_state, &tx) {
                Ok(()) => {
                    let _ = state.mempool.add_transaction(tx.clone());
                    HttpResponse::Ok().json(json!({
                        "success": true,
                        "txid": hex::encode(txid),
                    }))
                }
                Err(err) => {
                    HttpResponse::BadRequest().json(json!({
                        "error": err.to_string(),
                        "txid": hex::encode(txid),
                    }))
                }
            }
        }
        Err(err) => {
            HttpResponse::InternalServerError().json(json!({
                "error": err.to_string(),
                "txid": hex::encode(txid),
            }))
        }
    }
}

#[get("/validators")]
async fn get_validators(state: web::Data<AppState>) -> impl Responder {
    match state.storage.node_registry() {
        Ok(registry) => {
            let validators: Vec<_> = registry
                .values()
                .map(|entry| {
                    json!({
                        "node_public_key": hex::encode(&entry.node_public_key),
                        "node_address": hex::encode(entry.node_address),
                        "stake_address": hex::encode(entry.stake_address),
                        "stake_amount": entry.stake_amount.to_string(),
                        "joined_height": entry.joined_height,
                    })
                })
                .collect();
            HttpResponse::Ok().json(json!({
                "count": validators.len(),
                "validators": validators,
            }))
        }
        Err(err) => HttpResponse::InternalServerError().json(json!({ "error": err.to_string() })),
    }
}
