//! Minimal wallet and chain-inspection CLI used for end-to-end testing.
//!
//! Subcommands:
//!   gen                                generate a key pair, print priv/pub/address hex
//!   system-wallet                      print the system stake wallet address
//!   genesis-outpoint --pubkey <hex>    print the genesis out-point for a genesis recipient key
//!   seed-gen [--seed-phrase "..."]     generate a node identity from a seed phrase
//!   keystore-init --file <path> [--seed-phrase "..."]
//!                                      write a node keystore file (generates a phrase if omitted)
//!   keystore-show --file <path>        print the identity held in a keystore file
//!   transfer --priv <hex> --txid <hex> --index <n> --to <addrhex> --amount <units>
//!            [--change <addrhex> --change-amount <units>]
//!   register-node --node-priv <hex> --stake-address <addrhex>
//!                                      build a signed validator-registration transaction
//!   submit --api <url> --file <tx.json>
//!   validators --api <url>             print the registered validator nodes
//!   inspect --api <url>                walk the chain, print proposers, txs, stakes, balances

use std::collections::BTreeMap;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;

use vhenncoin_enet::block::{
    OutPoint, RegistrationPayload, Transaction, TransactionType, TxInput, TxOutput,
};
use vhenncoin_enet::consensus::{system_wallet_address, MIN_STAKE};
use vhenncoin_enet::crypto::{self, Keypair};
use vhenncoin_enet::genesis;
use vhenncoin_enet::keystore::Keystore;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gen") => cmd_gen(),
        Some("system-wallet") => println!("{}", hex::encode(system_wallet_address())),
        Some("genesis-outpoint") => cmd_genesis_outpoint(&args[1..]),
        Some("seed-gen") => cmd_seed_gen(&args[1..]),
        Some("keystore-init") => cmd_keystore_init(&args[1..]),
        Some("keystore-show") => cmd_keystore_show(&args[1..]),
        Some("transfer") => cmd_transfer(&args[1..]),
        Some("register-node") => cmd_register_node(&args[1..]),
        Some("submit") => cmd_submit(&args[1..]),
        Some("validators") => cmd_validators(&args[1..]),
        Some("inspect") => cmd_inspect(&args[1..]),
        _ => {
            eprintln!(
                "usage: wallet <gen|system-wallet|genesis-outpoint|seed-gen|keystore-init|\
                 keystore-show|transfer|register-node|submit|validators|inspect> ..."
            );
            std::process::exit(2);
        }
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn cmd_gen() {
    let kp = Keypair::generate();
    let pubkey = kp.public_key().to_encoded_point(true).as_bytes().to_vec();
    println!("priv {}", hex::encode(kp.to_bytes()));
    println!("pub {}", hex::encode(&pubkey));
    println!("addr {}", hex::encode(kp.address()));
}

fn cmd_seed_gen(args: &[String]) {
    let keystore = match flag(args, "--seed-phrase") {
        Some(phrase) => Keystore::from_seed_phrase(phrase).expect("valid seed phrase"),
        None => Keystore::generate().expect("generate identity"),
    };
    println!("seed-phrase {}", keystore.seed_phrase);
    println!("priv {}", keystore.private_key_hex());
    println!("pub {}", keystore.public_key_hex());
    println!("addr {}", keystore.address_hex());
}

fn cmd_keystore_init(args: &[String]) {
    let path = flag(args, "--file").expect("--file required");
    let keystore = match flag(args, "--seed-phrase") {
        Some(phrase) => Keystore::from_seed_phrase(phrase).expect("valid seed phrase"),
        None => Keystore::generate().expect("generate identity"),
    };
    keystore.save(path).expect("write keystore file");
    println!("file {}", path);
    println!("seed-phrase {}", keystore.seed_phrase);
    println!("priv {}", keystore.private_key_hex());
    println!("pub {}", keystore.public_key_hex());
    println!("addr {}", keystore.address_hex());
}

fn cmd_keystore_show(args: &[String]) {
    let path = flag(args, "--file").expect("--file required");
    let keystore = Keystore::load(path).expect("load keystore file");
    println!("seed-phrase {}", keystore.seed_phrase);
    println!("priv {}", keystore.private_key_hex());
    println!("pub {}", keystore.public_key_hex());
    println!("addr {}", keystore.address_hex());
}

fn cmd_genesis_outpoint(args: &[String]) {
    let pub_hex = flag(args, "--pubkey").expect("--pubkey required");
    let bytes = hex::decode(pub_hex).expect("valid pubkey hex");
    let key = crypto::parse_public_key(&bytes).expect("parse pubkey");
    let address = crypto::address_from_public_key(&key);
    let tx = genesis::genesis_transaction(address);
    println!("address {}", hex::encode(address));
    println!("txid {}", hex::encode(tx.txid()));
    println!("index 0");
}

fn cmd_transfer(args: &[String]) {
    let priv_hex = flag(args, "--priv").expect("--priv required");
    let txid_hex = flag(args, "--txid").expect("--txid required");
    let index: u32 = flag(args, "--index").unwrap_or("0").parse().expect("--index");
    let to_hex = flag(args, "--to").expect("--to required");
    let amount: u128 = flag(args, "--amount").expect("--amount required").parse().expect("--amount");

    let secret = hex::decode(priv_hex).expect("valid priv hex");
    let keypair = Keypair::from_bytes(&secret).expect("parse priv");

    let mut txid = [0u8; 32];
    txid.copy_from_slice(&hex::decode(txid_hex).expect("valid txid hex"));
    let mut recipient = [0u8; 32];
    recipient.copy_from_slice(&hex::decode(to_hex).expect("valid address hex"));

    let mut tx = Transaction {
        version: 1,
        tx_type: TransactionType::Transfer,
        inputs: vec![TxInput {
            previous_output: OutPoint {
                txid,
                output_index: index,
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
            recipient,
        }],
        lock_time: 0,
        registration: None,
        vote: None,
        removal: None,
    };
    // Optional change output so the remainder of the spent input returns to
    // the sender instead of being burned as an implicit fee.
    if let Some(change_hex) = flag(args, "--change") {
        let change_amount: u128 = flag(args, "--change-amount")
            .expect("--change-amount required with --change")
            .parse()
            .expect("--change-amount");
        let mut change_recipient = [0u8; 32];
        change_recipient
            .copy_from_slice(&hex::decode(change_hex).expect("valid change address hex"));
        tx.outputs.push(TxOutput {
            asset_id: crypto::native_asset_id(),
            amount: change_amount,
            recipient: change_recipient,
        });
    }
    let message = tx.signing_message(0);
    tx.inputs[0].signature = keypair.sign(&message);
    println!("{}", serde_json::to_string_pretty(&tx).expect("serialize tx"));
}

fn cmd_submit(args: &[String]) {
    let api = flag(args, "--api").expect("--api required");
    let file = flag(args, "--file").expect("--file required");
    let body = std::fs::read_to_string(file).expect("read tx file");
    println!("{}", http(api, "POST", "/transactions", Some(&body)));
}

fn cmd_register_node(args: &[String]) {
    let node_priv_hex = flag(args, "--node-priv").expect("--node-priv required");
    let stake_hex = flag(args, "--stake-address").expect("--stake-address required");

    let secret = hex::decode(node_priv_hex).expect("valid node priv hex");
    let keypair = Keypair::from_bytes(&secret).expect("parse node priv");

    let mut stake_address = [0u8; 32];
    stake_address
        .copy_from_slice(&hex::decode(stake_hex).expect("valid stake address hex"));

    let mut tx = Transaction {
        version: 1,
        tx_type: TransactionType::ValidatorRegistration,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        registration: Some(RegistrationPayload {
            node_public_key: keypair
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
        .expect("payload present")
        .signature = keypair.sign(&txid);
    println!("txid {}", hex::encode(txid));
    println!("{}", serde_json::to_string_pretty(&tx).expect("serialize tx"));
}

fn cmd_validators(args: &[String]) {
    let api = flag(args, "--api").expect("--api required");
    let raw = http(api, "GET", "/validators", None);
    let value: serde_json::Value = serde_json::from_str(&raw).expect("validators json");
    let count = value["count"].as_u64().unwrap_or(0);
    for entry in value["validators"].as_array().cloned().unwrap_or_default() {
        println!(
            "REG {} {} {} {} {}",
            entry["node_public_key"].as_str().unwrap_or("?"),
            entry["node_address"].as_str().unwrap_or("?"),
            entry["stake_address"].as_str().unwrap_or("?"),
            entry["stake_amount"].as_str().unwrap_or("?"),
            entry["joined_height"].as_u64().unwrap_or(0),
        );
    }
    println!("REGCOUNT {count}");
}

fn cmd_inspect(args: &[String]) {
    let api = flag(args, "--api").expect("--api required");
    let status: serde_json::Value =
        serde_json::from_str(&http(api, "GET", "/status", None)).expect("status json");
    let height = status["height"].as_u64().expect("height");
    let phase = status["phase"].as_str().unwrap_or("?").to_string();

    let system = system_wallet_address();
    let mut utxos: BTreeMap<(String, u32), (String, u128)> = BTreeMap::new();

    for h in 0..=height {
        let raw = http(api, "GET", &format!("/blocks/{h}"), None);
        let value: serde_json::Value = serde_json::from_str(&raw).expect("block json");
        let block: vhenncoin_enet::block::Block =
            serde_json::from_value(value["block"].clone()).expect("decode block");

        println!(
            "PROPOSER {} {}",
            block.header.height,
            hex::encode(block.consensus_proof.validator)
        );

        for tx in &block.transactions {
            let txid = hex::encode(tx.txid());
            println!("TX {} {}", block.header.height, txid);

            let mut sender = String::new();
            if let Some(input) = tx.inputs.first() {
                if let Ok(key) = crypto::parse_public_key(&input.public_key) {
                    sender = hex::encode(crypto::address_from_public_key(&key));
                }
            }

            for input in &tx.inputs {
                utxos.remove(&(
                    hex::encode(input.previous_output.txid),
                    input.previous_output.output_index,
                ));
            }

            for (index, output) in tx.outputs.iter().enumerate() {
                utxos.insert(
                    (txid.clone(), index as u32),
                    (hex::encode(output.recipient), output.amount),
                );
                if tx.tx_type == TransactionType::Transfer
                    && output.recipient == system
                    && output.amount >= MIN_STAKE
                {
                    println!(
                        "STAKE {} {} {}",
                        block.header.height, sender, output.amount
                    );
                }
            }
        }
    }

    let mut balances: BTreeMap<String, u128> = BTreeMap::new();
    for ((_, _), (recipient, amount)) in &utxos {
        *balances.entry(recipient.clone()).or_insert(0) += amount;
    }
    for (address, amount) in &balances {
        println!("BAL {address} {amount}");
    }

    // Registered validator nodes (node key, stake wallet, stake amount).
    let raw = http(api, "GET", "/validators", None);
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
        for entry in value["validators"].as_array().cloned().unwrap_or_default() {
            println!(
                "REG {} {} {} {} {}",
                entry["node_public_key"].as_str().unwrap_or("?"),
                entry["node_address"].as_str().unwrap_or("?"),
                entry["stake_address"].as_str().unwrap_or("?"),
                entry["stake_amount"].as_str().unwrap_or("?"),
                entry["joined_height"].as_u64().unwrap_or(0),
            );
        }
    }

    println!("HEAD {height}");
    println!("PHASE {phase}");
}

fn http(api: &str, method: &str, path: &str, body: Option<&str>) -> String {
    let host = api
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let mut stream = TcpStream::connect(host).expect("connect to api");
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(body) = body {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    if let Some(body) = body {
        request.push_str(body);
    }
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    let (_, payload) = response.split_once("\r\n\r\n").expect("http response");
    payload.to_string()
}
