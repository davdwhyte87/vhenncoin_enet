//! Mempool module for managing pending transactions.

use std::sync::Mutex;

use crate::block::Transaction;

#[derive(Clone, Debug)]
pub struct MempoolEntry {
    pub transaction: Transaction,
    pub timestamp: u64,
}

#[derive(Clone)]
pub struct Mempool {
    entries: std::sync::Arc<Mutex<Vec<MempoolEntry>>>,
}

impl Default for Mempool {
    fn default() -> Self {
        Self {
            entries: std::sync::Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Mempool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_transaction(&self, tx: Transaction) -> Result<(), String> {
        let mut entries = self.entries.lock().unwrap();
        entries.push(MempoolEntry {
            transaction: tx,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });
        Ok(())
    }

    pub fn get_pending_transactions(&self, limit: usize) -> Vec<Transaction> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .take(limit)
            .cloned()
            .map(|e| e.transaction)
            .collect()
    }

    pub fn drain_transactions(&self, limit: usize) -> Vec<Transaction> {
        let mut entries = self.entries.lock().unwrap();
        let to_take = std::cmp::min(limit, entries.len());
        entries.drain(0..to_take).map(|e| e.transaction).collect()
    }

    pub fn count(&self) -> usize {
        let entries = self.entries.lock().unwrap();
        entries.len()
    }

    pub fn size(&self) -> usize {
        self.count()
    }

    pub fn clear(&self) {
        let mut entries = self.entries.lock().unwrap();
        entries.clear();
    }
}