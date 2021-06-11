use crate::compact_formats::CompactBlock;
use log::info;
use std::sync::{atomic::AtomicU64, Arc};
use tokio::{
    sync::{
        mpsc::{self, UnboundedSender},
        RwLock,
    },
    task::{yield_now, JoinHandle},
};
use zcash_primitives::primitives::Nullifier;

use super::sparse_trie_map::SparseNullifierTree;

pub(crate) struct NullifierData {
    processed_height: Arc<AtomicU64>,
    tree: Arc<RwLock<SparseNullifierTree<u64>>>,
}

impl NullifierData {
    pub fn new() -> Self {
        Self {
            processed_height: Arc::new(AtomicU64::new(0)),
            tree: Arc::new(RwLock::new(SparseNullifierTree::new())),
        }
    }

    pub async fn setup_sync(&mut self) {
        self.processed_height.store(0, std::sync::atomic::Ordering::SeqCst);
        self.tree.write().await.clear();
    }

    pub async fn start(&self) -> (JoinHandle<()>, UnboundedSender<CompactBlock>) {
        info!("Starting nullifier_data");

        // Create a new channel where we'll receive the blocks
        let (tx, mut rx) = mpsc::unbounded_channel::<CompactBlock>();

        let nullifier_tree = self.tree.clone();
        let processed_height = self.processed_height.clone();

        let h = tokio::spawn(async move {
            // Grab a write lock
            let mut nf_tree = nullifier_tree.write().await;
            let mut last_height = 0;
            while let Some(cb) = rx.recv().await {
                for ctx in cb.vtx {
                    for cs in ctx.spends {
                        nf_tree.insert(&cs.nf, cb.height).unwrap();
                    }
                }

                last_height = cb.height;
                if last_height % 25_000 == 0 {
                    processed_height.store(last_height, std::sync::atomic::Ordering::SeqCst);

                    // Re-acquire the lock, allowing any other reads to proceed first
                    drop(nf_tree);
                    yield_now().await;
                    nf_tree = nullifier_tree.write().await;

                    info!("Nullifiers finished adding upto block {}", last_height);
                }
            }

            processed_height.store(last_height, std::sync::atomic::Ordering::SeqCst);
        });

        return (h, tx);
    }

    pub async fn finish(&self) {
        self.processed_height.store(0, std::sync::atomic::Ordering::SeqCst);
        self.tree.write().await.clear();
    }

    pub async fn is_nf_spent(&self, nf: Nullifier, after_height: u64) -> Option<u64> {
        // Wait for the processing to pass this block height
        while self.processed_height.load(std::sync::atomic::Ordering::SeqCst) > after_height {
            yield_now().await;
        }
        self.tree.read().await.lookup(&nf.to_vec())
    }
}
