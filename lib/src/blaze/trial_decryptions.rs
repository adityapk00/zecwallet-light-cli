use crate::{
    compact_formats::CompactBlock,
    lightwallet::{data::WalletTx, keys::Keys, wallet_txns::WalletTxns},
};
use futures::future;
use log::info;
use std::sync::Arc;
use tokio::{
    sync::{
        mpsc::{unbounded_channel, UnboundedSender},
        RwLock,
    },
    task::JoinHandle,
};

use zcash_primitives::{
    consensus::{BlockHeight, MAIN_NETWORK},
    note_encryption::try_sapling_compact_note_decryption,
    primitives::Nullifier,
    transaction::TxId,
};

use super::syncdata::BlazeSyncData;

pub struct TrialDecryptions {
    keys: Arc<RwLock<Keys>>,
    wallet_txns: Arc<RwLock<WalletTxns>>,
}

impl TrialDecryptions {
    pub fn new(keys: Arc<RwLock<Keys>>, wallet_txns: Arc<RwLock<WalletTxns>>) -> Self {
        Self { keys, wallet_txns }
    }

    pub async fn start(
        &self,
        bsync_data: Arc<RwLock<BlazeSyncData>>,
        detected_txid_sender: UnboundedSender<(TxId, Nullifier, BlockHeight, Option<u32>)>,
    ) -> (JoinHandle<()>, UnboundedSender<CompactBlock>) {
        println!("Starting trial decrptions processor");

        // Create a new channel where we'll receive the blocks
        let (tx, mut rx) = unbounded_channel::<CompactBlock>();

        let keys = self.keys.clone();
        let wallet_txns = self.wallet_txns.clone();

        // Get all the FVKs (used when we actually detect an incoming payment) and ivks (to do the detection iteself)
        let extfvks = Arc::new(keys.read().await.get_all_extfvks());
        let ivks = Arc::new(extfvks.iter().map(|i| i.fvk.vk.ivk()).collect::<Vec<_>>());

        let h = tokio::spawn(async move {
            let mut workers = vec![];
            let mut tasks = vec![];

            while let Some(cb) = rx.recv().await {
                let height = BlockHeight::from_u32(cb.height as u32);

                // Clone the IVKs for use in this block
                let extfvks = extfvks.clone();
                let ivks = ivks.clone();

                let keys = keys.clone();
                let wallet_txns = wallet_txns.clone();
                let bsync_data = bsync_data.clone();
                let detected_txid_sender = detected_txid_sender.clone();

                tasks.push(tokio::spawn(async move {
                    for (tx_num, ctx) in cb.vtx.iter().enumerate() {
                        for (output_num, co) in ctx.outputs.iter().enumerate() {
                            let cmu = co.cmu().ok()?;
                            let epk = co.epk().ok()?;

                            for (i, ivk) in ivks.iter().enumerate() {
                                let enc_ciphertext = co.ciphertext.clone();

                                if let Some((note, to)) = try_sapling_compact_note_decryption(
                                    &MAIN_NETWORK,
                                    height,
                                    &ivk,
                                    &epk,
                                    &cmu,
                                    &enc_ciphertext,
                                ) {
                                    let extfvk = extfvks.get(i).unwrap();
                                    let have_spending_key = keys.read().await.have_spending_key(extfvk);

                                    // Get the witness for the note
                                    let witness = bsync_data
                                        .read()
                                        .await
                                        .node_data
                                        .get_note_witness(height, tx_num, output_num)
                                        .await;

                                    let txid = WalletTx::new_txid(&ctx.hash);
                                    let nullifier = note.nf(&extfvk.fvk.vk, witness.position() as u64);

                                    wallet_txns.write().await.add_new_note(
                                        txid.clone(),
                                        height,
                                        cb.time as u64,
                                        note,
                                        to,
                                        &extfvks.get(i).unwrap(),
                                        have_spending_key,
                                        witness,
                                        &None,
                                    );

                                    info!("Trial decrypt Detected txid {}", &txid);

                                    detected_txid_sender
                                        .send((txid, nullifier, height, Some(output_num as u32)))
                                        .unwrap();

                                    // No need to try the other ivks if we found one
                                    break;
                                }
                            }
                        }
                    }

                    // Return a nothing-value
                    Some(())
                }));

                // Every 10_000 transactions, wait for them to execute
                if tasks.len() > 10_000 {
                    let exec_tasks = tasks.split_off(0);
                    workers.push(tokio::spawn(async move { future::join_all(exec_tasks).await }));

                    println!("Finished 10_000 trial decryptions, at block {}", height);
                }
            }

            drop(detected_txid_sender);

            workers.push(tokio::spawn(async move { future::join_all(tasks.into_iter()).await }));
            future::join_all(workers).await;

            println!("Finished final trial decryptions");
        });

        return (h, tx);
    }
}
