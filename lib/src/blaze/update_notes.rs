use std::sync::Arc;

use crate::lightclient::lightclient_config::MAX_REORG;
use crate::lightwallet::{data::WalletTx, wallet_txns::WalletTxns};

use futures::future::join_all;
use log::info;
use tokio::join;
use tokio::sync::{mpsc::unbounded_channel, RwLock};
use tokio::{sync::mpsc::UnboundedSender, task::JoinHandle};

use zcash_primitives::consensus::BlockHeight;
use zcash_primitives::primitives::Nullifier;
use zcash_primitives::transaction::TxId;

use super::syncdata::BlazeSyncData;

/// A processor to update notes that we have recieved in the wallet.
/// We need to identify if this note has been spent in future blocks.
/// If YES, then:
///    - Mark this note as spent
///    - In the future Tx, add the nullifiers as spent and do the accounting
///    - In the future Tx, mark incoming notes as change
///
/// If No, then:
///    - Update the witness for this note
pub struct UpdateNotes {
    wallet_txns: Arc<RwLock<WalletTxns>>,
}

impl UpdateNotes {
    pub fn new(wallet_txns: Arc<RwLock<WalletTxns>>) -> Self {
        Self { wallet_txns }
    }

    async fn update_witnesses(
        bsync_data: Arc<RwLock<BlazeSyncData>>,
        wallet_txns: Arc<RwLock<WalletTxns>>,
        txid: TxId,
        nullifier: Nullifier,
        output_num: Option<u32>,
        note_height: BlockHeight,
    ) {
        // Get the data first, so we don't hold on to the lock
        let wtn = wallet_txns.read().await.get_note_witness(&txid, &nullifier);

        if let Some((witnesses, created_height)) = wtn {
            // If we were sent an output number, then we need to stream after the given position
            let witnesses = if let Some(output_num) = output_num {
                bsync_data
                    .read()
                    .await
                    .node_data
                    .update_witness_after_pos(&created_height, &txid, output_num, witnesses)
                    .await
            } else {
                // If the output_num was not present, then this is an existing note, and it needs
                // to be updating starting at the given block height
                bsync_data
                    .read()
                    .await
                    .node_data
                    .update_witness_after_block(&note_height, witnesses)
                    .await
            };

            if witnesses.len() > MAX_REORG {
                panic!("Witnesses are too big");
            }
            info!("Finished updating witnesses for {}", txid);

            wallet_txns
                .write()
                .await
                .set_note_witnesses(&txid, &nullifier, witnesses);
        } else {
            // No witness, which means we don't have the spending key, so nothing to update.
        }
    }

    pub async fn start(
        &self,
        bsync_data: Arc<RwLock<BlazeSyncData>>,
        fetch_full_sender: UnboundedSender<(TxId, BlockHeight)>,
    ) -> (
        JoinHandle<()>,
        UnboundedSender<(TxId, Nullifier, BlockHeight, Option<u32>)>,
    ) {
        println!("Starting TxId processing");

        // Create a new channel where we'll be notified of TxIds that are to be processed
        let (tx, mut rx) = unbounded_channel::<(TxId, Nullifier, BlockHeight, Option<u32>)>();

        // Aside from the incoming Txns, we also need to update the notes that are currently in the wallet
        let wallet_txns = self.wallet_txns.clone();
        let tx_existing = tx.clone();
        let start_block = BlockHeight::from_u32(bsync_data.read().await.earliest_block() as u32);
        let h0 = tokio::spawn(async move {
            let notes = wallet_txns.read().await.get_notes_for_updating();
            for (txid, nf) in notes {
                tx_existing.send((txid, nf, start_block.clone(), None)).unwrap();
            }
        });

        let wallet_txns = self.wallet_txns.clone();
        let h1 = tokio::spawn(async move {
            let mut workers = vec![];

            // Recieve Txns that are sent to the wallet. We need to update the notes for this.
            while let Some((txid, nf, at_height, output_num)) = rx.recv().await {
                // If this nullifier was spent at a future height, fetch the TxId at the height and process it
                if let Some(spent_height) = bsync_data
                    .read()
                    .await
                    .nullifier_data
                    .is_nf_spent(nf, at_height.into())
                    .await
                {
                    info!("Note was spent, just add it as spent for TxId {}", txid);
                    let (ctx, ts) = bsync_data
                        .read()
                        .await
                        .node_data
                        .get_ctx_for_nf_at_height(&nf, spent_height)
                        .await;

                    let spent_txid = WalletTx::new_txid(&ctx.hash);
                    let spent_at_height = BlockHeight::from_u32(spent_height as u32);

                    // Mark this note as being spent
                    let value = wallet_txns
                        .write()
                        .await
                        .mark_txid_nf_spent(txid, &nf, &spent_txid, spent_at_height);

                    // Record the future tx, the one that has spent the nullifiers recieved in this Tx in the wallet
                    wallet_txns
                        .write()
                        .await
                        .add_new_spent(spent_txid, spent_at_height, ts, nf, value, txid, &None);

                    // Send the future Tx to be fetched too, in case it has only spent nullifiers and not recieved any change
                    fetch_full_sender.send((spent_txid, spent_at_height)).unwrap();
                } else {
                    info!("Note was NOT spent, update its witnesses for TxId {}", txid);

                    // If this note's nullifier was not spent, then we need to update the witnesses for this.
                    workers.push(tokio::spawn(Self::update_witnesses(
                        bsync_data.clone(),
                        wallet_txns.clone(),
                        txid,
                        nf,
                        output_num,
                        at_height,
                    )));
                }

                // Send it off to get the full transaction if this is a new Tx, that is, it has an output_num
                if output_num.is_some() {
                    fetch_full_sender.send((txid, at_height)).unwrap();
                }
            }

            drop(fetch_full_sender);

            // Wait for all the workers
            join_all(workers).await;
            println!("Finished TxID processing");
        });

        let h = tokio::spawn(async move {
            join!(h0, h1);
        });

        return (h, tx);
    }
}
