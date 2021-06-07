use crate::{
    lightclient::lightclient_config::LightClientConfig,
    lightwallet::{
        data::OutgoingTxMetadata,
        keys::{Keys, ToBase58Check},
        wallet_txns::WalletTxns,
    },
};

use log::info;
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
    iter::FromIterator,
    sync::Arc,
};
use tokio::{
    join,
    sync::{
        mpsc::{unbounded_channel, UnboundedSender},
        oneshot, RwLock,
    },
    task::JoinHandle,
};
use zcash_client_backend::encoding::encode_payment_address;

use zcash_primitives::{
    consensus::{BlockHeight, MAIN_NETWORK},
    legacy::TransparentAddress,
    memo::Memo,
    note_encryption::{try_sapling_note_decryption, try_sapling_output_recovery},
    transaction::{Transaction, TxId},
};

use super::syncdata::BlazeSyncData;

pub struct FetchFullTxns {
    config: LightClientConfig,
    keys: Arc<RwLock<Keys>>,
    wallet_txns: Arc<RwLock<WalletTxns>>,
}

impl FetchFullTxns {
    pub fn new(config: &LightClientConfig, keys: Arc<RwLock<Keys>>, wallet_txns: Arc<RwLock<WalletTxns>>) -> Self {
        Self {
            config: config.clone(),
            keys,
            wallet_txns,
        }
    }

    pub async fn start(
        &self,
        fulltx_fetcher: UnboundedSender<(TxId, oneshot::Sender<Result<Transaction, String>>)>,
        bsync_data: Arc<RwLock<BlazeSyncData>>,
    ) -> (
        JoinHandle<()>,
        UnboundedSender<(TxId, BlockHeight)>,
        UnboundedSender<(Transaction, BlockHeight)>,
    ) {
        let wallet_txns = self.wallet_txns.clone();
        let keys = self.keys.clone();
        let config = self.config.clone();
        let bsync_data_i = bsync_data.clone();

        let fetched_txids = Arc::new(RwLock::new(HashSet::new()));

        let (txid_tx, mut txid_rx) = unbounded_channel::<(TxId, BlockHeight)>();
        let h1: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            while let Some((txid, height)) = txid_rx.recv().await {
                // It is possible that we recieve the same txid multiple times, so we keep track of all the txids that were fetched
                if fetched_txids.read().await.contains(&txid) {
                    // We're already processing it or already processed it, so ignore
                    continue;
                }

                // Record that we fetched this txid
                fetched_txids.write().await.insert(txid.clone());

                let config = config.clone();
                let keys = keys.clone();
                let wallet_txns = wallet_txns.clone();

                let fulltx_fetcher = fulltx_fetcher.clone();

                let block_time = bsync_data_i.read().await.node_data.get_block_timestamp(&height).await;

                // Fetch the TxId from LightwalletD and process all the parts of it.
                let tx = {
                    let (tx, rx) = oneshot::channel();
                    fulltx_fetcher.send((txid, tx)).unwrap();
                    rx.await.unwrap()?
                };

                Self::scan_full_tx(config, tx, height, block_time, keys, wallet_txns).await?;
            }

            println!("Finished fetching all full transactions");
            Ok(())
        });

        let wallet_txns = self.wallet_txns.clone();
        let keys = self.keys.clone();
        let config = self.config.clone();
        let (tx_tx, mut tx_rx) = unbounded_channel::<(Transaction, BlockHeight)>();

        let h2: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            let bsync_data = bsync_data.clone();

            while let Some((tx, height)) = tx_rx.recv().await {
                let config = config.clone();
                let keys = keys.clone();
                let wallet_txns = wallet_txns.clone();

                let block_time = bsync_data.read().await.node_data.get_block_timestamp(&height).await;

                Self::scan_full_tx(config, tx, height, block_time, keys, wallet_txns).await?;
            }

            Ok(())
        });

        let h = tokio::spawn(async move {
            join!(h1, h2);
        });

        return (h, txid_tx, tx_tx);
    }

    async fn scan_full_tx(
        config: LightClientConfig,
        tx: Transaction,
        height: BlockHeight,
        block_time: u32,
        keys: Arc<RwLock<Keys>>,
        wallet_txns: Arc<RwLock<WalletTxns>>,
    ) -> Result<(), String> {
        // Remember if this is an outgoing Tx. Useful for when we want to grab the outgoing metadata.
        let mut is_outgoing_tx = false;

        // Step 1. Scan transparent spends
        let taddrs = keys.read().await.get_all_taddrs();
        let taddrs_set: HashSet<_> = taddrs.iter().map(|t| t.clone()).collect();

        // Scan all the inputs to see if we spent any transparent funds in this tx
        let mut total_transparent_value_spent = 0;
        let mut spent_utxos = vec![];

        {
            let current = &wallet_txns.read().await.current;
            for vin in tx.vin.iter() {
                // Find the prev txid that was spent
                let prev_txid = TxId { 0: *vin.prevout.hash() };
                let prev_n = vin.prevout.n() as u64;

                if let Some(wtx) = current.get(&prev_txid) {
                    // One of the tx outputs is a match
                    if let Some(spent_utxo) = wtx
                        .utxos
                        .iter()
                        .find(|u| u.txid == prev_txid && u.output_index == prev_n)
                    {
                        info!("Spent: utxo from {} was spent in {}", prev_txid, tx.txid());
                        total_transparent_value_spent += spent_utxo.value;
                        spent_utxos.push((prev_txid, prev_n as u32, tx.txid(), height));
                    }
                }
            }
        }

        // Mark all the UTXOs that were spent here back in their original txns.
        for (prev_txid, prev_n, txid, height) in spent_utxos {
            // Mark that this Tx spent some funds
            is_outgoing_tx = true;

            wallet_txns
                .write()
                .await
                .mark_txid_utxo_spent(prev_txid, prev_n, txid, height.into());
        }

        // If this Tx spent value, add the spent amount to the TxID
        if total_transparent_value_spent > 0 {
            wallet_txns.write().await.add_taddr_spent(
                tx.txid(),
                height,
                block_time as u64,
                &None,
                total_transparent_value_spent,
            );
        }

        // Step 2: Scan all transparent outputs to see if we recieved any money
        for (n, vout) in tx.vout.iter().enumerate() {
            match vout.script_pubkey.address() {
                Some(TransparentAddress::PublicKey(hash)) => {
                    let output_taddr = hash.to_base58check(&config.base58_pubkey_address(), &[]);
                    if taddrs_set.contains(&output_taddr) {
                        // This is our address. Add this as an output to the txid

                        wallet_txns.write().await.add_new_taddr_output(
                            tx.txid(),
                            output_taddr.clone(),
                            height.into(),
                            block_time as u64,
                            &None,
                            &vout,
                            n as u32,
                        );

                        // Ensure that we add any new HD addresses
                        keys.write().await.ensure_hd_taddresses(&output_taddr);
                    }
                }
                _ => {}
            }
        }

        // Collect all our z addresses, to check for change
        let z_addresses: HashSet<String> = HashSet::from_iter(keys.read().await.get_all_zaddresses().into_iter());

        // Collect all our OVKs, to scan for outputs
        let ovks: Vec<_> = keys
            .read()
            .await
            .get_all_extfvks()
            .iter()
            .map(|k| k.fvk.ovk.clone())
            .collect();

        let ivks: Vec<_> = keys
            .read()
            .await
            .get_all_extfvks()
            .iter()
            .map(|k| k.fvk.vk.ivk())
            .collect();

        // Step 3: Scan shielded sapling outputs to see if anyone of them is us, and if it is, extract the memo. Note that if this
        // is invoked by a transparent transaction, and we have not seen this Tx from the trial_decryptions processor, the Note
        // might not exist, and the memo updating might be a No-Op. That's Ok, the memo will get updated when this Tx is scanned
        // a second time by the Full Tx Fetcher
        for output in tx.shielded_outputs.iter() {
            let cmu = output.cmu;
            let ct = output.enc_ciphertext;

            // Search all of our keys
            for ivk in ivks.iter() {
                let epk_prime = output.ephemeral_key;

                let (note, _to, memo) =
                    match try_sapling_note_decryption(&MAIN_NETWORK, height, &ivk, &epk_prime, &cmu, &ct) {
                        Some(ret) => ret,
                        None => continue,
                    };

                info!("A sapling note was received into the wallet in {}", tx.txid());
                match memo.try_into() {
                    Ok(m) => {
                        wallet_txns.write().await.add_memo_to_note(&tx.txid(), note, m);
                    }
                    _ => {
                        //error!("Couldn't parse memo");
                    }
                }
            }

            // Also scan the output to see if it can be decoded with our OutgoingViewKey
            // If it can, then we sent this transaction, so we should be able to get
            // the memo and value for our records

            // Search all ovks that we have
            let mut outgoing_metadatas: Vec<_> = ovks
                .iter()
                .filter_map(|ovk| {
                    match try_sapling_output_recovery(
                        &MAIN_NETWORK,
                        height,
                        &ovk,
                        &output.cv,
                        &output.cmu,
                        &output.ephemeral_key,
                        &output.enc_ciphertext,
                        &output.out_ciphertext,
                    ) {
                        Some((note, payment_address, memo_bytes)) => {
                            // Mark this tx as an outgoing tx, so we can grab all outgoing metadata
                            is_outgoing_tx = true;

                            let address = encode_payment_address(config.hrp_sapling_address(), &payment_address);

                            // Check if this is change, and if it also doesn't have a memo, don't add
                            // to the outgoing metadata.
                            // If this is change (i.e., funds sent to ourself) AND has a memo, then
                            // presumably the users is writing a memo to themself, so we will add it to
                            // the outgoing metadata, even though it might be confusing in the UI, but hopefully
                            // the user can make sense of it.
                            match Memo::try_from(memo_bytes) {
                                Err(_) => None,
                                Ok(memo) => {
                                    if z_addresses.contains(&address) && memo == Memo::Empty {
                                        None
                                    } else {
                                        Some(OutgoingTxMetadata {
                                            address,
                                            value: note.value,
                                            memo,
                                        })
                                    }
                                }
                            }
                        }
                        None => None,
                    }
                })
                .collect();

            // If this Tx in outgoing, i.e., we recieved sent some money in this Tx, then we need to grab all transparent outputs
            // that don't belong to us as the outgoing metadata
            let mut taddr_outgoing_metadatas = vec![];
            if is_outgoing_tx {
                for vout in tx.vout.iter() {
                    let taddr = keys.read().await.address_from_pubkeyhash(vout.script_pubkey.address());

                    if taddr.is_some() && !taddrs_set.contains(&taddr.clone().unwrap()) {
                        let taddr = taddr.unwrap();

                        taddr_outgoing_metadatas.push(OutgoingTxMetadata {
                            address: taddr,
                            value: vout.value.into(),
                            memo: Memo::Empty,
                        });
                    }
                }

                // Also, if this is an outgoing transaction, then mark all the *incoming* sapling notes to this Tx as change.
                // Note that this is also done in `WalletTxns::add_new_spent`, but that doesn't take into account transparent spends,
                // so we'll do it again here.
                wallet_txns.write().await.mark_notes_as_change(&tx.txid());
            }

            // Add the z and t outgoing metadatas
            outgoing_metadatas.extend(taddr_outgoing_metadatas);

            if !outgoing_metadatas.is_empty() {
                wallet_txns
                    .write()
                    .await
                    .add_outgoing_metadata(&tx.txid(), outgoing_metadatas);
            }
        }

        println!("### Finished Fetching full tx {}", tx.txid());
        Ok(())
    }
}
