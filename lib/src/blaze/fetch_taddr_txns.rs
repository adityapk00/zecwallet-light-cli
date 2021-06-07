use crate::compact_formats::RawTransaction;

use crate::lightwallet::keys::Keys;
use std::sync::Arc;
use tokio::sync::mpsc::unbounded_channel;
use tokio::{
    sync::{mpsc::UnboundedSender, RwLock},
    task::JoinHandle,
};
use zcash_primitives::consensus::BlockHeight;

use zcash_primitives::transaction::Transaction;

pub struct FetchTaddrTxns {
    keys: Arc<RwLock<Keys>>,
}

impl FetchTaddrTxns {
    pub fn new(keys: Arc<RwLock<Keys>>) -> Self {
        Self { keys }
    }

    pub async fn start(
        &self,
        start_height: u64,
        end_height: u64,
        taddr_fetcher: UnboundedSender<((Vec<String>, u64, u64), UnboundedSender<Result<RawTransaction, String>>)>,
        full_tx_scanner: UnboundedSender<(Transaction, BlockHeight)>,
    ) -> JoinHandle<Result<(), String>> {
        let keys = self.keys.clone();

        tokio::spawn(async move {
            let taddrs = keys.read().await.get_all_taddrs();

            // Fetch all transactions for all t-addresses in parallel, and process them in height order
            let req = (taddrs, start_height, end_height);
            let (res_tx, mut res_rx) = unbounded_channel();
            taddr_fetcher.send((req, res_tx)).unwrap();

            let mut prev_height = u64::MAX;

            while let Some(rtx_r) = res_rx.recv().await {
                let rtx = rtx_r?;

                // We should be reciving transactions strictly in height order, so make sure
                if rtx.height > prev_height {
                    panic!("Wrong height order while processing transparent transactions!");
                }
                prev_height = rtx.height;

                let tx = Transaction::read(&rtx.data[..]).map_err(|e| format!("{}", e))?;
                full_tx_scanner
                    .send((tx, BlockHeight::from_u32(rtx.height as u32)))
                    .unwrap();
            }

            Ok(())
        })
    }
}
