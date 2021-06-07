use crate::compact_formats::RawTransaction;

use crate::lightwallet::keys::Keys;
use std::sync::Arc;
use tokio::{
    sync::{mpsc::UnboundedSender, oneshot, RwLock},
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
        taddr_fetcher: UnboundedSender<((String, u64, u64), oneshot::Sender<Result<Vec<RawTransaction>, String>>)>,
        full_tx_scanner: UnboundedSender<(Transaction, BlockHeight)>,
    ) -> JoinHandle<Result<(), String>> {
        let keys = self.keys.clone();

        tokio::spawn(async move {
            // Fetch for each Transparent address
            let taddrs = keys.read().await.get_all_taddrs();

            for taddr in taddrs {
                let req = (taddr, start_height, end_height);
                let (res_tx, res_rx) = oneshot::channel();
                taddr_fetcher.send((req, res_tx)).unwrap();

                let txns = res_rx.await.map_err(|e| format!("{}", e))??;
                for rtx in txns {
                    let tx = Transaction::read(&rtx.data[..]).map_err(|e| format!("{}", e))?;
                    full_tx_scanner
                        .send((tx, BlockHeight::from_u32(rtx.height as u32)))
                        .unwrap();
                }
            }

            Ok(())
        })
    }
}
