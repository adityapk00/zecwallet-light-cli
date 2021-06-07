use std::collections::HashMap;
use std::sync::Arc;

use crate::compact_formats::compact_tx_streamer_client::CompactTxStreamerClient;
use crate::compact_formats::{
    BlockId, BlockRange, ChainSpec, CompactBlock, Empty, LightdInfo, PriceRequest, PriceResponse, RawTransaction,
    TransparentAddressBlockFilter, TreeState, TxFilter,
};
use futures::future::join_all;
use log::warn;
use tokio::join;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tonic::{
    transport::{Channel, Error},
    Request,
};
use zcash_primitives::transaction::{Transaction, TxId};

#[derive(Clone)]
pub struct GrpcConnector {
    uri: http::Uri,
}

impl GrpcConnector {
    pub fn new(uri: http::Uri) -> Self {
        Self { uri }
    }

    async fn get_client(&self) -> Result<CompactTxStreamerClient<Channel>, Error> {
        let channel = Channel::builder(self.uri.clone()).connect().await?;

        Ok(CompactTxStreamerClient::new(channel))
    }

    pub async fn start_saplingtree_fetcher(
        &self,
    ) -> (
        JoinHandle<()>,
        UnboundedSender<(u64, oneshot::Sender<Result<TreeState, String>>)>,
    ) {
        let (tx, mut rx) = unbounded_channel::<(u64, oneshot::Sender<Result<TreeState, String>>)>();
        let uri = self.uri.clone();

        let h = tokio::spawn(async move {
            let uri = uri.clone();
            while let Some((height, result_tx)) = rx.recv().await {
                result_tx
                    .send(Self::get_sapling_tree(uri.clone(), height).await)
                    .unwrap()
            }
        });

        (h, tx)
    }

    pub async fn start_taddr_txn_fetcher(
        &self,
    ) -> (
        JoinHandle<()>,
        UnboundedSender<((Vec<String>, u64, u64), UnboundedSender<Result<RawTransaction, String>>)>,
    ) {
        let (tx, mut rx) =
            unbounded_channel::<((Vec<String>, u64, u64), UnboundedSender<Result<RawTransaction, String>>)>();
        let uri = self.uri.clone();

        let h = tokio::spawn(async move {
            let uri = uri.clone();
            while let Some(((taddrs, start_height, end_height), result_tx)) = rx.recv().await {
                let mut tx_rs = vec![];
                let mut tx_rs_workers = vec![];

                // Create a stream for every t-addr
                for taddr in taddrs {
                    let (tx_s, tx_r) = unbounded_channel();
                    tx_rs.push(tx_r);
                    tx_rs_workers.push(tokio::spawn(Self::get_taddr_txns(
                        uri.clone(),
                        taddr,
                        start_height,
                        end_height,
                        tx_s,
                    )));
                }

                // Wait for all the t-addr transactions to be fetched from LightwalletD and sent to the h1 handle.
                let h0 = tokio::spawn(async move { join_all(tx_rs_workers).await });

                // Process every transparent address transaction, in order of height
                let h1 = tokio::spawn(async move {
                    // Now, read the transactions one-at-a-time, and then dispatch them in height order
                    let mut txns_top = vec![];

                    // Fill the array with the first transaction for every taddress
                    for tx_r in tx_rs.iter_mut() {
                        if let Some(Ok(txn)) = tx_r.recv().await {
                            txns_top.push(Some(txn));
                        } else {
                            txns_top.push(None);
                        }
                    }

                    // While at least one of them is still returning transactions
                    while txns_top.iter().any(|t| t.is_some()) {
                        // Find the txn with the lowest height
                        let (_height, idx) =
                            txns_top
                                .iter()
                                .enumerate()
                                .fold((u64::MAX, 0), |(prev_height, prev_idx), (idx, t)| {
                                    if let Some(txn) = t {
                                        if txn.height < prev_height {
                                            (txn.height, idx)
                                        } else {
                                            (prev_height, prev_idx)
                                        }
                                    } else {
                                        (prev_height, prev_idx)
                                    }
                                });

                        // Grab the tx at the index
                        let txn = txns_top[idx].as_ref().unwrap().clone();

                        // Replace the tx at the index that was just grabbed
                        if let Some(Ok(txn)) = tx_rs[idx].recv().await {
                            txns_top[idx] = Some(txn);
                        } else {
                            txns_top[idx] = None;
                        }

                        // Dispatch the result
                        result_tx.send(Ok(txn)).unwrap();
                    }
                });

                // Wait for senders and recievers
                join!(h0, h1);
            }
        });

        (h, tx)
    }

    pub async fn start_fulltx_fetcher(
        &self,
    ) -> (
        JoinHandle<()>,
        UnboundedSender<(TxId, oneshot::Sender<Result<Transaction, String>>)>,
    ) {
        let (tx, mut rx) = unbounded_channel::<(TxId, oneshot::Sender<Result<Transaction, String>>)>();
        let uri = self.uri.clone();

        let h = tokio::spawn(async move {
            let uri = uri.clone();
            while let Some((txid, result_tx)) = rx.recv().await {
                result_tx.send(Self::get_full_tx(uri.clone(), &txid).await).unwrap()
            }
        });

        (h, tx)
    }

    pub async fn get_block_range(
        &self,
        start_height: u64,
        end_height: u64,
        tx: UnboundedSender<CompactBlock>,
    ) -> Result<(), String> {
        let mut client = self.get_client().await.map_err(|e| format!("{}", e))?;

        let bs = BlockId {
            height: start_height,
            hash: vec![],
        };
        let be = BlockId {
            height: end_height,
            hash: vec![],
        };

        let request = Request::new(BlockRange {
            start: Some(bs),
            end: Some(be),
        });

        let mut response = client
            .get_block_range(request)
            .await
            .map_err(|e| format!("{}", e))?
            .into_inner();

        while let Some(block) = response.message().await.map_err(|e| format!("{}", e))? {
            tx.send(block).map_err(|e| format!("{}", e))?;
        }

        Ok(())
    }

    async fn get_full_tx(uri: http::Uri, txid: &TxId) -> Result<Transaction, String> {
        let client = Arc::new(GrpcConnector::new(uri));
        let request = Request::new(TxFilter {
            block: None,
            index: 0,
            hash: txid.0.to_vec(),
        });

        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let response = client.get_transaction(request).await.map_err(|e| format!("{}", e))?;

        Transaction::read(&response.into_inner().data[..]).map_err(|e| format!("Error parsing Transaction: {}", e))
    }

    async fn get_taddr_txns(
        uri: http::Uri,
        taddr: String,
        start_height: u64,
        end_height: u64,
        txns_sender: UnboundedSender<Result<RawTransaction, String>>,
    ) -> Result<(), String> {
        let client = Arc::new(GrpcConnector::new(uri));

        // Make sure start_height is smaller than end_height, because the API expects it like that
        let (start_height, end_height) = if start_height < end_height {
            (start_height, end_height)
        } else {
            (end_height, start_height)
        };

        let start = Some(BlockId {
            height: start_height,
            hash: vec![],
        });
        let end = Some(BlockId {
            height: end_height,
            hash: vec![],
        });

        let args = TransparentAddressBlockFilter {
            address: taddr,
            range: Some(BlockRange { start, end }),
        };
        let request = Request::new(args.clone());

        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let maybe_response = match client.get_taddress_txids(request).await {
            Ok(r) => r,
            Err(e) => {
                if e.code() == tonic::Code::Unimplemented {
                    // Try the old, legacy API
                    let request = Request::new(args);
                    client.get_address_txids(request).await.map_err(|e| format!("{}", e))?
                } else {
                    return Err(format!("{}", e));
                }
            }
        };

        let mut response = maybe_response.into_inner();

        while let Some(tx) = response.message().await.map_err(|e| format!("{}", e))? {
            txns_sender.send(Ok(tx)).unwrap();
        }

        Ok(())
    }

    pub async fn get_info(uri: http::Uri) -> Result<LightdInfo, String> {
        let client = Arc::new(GrpcConnector::new(uri));

        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let request = Request::new(Empty {});

        let response = client
            .get_lightd_info(request)
            .await
            .map_err(|e| format!("Error with response: {:?}", e))?;
        Ok(response.into_inner())
    }

    async fn get_sapling_tree(uri: http::Uri, height: u64) -> Result<TreeState, String> {
        let client = Arc::new(GrpcConnector::new(uri));
        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let b = BlockId {
            height: height as u64,
            hash: vec![],
        };
        let response = client
            .get_tree_state(Request::new(b))
            .await
            .map_err(|e| format!("Error with response: {:?}", e))?;

        Ok(response.into_inner())
    }

    pub async fn get_current_zec_price(uri: http::Uri) -> Result<PriceResponse, String> {
        let client = Arc::new(GrpcConnector::new(uri));
        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;
        let request = Request::new(Empty {});

        let response = client
            .get_current_zec_price(request)
            .await
            .map_err(|e| format!("Error with response: {:?}", e))?;

        Ok(response.into_inner())
    }

    pub async fn get_historical_zec_prices(
        uri: http::Uri,
        txids: Vec<(TxId, u64)>,
        currency: String,
    ) -> Result<HashMap<TxId, Option<f64>>, String> {
        let client = Arc::new(GrpcConnector::new(uri));
        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let mut prices = HashMap::new();

        for (txid, ts) in txids {
            let r = Request::new(PriceRequest {
                timestamp: ts,
                currency: currency.clone(),
            });
            match client.get_zec_price(r).await {
                Ok(response) => {
                    let price_response = response.into_inner();
                    prices.insert(txid, Some(price_response.price));
                }
                Err(e) => {
                    // If the server doesn't support this, bail
                    if e.code() == tonic::Code::Unimplemented {
                        return Err(format!("Unsupported by server"));
                    }

                    // Ignore other errors, these are probably just for the particular date/time
                    // and will be retried anyway
                    warn!("Ignoring grpc error: {}", e);
                    prices.insert(txid, None);
                }
            }
        }

        Ok(prices)
    }

    // get_latest_block GRPC call
    pub async fn get_latest_block(uri: http::Uri) -> Result<BlockId, String> {
        let client = Arc::new(GrpcConnector::new(uri));
        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let request = Request::new(ChainSpec {});

        let response = client
            .get_latest_block(request)
            .await
            .map_err(|e| format!("Error with response: {:?}", e))?;

        Ok(response.into_inner())
    }

    pub async fn send_transaction(uri: http::Uri, tx_bytes: Box<[u8]>) -> Result<String, String> {
        let client = Arc::new(GrpcConnector::new(uri));
        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let request = Request::new(RawTransaction {
            data: tx_bytes.to_vec(),
            height: 0,
        });

        let response = client
            .send_transaction(request)
            .await
            .map_err(|e| format!("Send Error: {}", e))?;

        let sendresponse = response.into_inner();
        if sendresponse.error_code == 0 {
            let mut txid = sendresponse.error_message;
            if txid.starts_with("\"") && txid.ends_with("\"") {
                txid = txid[1..txid.len() - 1].to_string();
            }

            Ok(txid)
        } else {
            Err(format!("Error: {:?}", sendresponse))
        }
    }
}
