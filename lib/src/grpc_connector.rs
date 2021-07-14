use std::collections::HashMap;
use std::sync::Arc;

use crate::compact_formats::compact_tx_streamer_client::CompactTxStreamerClient;
use crate::compact_formats::{
    BlockId, BlockRange, ChainSpec, CompactBlock, Empty, LightdInfo, PriceRequest, PriceResponse, RawTransaction,
    TransparentAddressBlockFilter, TreeState, TxFilter,
};
use futures::future::join_all;
use log::warn;

use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_rustls::rustls::ClientConfig;
use tonic::transport::ClientTlsConfig;
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
        let channel = if self.uri.scheme_str() == Some("http") {
            //println!("http");
            Channel::builder(self.uri.clone()).connect().await?
        } else {
            //println!("https");
            let mut config = ClientConfig::new();

            config.alpn_protocols.push(b"h2".to_vec());
            config
                .root_store
                .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

            let tls = ClientTlsConfig::new()
                .rustls_client_config(config)
                .domain_name(self.uri.host().unwrap());

            Channel::builder(self.uri.clone()).tls_config(tls)?.connect().await?
        };

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
        oneshot::Sender<(
            (Vec<String>, u64, u64),
            oneshot::Sender<Vec<UnboundedReceiver<Result<RawTransaction, String>>>>,
        )>,
    ) {
        let (tx, rx) = oneshot::channel::<(
            (Vec<String>, u64, u64),
            oneshot::Sender<Vec<UnboundedReceiver<Result<RawTransaction, String>>>>,
        )>();
        let uri = self.uri.clone();

        let h = tokio::spawn(async move {
            let uri = uri.clone();
            if let Ok(((taddrs, start_height, end_height), result_tx)) = rx.await {
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

                // Dispatch a set of recievers
                result_tx.send(tx_rs).unwrap();

                // // Wait for all the t-addr transactions to be fetched from LightwalletD and sent to the h1 handle.
                join_all(tx_rs_workers).await;
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

    pub async fn monitor_mempool(uri: http::Uri, mempool_tx: UnboundedSender<RawTransaction>) -> Result<(), String> {
        let client = Arc::new(GrpcConnector::new(uri));

        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let request = Request::new(Empty {});

        let mut response = client
            .get_mempool_stream(request)
            .await
            .map_err(|e| format!("{}", e))?
            .into_inner();
        while let Some(rtx) = response.message().await.map_err(|e| format!("{}", e))? {
            mempool_tx.send(rtx).map_err(|e| format!("{}", e))?;
        }

        Ok(())
    }

    pub async fn get_sapling_tree(uri: http::Uri, height: u64) -> Result<TreeState, String> {
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
