use crate::compact_formats::compact_tx_streamer_server::CompactTxStreamer;
use crate::compact_formats::{
    Address, AddressList, Balance, BlockId, BlockRange, ChainSpec, CompactBlock, CompactTx, Duration, Empty, Exclude,
    GetAddressUtxosArg, GetAddressUtxosReply, GetAddressUtxosReplyList, LightdInfo, PingResponse, PriceRequest,
    PriceResponse, RawTransaction, SendResponse, TransparentAddressBlockFilter, TreeState, TxFilter,
};
use crate::lightwallet::data::WalletTx;
use futures::Stream;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use zcash_primitives::transaction::{Transaction, TxId};

use super::lightclient_config::LightClientConfig;

#[derive(Debug)]
pub struct TestServerData {
    blocks: Vec<CompactBlock>,
    txns: HashMap<TxId, (Vec<String>, RawTransaction)>,
    sent_txns: Vec<RawTransaction>,
    config: LightClientConfig,
}

impl TestServerData {
    pub fn new(config: LightClientConfig) -> Self {
        Self {
            blocks: vec![],
            txns: HashMap::new(),
            sent_txns: vec![],
            config,
        }
    }
}

#[derive(Debug)]
pub struct TestGRPCService {
    data: Arc<RwLock<TestServerData>>,
}

impl TestGRPCService {
    pub fn new(config: LightClientConfig) -> (Self, Arc<RwLock<TestServerData>>) {
        let data = Arc::new(RwLock::new(TestServerData::new(config)));
        let s = Self { data: data.clone() };

        (s, data)
    }
}

#[tonic::async_trait]
impl CompactTxStreamer for TestGRPCService {
    async fn get_latest_block(&self, _request: Request<ChainSpec>) -> Result<Response<BlockId>, Status> {
        match self.data.read().await.blocks.iter().max_by_key(|b| b.height) {
            Some(latest_block) => Ok(Response::new(BlockId {
                height: latest_block.height,
                hash: latest_block.hash.clone(),
            })),
            None => Err(Status::unavailable("No blocks")),
        }
    }

    async fn get_block(&self, request: Request<BlockId>) -> Result<Response<CompactBlock>, Status> {
        let height = request.into_inner().height;

        match self.data.read().await.blocks.iter().find(|b| b.height == height) {
            Some(b) => Ok(Response::new(b.clone())),
            None => Err(Status::unavailable(format!("Block {} not found", height))),
        }
    }

    type GetBlockRangeStream = Pin<Box<dyn Stream<Item = Result<CompactBlock, Status>> + Send + Sync>>;
    async fn get_block_range(
        &self,
        request: Request<BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeStream>, Status> {
        let request = request.into_inner();
        let start = request.start.unwrap().height;
        let end = request.end.unwrap().height;

        if start < end {
            return Err(Status::unimplemented(format!(
                "Can't stream blocks from smaller to heighest yet"
            )));
        }

        let (tx, rx) = mpsc::channel(self.data.read().await.blocks.len());

        let blocks = self.data.read().await.blocks.clone();
        tokio::spawn(async move {
            for b in blocks {
                if b.height <= start && b.height >= end {
                    tx.send(Ok(b)).await.unwrap();
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn get_zec_price(&self, request: Request<PriceRequest>) -> Result<Response<PriceResponse>, Status> {
        todo!()
    }

    async fn get_current_zec_price(&self, request: Request<Empty>) -> Result<Response<PriceResponse>, Status> {
        todo!()
    }

    async fn get_transaction(&self, request: Request<TxFilter>) -> Result<Response<RawTransaction>, Status> {
        let txid = WalletTx::new_txid(&request.into_inner().hash);
        match self.data.read().await.txns.get(&txid) {
            Some((_taddrs, tx)) => Ok(Response::new(tx.clone())),
            None => Err(Status::unimplemented(format!("Can't find txid {}", txid))),
        }
    }

    async fn send_transaction(&self, request: Request<RawTransaction>) -> Result<Response<SendResponse>, Status> {
        let rtx = request.into_inner();
        let txid = Transaction::read(&rtx.data[..]).unwrap().txid();

        self.data.write().await.sent_txns.push(rtx);
        Ok(Response::new(SendResponse {
            error_message: txid.to_string(),
            error_code: 0,
        }))
    }

    type GetTaddressTxidsStream = Pin<Box<dyn Stream<Item = Result<RawTransaction, Status>> + Send + Sync>>;

    async fn get_taddress_txids(
        &self,
        request: Request<TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTxidsStream>, Status> {
        let (tx, rx) = mpsc::channel(self.data.read().await.txns.len());
        let taddr = request.into_inner().address;

        let txns = self.data.read().await.txns.clone();
        tokio::spawn(async move {
            for (taddrs, rtx) in txns.values() {
                if taddrs.contains(&taddr) {
                    tx.send(Ok(rtx.clone())).await.unwrap();
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    type GetAddressTxidsStream = Pin<Box<dyn Stream<Item = Result<RawTransaction, Status>> + Send + Sync>>;

    async fn get_address_txids(
        &self,
        request: Request<TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetAddressTxidsStream>, Status> {
        self.get_taddress_txids(request).await
    }

    async fn get_taddress_balance(&self, request: Request<AddressList>) -> Result<Response<Balance>, Status> {
        todo!()
    }

    async fn get_taddress_balance_stream(
        &self,
        request: Request<tonic::Streaming<Address>>,
    ) -> Result<Response<Balance>, Status> {
        todo!()
    }

    type GetMempoolTxStream = Pin<Box<dyn Stream<Item = Result<CompactTx, Status>> + Send + Sync>>;

    async fn get_mempool_tx(&self, request: Request<Exclude>) -> Result<Response<Self::GetMempoolTxStream>, Status> {
        todo!()
    }

    async fn get_tree_state(&self, request: Request<BlockId>) -> Result<Response<TreeState>, Status> {
        todo!()
    }

    async fn get_address_utxos(
        &self,
        request: Request<GetAddressUtxosArg>,
    ) -> Result<Response<GetAddressUtxosReplyList>, Status> {
        todo!()
    }

    type GetAddressUtxosStreamStream = Pin<Box<dyn Stream<Item = Result<GetAddressUtxosReply, Status>> + Send + Sync>>;

    async fn get_address_utxos_stream(
        &self,
        request: Request<GetAddressUtxosArg>,
    ) -> Result<Response<Self::GetAddressUtxosStreamStream>, Status> {
        todo!()
    }

    async fn get_lightd_info(&self, request: Request<Empty>) -> Result<Response<LightdInfo>, Status> {
        let mut ld = LightdInfo::default();
        ld.version = format!("Test GRPC Server");
        ld.block_height = self
            .data
            .read()
            .await
            .blocks
            .iter()
            .map(|b| b.height)
            .max()
            .unwrap_or(0);
        ld.taddr_support = true;
        ld.chain_name = self.data.read().await.config.chain_name.clone();
        ld.sapling_activation_height = self.data.read().await.config.sapling_activation_height;

        Ok(Response::new(ld))
    }

    async fn ping(&self, request: Request<Duration>) -> Result<Response<PingResponse>, Status> {
        todo!()
    }
}
