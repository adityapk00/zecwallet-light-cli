use crate::compact_formats::compact_tx_streamer_server::CompactTxStreamer;
use crate::compact_formats::{
    Address, AddressList, Balance, BlockId, BlockRange, ChainSpec, CompactBlock, CompactTx, Duration, Empty, Exclude,
    GetAddressUtxosArg, GetAddressUtxosReply, GetAddressUtxosReplyList, LightdInfo, PingResponse, PriceRequest,
    PriceResponse, RawTransaction, SendResponse, TransparentAddressBlockFilter, TreeState, TxFilter,
};
use crate::lightwallet::data::WalletTx;
use crate::lightwallet::now;
use futures::Stream;
use std::cmp;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use zcash_primitives::block::BlockHash;
use zcash_primitives::merkle_tree::CommitmentTree;
use zcash_primitives::sapling::Node;
use zcash_primitives::transaction::{Transaction, TxId};

use super::lightclient_config::LightClientConfig;

#[derive(Debug)]
pub struct TestServerData {
    pub blocks: Vec<CompactBlock>,
    pub txns: HashMap<TxId, (Vec<String>, RawTransaction)>,
    pub sent_txns: Vec<RawTransaction>,
    pub config: LightClientConfig,
    pub zec_price: f64,
}

impl TestServerData {
    pub fn new(config: LightClientConfig) -> Self {
        let data = Self {
            blocks: vec![],
            txns: HashMap::new(),
            sent_txns: vec![],
            config,
            zec_price: 140.5,
        };

        data
    }

    pub fn add_txns(&mut self, txns: Vec<(Transaction, u64, Vec<String>)>) {
        for (tx, height, taddrs) in txns {
            let mut rtx = RawTransaction::default();
            let mut data = vec![];
            tx.write(&mut data).unwrap();
            rtx.data = data;
            rtx.height = height;
            self.txns.insert(tx.txid(), (taddrs, rtx));
        }
    }

    pub fn add_blocks(&mut self, cbs: Vec<CompactBlock>) {
        if cbs.is_empty() {
            panic!("No blocks");
        }

        if cbs.len() > 1 {
            if cbs.first().unwrap().height < cbs.last().unwrap().height {
                panic!(
                    "Blocks are in the wrong order. First={} Last={}",
                    cbs.first().unwrap().height,
                    cbs.last().unwrap().height
                );
            }
        }

        if !self.blocks.is_empty() {
            if self.blocks.first().unwrap().height + 1 != cbs.last().unwrap().height {
                panic!(
                    "New blocks are in wrong order. expecting={}, got={}",
                    self.blocks.first().unwrap().height + 1,
                    cbs.last().unwrap().height
                );
            }
        }

        for blk in cbs.into_iter().rev() {
            self.blocks.insert(0, blk);
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

        if self.data.read().await.blocks.len() > 1 {
            if self.data.read().await.blocks.first().unwrap().height
                < self.data.read().await.blocks.last().unwrap().height
            {}
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

    async fn get_zec_price(&self, _request: Request<PriceRequest>) -> Result<Response<PriceResponse>, Status> {
        self.get_current_zec_price(Request::new(Empty {})).await
    }

    async fn get_current_zec_price(&self, _request: Request<Empty>) -> Result<Response<PriceResponse>, Status> {
        let mut res = PriceResponse::default();
        res.currency = "USD".to_string();
        res.timestamp = now() as i64;
        res.price = self.data.read().await.zec_price;

        Ok(Response::new(res))
    }

    async fn get_transaction(&self, request: Request<TxFilter>) -> Result<Response<RawTransaction>, Status> {
        let txid = WalletTx::new_txid(&request.into_inner().hash);
        match self.data.read().await.txns.get(&txid) {
            Some((_taddrs, tx)) => Ok(Response::new(tx.clone())),
            None => Err(Status::invalid_argument(format!("Can't find txid {}", txid))),
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
        let buf_size = cmp::max(self.data.read().await.txns.len(), 1);
        let (tx, rx) = mpsc::channel(buf_size);

        let request = request.into_inner();
        let taddr = request.address;
        let start_block = request.range.as_ref().unwrap().start.as_ref().unwrap().height;
        let end_block = request.range.as_ref().unwrap().end.as_ref().unwrap().height;

        let txns = self.data.read().await.txns.clone();
        tokio::spawn(async move {
            let mut txns_to_send = txns
                .values()
                .filter_map(|(taddrs, rtx)| {
                    if taddrs.contains(&taddr) && rtx.height >= start_block && rtx.height <= end_block {
                        Some(rtx.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            txns_to_send.sort_by_key(|rtx| rtx.height);

            for rtx in txns_to_send {
                tx.send(Ok(rtx)).await.unwrap();
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

    async fn get_taddress_balance(&self, _request: Request<AddressList>) -> Result<Response<Balance>, Status> {
        todo!()
    }

    async fn get_taddress_balance_stream(
        &self,
        _request: Request<tonic::Streaming<Address>>,
    ) -> Result<Response<Balance>, Status> {
        todo!()
    }

    type GetMempoolTxStream = Pin<Box<dyn Stream<Item = Result<CompactTx, Status>> + Send + Sync>>;

    async fn get_mempool_tx(&self, _request: Request<Exclude>) -> Result<Response<Self::GetMempoolTxStream>, Status> {
        todo!()
    }

    async fn get_tree_state(&self, request: Request<BlockId>) -> Result<Response<TreeState>, Status> {
        let block = request.into_inner();

        let tree = self
            .data
            .read()
            .await
            .blocks
            .iter()
            .fold(CommitmentTree::<Node>::empty(), |mut tree, cb| {
                for tx in &cb.vtx {
                    for co in &tx.outputs {
                        tree.append(Node::new(co.cmu().unwrap().into())).unwrap();
                    }
                }

                tree
            });

        let mut ts = TreeState::default();
        ts.hash = BlockHash::from_slice(
            &self
                .data
                .read()
                .await
                .blocks
                .iter()
                .find(|cb| cb.height == block.height)
                .unwrap()
                .hash[..],
        )
        .to_string();
        ts.height = block.height;

        let mut tree_bytes = vec![];
        tree.write(&mut tree_bytes).unwrap();
        ts.tree = hex::encode(tree_bytes);

        Ok(Response::new(ts))
    }

    async fn get_address_utxos(
        &self,
        _request: Request<GetAddressUtxosArg>,
    ) -> Result<Response<GetAddressUtxosReplyList>, Status> {
        todo!()
    }

    type GetAddressUtxosStreamStream = Pin<Box<dyn Stream<Item = Result<GetAddressUtxosReply, Status>> + Send + Sync>>;

    async fn get_address_utxos_stream(
        &self,
        _request: Request<GetAddressUtxosArg>,
    ) -> Result<Response<Self::GetAddressUtxosStreamStream>, Status> {
        todo!()
    }

    async fn get_lightd_info(&self, _request: Request<Empty>) -> Result<Response<LightdInfo>, Status> {
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

    async fn ping(&self, _request: Request<Duration>) -> Result<Response<PingResponse>, Status> {
        todo!()
    }
}
