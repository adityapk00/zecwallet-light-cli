use std::sync::Arc;

use futures::FutureExt;
use portpicker;
use tokio::sync::{oneshot, RwLock};
use tokio::task::JoinHandle;
use tonic::transport::{Channel, Server};
use tonic::Request;

use crate::compact_formats::compact_tx_streamer_client::CompactTxStreamerClient;
use crate::compact_formats::compact_tx_streamer_server::CompactTxStreamerServer;
use crate::compact_formats::{
    BlockId, BlockRange, ChainSpec, CompactBlock, Empty, LightdInfo, PriceRequest, PriceResponse, RawTransaction,
    TransparentAddressBlockFilter, TreeState, TxFilter,
};
use crate::lightclient::lightclient_config::LightClientConfig;
use crate::lightclient::test_server::TestGRPCService;

use super::test_server::TestServerData;

fn create_test_server() -> (
    Arc<RwLock<TestServerData>>,
    String,
    oneshot::Receiver<bool>,
    oneshot::Sender<bool>,
    JoinHandle<()>,
) {
    let (ready_tx, ready_rx) = oneshot::channel();
    let (stop_tx, stop_rx) = oneshot::channel();

    let port = portpicker::pick_unused_port().unwrap();
    let uri = format!("127.0.0.1:{}", port);
    let addr = uri.parse().unwrap();

    println!("GRPC Server listening on: {}", addr);
    let (service, data) = TestGRPCService::new(LightClientConfig::create_unconnected("main".to_string(), None));

    let h1 = tokio::spawn(async move {
        let svc = CompactTxStreamerServer::new(service);

        ready_tx.send(true).unwrap();

        Server::builder()
            .add_service(svc)
            .serve_with_shutdown(addr, stop_rx.map(drop))
            .await
            .unwrap();
        println!("Server stopped");
    });

    (data, format!("http://{}", uri), ready_rx, stop_tx, h1)
}

#[tokio::test]
async fn test_basic() {
    let (data, uri, ready_rx, stop_tx, h1) = create_test_server();

    ready_rx.await.unwrap();

    let mut client = CompactTxStreamerClient::new(Channel::builder(uri.parse().unwrap()).connect().await.unwrap());

    let r = client
        .get_lightd_info(Request::new(Empty {}))
        .await
        .unwrap()
        .into_inner();
    println!("{:?}", r);

    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}
