use std::sync::Arc;

use futures::FutureExt;
use portpicker;
use tempdir::TempDir;
use tokio::sync::{oneshot, RwLock};
use tokio::task::JoinHandle;
use tonic::transport::{Channel, Server};
use tonic::Request;

use crate::blaze::test_utils::FakeCompactBlockList;
use crate::compact_formats::compact_tx_streamer_client::CompactTxStreamerClient;
use crate::compact_formats::compact_tx_streamer_server::CompactTxStreamerServer;
use crate::compact_formats::Empty;
use crate::lightclient::lightclient_config::LightClientConfig;
use crate::lightclient::test_server::TestGRPCService;
use crate::lightclient::LightClient;

use super::test_server::TestServerData;

async fn create_test_server() -> (
    Arc<RwLock<TestServerData>>,
    LightClientConfig,
    oneshot::Receiver<bool>,
    oneshot::Sender<bool>,
    JoinHandle<()>,
) {
    let (ready_tx, ready_rx) = oneshot::channel();
    let (stop_tx, stop_rx) = oneshot::channel();

    let port = portpicker::pick_unused_port().unwrap();
    let server_port = format!("127.0.0.1:{}", port);
    let uri = format!("http://{}", server_port);
    let addr = server_port.parse().unwrap();

    let mut config = LightClientConfig::create_unconnected("main".to_string(), None);
    config.server = uri.parse().unwrap();

    let (service, data) = TestGRPCService::new(config.clone());

    let (data_dir_tx, data_dir_rx) = oneshot::channel();

    let h1 = tokio::spawn(async move {
        let svc = CompactTxStreamerServer::new(service);

        // We create the temp dir here, so that we can clean it up after the test runs
        let temp_dir = TempDir::new(&format!("test{}", port).as_str()).unwrap();

        // Send the path name. Do into_path() to preserve the temp directory
        data_dir_tx
            .send(temp_dir.path().canonicalize().unwrap().to_str().unwrap().to_string())
            .unwrap();

        ready_tx.send(true).unwrap();
        Server::builder()
            .add_service(svc)
            .serve_with_shutdown(addr, stop_rx.map(drop))
            .await
            .unwrap();

        println!("Server stopped");
    });

    let data_dir = data_dir_rx.await.unwrap();
    println!("GRPC Server listening on: {}. With datadir {}", addr, data_dir);
    config.data_dir = Some(data_dir);

    (data, config, ready_rx, stop_tx, h1)
}

async fn mine_random_blocks(
    fcbl: &mut FakeCompactBlockList,
    data: &Arc<RwLock<TestServerData>>,
    lc: &LightClient,
    num: u64,
) {
    let cbs = fcbl.add_blocks(num).into_compact_blocks();

    data.write().await.add_blocks(cbs.clone());
    lc.do_sync(true).await.unwrap();
}

async fn mine_pending_blocks(fcbl: &mut FakeCompactBlockList, data: &Arc<RwLock<TestServerData>>, lc: &LightClient) {
    let cbs = fcbl.into_compact_blocks();

    data.write().await.add_blocks(cbs.clone());
    data.write().await.add_txns(fcbl.into_txns());

    lc.do_sync(true).await.unwrap();
}

#[tokio::test]
async fn basic_no_wallet_txns() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server().await;

    ready_rx.await.unwrap();

    let uri = config.server.clone();
    let mut client = CompactTxStreamerClient::new(Channel::builder(uri).connect().await.unwrap());

    let r = client
        .get_lightd_info(Request::new(Empty {}))
        .await
        .unwrap()
        .into_inner();
    println!("{:?}", r);

    let lc = LightClient::test_new(&config, None).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    mine_random_blocks(&mut fcbl, &data, &lc, 100).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 100);

    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn z_incoming_z_outgoing() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server().await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // Mine 100 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 100).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 100);

    // Send an incoming tx
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let value = 10_000;
    let (_nf, _tx, _height) = fcbl.add_tx_paying(&extfvk1, value);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    assert_eq!(lc.wallet.last_scanned_height().await, 101);

    let b = lc.do_balance().await;
    assert_eq!(b["zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["unverified_zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["spendable_zbalance"].as_u64().unwrap(), 0);

    // Then add another 5 blocks, so the funds will become confirmed
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;
    let b = lc.do_balance().await;
    assert_eq!(b["zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["unverified_zbalance"].as_u64().unwrap(), 0);
    assert_eq!(b["spendable_zbalance"].as_u64().unwrap(), value);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}
