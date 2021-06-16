use std::sync::Arc;

use futures::FutureExt;
use json::JsonValue;
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
use crate::lightwallet::fee;

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

    // 1. Mine 100 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 100).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 100);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let value = 100_000;
    let (_nf, tx, _height) = fcbl.add_tx_paying(&extfvk1, value);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    assert_eq!(lc.wallet.last_scanned_height().await, 101);

    // 3. Check the balance is correct, and we recieved the incoming tx from outside
    let b = lc.do_balance().await;
    assert_eq!(b["zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["unverified_zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["spendable_zbalance"].as_u64().unwrap(), 0);
    assert_eq!(
        b["z_addresses"][0]["address"],
        lc.wallet.keys().read().await.get_all_zaddresses()[0]
    );
    assert_eq!(b["z_addresses"][0]["zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["z_addresses"][0]["unverified_zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["z_addresses"][0]["spendable_zbalance"].as_u64().unwrap(), 0);

    let list = lc.do_list_transactions(false).await;
    if let JsonValue::Array(list) = list {
        assert_eq!(list.len(), 1);
        let jv = list[0].clone();

        assert_eq!(jv["txid"], tx.txid().to_string());
        assert_eq!(jv["amount"].as_u64().unwrap(), value);
        assert_eq!(jv["address"], lc.wallet.keys().read().await.get_all_zaddresses()[0]);
        assert_eq!(jv["block_height"].as_u64().unwrap(), 101);
    } else {
        panic!("Expecting an array");
    }

    // 4. Then add another 5 blocks, so the funds will become confirmed
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;
    let b = lc.do_balance().await;
    assert_eq!(b["zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["unverified_zbalance"].as_u64().unwrap(), 0);
    assert_eq!(b["spendable_zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["z_addresses"][0]["zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["z_addresses"][0]["spendable_zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["z_addresses"][0]["unverified_zbalance"].as_u64().unwrap(), 0);

    // 5. Send z-to-z tx to external z address with a memo
    let fee = fee::get_default_fee(107);
    let sent_value = 1000;
    let outgoing_memo = "Outgoing Memo".to_string();

    let sent_txid = lc
        .test_do_send(vec![(EXT_ZADDR, sent_value, Some(outgoing_memo.clone()))])
        .await
        .unwrap();

    // 6. Check the unconfirmed txn is present
    // 6.1 Check notes

    let notes = lc.do_list_notes(true).await;
    assert_eq!(notes["unspent_notes"].len(), 0);
    assert_eq!(notes["spent_notes"].len(), 0);
    assert_eq!(notes["pending_notes"].len(), 1);
    assert_eq!(notes["pending_notes"][0]["created_in_txid"], tx.txid().to_string());
    assert_eq!(notes["pending_notes"][0]["unconfirmed_spent"], sent_txid);
    assert_eq!(notes["pending_notes"][0]["spent"].is_null(), true);
    assert_eq!(notes["pending_notes"][0]["spent_at_height"].is_null(), true);

    // Check txn list
    let list = lc.do_list_transactions(false).await;

    assert_eq!(list.len(), 2);
    let jv = list.members().find(|jv| jv["txid"] == sent_txid).unwrap();

    assert_eq!(jv["txid"], sent_txid);
    assert_eq!(jv["amount"].as_i64().unwrap(), -(sent_value as i64 + fee as i64));
    assert_eq!(jv["unconfirmed"].as_bool().unwrap(), true);
    assert_eq!(jv["block_height"].as_u64().unwrap(), 107);

    assert_eq!(jv["outgoing_metadata"][0]["address"], EXT_ZADDR.to_string());
    assert_eq!(jv["outgoing_metadata"][0]["memo"], outgoing_memo);
    assert_eq!(jv["outgoing_metadata"][0]["value"].as_u64().unwrap(), sent_value);

    // 7. Mine the sent transaction
    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    let list = lc.do_list_transactions(false).await;

    assert_eq!(list.len(), 2);
    let jv = list.members().find(|jv| jv["txid"] == sent_txid).unwrap();

    assert_eq!(jv.contains("unconfirmed"), false);
    assert_eq!(jv["block_height"].as_u64().unwrap(), 107);

    // 8. Check the notes to see that we have one spent note and one unspent note (change)
    let notes = lc.do_list_notes(true).await;
    assert_eq!(notes["unspent_notes"].len(), 1);
    assert_eq!(notes["unspent_notes"][0]["created_in_block"].as_u64().unwrap(), 107);
    assert_eq!(notes["unspent_notes"][0]["created_in_txid"], sent_txid);
    assert_eq!(
        notes["unspent_notes"][0]["value"].as_u64().unwrap(),
        value - sent_value - 1000 /* TODO fees are messed up in tests because of block height issues */
    );
    assert_eq!(notes["unspent_notes"][0]["is_change"].as_bool().unwrap(), true);
    assert_eq!(notes["unspent_notes"][0]["spendable"].as_bool().unwrap(), false); // Not yet spendable

    assert_eq!(notes["spent_notes"].len(), 1);
    assert_eq!(notes["spent_notes"][0]["created_in_block"].as_u64().unwrap(), 101);
    assert_eq!(notes["spent_notes"][0]["value"].as_u64().unwrap(), value);
    assert_eq!(notes["spent_notes"][0]["is_change"].as_bool().unwrap(), false);
    assert_eq!(notes["spent_notes"][0]["spendable"].as_bool().unwrap(), false); // Already spent
    assert_eq!(notes["spent_notes"][0]["spent"], sent_txid);
    assert_eq!(notes["spent_notes"][0]["spent_at_height"].as_u64().unwrap(), 107);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

const EXT_ZADDR: &str = "zs1va5902apnzlhdu0pw9r9q7ca8s4vnsrp2alr6xndt69jnepn2v2qrj9vg3wfcnjyks5pg65g9dc";
