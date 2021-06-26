use std::sync::Arc;

use ff::{Field, PrimeField};
use futures::FutureExt;
use group::GroupEncoding;
use json::JsonValue;
use jubjub::ExtendedPoint;
use portpicker;
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1};
use tempdir::TempDir;
use tokio::sync::{oneshot, RwLock};
use tokio::task::JoinHandle;
use tonic::transport::{Channel, Server};
use tonic::Request;

use zcash_client_backend::address::RecipientAddress;
use zcash_client_backend::encoding::{
    encode_extended_full_viewing_key, encode_extended_spending_key, encode_payment_address,
};
use zcash_primitives::consensus::MAIN_NETWORK;
use zcash_primitives::memo::Memo;
use zcash_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use zcash_primitives::note_encryption::SaplingNoteEncryption;
use zcash_primitives::primitives::{Note, Rseed, ValueCommitment};
use zcash_primitives::redjubjub::Signature;
use zcash_primitives::sapling::Node;
use zcash_primitives::transaction::components::amount::DEFAULT_FEE;
use zcash_primitives::transaction::components::{OutputDescription, GROTH_PROOF_SIZE};
use zcash_primitives::transaction::TransactionData;
use zcash_primitives::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};

use crate::blaze::test_utils::{FakeCompactBlockList, FakeTransaction};
use crate::compact_formats::compact_tx_streamer_client::CompactTxStreamerClient;
use crate::compact_formats::compact_tx_streamer_server::CompactTxStreamerServer;
use crate::compact_formats::{CompactOutput, CompactTx, Empty};
use crate::lightclient::lightclient_config::LightClientConfig;
use crate::lightclient::test_server::TestGRPCService;
use crate::lightclient::LightClient;
use crate::lightwallet::data::WalletTx;

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
    let mut v = fcbl.into_txns();

    // Add all the t-addr spend's t-addresses into the maps, so the test grpc server
    // knows to serve this tx when the txns for this particular taddr are requested.
    for (t, _h, taddrs) in v.iter_mut() {
        for vin in &t.vin {
            let prev_txid = WalletTx::new_txid(&vin.prevout.hash().to_vec());
            if let Some(wtx) = lc.wallet.txns.read().await.current.get(&prev_txid) {
                if let Some(utxo) = wtx.utxos.iter().find(|u| u.output_index as u32 == vin.prevout.n()) {
                    if !taddrs.contains(&utxo.address) {
                        taddrs.push(utxo.address.clone());
                    }
                }
            }
        }
    }

    data.write().await.add_txns(v);

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

    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn z_incoming_z_outgoing() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server().await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let value = 100_000;
    let (tx, _height, _) = fcbl.add_tx_paying(&extfvk1, value);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    assert_eq!(lc.wallet.last_scanned_height().await, 11);

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
        assert_eq!(jv["block_height"].as_u64().unwrap(), 11);
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
    let sent_value = 2000;
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
    assert_eq!(
        jv["amount"].as_i64().unwrap(),
        -(sent_value as i64 + i64::from(DEFAULT_FEE))
    );
    assert_eq!(jv["unconfirmed"].as_bool().unwrap(), true);
    assert_eq!(jv["block_height"].as_u64().unwrap(), 17);

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
    assert_eq!(jv["block_height"].as_u64().unwrap(), 17);

    // 8. Check the notes to see that we have one spent note and one unspent note (change)
    let notes = lc.do_list_notes(true).await;
    assert_eq!(notes["unspent_notes"].len(), 1);
    assert_eq!(notes["unspent_notes"][0]["created_in_block"].as_u64().unwrap(), 17);
    assert_eq!(notes["unspent_notes"][0]["created_in_txid"], sent_txid);
    assert_eq!(
        notes["unspent_notes"][0]["value"].as_u64().unwrap(),
        value - sent_value - u64::from(DEFAULT_FEE)
    );
    assert_eq!(notes["unspent_notes"][0]["is_change"].as_bool().unwrap(), true);
    assert_eq!(notes["unspent_notes"][0]["spendable"].as_bool().unwrap(), false); // Not yet spendable

    assert_eq!(notes["spent_notes"].len(), 1);
    assert_eq!(notes["spent_notes"][0]["created_in_block"].as_u64().unwrap(), 11);
    assert_eq!(notes["spent_notes"][0]["value"].as_u64().unwrap(), value);
    assert_eq!(notes["spent_notes"][0]["is_change"].as_bool().unwrap(), false);
    assert_eq!(notes["spent_notes"][0]["spendable"].as_bool().unwrap(), false); // Already spent
    assert_eq!(notes["spent_notes"][0]["spent"], sent_txid);
    assert_eq!(notes["spent_notes"][0]["spent_at_height"].as_u64().unwrap(), 17);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn multiple_incoming_same_tx() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server().await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let value = 100_000;

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Construct the Fake tx.
    let to = extfvk1.default_address().unwrap().1;

    // Create fake note for the account
    let mut ctx = CompactTx::default();
    let mut td = TransactionData::new();

    // Add 4 outputs
    for i in 0..4 {
        let mut rng = OsRng;
        let value = value + i;
        let note = Note {
            g_d: to.diversifier().g_d().unwrap(),
            pk_d: to.pk_d().clone(),
            value,
            rseed: Rseed::BeforeZip212(jubjub::Fr::random(rng)),
        };

        let mut encryptor =
            SaplingNoteEncryption::new(None, note.clone(), to.clone(), Memo::default().into(), &mut rng);

        let mut rng = OsRng;
        let rcv = jubjub::Fr::random(&mut rng);
        let cv = ValueCommitment {
            value,
            randomness: rcv.clone(),
        };

        let cmu = note.cmu();
        let od = OutputDescription {
            cv: cv.commitment().into(),
            cmu: note.cmu(),
            ephemeral_key: ExtendedPoint::from(*encryptor.epk()),
            enc_ciphertext: encryptor.encrypt_note_plaintext(),
            out_ciphertext: encryptor.encrypt_outgoing_plaintext(&cv.commitment().into(), &cmu),
            zkproof: [0; GROTH_PROOF_SIZE],
        };

        let mut cmu = vec![];
        cmu.extend_from_slice(&note.cmu().to_repr());
        let mut epk = vec![];
        epk.extend_from_slice(&encryptor.epk().to_bytes());
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        // Create a fake CompactBlock containing the note
        let mut cout = CompactOutput::default();
        cout.cmu = cmu;
        cout.epk = epk;
        cout.ciphertext = enc_ciphertext[..52].to_vec();
        ctx.outputs.push(cout);

        td.shielded_outputs.push(od);
    }

    td.binding_sig = Signature::read(&vec![0u8; 64][..]).ok();
    let tx = td.freeze().unwrap();
    ctx.hash = tx.txid().clone().0.to_vec();

    // Add and mine the block
    fcbl.txns.push((tx.clone(), fcbl.next_height, vec![]));
    fcbl.add_empty_block().add_txs(vec![ctx]);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 11);

    // 2. Check the notes - that we recieved 4 notes
    let notes = lc.do_list_notes(true).await;
    let txns = lc.do_list_transactions(false).await;
    for i in 0..4 {
        assert_eq!(notes["unspent_notes"][i]["created_in_block"].as_u64().unwrap(), 11);
        assert_eq!(notes["unspent_notes"][i]["value"].as_u64().unwrap(), value + i as u64);
        assert_eq!(notes["unspent_notes"][i]["is_change"].as_bool().unwrap(), false);
        assert_eq!(
            notes["unspent_notes"][i]["address"],
            lc.wallet.keys().read().await.get_all_zaddresses()[0]
        );

        assert_eq!(txns[i]["txid"], tx.txid().to_string());
        assert_eq!(txns[i]["block_height"].as_u64().unwrap(), 11);
        assert_eq!(
            txns[i]["address"],
            lc.wallet.keys().read().await.get_all_zaddresses()[0]
        );
        assert_eq!(txns[i]["amount"].as_u64().unwrap(), value + i as u64);
    }

    // 3. Send a big tx, so all the value is spent
    let sent_value = value * 3 + u64::from(DEFAULT_FEE);
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await; // make the funds spentable
    let sent_txid = lc.test_do_send(vec![(EXT_ZADDR, sent_value, None)]).await.unwrap();

    // 4. Mine the sent transaction
    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 5. Check the notes - that we spent all 4 notes
    let notes = lc.do_list_notes(true).await;
    let txns = lc.do_list_transactions(false).await;
    for i in 0..4 {
        assert_eq!(notes["spent_notes"][i]["spent"], sent_txid);
        assert_eq!(notes["spent_notes"][i]["spent_at_height"].as_u64().unwrap(), 17);
    }
    assert_eq!(txns[4]["txid"], sent_txid);
    assert_eq!(txns[4]["block_height"], 17);
    assert_eq!(
        txns[4]["amount"].as_i64().unwrap(),
        -(sent_value as i64) - i64::from(DEFAULT_FEE)
    );
    assert_eq!(txns[4]["outgoing_metadata"][0]["address"], EXT_ZADDR.to_string());
    assert_eq!(txns[4]["outgoing_metadata"][0]["value"].as_u64().unwrap(), sent_value);
    assert_eq!(txns[4]["outgoing_metadata"][0]["memo"].is_null(), true);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn z_incoming_multiz_outgoing() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server().await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let value = 100_000;
    let (_tx, _height, _) = fcbl.add_tx_paying(&extfvk1, value);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;

    // 3. send a txn to multiple addresses
    let tos = vec![
        (EXT_ZADDR, 1, Some("ext1-1".to_string())),
        (EXT_ZADDR, 2, Some("ext1-2".to_string())),
        (EXT_ZADDR2, 20, Some("ext2-20".to_string())),
    ];
    let sent_txid = lc.test_do_send(tos.clone()).await.unwrap();
    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 4. Check the outgoing txn list
    let list = lc.do_list_transactions(false).await;

    assert_eq!(list[1]["block_height"].as_u64().unwrap(), 17);
    assert_eq!(list[1]["txid"], sent_txid);
    assert_eq!(
        list[1]["amount"].as_i64().unwrap(),
        -i64::from(DEFAULT_FEE) - (tos.iter().map(|(_, a, _)| *a).sum::<u64>() as i64)
    );

    for (addr, amt, memo) in &tos {
        // Find the correct value, since the outgoing metadata can be shuffled
        let jv = list[1]["outgoing_metadata"]
            .members()
            .find(|j| j["value"].as_u64().unwrap() == *amt)
            .unwrap();
        assert_eq!(jv["memo"], *memo.as_ref().unwrap());
        assert_eq!(jv["address"], addr.to_string());
    }

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn z_to_z_scan_together() {
    // Create an incoming tx, and then send that tx, and scan everything together, to make sure it works.
    let (data, config, ready_rx, stop_tx, h1) = create_test_server().await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Start with 10 blocks that are unmined
    fcbl.add_blocks(10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let value = 100_000;
    let (tx, _height, note) = fcbl.add_tx_paying(&extfvk1, value);

    // 3. Calculate witness so we can get the nullifier without it getting mined
    let tree = fcbl
        .blocks
        .iter()
        .fold(CommitmentTree::<Node>::empty(), |mut tree, fcb| {
            for tx in &fcb.block.vtx {
                for co in &tx.outputs {
                    tree.append(Node::new(co.cmu().unwrap().into())).unwrap();
                }
            }

            tree
        });
    let witness = IncrementalWitness::from_tree(&tree);
    let nf = note.nf(&extfvk1.fvk.vk, witness.position() as u64);

    let pa = if let Some(RecipientAddress::Shielded(pa)) = RecipientAddress::decode(&MAIN_NETWORK, EXT_ZADDR) {
        pa
    } else {
        panic!("Couldn't parse address")
    };
    let spent_value = 250;
    let spent_tx = fcbl.add_tx_spending(&nf, spent_value, &extfvk1.fvk.ovk, &pa);

    // 4. Mine the blocks and sync the lightwallet
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 5. Check the tx list to make sure we got all txns
    let list = lc.do_list_transactions(false).await;

    assert_eq!(list[0]["block_height"].as_u64().unwrap(), 11);
    assert_eq!(list[0]["txid"], tx.txid().to_string());

    assert_eq!(list[1]["block_height"].as_u64().unwrap(), 12);
    assert_eq!(list[1]["txid"], spent_tx.txid().to_string());
    assert_eq!(list[1]["amount"].as_i64().unwrap(), -(value as i64));
    assert_eq!(list[1]["outgoing_metadata"][0]["address"], EXT_ZADDR.to_string());
    assert_eq!(list[1]["outgoing_metadata"][0]["value"].as_u64().unwrap(), spent_value);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn z_incoming_viewkey() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server().await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);
    assert_eq!(lc.do_balance().await["zbalance"].as_u64().unwrap(), 0);

    // 2. Create a new Viewkey and import it
    let iextsk = ExtendedSpendingKey::master(&[1u8; 32]);
    let iextfvk = ExtendedFullViewingKey::from(&iextsk);
    let iaddr = encode_payment_address(config.hrp_sapling_address(), &iextfvk.default_address().unwrap().1);
    let addrs = lc
        .do_import_vk(
            encode_extended_full_viewing_key(config.hrp_sapling_viewing_key(), &iextfvk),
            1,
        )
        .await
        .unwrap();
    // Make sure address is correct
    assert_eq!(addrs[0], iaddr);

    let value = 100_000;
    let (tx, _height, _) = fcbl.add_tx_paying(&iextfvk, value);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;

    // 3. Test that we have the txn
    let list = lc.do_list_transactions(false).await;
    assert_eq!(lc.do_balance().await["zbalance"].as_u64().unwrap(), value);
    assert_eq!(lc.do_balance().await["spendable_zbalance"].as_u64().unwrap(), 0);
    assert_eq!(list[0]["txid"], tx.txid().to_string());
    assert_eq!(list[0]["amount"].as_u64().unwrap(), value);
    assert_eq!(list[0]["address"], iaddr);

    // 4. Also do a rescan, just for fun
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    lc.do_rescan().await.unwrap();
    // Test all the same values
    let list = lc.do_list_transactions(false).await;
    assert_eq!(lc.do_balance().await["zbalance"].as_u64().unwrap(), value);
    assert_eq!(lc.do_balance().await["spendable_zbalance"].as_u64().unwrap(), 0);
    assert_eq!(list[0]["txid"], tx.txid().to_string());
    assert_eq!(list[0]["amount"].as_u64().unwrap(), value);
    assert_eq!(list[0]["address"], iaddr);

    // 5. Import the corresponding spending key.
    let sk_addr = lc
        .do_import_sk(
            encode_extended_spending_key(config.hrp_sapling_private_key(), &iextsk),
            1,
        )
        .await
        .unwrap();

    assert_eq!(sk_addr[0], iaddr);
    assert_eq!(lc.do_balance().await["zbalance"].as_u64().unwrap(), value);
    assert_eq!(lc.do_balance().await["spendable_zbalance"].as_u64().unwrap(), 0);

    // 6. Rescan to make the funds spendable (i.e., update witnesses)
    lc.do_rescan().await.unwrap();
    assert_eq!(lc.do_balance().await["zbalance"].as_u64().unwrap(), value);
    assert_eq!(lc.do_balance().await["spendable_zbalance"].as_u64().unwrap(), value);

    // 7. Spend funds from the now-imported private key.
    let sent_value = 3000;
    let outgoing_memo = "Outgoing Memo".to_string();

    let sent_txid = lc
        .test_do_send(vec![(EXT_ZADDR, sent_value, Some(outgoing_memo.clone()))])
        .await
        .unwrap();
    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 8. Make sure tx is present
    let list = lc.do_list_transactions(false).await;
    assert_eq!(list[1]["txid"], sent_txid);
    assert_eq!(
        list[1]["amount"].as_i64().unwrap(),
        -((sent_value + u64::from(DEFAULT_FEE)) as i64)
    );
    assert_eq!(list[1]["outgoing_metadata"][0]["address"], EXT_ZADDR.to_string());
    assert_eq!(list[1]["outgoing_metadata"][0]["value"].as_u64().unwrap(), sent_value);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn t_incoming_t_outgoing() {
    let secp = Secp256k1::new();
    let (data, config, ready_rx, stop_tx, h1) = create_test_server().await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None).await.unwrap();
    lc.init_logging().unwrap();

    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;

    // 2. Get an incoming tx to a t address
    let sk = lc.wallet.keys().read().await.tkeys[0];
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let taddr = lc.wallet.keys().read().await.address_from_sk(&sk);
    let value = 100_000;

    let mut ftx = FakeTransaction::new();
    ftx.add_t_output(&pk, taddr.clone(), value);
    let (tx, _) = fcbl.add_ftx(ftx);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 3. Test the list
    let list = lc.do_list_transactions(false).await;
    assert_eq!(list[0]["block_height"].as_u64().unwrap(), 11);
    assert_eq!(list[0]["txid"], tx.txid().to_string());
    assert_eq!(list[0]["address"], taddr);
    assert_eq!(list[0]["amount"].as_u64().unwrap(), value);

    // 4. We can spend the funds immediately, since this is a taddr
    let sent_value = 20_000;
    let sent_txid = lc.test_do_send(vec![(EXT_TADDR, sent_value, None)]).await.unwrap();

    // 5. Test the unconfirmed send.
    let list = lc.do_list_transactions(false).await;
    assert_eq!(list[1]["block_height"].as_u64().unwrap(), 12);
    assert_eq!(list[1]["txid"], sent_txid);
    assert_eq!(
        list[1]["amount"].as_i64().unwrap(),
        -(sent_value as i64 + i64::from(DEFAULT_FEE))
    );
    assert_eq!(list[1]["unconfirmed"].as_bool().unwrap(), true);
    assert_eq!(list[1]["outgoing_metadata"][0]["address"], EXT_TADDR);
    assert_eq!(list[1]["outgoing_metadata"][0]["value"].as_u64().unwrap(), sent_value);

    // 7. Mine the sent transaction
    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    let notes = lc.do_list_notes(true).await;
    assert_eq!(notes["spent_utxos"][0]["created_in_block"].as_u64().unwrap(), 11);
    assert_eq!(notes["spent_utxos"][0]["spent_at_height"].as_u64().unwrap(), 12);
    assert_eq!(notes["spent_utxos"][0]["spent"], sent_txid);

    // Change shielded note
    assert_eq!(notes["unspent_notes"][0]["created_in_block"].as_u64().unwrap(), 12);
    assert_eq!(notes["unspent_notes"][0]["created_in_txid"], sent_txid);
    assert_eq!(notes["unspent_notes"][0]["is_change"].as_bool().unwrap(), true);
    assert_eq!(
        notes["unspent_notes"][0]["value"].as_u64().unwrap(),
        value - sent_value - u64::from(DEFAULT_FEE)
    );

    let list = lc.do_list_transactions(false).await;
    assert_eq!(list[1]["block_height"].as_u64().unwrap(), 12);
    assert_eq!(list[1]["txid"], sent_txid);
    assert_eq!(list[1]["unconfirmed"].as_bool(), None);
    assert_eq!(list[1]["outgoing_metadata"][0]["address"], EXT_TADDR);
    assert_eq!(list[1]["outgoing_metadata"][0]["value"].as_u64().unwrap(), sent_value);

    // Make sure everything is fine even after the rescan

    lc.do_rescan().await.unwrap();

    let list = lc.do_list_transactions(false).await;
    assert_eq!(list[1]["block_height"].as_u64().unwrap(), 12);
    assert_eq!(list[1]["txid"], sent_txid);
    assert_eq!(list[1]["unconfirmed"].as_bool(), None);
    assert_eq!(list[1]["outgoing_metadata"][0]["address"], EXT_TADDR);
    assert_eq!(list[1]["outgoing_metadata"][0]["value"].as_u64().unwrap(), sent_value);

    let notes = lc.do_list_notes(true).await;
    // Change shielded note
    assert_eq!(notes["unspent_notes"][0]["created_in_block"].as_u64().unwrap(), 12);
    assert_eq!(notes["unspent_notes"][0]["created_in_txid"], sent_txid);
    assert_eq!(notes["unspent_notes"][0]["is_change"].as_bool().unwrap(), true);
    assert_eq!(
        notes["unspent_notes"][0]["value"].as_u64().unwrap(),
        value - sent_value - u64::from(DEFAULT_FEE)
    );

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn mixed_txn() {
    let secp = Secp256k1::new();
    let (data, config, ready_rx, stop_tx, h1) = create_test_server().await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let zvalue = 100_000;
    let (_ztx, _height, _) = fcbl.add_tx_paying(&extfvk1, zvalue);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;

    // 3. Send an incoming t-address txn
    let sk = lc.wallet.keys().read().await.tkeys[0];
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let taddr = lc.wallet.keys().read().await.address_from_sk(&sk);
    let tvalue = 200_000;

    let mut ftx = FakeTransaction::new();
    ftx.add_t_output(&pk, taddr.clone(), tvalue);
    let (_ttx, _) = fcbl.add_ftx(ftx);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 4. Send a tx to both external t-addr and external z addr and mine it
    let sent_zvalue = 80_000;
    let sent_tvalue = 140_000;
    let sent_zmemo = "Ext z".to_string();
    let tos = vec![
        (EXT_ZADDR, sent_zvalue, Some(sent_zmemo.clone())),
        (EXT_TADDR, sent_tvalue, None),
    ];
    lc.test_do_send(tos).await.unwrap();

    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    let notes = lc.do_list_notes(true).await;
    let list = lc.do_list_transactions(false).await;

    // 5. Check everything
    assert_eq!(notes["unspent_notes"].len(), 1);
    assert_eq!(notes["unspent_notes"][0]["created_in_block"].as_u64().unwrap(), 18);
    assert_eq!(notes["unspent_notes"][0]["is_change"].as_bool().unwrap(), true);
    assert_eq!(
        notes["unspent_notes"][0]["value"].as_u64().unwrap(),
        tvalue + zvalue - sent_tvalue - sent_zvalue - u64::from(DEFAULT_FEE)
    );

    assert_eq!(notes["spent_notes"].len(), 1);
    assert_eq!(
        notes["spent_notes"][0]["spent"],
        notes["unspent_notes"][0]["created_in_txid"]
    );

    assert_eq!(notes["pending_notes"].len(), 0);
    assert_eq!(notes["utxos"].len(), 0);
    assert_eq!(notes["pending_utxos"].len(), 0);

    assert_eq!(notes["spent_utxos"].len(), 1);
    assert_eq!(
        notes["spent_utxos"][0]["spent"],
        notes["unspent_notes"][0]["created_in_txid"]
    );

    assert_eq!(list.len(), 3);
    assert_eq!(list[2]["block_height"].as_u64().unwrap(), 18);
    assert_eq!(
        list[2]["amount"].as_i64().unwrap(),
        0 - (sent_tvalue + sent_zvalue + u64::from(DEFAULT_FEE)) as i64
    );
    assert_eq!(list[2]["txid"], notes["unspent_notes"][0]["created_in_txid"]);
    assert_eq!(
        list[2]["outgoing_metadata"]
            .members()
            .find(|j| j["address"].to_string() == EXT_ZADDR && j["value"].as_u64().unwrap() == sent_zvalue)
            .unwrap()["memo"]
            .to_string(),
        sent_zmemo
    );
    assert_eq!(
        list[2]["outgoing_metadata"]
            .members()
            .find(|j| j["address"].to_string() == EXT_TADDR)
            .unwrap()["value"]
            .as_u64()
            .unwrap(),
        sent_tvalue
    );

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn aborted_resync() {
    let secp = Secp256k1::new();
    let (data, config, ready_rx, stop_tx, h1) = create_test_server().await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let zvalue = 100_000;
    let (_ztx, _height, _) = fcbl.add_tx_paying(&extfvk1, zvalue);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;

    // 3. Send an incoming t-address txn
    let sk = lc.wallet.keys().read().await.tkeys[0];
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let taddr = lc.wallet.keys().read().await.address_from_sk(&sk);
    let tvalue = 200_000;

    let mut ftx = FakeTransaction::new();
    ftx.add_t_output(&pk, taddr.clone(), tvalue);
    let (_ttx, _) = fcbl.add_ftx(ftx);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 4. Send a tx to both external t-addr and external z addr and mine it
    let sent_zvalue = 80_000;
    let sent_tvalue = 140_000;
    let sent_zmemo = "Ext z".to_string();
    let tos = vec![
        (EXT_ZADDR, sent_zvalue, Some(sent_zmemo.clone())),
        (EXT_TADDR, sent_tvalue, None),
    ];
    let sent_txid = lc.test_do_send(tos).await.unwrap();

    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;

    let notes_before = lc.do_list_notes(true).await;
    let list_before = lc.do_list_transactions(false).await;
    let witness_before = lc
        .wallet
        .txns
        .read()
        .await
        .current
        .get(&WalletTx::new_txid(
            &hex::decode(sent_txid.clone()).unwrap().into_iter().rev().collect(),
        ))
        .unwrap()
        .notes
        .get(0)
        .unwrap()
        .witnesses
        .clone();

    // 5. Now, we'll manually remove some of the blocks in the wallet, pretending that the sync was aborted in the middle.
    // We'll remove the top 20 blocks, so now the wallet only has the first 3 blocks
    lc.wallet.blocks.write().await.drain(0..20);
    assert_eq!(lc.wallet.last_scanned_height().await, 3);

    // 6. Do a sync again
    lc.do_sync(true).await.unwrap();
    assert_eq!(lc.wallet.last_scanned_height().await, 23);

    // 7. Should be exactly the same
    let notes_after = lc.do_list_notes(true).await;
    let list_after = lc.do_list_transactions(false).await;
    let witness_after = lc
        .wallet
        .txns
        .read()
        .await
        .current
        .get(&WalletTx::new_txid(
            &hex::decode(sent_txid).unwrap().into_iter().rev().collect(),
        ))
        .unwrap()
        .notes
        .get(0)
        .unwrap()
        .witnesses
        .clone();

    assert_eq!(notes_before, notes_after);
    assert_eq!(list_before, list_after);
    assert_eq!(witness_before.top_height, witness_after.top_height);
    assert_eq!(witness_before.len(), witness_after.len());
    for i in 0..witness_before.len() {
        let mut before_bytes = vec![];
        witness_before.get(i).unwrap().write(&mut before_bytes).unwrap();

        let mut after_bytes = vec![];
        witness_after.get(i).unwrap().write(&mut after_bytes).unwrap();

        assert_eq!(hex::encode(before_bytes), hex::encode(after_bytes));
    }

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn no_change() {
    let secp = Secp256k1::new();
    let (data, config, ready_rx, stop_tx, h1) = create_test_server().await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let zvalue = 100_000;
    let (_ztx, _height, _) = fcbl.add_tx_paying(&extfvk1, zvalue);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;

    // 3. Send an incoming t-address txn
    let sk = lc.wallet.keys().read().await.tkeys[0];
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let taddr = lc.wallet.keys().read().await.address_from_sk(&sk);
    let tvalue = 200_000;

    let mut ftx = FakeTransaction::new();
    ftx.add_t_output(&pk, taddr.clone(), tvalue);
    let (_ttx, _) = fcbl.add_ftx(ftx);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 4. Send a tx to both external t-addr and external z addr and mine it
    let sent_zvalue = tvalue + zvalue - u64::from(DEFAULT_FEE);
    let tos = vec![(EXT_ZADDR, sent_zvalue, None)];
    let sent_txid = lc.test_do_send(tos).await.unwrap();

    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    let notes = lc.do_list_notes(true).await;
    assert_eq!(notes["unspent_notes"].len(), 0);
    assert_eq!(notes["pending_notes"].len(), 0);
    assert_eq!(notes["utxos"].len(), 0);
    assert_eq!(notes["pending_utxos"].len(), 0);

    assert_eq!(notes["spent_notes"].len(), 1);
    assert_eq!(notes["spent_utxos"].len(), 1);
    assert_eq!(notes["spent_notes"][0]["spent"], sent_txid);
    assert_eq!(notes["spent_utxos"][0]["spent"], sent_txid);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

const EXT_TADDR: &str = "t1NoS6ZgaUTpmjkge2cVpXGcySasdYDrXqh";
const EXT_ZADDR: &str = "zs1va5902apnzlhdu0pw9r9q7ca8s4vnsrp2alr6xndt69jnepn2v2qrj9vg3wfcnjyks5pg65g9dc";
const EXT_ZADDR2: &str = "zs1fxgluwznkzm52ux7jkf4st5znwzqay8zyz4cydnyegt2rh9uhr9458z0nk62fdsssx0cqhy6lyv";
