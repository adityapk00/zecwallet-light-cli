use log::{error};
use zcash_primitives::transaction::{TxId};

use crate::grpc_client::{ChainSpec, BlockId, BlockRange, RawTransaction, CompactBlock,
                         TransparentAddressBlockFilter, TxFilter, Empty, LightdInfo, TreeState};
use tonic::transport::{Channel, ClientTlsConfig};
use tokio_rustls::{rustls::ClientConfig};
use tonic::{Request};

use threadpool::ThreadPool;
use std::sync::mpsc::channel;

use crate::PubCertificate;
use crate::grpc_client::compact_tx_streamer_client::CompactTxStreamerClient;

async fn get_client(uri: &http::Uri) -> Result<CompactTxStreamerClient<Channel>, Box<dyn std::error::Error>> {
    if uri.host().is_none() {
        return Err(format!("No Host to connect to"))?;
    }

    let channel = if uri.scheme_str() == Some("http") {
        //println!("http");
        Channel::builder(uri.clone()).connect().await?
    } else {
        //println!("https");
        let mut config = ClientConfig::new();

        config.alpn_protocols.push(b"h2".to_vec());
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config.root_store.add_pem_file(
                &mut PubCertificate::get("lightwalletd-zecwallet-co-chain.pem").unwrap().as_ref()).unwrap();

        let tls = ClientTlsConfig::new()
            .rustls_client_config(config)
            .domain_name(uri.host().unwrap());
        
        Channel::builder(uri.clone())
            .tls_config(tls)
            .connect()
            .await?
    };

    Ok(CompactTxStreamerClient::new(channel))
}

// ==============
// GRPC code
// ==============
async fn get_lightd_info(uri: &http::Uri) -> Result<LightdInfo, Box<dyn std::error::Error>> {
    let mut client = get_client(uri).await?;

    let request = Request::new(Empty {});

    let response = client.get_lightd_info(request).await?;

    Ok(response.into_inner())
}

pub fn get_info(uri: &http::Uri) -> Result<LightdInfo, String> {
    let mut rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    rt.block_on(get_lightd_info(uri)).map_err( |e| e.to_string())
}

async fn get_sapling_tree_async(uri: &http::Uri, height: i32) -> Result<TreeState, Box<dyn std::error::Error>> {
    let mut client = get_client(uri).await?;

    let b = BlockId{ height: height as u64, hash: vec![]};
    let response = client.get_tree_state(Request::new(b)).await?;

    Ok(response.into_inner())
}

pub fn get_sapling_tree(uri: &http::Uri, height: i32) -> Result<TreeState, String> {
    let mut rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(get_sapling_tree_async(uri, height)).map_err(|e| e.to_string())
}

async fn get_block_range<F : 'static + std::marker::Send>(uri: &http::Uri, start_height: u64, end_height: u64, pool: ThreadPool, c: F) 
    -> Result<(), Box<dyn std::error::Error>> 
where F : Fn(&[u8], u64) {
    let mut client = get_client(uri).await?;

    let bs = BlockId{ height: start_height, hash: vec!()};
    let be = BlockId{ height: end_height,   hash: vec!()};

    let request = Request::new(BlockRange{ start: Some(bs), end: Some(be) });

    // Channel where the blocks are sent. A None signifies end of all blocks
    let (tx, rx) = channel::<Option<CompactBlock>>();

    // Channel that the processor signals it is done, so the method can return
    let (ftx, frx) = channel();

    // The processor runs on a different thread, so that the network calls don't
    // block on this
    pool.execute(move || {
        while let Some(block) = rx.recv().unwrap() {
            use prost::Message;
            let mut encoded_buf = vec![];

            block.encode(&mut encoded_buf).unwrap();
            c(&encoded_buf, block.height);
        }
        
        ftx.send(Ok(())).unwrap();
    });

    let mut response = client.get_block_range(request).await?.into_inner();
    while let Some(block) = response.message().await? {
        tx.send(Some(block)).unwrap();
    }
    tx.send(None).unwrap();

    // Wait for the processor to exit
    frx.iter().take(1).collect::<Result<Vec<()>, String>>()?;

    Ok(())
}

pub fn fetch_blocks<F : 'static + std::marker::Send>(uri: &http::Uri, start_height: u64, end_height: u64, pool: ThreadPool, c: F) -> Result<(), String>
    where F : Fn(&[u8], u64)  {
    
    let mut rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            let es = format!("Error creating runtime {:?}", e);
            error!("{}", es);
            eprintln!("{}", e);
            return Err(es);
        }
    };

    match rt.block_on(get_block_range(uri, start_height, end_height, pool, c)) {
        Ok(o) => Ok(o),
        Err(e) => {
            let e = format!("Error fetching blocks {:?}", e);
            error!("{}", e);
            eprintln!("{}", e);
            Err(e)
        }
    }
}


// get_address_txids GRPC call
async fn get_address_txids<F : 'static + std::marker::Send>(uri: &http::Uri, address: String, 
        start_height: u64, end_height: u64, c: F) -> Result<(), Box<dyn std::error::Error>>
    where F : Fn(&[u8], u64) {

    let mut client = get_client(uri).await?;
    let start = Some(BlockId{ height: start_height, hash: vec!()});
    let end   = Some(BlockId{ height: end_height,   hash: vec!()});

    let args = TransparentAddressBlockFilter{ address, range: Some(BlockRange{start, end}) };
    let request = Request::new(args.clone());

    let maybe_response = match client.get_taddress_txids(request).await {
        Ok(r) => r,
        Err(e) => {
            if e.code() == tonic::Code::Unimplemented {
                // Try the old, legacy API
                let request = Request::new(args);
                client.get_address_txids(request).await?
            } else {
                return Err(e)?;
            }
        }
    };

    let mut response = maybe_response.into_inner();

    while let Some(tx) = response.message().await? {
        c(&tx.data, tx.height);
    }

    Ok(())
}


pub fn fetch_transparent_txids<F: 'static + std::marker::Send>(uri: &http::Uri, address: String, 
        start_height: u64, end_height: u64, c: F) -> Result<(), String>
    where F : Fn(&[u8], u64) {
    
    let mut rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            let e = format!("Error creating runtime {:?}", e);
            error!("{}", e);
            eprintln!("{}", e);
            return Err(e);
        }
    };

    match rt.block_on(get_address_txids(uri, address.clone(), start_height, end_height, c)) {
        Ok(o) => Ok(o),
        Err(e) => {
            let e = format!("Error with get_address_txids runtime {:?}", e);
            error!("{}", e);
            eprintln!("{}", e);
            Err(e)
        }
    }
}


// get_transaction GRPC call
async fn get_transaction(uri: &http::Uri, txid: TxId) 
    -> Result<RawTransaction, Box<dyn std::error::Error>> {
    let mut client = get_client(uri).await?;
    let request = Request::new(TxFilter { block: None, index: 0, hash: txid.0.to_vec() });

    let response = client.get_transaction(request).await?;

    Ok(response.into_inner())
}

pub fn fetch_full_tx(uri: &http::Uri, txid: TxId) -> Result<Vec<u8>, String> {
    let mut rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            let errstr = format!("Error creating runtime {}", e.to_string());
            error!("{}", errstr);
            eprintln!("{}", errstr);
            return Err(errstr);
        }
    };

    match rt.block_on(get_transaction(uri, txid)) {
        Ok(rawtx) => Ok(rawtx.data.to_vec()),
        Err(e) => {
            let errstr = format!("Error in get_transaction runtime {}", e.to_string());
            error!("{}", errstr);
            eprintln!("{}", errstr);
            Err(errstr)
        }
    }    
}

// send_transaction GRPC call
async fn send_transaction(uri: &http::Uri, tx_bytes: Box<[u8]>) -> Result<String, Box<dyn std::error::Error>> {
    let mut client = get_client(uri).await?;

    let request = Request::new(RawTransaction {data: tx_bytes.to_vec(), height: 0});

    let response = client.send_transaction(request).await?;

    let sendresponse = response.into_inner();
    if sendresponse.error_code == 0 {
        let mut txid = sendresponse.error_message;
        if txid.starts_with("\"") && txid.ends_with("\"") {
            txid = txid[1..txid.len()-1].to_string();
        }

        Ok(txid)
    } else {
        Err(Box::from(format!("Error: {:?}", sendresponse)))
    }
}

pub fn broadcast_raw_tx(uri: &http::Uri, tx_bytes: Box<[u8]>) -> Result<String, String> {
    let mut rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    rt.block_on(send_transaction(uri, tx_bytes)).map_err( |e| e.to_string())
}

// get_latest_block GRPC call
async fn get_latest_block(uri: &http::Uri) -> Result<BlockId, Box<dyn std::error::Error>> {
    let mut client = get_client(uri).await?;

    let request = Request::new(ChainSpec {});

    let response = client.get_latest_block(request).await?;

    Ok(response.into_inner())
}

pub fn fetch_latest_block(uri: &http::Uri) -> Result<BlockId, String> {
    let mut rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            let errstr = format!("Error creating runtime {}", e.to_string());
            eprintln!("{}", errstr);
            return Err(errstr);
        }
    };

    rt.block_on(get_latest_block(uri)).map_err(|e| {
        let errstr = format!("Error getting latest block {}", e.to_string());
        eprintln!("{}", errstr);
        errstr
    })
}
