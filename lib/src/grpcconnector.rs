use log::{error};
use zcash_primitives::transaction::{TxId};

use crate::grpc_client::{ChainSpec, BlockId, BlockRange, RawTransaction, 
                         TransparentAddressBlockFilter, TxFilter, Empty, LightdInfo};
use tonic::transport::{Channel, ClientTlsConfig};
use tokio_rustls::{rustls::ClientConfig};
use tonic::{Request};

use crate::PubCertificate;
use crate::grpc_client::compact_tx_streamer_client::CompactTxStreamerClient;

async fn get_client(uri: &http::Uri) -> Result<CompactTxStreamerClient<Channel>, Box<dyn std::error::Error>> {
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


async fn get_block_range<F : 'static + std::marker::Send>(uri: &http::Uri, start_height: u64, end_height: u64, mut c: F) 
    -> Result<(), Box<dyn std::error::Error>> 
where F : FnMut(&[u8], u64) {
    let mut client = get_client(uri).await?;

    let bs = BlockId{ height: start_height, hash: vec!()};
    let be = BlockId{ height: end_height,   hash: vec!()};

    let request = Request::new(BlockRange{ start: Some(bs), end: Some(be) });

    let mut response = client.get_block_range(request).await?.into_inner();
    //println!("{:?}", response);
    while let Some(block) = response.message().await? {
        use prost::Message;
        let mut encoded_buf = vec![];

        block.encode(&mut encoded_buf).unwrap();
        c(&encoded_buf, block.height);
    }

    Ok(())
}

pub fn fetch_blocks<F : 'static + std::marker::Send>(uri: &http::Uri, start_height: u64, end_height: u64, c: F)
    where F : FnMut(&[u8], u64) {
    
    let mut rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            error!("Error fetching blocks {}", e.to_string());
            eprintln!("{}", e);
            return;
        }
    };

    rt.block_on(get_block_range(uri, start_height, end_height, c)).unwrap();
}


// get_address_txids GRPC call
async fn get_address_txids<F : 'static + std::marker::Send>(uri: &http::Uri, address: String, 
        start_height: u64, end_height: u64, c: F) -> Result<(), Box<dyn std::error::Error>>
    where F : Fn(&[u8], u64) {

    let mut client = get_client(uri).await?;
    let start = Some(BlockId{ height: start_height, hash: vec!()});
    let end   = Some(BlockId{ height: end_height,   hash: vec!()});

    let request = Request::new(TransparentAddressBlockFilter{ address, range: Some(BlockRange{start, end}) });

    let maybe_response = client.get_address_txids(request).await?;
    let mut response = maybe_response.into_inner();

    while let Some(tx) = response.message().await? {
        c(&tx.data, tx.height);
    }

    Ok(())
}


pub fn fetch_transparent_txids<F : 'static + std::marker::Send>(uri: &http::Uri, address: String, 
        start_height: u64, end_height: u64, c: F)
    where F : Fn(&[u8], u64) {
    
    let mut rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            error!("Error creating runtime {}", e.to_string());
            eprintln!("{}", e);
            return;
        }
    };

    rt.block_on(get_address_txids(uri, address, start_height, end_height, c)).unwrap();
}


// get_transaction GRPC call
async fn get_transaction(uri: &http::Uri, txid: TxId) 
    -> Result<RawTransaction, Box<dyn std::error::Error>> {
    let mut client = get_client(uri).await?;
    let request = Request::new(TxFilter { block: None, index: 0, hash: txid.0.to_vec() });

    let response = client.get_transaction(request).await?;

    Ok(response.into_inner())
}

pub fn fetch_full_tx<F : 'static + std::marker::Send>(uri: &http::Uri, txid: TxId, c: F)
        where F : Fn(&[u8]) {
    let mut rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            error!("Error creating runtime {}", e.to_string());
            eprintln!("{}", e);
            return;
        }
    };

    match rt.block_on(get_transaction(uri, txid)) {
        Ok(rawtx) => c(&rawtx.data),
        Err(e) => {
            error!("Error in get_transaction runtime {}", e.to_string());
            eprintln!("{}", e);
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

pub fn fetch_latest_block<F : 'static + std::marker::Send>(uri: &http::Uri, mut c : F) 
    where F : FnMut(BlockId) {
    let mut rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            error!("Error creating runtime {}", e.to_string());
            eprintln!("{}", e);
            return;
        }
    };

    match rt.block_on(get_latest_block(uri)) {
        Ok(b) => c(b),
        Err(e) => {
            error!("Error getting latest block {}", e.to_string());
            eprintln!("{}", e);
        }
    };
}
