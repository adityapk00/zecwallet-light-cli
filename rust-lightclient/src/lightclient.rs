use crate::lightwallet::LightWallet;

use std::fs::File;
use std::io;
use std::io::prelude::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use std::error::Error;

use zcash_primitives::transaction::{TxId, Transaction};
use zcash_primitives::note_encryption::Memo;

use futures::Future;
use hyper::client::connect::{Destination, HttpConnector};
use tower_grpc::Request;
use tower_hyper::{client, util};
use tower_util::MakeService;
use futures::stream::Stream;

use crate::grpc_client::{ChainSpec, BlockId, BlockRange, RawTransaction, TxFilter, Empty};
use crate::grpc_client::client::CompactTxStreamer;

// Used below to return the grpc "Client" type to calling methods
type Client = crate::grpc_client::client::CompactTxStreamer<tower_request_modifier::RequestModifier<tower_hyper::client::Connection<tower_grpc::BoxBody>, tower_grpc::BoxBody>>;


pub struct LightClient {
    pub wallet          : Arc<LightWallet>,
    pub sapling_output  : Vec<u8>,
    pub sapling_spend   : Vec<u8>,
}

impl LightClient {
    pub fn new() -> Self {
        let mut w = LightClient {
            wallet          : Arc::new(LightWallet::new()), 
            sapling_output  : vec![], 
            sapling_spend   : vec![]
        };

        // Read Sapling Params
        let mut f = File::open("/home/adityapk/.zcash-params/sapling-output.params").unwrap();
        f.read_to_end(&mut w.sapling_output).unwrap();
        let mut f = File::open("/home/adityapk/.zcash-params/sapling-spend.params").unwrap();
        f.read_to_end(&mut w.sapling_spend).unwrap();

        w.wallet.set_initial_block(500000,
                            "004fada8d4dbc5e80b13522d2c6bd0116113c9b7197f0c6be69bc7a62f2824cd",
                            "01b733e839b5f844287a6a491409a991ec70277f39a50c99163ed378d23a829a0700100001916db36dfb9a0cf26115ed050b264546c0fa23459433c31fd72f63d188202f2400011f5f4e3bd18da479f48d674dbab64454f6995b113fa21c9d8853a9e764fb3e1f01df9d2c233ca60360e3c2bb73caf5839a1be634c8b99aea22d02abda2e747d9100001970d41722c078288101acd0a75612acfb4c434f2a55aab09fb4e812accc2ba7301485150f0deac7774dcd0fe32043bde9ba2b6bbfff787ad074339af68e88ee70101601324f1421e00a43ef57f197faf385ee4cac65aab58048016ecbd94e022973701e1b17f4bd9d1b6ca1107f619ac6d27b53dd3350d5be09b08935923cbed97906c0000000000011f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d39");

        return w;
    }

    pub fn last_scanned_height(&self) -> u64 {
        self.wallet.last_scanned_height() as u64
    }

    pub fn do_address(&self) {        
        println!("Address: {}", self.wallet.address());
        println!("Balance: {}", self.wallet.balance());
    }

    pub fn do_read(&mut self) {
        print!("Reading wallet...");
        io::stdout().flush().ok().expect("Could not flush stdout");
        let mut file_buffer = File::open("wallet.dat").unwrap();
        
        let lw = LightWallet::read(&mut file_buffer).unwrap();
        self.wallet = Arc::new(lw);
        println!("[OK]");
    }

    pub fn do_save(&self) {
        print!("Saving wallet...");
        io::stdout().flush().ok().expect("Could not flush stdout");
        let mut file_buffer = File::create("wallet.dat").unwrap();
        
        self.wallet.write(&mut file_buffer).unwrap();
        println!("[OK]");
    }


    pub fn do_info(&self) {
        let uri: http::Uri = format!("http://127.0.0.1:9067").parse().unwrap();

        let say_hello = self.make_grpc_client(uri).unwrap()
            .and_then(move |mut client| {
                client.get_lightd_info(Request::new(Empty{}))
            })
            .and_then(move |response| {
                //let tx = Transaction::read(&response.into_inner().data[..]).unwrap();
                println!("{:?}", response.into_inner());

                Ok(())
            })
            .map_err(|e| {
                println!("ERR = {:?}", e);
            });

        tokio::runtime::current_thread::Runtime::new().unwrap().block_on(say_hello).unwrap()
    }

    pub fn do_sync(&self) {
        // Sync is 3 parts
        // 1. Get the latest block
        // 2. Get all the blocks that we don't have
        // 3. Find all new Txns that don't have the full Tx, and get them as full transactions 
        //    and scan them, mainly to get the memos
        let mut last_scanned_height = self.wallet.last_scanned_height() as u64;
        let mut end_height = last_scanned_height + 1000;

        // This will hold the latest block fetched from the RPC
        let latest_block_height = Arc::new(AtomicU64::new(0));
        // TODO: this could be a oneshot channel
        let latest_block_height_clone = latest_block_height.clone();
        self.fetch_latest_block(move |block: BlockId| {
                latest_block_height_clone.store(block.height, Ordering::SeqCst);
            });
        let last_block = latest_block_height.load(Ordering::SeqCst);

        let bytes_downloaded = Arc::new(AtomicUsize::new(0));

        // Fetch CompactBlocks in increments
        loop {
            let local_light_wallet = self.wallet.clone();
            let local_bytes_downloaded = bytes_downloaded.clone();

            let simple_callback = move |encoded_block: &[u8]| {
                local_light_wallet.scan_block(encoded_block);
                local_bytes_downloaded.fetch_add(encoded_block.len(), Ordering::SeqCst);
            };

            print!("Syncing {}/{}, Balance = {}           \r", 
                last_scanned_height, last_block, self.wallet.balance());

            self.fetch_blocks(last_scanned_height, end_height, simple_callback);

            last_scanned_height = end_height + 1;
            end_height = last_scanned_height + 1000 - 1;

            if last_scanned_height > last_block {
                break;
            } else if end_height > last_block {
                end_height = last_block;
            }        
        }    

        println!("Synced to {}, Downloaded {} kB                               \r", 
                last_block, bytes_downloaded.load(Ordering::SeqCst) / 1024);


        // Get the Raw transaction for all the wallet transactions

        // We need to first copy over the Txids from the wallet struct, because
        // we need to free the read lock from here (Because we'll self.wallet.txs later)
        let txids_to_fetch: Vec<TxId>;
        {
            // First, build a list of all the TxIDs and Memos that we need 
            // to fetch. 
            // 1. Get all (txid, Option<Memo>)
            // 2. Filter out all txids where the Memo is None 
            //     (Which means that particular txid was never fetched. Remember
            //      that when memos are fetched, if they are empty, they become 
            //      Some(f60000...)
            let txids_and_memos = self.wallet.txs.read().unwrap().iter()
                .flat_map( |(txid, wtx)| {  // flat_map because we're collecting vector of vectors
                    wtx.notes.iter()
                        .filter( |nd| nd.memo.is_none())                // only get if memo is None (i.e., it has not been fetched)
                        .map( |nd| (txid.clone(), nd.memo.clone()) )    // collect (txid, memo) Clone everything because we want copies, so we can release the read lock
                        .collect::<Vec<(TxId, Option<Memo>)>>()         // convert to vector
                })
                .collect::<Vec<(TxId, Option<Memo>)>>();
                
            println!("{:?}", txids_and_memos);
            // TODO: Assert that all the memos here are None

            txids_to_fetch = txids_and_memos.iter()
                .map( | (txid, _) | txid.clone() )  // We're only interested in the txids, so drop the Memo, which is None anyway
                .collect::<Vec<TxId>>();            // and convert into Vec
        }

        // And go and fetch the txids, getting the full transaction, so we can 
        // read the memos        
        for txid in txids_to_fetch {
            let light_wallet_clone = self.wallet.clone();
            println!("Scanning txid {}", txid);

            self.fetch_full_tx(txid, move |tx_bytes: &[u8] | {
                let tx = Transaction::read(tx_bytes).unwrap();

                light_wallet_clone.scan_full_tx(&tx);
            });
        };

        // Print all the memos for fun.
        let memos = self.wallet.txs.read().unwrap()
                    .values().flat_map(|wtx| {
                        wtx.notes.iter().map(|nd| nd.memo.clone() ).collect::<Vec<Option<Memo>>>()
                    })
                    .map( |m| match m {
                        Some(memo) => {
                            match memo.to_utf8() {
                                Some(Ok(memo_str)) => Some(memo_str),
                                _ => None
                            }
                        }
                        _ => None
                    })
                    .collect::<Vec<Option<String>>>();

        println!("All Wallet Txns {:?}", memos);
    }

    pub fn do_send(&self, addr: String, value: u64, memo: Option<String>) {
        let rawtx = self.wallet.send_to_address(
            u32::from_str_radix("2bb40e60", 16).unwrap(),   // Blossom ID
            &self.sapling_spend, &self.sapling_output,
            &addr, value, memo
        );
        
        match rawtx {
            Some(txbytes)   => self.broadcast_raw_tx(txbytes),
            None            => eprintln!("No Tx to broadcast")
        };
    }

    pub fn fetch_blocks<F : 'static + std::marker::Send>(&self, start_height: u64, end_height: u64, c: F)
        where F : Fn(&[u8]) {
        // Fetch blocks
        let uri: http::Uri = format!("http://127.0.0.1:9067").parse().unwrap();

        let dst = Destination::try_from_uri(uri.clone()).unwrap();
        let connector = util::Connector::new(HttpConnector::new(4));
        let settings = client::Builder::new().http2_only(true).clone();
        let mut make_client = client::Connect::with_builder(connector, settings);

        let say_hello = make_client
            .make_service(dst)
            .map_err(|e| panic!("connect error: {:?}", e))
            .and_then(move |conn| {

                let conn = tower_request_modifier::Builder::new()
                    .set_origin(uri)
                    .build(conn)
                    .unwrap();

                // Wait until the client is ready...
                CompactTxStreamer::new(conn)
                    .ready()
                    .map_err(|e| eprintln!("streaming error {:?}", e))
            })
            .and_then(move |mut client| {
                let bs = BlockId{ height: start_height, hash: vec!()};
                let be = BlockId{ height: end_height,   hash: vec!()};

                let br = Request::new(BlockRange{ start: Some(bs), end: Some(be)});
                client
                    .get_block_range(br)
                    .map_err(|e| {
                        eprintln!("RouteChat request failed; err={:?}", e);
                    })
                    .and_then(move |response| {
                        let inbound = response.into_inner();
                        inbound.for_each(move |b| {
                            use prost::Message;
                            let mut encoded_buf = vec![];

                            b.encode(&mut encoded_buf).unwrap();
                            c(&encoded_buf);

                            Ok(())
                        })
                        .map_err(|e| eprintln!("gRPC inbound stream error: {:?}", e))                    
                    })
            });

        tokio::runtime::current_thread::Runtime::new().unwrap().block_on(say_hello).unwrap();
    }


    pub fn fetch_full_tx<F : 'static + std::marker::Send>(&self, txid: TxId, c: F)
            where F : Fn(&[u8]) {
        let uri: http::Uri = format!("http://127.0.0.1:9067").parse().unwrap();

        let say_hello = self.make_grpc_client(uri).unwrap()
            .and_then(move |mut client| {
                let txfilter = TxFilter { block: None, index: 0, hash: txid.0.to_vec() };
                client.get_transaction(Request::new(txfilter))
            })
            .and_then(move |response| {
                //let tx = Transaction::read(&response.into_inner().data[..]).unwrap();
                c(&response.into_inner().data);

                Ok(())
            })
            .map_err(|e| {
                println!("ERR = {:?}", e);
            });

        tokio::runtime::current_thread::Runtime::new().unwrap().block_on(say_hello).unwrap()
    }

    pub fn broadcast_raw_tx(&self, tx_bytes: Box<[u8]>) {
        let uri: http::Uri = format!("http://127.0.0.1:9067").parse().unwrap();

        let say_hello = self.make_grpc_client(uri).unwrap()
            .and_then(move |mut client| {
                client.send_transaction(Request::new(RawTransaction {data: tx_bytes.to_vec()}))
            })
            .and_then(move |response| {
                println!("{:?}", response.into_inner());
                Ok(())
            })
            .map_err(|e| {
                println!("ERR = {:?}", e);
            });

        tokio::runtime::current_thread::Runtime::new().unwrap().block_on(say_hello).unwrap()
    }

    pub fn fetch_latest_block<F : 'static + std::marker::Send>(&self, mut c : F) 
        where F : FnMut(BlockId) {
        let uri: http::Uri = format!("http://127.0.0.1:9067").parse().unwrap();

        let say_hello = self.make_grpc_client(uri).unwrap()
            .and_then(|mut client| {
                client.get_latest_block(Request::new(ChainSpec {}))
            })
            .and_then(move |response| {
                c(response.into_inner());
                Ok(())
            })
            .map_err(|e| {
                println!("ERR = {:?}", e);
            });

        tokio::runtime::current_thread::Runtime::new().unwrap().block_on(say_hello).unwrap()
    }
    
    fn make_grpc_client(&self, uri: http::Uri) -> Result<Box<dyn Future<Item=Client, Error=tower_grpc::Status> + Send>, Box<dyn Error>> {
        let dst = Destination::try_from_uri(uri.clone())?;
        let connector = util::Connector::new(HttpConnector::new(4));
        let settings = client::Builder::new().http2_only(true).clone();
        let mut make_client = client::Connect::with_builder(connector, settings);

        let say_hello = make_client
            .make_service(dst)
            .map_err(|e| panic!("connect error: {:?}", e))
            .and_then(move |conn| {

                let conn = tower_request_modifier::Builder::new()
                    .set_origin(uri)
                    .build(conn)
                    .unwrap();

                // Wait until the client is ready...
                CompactTxStreamer::new(conn).ready()
            });
        Ok(Box::new(say_hello))
    }
}





/*
 TLS Example https://gist.github.com/kiratp/dfcbcf0aa713a277d5d53b06d9db9308
 
// [dependencies]
// futures = "0.1.27"
// http = "0.1.17"
// tokio = "0.1.21"
// tower-request-modifier = { git = "https://github.com/tower-rs/tower-http" }
// tower-grpc = { version = "0.1.0", features = ["tower-hyper"] }
// tower-service = "0.2"
// tower-util = "0.1"
// tokio-rustls = "0.10.0-alpha.3"
// webpki = "0.19.1"
// webpki-roots = "0.16.0"
// tower-h2 = { git = "https://github.com/tower-rs/tower-h2" }
// openssl = "*"
// openssl-probe = "*"

use std::thread;
use std::sync::{Arc};
use futures::{future, Future};
use tower_util::MakeService;

use tokio_rustls::client::TlsStream;
use tokio_rustls::{rustls::ClientConfig, TlsConnector};
use std::net::SocketAddr;

use tokio::executor::DefaultExecutor;
use tokio::net::tcp::TcpStream;
use tower_h2;

use std::net::ToSocketAddrs;



struct Dst(SocketAddr);


impl tower_service::Service<()> for Dst {
    type Response = TlsStream<TcpStream>;
    type Error = ::std::io::Error;
    type Future = Box<dyn Future<Item = TlsStream<TcpStream>, Error = ::std::io::Error> + Send>;

    fn poll_ready(&mut self) -> futures::Poll<(), Self::Error> {
        Ok(().into())
    }

    fn call(&mut self, _: ()) -> Self::Future {
        println!("{:?}", self.0);
        let mut config = ClientConfig::new();

        config.alpn_protocols.push(b"h2".to_vec());
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let config = Arc::new(config);
        let tls_connector = TlsConnector::from(config);

        let addr_string_local = "mydomain.com";

        let domain = webpki::DNSNameRef::try_from_ascii_str(addr_string_local).unwrap();
        let domain_local = domain.to_owned();

        let stream = TcpStream::connect(&self.0).and_then(move |sock| {
            sock.set_nodelay(true).unwrap();
            tls_connector.connect(domain_local.as_ref(), sock)
        })
        .map(move |tcp| tcp);

        Box::new(stream)
    }
}

// Same implementation but without TLS. Should make it straightforward to run without TLS
// when testing on local machine

// impl tower_service::Service<()> for Dst {
//     type Response = TcpStream;
//     type Error = ::std::io::Error;
//     type Future = Box<dyn Future<Item = TcpStream, Error = ::std::io::Error> + Send>;

//     fn poll_ready(&mut self) -> futures::Poll<(), Self::Error> {
//         Ok(().into())
//     }

//     fn call(&mut self, _: ()) -> Self::Future {
//         let mut config = ClientConfig::new();
//         config.alpn_protocols.push(b"h2".to_vec());
//         config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

//         let addr_string_local = "mydomain.com".to_string();
//         let addr = addr_string_local.as_str();
        
//         let stream = TcpStream::connect(&self.0)
//             .and_then(move |sock| {
//                 sock.set_nodelay(true).unwrap();
//                 Ok(sock)
//             });
//         Box::new(stream)
//     }
// }


fn connect() {
    let keepalive = future::loop_fn((), move |_| {
        let uri: http::Uri = "https://mydomain.com".parse().unwrap();
        println!("Connecting to network at: {:?}", uri);

        let addr = "https://mydomain.com:443"
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        let h2_settings = Default::default();
        let mut make_client = tower_h2::client::Connect::new(Dst {0: addr}, h2_settings, DefaultExecutor::current());

        make_client
            .make_service(())
            .map_err(|e| {
                eprintln!("HTTP/2 connection failed; err={:?}", e);
            })
            .and_then(move |conn| {
                let conn = tower_request_modifier::Builder::new()
                    .set_origin(uri)
                    .build(conn)
                    .unwrap();

                MyGrpcService::new(conn)
                    // Wait until the client is ready...
                    .ready()
                    .map_err(|e| eprintln!("client closed: {:?}", e))
            })
            .and_then(move |mut client| {
                // do stuff
            })
            .then(|e| {
                eprintln!("Reopening client connection to network: {:?}", e);
                let retry_sleep = std::time::Duration::from_secs(1);

                thread::sleep(retry_sleep);
                Ok(future::Loop::Continue(()))
            })
    });

    thread::spawn(move || tokio::run(keepalive));
}

pub fn main() {
    connect();
}

 */