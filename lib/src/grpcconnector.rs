use log::{error};

use std::sync::{Arc};
use std::net::ToSocketAddrs;
use std::net::SocketAddr;

use futures::{Future};
use futures::stream::Stream;

use tower_h2;
use tower_util::MakeService;
use tower_grpc::Request;

use tokio_rustls::client::TlsStream;
use tokio_rustls::{rustls::ClientConfig, TlsConnector};

use tokio::executor::DefaultExecutor;
use tokio::net::tcp::TcpStream;

use zcash_primitives::transaction::{TxId};

use crate::grpc_client::{ChainSpec, BlockId, BlockRange, RawTransaction, 
                         TransparentAddressBlockFilter, TxFilter, Empty, LightdInfo};
use crate::grpc_client::client::CompactTxStreamer;

mod danger {
    use rustls;
    use webpki;

    pub struct NoCertificateVerification {}

    impl rustls::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(&self,
                              _roots: &rustls::RootCertStore,
                              _presented_certs: &[rustls::Certificate],
                              _dns_name: webpki::DNSNameRef<'_>,
                              _ocsp: &[u8]) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
            Ok(rustls::ServerCertVerified::assertion())
        }
    }
}

/// A Secure (https) grpc destination.
struct Dst {
    addr:        SocketAddr, 
    host:        String,
    no_cert:     bool,
}

impl tower_service::Service<()> for Dst {
    type Response = TlsStream<TcpStream>;
    type Error = ::std::io::Error;
    type Future = Box<dyn Future<Item = TlsStream<TcpStream>, Error = ::std::io::Error> + Send>;

    fn poll_ready(&mut self) -> futures::Poll<(), Self::Error> {
        Ok(().into())
    }

    fn call(&mut self, _: ()) -> Self::Future {
        let mut config = ClientConfig::new();


        config.alpn_protocols.push(b"h2".to_vec());
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        
        if self.no_cert {
            config.dangerous()
                .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
        }

        let config = Arc::new(config);
        let tls_connector = TlsConnector::from(config);

        let addr_string_local = self.host.clone();

        let domain = match webpki::DNSNameRef::try_from_ascii_str(&addr_string_local) {
            Ok(d)  => d,
            Err(_) => webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap()
        };
        let domain_local = domain.to_owned();

        let stream = TcpStream::connect(&self.addr).and_then(move |sock| {
            sock.set_nodelay(true).unwrap();
            tls_connector.connect(domain_local.as_ref(), sock)
        })
            .map(move |tcp| tcp);

        Box::new(stream)
    }
}

// Same implementation but without TLS. Should make it straightforward to run without TLS
// when testing on local machine
//
// impl tower_service::Service<()> for Dst {
//     type Response = TcpStream;
//     type Error = ::std::io::Error;
//     type Future = Box<dyn Future<Item = TcpStream, Error = ::std::io::Error> + Send>;
//
//     fn poll_ready(&mut self) -> futures::Poll<(), Self::Error> {
//         Ok(().into())
//     }
//
//     fn call(&mut self, _: ()) -> Self::Future {
//         let mut config = ClientConfig::new();
//         config.alpn_protocols.push(b"h2".to_vec());
//         config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
//
//         let stream = TcpStream::connect(&self.addr)
//             .and_then(move |sock| {
//                 sock.set_nodelay(true).unwrap();
//                 Ok(sock)
//             });
//         Box::new(stream)
//     }
// }


macro_rules! make_grpc_client {
    ($protocol:expr, $host:expr, $port:expr, $nocert:expr) => {{
        let uri: http::Uri = format!("{}://{}", $protocol, $host).parse().unwrap();

        let addr = format!("{}:{}", $host, $port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        let h2_settings = Default::default();
        let mut make_client = tower_h2::client::Connect::new(Dst {addr, host: $host.to_string(), no_cert: $nocert}, h2_settings, DefaultExecutor::current());

        make_client
            .make_service(())
            .map_err(|e| { format!("HTTP/2 connection failed; err={:?}.\nIf you're connecting to a local server, please pass --dangerous to trust the server without checking its TLS certificate", e) })
            .and_then(move |conn| {
                let conn = tower_request_modifier::Builder::new()
                    .set_origin(uri)
                    .build(conn)
                    .unwrap();

                CompactTxStreamer::new(conn)
                    // Wait until the client is ready...
                    .ready()
                    .map_err(|e| { format!("client closed: {:?}", e) })
            })
    }};
}


// ==============
// GRPC code
// ==============

pub fn get_info(uri: http::Uri, no_cert: bool) -> Result<LightdInfo, String> {
    let runner = make_grpc_client!(uri.scheme_str().unwrap(), uri.host().unwrap(), uri.port_part().unwrap(), no_cert)
        .and_then(move |mut client| {
            client.get_lightd_info(Request::new(Empty{}))
                .map_err(|e| {
                    format!("ERR = {:?}", e)
                })
                .and_then(move |response| {
                    Ok(response.into_inner())
                })
                .map_err(|e| {
                    format!("ERR = {:?}", e)
                })
        });

    tokio::runtime::current_thread::Runtime::new().unwrap().block_on(runner)
}


pub fn fetch_blocks<F : 'static + std::marker::Send>(uri: &http::Uri, start_height: u64, end_height: u64, no_cert: bool, mut c: F)
    where F : FnMut(&[u8], u64) {
    let runner = make_grpc_client!(uri.scheme_str().unwrap(), uri.host().unwrap(), uri.port_part().unwrap(), no_cert)
        .and_then(move |mut client| {
            let bs = BlockId{ height: start_height, hash: vec!()};
            let be = BlockId{ height: end_height,   hash: vec!()};

            let br = Request::new(BlockRange{ start: Some(bs), end: Some(be)});
            client
                .get_block_range(br)
                .map_err(|e| {
                    format!("RouteChat request failed; err={:?}", e)
                })
                .and_then(move |response| {
                    let inbound = response.into_inner();
                    inbound.for_each(move |b| {
                        use prost::Message;
                        let mut encoded_buf = vec![];

                        b.encode(&mut encoded_buf).unwrap();
                        c(&encoded_buf, b.height);

                        Ok(())
                    })
                    .map_err(|e| format!("gRPC inbound stream error: {:?}", e))
                })
        });

    match tokio::runtime::current_thread::Runtime::new().unwrap().block_on(runner) {
        Ok(_)  => {}, // The result is processed in callbacks, so nothing to do here
        Err(e) => {
            error!("Error while executing fetch_blocks: {}", e);
            eprintln!("{}", e);
        }
    };
}

pub fn fetch_transparent_txids<F : 'static + std::marker::Send>(uri: &http::Uri, address: String, 
    start_height: u64, end_height: u64, no_cert: bool, c: F)
        where F : Fn(&[u8], u64) {
    let runner = make_grpc_client!(uri.scheme_str().unwrap(), uri.host().unwrap(), uri.port_part().unwrap(), no_cert)
        .and_then(move |mut client| {
            let start = Some(BlockId{ height: start_height, hash: vec!()});
            let end   = Some(BlockId{ height: end_height,   hash: vec!()});

            let br = Request::new(TransparentAddressBlockFilter{ address, range: Some(BlockRange{start, end}) });

            client
                .get_address_txids(br)
                .map_err(|e| {
                    format!("RouteChat request failed; err={:?}", e)
                })
                .and_then(move |response| {
                    let inbound = response.into_inner();
                    inbound.for_each(move |tx| {
                        //let tx = Transaction::read(&tx.into_inner().data[..]).unwrap();
                        c(&tx.data, tx.height);

                        Ok(())
                    })
                    .map_err(|e| format!("gRPC inbound stream error: {:?}", e))
                })
        });

    match tokio::runtime::current_thread::Runtime::new().unwrap().block_on(runner) {
        Ok(_)  => {}, // The result is processed in callbacks, so nothing to do here
        Err(e) => {
            error!("Error while executing fetch_transparent_txids: {}", e);
            eprintln!("{}", e);
        }
    };
}

pub fn fetch_full_tx<F : 'static + std::marker::Send>(uri: &http::Uri, txid: TxId, no_cert: bool, c: F)
        where F : Fn(&[u8]) {
    let runner = make_grpc_client!(uri.scheme_str().unwrap(), uri.host().unwrap(), uri.port_part().unwrap(), no_cert)
        .and_then(move |mut client| {
            let txfilter = TxFilter { block: None, index: 0, hash: txid.0.to_vec() };
            client.get_transaction(Request::new(txfilter))
                    .map_err(|e| {
                    format!("RouteChat request failed; err={:?}", e)
                })
                .and_then(move |response| {
                    c(&response.into_inner().data);

                    Ok(())
                })
                .map_err(|e| { format!("ERR = {:?}", e) })
        });

    match tokio::runtime::current_thread::Runtime::new().unwrap().block_on(runner) {
        Ok(_)  => {}, // The result is processed in callbacks, so nothing to do here
        Err(e) => {
            error!("Error while executing fetch_full_tx: {}", e);
            eprintln!("{}", e);
        }
    };
}

pub fn broadcast_raw_tx(uri: &http::Uri, no_cert: bool, tx_bytes: Box<[u8]>) -> Result<String, String> {
    let runner = make_grpc_client!(uri.scheme_str().unwrap(), uri.host().unwrap(), uri.port_part().unwrap(), no_cert)
        .and_then(move |mut client| {
            client.send_transaction(Request::new(RawTransaction {data: tx_bytes.to_vec(), height: 0}))
                .map_err(|e| {
                    format!("ERR = {:?}", e)
                })
                .and_then(move |response| {
                    let sendresponse = response.into_inner();
                    if sendresponse.error_code == 0 {
                        let mut txid = sendresponse.error_message;
                        if txid.starts_with("\"") && txid.ends_with("\"") {
                            txid = txid[1..txid.len()-1].to_string();
                        }

                        Ok(txid)
                    } else {
                        Err(format!("Error: {:?}", sendresponse))
                    }
                })
                .map_err(|e| { format!("ERR = {:?}", e) })
        });

    tokio::runtime::current_thread::Runtime::new().unwrap().block_on(runner)
}

pub fn fetch_latest_block<F : 'static + std::marker::Send>(uri: &http::Uri, no_cert: bool, mut c : F) 
    where F : FnMut(BlockId) {
    let runner = make_grpc_client!(uri.scheme_str().unwrap(), uri.host().unwrap(), uri.port_part().unwrap(), no_cert)
        .and_then(|mut client| {
            client.get_latest_block(Request::new(ChainSpec {}))
            .map_err(|e| { format!("ERR = {:?}", e) })
            .and_then(move |response| {
                c(response.into_inner());
                Ok(())
            })
            .map_err(|e| { format!("ERR = {:?}", e) })
        });

    match tokio::runtime::current_thread::Runtime::new().unwrap().block_on(runner) {
        Ok(_)  => {}, // The result is processed in callbacks, so nothing to do here
        Err(e) => {
            error!("Error while executing fetch_latest_block: {}", e);
            eprintln!("{}", e);
        }
    };
}
