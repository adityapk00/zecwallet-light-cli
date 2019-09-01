
use futures::Future;
use hyper::client::connect::{Destination, HttpConnector};
use tower_grpc::Request;
use tower_hyper::{client, util};
use tower_util::MakeService;

pub mod grpc_client {
    include!(concat!(env!("OUT_DIR"), "/cash.z.wallet.sdk.rpc.rs"));
}

pub fn main() {
    let uri: http::Uri = format!("http://127.0.0.1:9067").parse().unwrap();

    let dst = Destination::try_from_uri(uri.clone()).unwrap();
    let connector = util::Connector::new(HttpConnector::new(4));
    let settings = client::Builder::new().http2_only(true).clone();
    let mut make_client = client::Connect::with_builder(connector, settings);

    let say_hello = make_client
        .make_service(dst)
        .map_err(|e| panic!("connect error: {:?}", e))
        .and_then(move |conn| {
            use crate::grpc_client::client::CompactTxStreamer;

            let conn = tower_request_modifier::Builder::new()
                .set_origin(uri)
                .build(conn)
                .unwrap();

            // Wait until the client is ready...
            CompactTxStreamer::new(conn).ready()
        })
        .and_then(|mut client| {
            use crate::grpc_client::ChainSpec;

            client.get_latest_block(Request::new(ChainSpec {}))
        })
        .and_then(|response| {
            println!("RESPONSE = {:?}", response);
            Ok(())
        })
        .map_err(|e| {
            println!("ERR = {:?}", e);
        });

    tokio::run(say_hello);
}