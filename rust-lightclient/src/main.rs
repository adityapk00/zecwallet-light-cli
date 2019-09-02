
use futures::Future;
use hyper::client::connect::{Destination, HttpConnector};
use tower_grpc::Request;
use tower_hyper::{client, util};
use tower_util::MakeService;
use futures::stream::Stream;

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
            CompactTxStreamer::new(conn)
                .ready()
                .map_err(|e| eprintln!("streaming error {:?}", e))
        })
        .and_then(|mut client| {
            use crate::grpc_client::BlockId;
            use crate::grpc_client::BlockRange;

            let bs = BlockId{ height: 588300, hash: vec!()};
            let be = BlockId{ height: 588390, hash: vec!()};

            let br = Request::new(BlockRange{ start: Some(bs), end: Some(be)});
            client
                .get_block_range(br)
                .map_err(|e| {
                    eprintln!("RouteChat request failed; err={:?}", e);
                })
                .and_then(|response| {
                    let inbound = response.into_inner();
                    inbound.for_each(|b| {
                        println!("RESPONSE = {:?}", b);
                        Ok(())
                    })
                    .map_err(|e| eprintln!("gRPC inbound stream error: {:?}", e))                    
                })
        });

    tokio::run(say_hello);
}