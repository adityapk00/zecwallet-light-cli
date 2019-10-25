#[macro_use]
extern crate rust_embed;

pub mod lightclient;
pub mod grpcconnector;
pub mod lightwallet;
pub mod commands;


#[derive(RustEmbed)]
#[folder = "zcash-params/"]
pub struct SaplingParams;

pub const ANCHOR_OFFSET: u32 = 4;


pub mod grpc_client {
    include!(concat!(env!("OUT_DIR"), "/cash.z.wallet.sdk.rpc.rs"));
}
