#[macro_use]
extern crate rust_embed;

pub mod lightclient;
pub mod grpcconnector;
pub mod lightwallet;
pub mod commands;


#[derive(RustEmbed)]
#[folder = "zcash-params/"]
pub struct SaplingParams;

#[derive(RustEmbed)]
#[folder = "res/"]
pub struct PubCertificate;


pub const ANCHOR_OFFSET: u32 = 4;

pub mod grpc_client {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}
