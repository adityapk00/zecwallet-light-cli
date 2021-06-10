use std::{cmp::max, sync::Arc};

use crate::{
    compact_formats::CompactBlock, grpc_connector::GrpcConnector, lightclient::lightclient_config::LightClientConfig,
};
use tokio::{
    join,
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
};

pub struct FetchCompactBlocks {
    config: LightClientConfig,
}

impl FetchCompactBlocks {
    pub fn new(config: &LightClientConfig) -> Self {
        Self { config: config.clone() }
    }

    async fn fetch_blocks_range(
        &self,
        receivers: &Vec<UnboundedSender<CompactBlock>>,
        start_block: u64,
        end_block: u64,
    ) {
        let grpc_client = Arc::new(GrpcConnector::new(self.config.server.clone()));
        const STEP: u64 = 10_000;

        // We need the `rev()` here because ranges can only go up
        for b in (end_block..(start_block + 1)).rev().step_by(STEP as usize) {
            let start = b;
            let end = max(b - STEP + 1, end_block);
            if start < end {
                panic!("Wrong block order");
            }

            println!("Fetching blocks {}-{}", start, end);

            let grpc_client = grpc_client.clone();
            let receivers = receivers.clone();
            let (tx, mut rx) = unbounded_channel();

            let h1 = tokio::spawn(async move { grpc_client.get_block_range(start, end, tx).await });

            let h2 = tokio::spawn(async move {
                while let Some(block) = rx.recv().await {
                    // Send the CompactBlock to all recievers
                    for r in &receivers {
                        r.send(block.clone()).unwrap();
                    }
                }
            });

            let (r1, r2) = join!(h1, h2);
        }
    }

    // Load all the blocks from LightwalletD
    pub async fn start(
        &self,
        receivers: Vec<UnboundedSender<CompactBlock>>,
        start_block: u64,
        end_block: u64,
        mut reorg_rx: UnboundedReceiver<Option<u64>>,
    ) {
        if start_block < end_block {
            panic!("Expected blocks in reverse order");
        }

        println!("Starting fetch compact blocks");
        self.fetch_blocks_range(&receivers, start_block, end_block).await;

        // After fetching all the normal blocks, we actually wait to see if any re-org'd blocks are recieved
        while let Some(Some(reorg_block)) = reorg_rx.recv().await {
            // Fetch the additional block.
            self.fetch_blocks_range(&receivers, reorg_block, reorg_block).await;
        }

        println!("Finished fetch compact blocks, closing channels");
    }
}
