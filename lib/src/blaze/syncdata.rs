use crate::{lightclient::lightclient_config::LightClientConfig, lightwallet::data::BlockData};

use super::{node_and_witness_data::NodeAndWitnessData, nullifier_data::NullifierData};

pub struct BlazeSyncData {
    sync_id: u32,
    start_block: u64,
    end_block: u64,

    in_progress: bool,

    pub(crate) nullifier_data: NullifierData,
    pub(crate) node_data: NodeAndWitnessData,
}

impl BlazeSyncData {
    pub fn new(config: &LightClientConfig) -> Self {
        Self {
            sync_id: 0,
            start_block: 0,
            end_block: 0,
            in_progress: false,

            nullifier_data: NullifierData::new(),
            node_data: NodeAndWitnessData::new(config),
        }
    }

    pub fn earliest_block(&self) -> u64 {
        self.end_block
    }

    pub async fn setup_for_sync(&mut self, start_block: u64, end_block: u64, existing_blocks: Vec<BlockData>) {
        if start_block < end_block {
            panic!("Blocks should be backwards");
        }
        self.sync_id += 1;
        self.start_block = start_block;
        self.end_block = end_block;

        self.in_progress = true;

        self.nullifier_data.setup_sync().await;
        self.node_data.setup_sync(existing_blocks).await;
    }
}
