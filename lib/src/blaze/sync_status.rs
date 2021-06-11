use core::fmt;
use std::cmp;

#[derive(Clone, Debug, Default)]
pub struct SyncStatus {
    pub in_progress: bool,

    pub sync_id: u64,
    pub start_block: u64,
    pub end_block: u64,

    pub blocks_done: u64,
    pub blocks_tree_done: u64,
    pub trial_dec_done: u64,
    pub txn_scan_done: u64,

    pub blocks_total: u64,
}

impl SyncStatus {
    /// Setup a new sync status in prep for an upcoming sync
    pub fn new_sync(sync_id: u64, start_block: u64, end_block: u64) -> Self {
        Self {
            in_progress: true,
            sync_id,
            start_block,
            end_block,
            blocks_done: 0,
            blocks_tree_done: 0,
            trial_dec_done: 0,
            blocks_total: 0,
            txn_scan_done: 0,
        }
    }

    /// Finish up a sync
    pub fn finish(&mut self) {
        self.in_progress = false;
    }

    fn perct(&self, num: u64) -> u8 {
        cmp::min(((num * 100) / self.blocks_total) as u8, 100)
    }
}

impl fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.blocks_total > 0 && self.in_progress {
            write!(
                f,
                "id: {}, blocks: {}%, decryptions: {}%, witnesses: {}%, tx_scan: {}%",
                self.sync_id,
                self.perct(self.blocks_done),
                self.perct(self.trial_dec_done),
                self.perct(self.blocks_tree_done),
                self.perct(self.txn_scan_done),
            )
        } else {
            write!(f, "id: {}, in_progress: {}", self.sync_id, self.in_progress)
        }
    }
}
