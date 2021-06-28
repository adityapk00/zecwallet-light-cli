use core::fmt;
use std::cmp;

#[derive(Clone, Debug, Default)]
pub struct SyncStatus {
    pub in_progress: bool,
    pub last_error: Option<String>,

    pub sync_id: u64,
    pub start_block: u64,
    pub end_block: u64,

    pub blocks_done: u64,
    pub blocks_tree_done: u64,
    pub trial_dec_done: u64,
    pub txn_scan_done: u64,

    pub blocks_total: u64,

    pub batch_num: usize,
    pub batch_total: usize,
}

impl SyncStatus {
    pub fn start_new(&mut self, batch_total: usize) {
        self.sync_id += 1;
        self.last_error = None;
        self.in_progress = true;
        self.blocks_done = 0;
        self.blocks_tree_done = 0;
        self.trial_dec_done = 0;
        self.blocks_total = 0;
        self.txn_scan_done = 0;
        self.batch_num = 0;
        self.batch_total = batch_total;
    }

    /// Setup a new sync status in prep for an upcoming sync
    pub fn new_sync_batch(&mut self, start_block: u64, end_block: u64, batch_num: usize) {
        self.in_progress = true;
        self.last_error = None;

        self.start_block = start_block;
        self.end_block = end_block;
        self.blocks_done = 0;
        self.blocks_tree_done = 0;
        self.trial_dec_done = 0;
        self.blocks_total = 0;
        self.txn_scan_done = 0;
        self.batch_num = batch_num;
    }

    /// Finish up a sync
    pub fn finish(&mut self) {
        self.in_progress = false;
    }

    fn perct(&self, num: u64) -> u8 {
        let a = if self.blocks_total > 0 {
            let (b, d) = if self.batch_total > 0 {
                ((self.batch_num * 100 / self.batch_total), self.batch_total)
            } else {
                (0, 1)
            };
            let p = cmp::min(((num * 100) / self.blocks_total) as u8, 100);
            b + (p as usize / d)
        } else {
            0
        };

        cmp::min(100, a as u8)
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
            write!(
                f,
                "id: {}, in_progress: {}, errors: {}",
                self.sync_id,
                self.in_progress,
                self.last_error.as_ref().unwrap_or(&"None".to_string())
            )
        }
    }
}
