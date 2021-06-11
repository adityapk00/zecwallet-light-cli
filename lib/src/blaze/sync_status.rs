#[derive(Clone, Debug)]
pub struct SyncStatus {
    pub blocks_done: u64,
    pub blocks_tree_done: u64,
    pub trial_dec_done: u64,

    pub blocks_total: u64,
}

impl SyncStatus {
    pub fn new() -> Self {
        Self {
            blocks_done: 0,
            blocks_tree_done: 0,
            trial_dec_done: 0,
            blocks_total: 0,
        }
    }
}
