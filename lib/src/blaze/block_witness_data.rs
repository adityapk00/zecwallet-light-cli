use crate::{
    compact_formats::{CompactBlock, CompactTx, TreeState},
    lightclient::{
        checkpoints,
        lightclient_config::{LightClientConfig, MAX_REORG},
    },
    lightwallet::{
        data::{BlockData, WalletTx, WitnessCache},
        wallet_txns::WalletTxns,
    },
};
use futures::{future::join_all, stream::FuturesUnordered, StreamExt};
use log::{info, warn};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{
        mpsc::{self, unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot::{self, Sender},
        RwLock,
    },
    task::{yield_now, JoinHandle},
    time::sleep,
};
use zcash_primitives::{
    consensus::BlockHeight,
    merkle_tree::{CommitmentTree, IncrementalWitness},
    primitives::Nullifier,
    sapling::Node,
    transaction::TxId,
};

use super::{fixed_size_buffer::FixedSizeBuffer, sync_status::SyncStatus};

pub struct BlockAndWitnessData {
    // List of all blocks and their hashes/commitment trees. Stored from smallest block height to tallest block height
    blocks: Arc<RwLock<Vec<BlockData>>>,

    // List of existing blocks in the wallet. Used for reorgs
    existing_blocks: Arc<RwLock<Vec<BlockData>>>,

    // List of sapling tree states that were fetched from the server, which need to be verified before we return from the
    // function
    verification_list: Arc<RwLock<Vec<TreeState>>>,

    // How many blocks to process at a time.
    batch_size: u64,

    // Link to the syncstatus where we can update progress
    sync_status: Arc<RwLock<SyncStatus>>,

    sapling_activation_height: u64,
}

impl BlockAndWitnessData {
    pub fn new(config: &LightClientConfig, sync_status: Arc<RwLock<SyncStatus>>) -> Self {
        Self {
            blocks: Arc::new(RwLock::new(vec![])),
            existing_blocks: Arc::new(RwLock::new(vec![])),
            verification_list: Arc::new(RwLock::new(vec![])),
            batch_size: 25_000,
            sync_status,
            sapling_activation_height: config.sapling_activation_height,
        }
    }

    #[cfg(test)]
    pub fn new_with_batchsize(config: &LightClientConfig, batch_size: u64) -> Self {
        let mut s = Self::new(config, Arc::new(RwLock::new(SyncStatus::default())));
        s.batch_size = batch_size;

        s
    }

    pub async fn setup_sync(&mut self, existing_blocks: Vec<BlockData>) {
        if !existing_blocks.is_empty() {
            if existing_blocks.first().unwrap().height < existing_blocks.last().unwrap().height {
                panic!("Blocks are in wrong order");
            }
        }
        self.verification_list.write().await.clear();

        self.blocks.write().await.clear();

        self.existing_blocks.write().await.clear();
        self.existing_blocks.write().await.extend(existing_blocks);
    }

    // Finish up the sync. This method will delete all the elements in the blocks, and return
    // the top `num` blocks
    pub async fn finish_get_blocks(&self, num: usize) -> Vec<BlockData> {
        self.verification_list.write().await.clear();

        {
            let mut blocks = self.blocks.write().await;
            blocks.extend(self.existing_blocks.write().await.drain(..));

            blocks.truncate(num);
            blocks.to_vec()
        }
    }

    pub async fn get_ctx_for_nf_at_height(&self, nullifier: &Nullifier, height: u64) -> (CompactTx, u32) {
        self.wait_for_block(height).await;

        let cb = {
            let blocks = self.blocks.read().await;
            let pos = blocks.first().unwrap().height - height;
            let bd = blocks.get(pos as usize).unwrap();

            bd.cb()
        };

        for ctx in &cb.vtx {
            for cs in &ctx.spends {
                if cs.nf == nullifier.to_vec() {
                    return (ctx.clone(), cb.time);
                }
            }
        }

        panic!("Tx not found");
    }

    async fn verify_sapling_tree(
        blocks: Arc<RwLock<Vec<BlockData>>>,
        verification_list: Arc<RwLock<Vec<TreeState>>>,
        start_block: u64,
        end_block: u64,
        actual_end_block: u64,
    ) -> Result<(), String> {
        if blocks.read().await.is_empty() {
            return Ok(());
        }

        // Verify everything in the verification_list
        {
            assert!(actual_end_block <= end_block);

            let verification_list = verification_list.read().await;
            let blocks = blocks.read().await;
            if blocks.first().unwrap().height != start_block {
                return Err(format!("Wrong start block!"));
            }

            if blocks.last().unwrap().height != actual_end_block {
                return Err(format!("Wrong end block!"));
            }

            for v in verification_list.iter() {
                let pos = blocks.first().unwrap().height - v.height;

                if pos >= blocks.len() as u64 {
                    continue;
                }

                let b = blocks.get(pos as usize).unwrap();

                if b.height != v.height {
                    return Err(format!("Verification failed: Wrong height!"));
                }
                if b.hash() != v.hash {
                    return Err(format!("Verfification hash failed!"));
                }

                let mut write_buf = vec![];
                b.tree.as_ref().unwrap().write(&mut write_buf).unwrap();
                if hex::encode(write_buf) != v.tree {
                    return Err(format!("Verification tree failed!"));
                }
            }

            info!("Sapling Tree verification succeeded!");
        }

        // Verify all the blocks are in order
        {
            let blocks = blocks.read().await;
            if blocks.len() as u64 != start_block - actual_end_block + 1 {
                return Err(format!("Wrong number of blocks"));
            }

            for (i, b) in blocks.iter().enumerate() {
                if b.height != start_block - i as u64 {
                    return Err(format!("Wrong block height found in final processed blocks"));
                }
                if b.tree.is_none() {
                    return Err(format!("Block {} didn't have a commitment tree", b.height));
                }
            }
        }

        // Verify all the checkpoints that were passed
        {
            let checkpoints = checkpoints::get_all_main_checkpoints();
            let blocks_start = blocks.read().await.first().unwrap().height as usize;
            let blocks_end = blocks.read().await.last().unwrap().height as usize;

            let mut workers: Vec<JoinHandle<Result<(), String>>> = vec![];

            for (height, hash, tree_str) in checkpoints {
                let height = height as usize;
                if height >= blocks_end && height <= blocks_start {
                    let blocks = blocks.clone();

                    workers.push(tokio::spawn(async move {
                        let write_buf = {
                            // Read Lock
                            let blocks = blocks.read().await;
                            let b = &blocks[blocks_start - height];

                            if b.height as usize != height {
                                return Err(format!("Checkpoint Wrong block at {}", height));
                            }

                            if b.hash() != hash {
                                return Err(format!("Checkpoint Block hash verification failed at {}", height));
                            }

                            let mut write_buf = vec![];
                            b.tree.as_ref().unwrap().write(&mut write_buf).unwrap();
                            write_buf
                        };

                        if hex::encode(write_buf) != tree_str {
                            return Err(format!("Checkpoint sapling tree verification failed at {}", height));
                        }

                        Ok(())
                    }));
                }
            }

            if let Err(e) = join_all(workers)
                .await
                .into_iter()
                .map(|r| match r {
                    Ok(Ok(_)) => Ok(()),
                    Ok(Err(e)) => Err(e),
                    Err(e) => Err(format!("{}", e)),
                })
                .collect::<Result<(), String>>()
            {
                return Err(format!("Verification failed {}", e));
            }
        }

        Ok(())
    }

    // Add the processed Blocks (i.e., Blocks that already have the CommitmentTree filled in) in batches.
    // Since the blocks can arrive out-of-order, we need to maintain an internal queue that will ensure that the
    // processed blocks are added in the correct order into `blocks`.
    // At the end of the function, when all the blocks have been processed, we also verify all the tree states that we
    // fetched from LightwalletD
    async fn finish_processed_blocks(
        blocks: Arc<RwLock<Vec<BlockData>>>,
        mut processed_rx: UnboundedReceiver<Vec<BlockData>>,
        verification_list: Arc<RwLock<Vec<TreeState>>>,
        start_block: u64,
        end_block: u64,
    ) -> Result<(), String> {
        let mut queue: Vec<Vec<BlockData>> = vec![];

        while let Some(mut blks) = processed_rx.recv().await {
            let next_expecting = if blocks.read().await.is_empty() {
                start_block
            } else {
                blocks.read().await.last().unwrap().height - 1
            };

            // If the block is what we're expecting, just add it
            if blks.first().unwrap().height == next_expecting {
                blocks.write().await.append(&mut blks);

                // Now process the queue
                queue.sort_by(|a, b| b.first().unwrap().height.cmp(&a.first().unwrap().height));

                // Verify the queue is in right order
                if queue.len() >= 2 {
                    for i in 0..(queue.len() - 1) {
                        if queue[i].first().unwrap().height <= queue[i + 1].first().unwrap().height {
                            return Err(format!("Sorted queue is in the wrong order"));
                        }
                    }
                }

                let mut new_queue = vec![];
                for mut bd in queue.into_iter() {
                    // Override the next_expecting, since we just added to `blocks`
                    let next_expecting = blocks.read().await.last().unwrap().height - 1;

                    if bd.first().unwrap().height == next_expecting {
                        blocks.write().await.append(&mut bd);
                    } else {
                        new_queue.push(bd);
                    }
                }
                queue = new_queue;
            } else {
                // Add it to the queue
                queue.push(blks);
            }
        }

        if !queue.is_empty() {
            return Err(format!("Block Data queue at the end of processing was not empty!"));
        }

        if blocks.read().await.last().is_none() {
            warn!("No blocks were read!");
            Ok(())
        } else {
            let actual_end_block = blocks.read().await.last().unwrap().height;
            Self::verify_sapling_tree(blocks, verification_list, start_block, end_block, actual_end_block).await
        }
    }

    // Process block batches sent on `blk_rx`. These blocks don't have the block's `CommitmentTree` yet,
    // so we'll have to fetch it from LightwalletD every 25,000 blocks, and then calculate it from the CompactOutputs
    // for all the blocks.
    // Keep all the fetched Sapling Tree's from LightwalletD in `verification_list`, so we can verify what the
    // LightwalletD told us was correct.
    async fn process_blocks_with_commitment_tree(
        uri_fetcher: UnboundedSender<(u64, oneshot::Sender<Result<TreeState, String>>)>,
        mut blk_rx: UnboundedReceiver<Vec<BlockData>>,
        verification_list: Arc<RwLock<Vec<TreeState>>>,
        processed_tx: UnboundedSender<Vec<BlockData>>,
        existing_blocks: Arc<RwLock<Vec<BlockData>>>,
        workers: Arc<RwLock<FuturesUnordered<JoinHandle<Result<(), String>>>>>,
        total_workers_tx: Sender<usize>,
        sync_status: Arc<RwLock<SyncStatus>>,
        sapling_activation_height: u64,
    ) -> Result<(), String> {
        let mut total = 0;
        while let Some(mut blks) = blk_rx.recv().await {
            let start = blks.first().unwrap().height;
            let end = blks.last().unwrap().height;

            let existing_blocks = existing_blocks.clone();
            let verification_list = verification_list.clone();
            let processed_tx = processed_tx.clone();
            let uri_fetcher = uri_fetcher.clone();
            let sync_status = sync_status.clone();

            total += 1;
            workers.read().await.push(tokio::spawn(async move {
                // Process the compact blocks.
                // Step 0: Sanity check. We're expecting blocks in reverse order
                if blks.last().unwrap().height > blks.first().unwrap().height {
                    return Err(format!(
                        "Expecting blocks in reverse order, but they were in forward order."
                    ));
                }

                // Step 1: Fetch the (earliest's block - 1)'s sapling root from the server
                let height_to_fetch = blks.last().unwrap().height - 1;
                let mut tree = if height_to_fetch < sapling_activation_height {
                    CommitmentTree::empty()
                } else {
                    let existing_blocks = existing_blocks.read().await;
                    if !existing_blocks.is_empty()
                        && existing_blocks.first().unwrap().height == height_to_fetch
                        && existing_blocks.first().unwrap().tree.is_some()
                    {
                        existing_blocks.first().unwrap().tree.as_ref().unwrap().clone()
                    } else {
                        let fetched_tree = {
                            let (tx, rx) = oneshot::channel();
                            uri_fetcher.send((height_to_fetch, tx)).unwrap();
                            rx.await.unwrap()?
                        };

                        // Step 2: Save the tree into a list to verify later
                        verification_list.write().await.push(fetched_tree.clone());
                        let tree_bytes =
                            hex::decode(fetched_tree.tree).map_err(|e| format!("Error decoding tree: {:?}", e))?;

                        CommitmentTree::read(&tree_bytes[..])
                            .map_err(|e| format!("Error building saplingtree: {:?}", e))?
                    }
                };

                // Step 3: Start processing the witness for each block
                // Process from smallest block first
                for b in blks.iter_mut().rev() {
                    let cb = b.cb();
                    for tx in &cb.vtx {
                        for co in &tx.outputs {
                            let node = Node::new(co.cmu().unwrap().into());
                            tree.append(node).unwrap();
                        }
                    }
                    b.tree = Some(tree.clone());
                }

                // Step 4: Update progress
                sync_status.write().await.blocks_tree_done += blks.len() as u64;

                // Step 5: We'd normally just add the processed blocks to the vec, but the batch processing might
                // happen out-of-order, so we dispatch it to another thread to be added to the blocks properly.
                processed_tx.send(blks).map_err(|_| format!("Error sending")).unwrap();

                info!("Processed block witness for blocks {}-{}", start, end);
                Ok::<(), String>(())
            }));
        }
        total_workers_tx.send(total).unwrap();

        Ok(())
    }

    // Invalidate the block (and wallet txns associated with it) at the given block height
    pub async fn invalidate_block(
        reorg_height: u64,
        existing_blocks: Arc<RwLock<Vec<BlockData>>>,
        wallet_txns: Arc<RwLock<WalletTxns>>,
    ) {
        // First, pop the first block (which is the top block) in the existing_blocks.
        let top_wallet_block = existing_blocks.write().await.drain(0..1).next().unwrap();
        if top_wallet_block.height != reorg_height {
            panic!("Wrong block reorg'd");
        }

        // Remove all wallet txns at the height
        wallet_txns.write().await.remove_txns_at_height(reorg_height);
    }

    /// Start a new sync where we ingest all the blocks
    pub async fn start(
        &self,
        start_block: u64,
        end_block: u64,
        wallet_txns: Arc<RwLock<WalletTxns>>,
        uri_fetcher: UnboundedSender<(u64, oneshot::Sender<Result<TreeState, String>>)>,
        reorg_tx: UnboundedSender<Option<u64>>,
    ) -> (JoinHandle<Result<u64, String>>, UnboundedSender<CompactBlock>) {
        //info!("Starting node and witness sync");

        let sapling_activation_height = self.sapling_activation_height;
        let batch_size = self.batch_size;

        // Create a new channel where we'll receive the blocks
        let (tx, mut rx) = mpsc::unbounded_channel::<CompactBlock>();

        let blocks = self.blocks.clone();
        let verification_list = self.verification_list.clone();

        let (processed_tx, processed_rx) = unbounded_channel::<Vec<BlockData>>();
        let (blk_tx, blk_rx) = unbounded_channel::<Vec<BlockData>>();

        let sync_status = self.sync_status.clone();
        sync_status.write().await.blocks_total = start_block - end_block + 1;

        // Handle 0:
        // Process the incoming compact blocks, collect them into `BlockData` and pass them on
        // for further processing.
        // We also trigger the node commitment tree update every `batch_size` blocks using the Sapling tree fetched
        // from the server temporarily, but we verify it before we return it
        let existing_blocks = self.existing_blocks.clone();
        let h0: JoinHandle<Result<u64, String>> = tokio::spawn(async move {
            // Temporary holding place for blocks while we process them.
            let mut blks = vec![];
            let mut earliest_block_height = 0;

            // Reorg stuff
            let mut last_block_expecting = end_block;

            // We'll process 25_000 blocks at a time.
            while let Some(cb) = rx.recv().await {
                if cb.height % batch_size == 0 {
                    if !blks.is_empty() {
                        // We'll now dispatch these blocks for updating the witness
                        sync_status.write().await.blocks_done += blks.len() as u64;
                        blk_tx.send(blks).map_err(|_| format!("Error sending"))?;

                        blks = vec![];
                    }
                }

                // Check if this is the last block we are expecting
                if cb.height == last_block_expecting {
                    // Check to see if the prev block's hash matches, and if it does, finish the task
                    let reorg_block = match existing_blocks.read().await.first() {
                        Some(top_block) => {
                            if top_block.hash() == cb.prev_hash().to_string() {
                                None
                            } else {
                                // send a reorg signal
                                Some(top_block.height)
                            }
                        }
                        None => {
                            // There is no top wallet block, so we can't really check for reorgs.
                            None
                        }
                    };

                    // If there was a reorg, then we need to invalidate the block and its associated txns
                    if let Some(reorg_height) = reorg_block {
                        Self::invalidate_block(reorg_height, existing_blocks.clone(), wallet_txns.clone()).await;
                        last_block_expecting = reorg_height;
                    }
                    reorg_tx.send(reorg_block).unwrap();
                }

                earliest_block_height = cb.height;
                blks.push(BlockData::new(cb));
            }

            if !blks.is_empty() {
                // We'll now dispatch these blocks for updating the witness
                sync_status.write().await.blocks_done += blks.len() as u64;
                blk_tx.send(blks).map_err(|_| format!("Error sending"))?;
            }

            Ok(earliest_block_height)
        });

        // Handle 1:
        // Process downloaded blocks. That is, get the sapling tree from the server for the previous block, then update the
        // commitment tree for each block in the batch. Note that each's block's `tree` is the state of the tree at the END
        // of the block.
        let workers = Arc::new(RwLock::new(FuturesUnordered::new()));
        let (total_workers_tx, total_workers_rx) = oneshot::channel();
        let sync_status = self.sync_status.clone();
        let h1 = tokio::spawn(Self::process_blocks_with_commitment_tree(
            uri_fetcher,
            blk_rx,
            verification_list.clone(),
            processed_tx,
            self.existing_blocks.clone(),
            workers.clone(),
            total_workers_tx,
            sync_status,
            sapling_activation_height,
        ));

        // Handle 2:
        // A task to add the processed blocks to the main blocks struct. Note that since the blocks might be processed
        // out of order, we need to make sure to add them in correct order.
        let h2 = tokio::spawn(Self::finish_processed_blocks(
            blocks,
            processed_rx,
            verification_list.clone(),
            start_block,
            end_block,
        ));

        // Handle: Final
        // Join all the handles
        let h = tokio::spawn(async move {
            // Collect all the Node's CommitmentTree updation workers
            let h3 = tokio::spawn(async move {
                let total = total_workers_rx.await.unwrap();
                let mut i = 0;
                let mut results = vec![];

                while i < total {
                    if let Some(r) = workers.write().await.next().await {
                        results.push(match r.map_err(|e| format!("{}", e)) {
                            Ok(r) => r,
                            Err(e) => Err(e),
                        });
                        i += 1;
                    } else {
                        //info!("Waiting for workers. Have {}, waiting for {}", i, total);
                        sleep(Duration::from_millis(100)).await;
                        yield_now().await;
                    }
                }

                // Conver vec<> to result<>
                results.into_iter().collect()
            });

            let earliest_block = h0.await.map_err(|e| format!("Error processing blocks: {}", e))??;

            let results = join_all(vec![h1, h2, h3])
                .await
                .into_iter()
                .collect::<Result<Result<(), String>, _>>();

            results.map_err(|e| format!("Error joining all handles: {}", e))??;

            // Return the earlist block that was synced, accounting for all reorgs
            return Ok(earliest_block);
        });

        return (h, tx);
    }

    async fn wait_for_first_block(&self) -> u64 {
        while self.blocks.read().await.is_empty() {
            yield_now().await;
            sleep(Duration::from_millis(100)).await;

            //info!("Waiting for first block, blocks are empty!");
        }

        self.blocks.read().await.first().unwrap().height
    }

    async fn wait_for_block(&self, height: u64) {
        self.wait_for_first_block().await;

        while self.blocks.read().await.last().unwrap().height > height {
            yield_now().await;
            sleep(Duration::from_millis(100)).await;

            // info!(
            //     "Waiting for block {}, current at {}",
            //     height,
            //     self.blocks.read().await.last().unwrap().height
            // );
        }
    }

    pub(crate) async fn is_nf_spent(&self, nf: Nullifier, after_height: u64) -> Option<u64> {
        self.wait_for_block(after_height).await;

        {
            // Read Lock
            let blocks = self.blocks.read().await;
            let pos = blocks.first().unwrap().height - after_height;
            let nf = nf.to_vec();

            for i in (0..pos + 1).rev() {
                let cb = &blocks.get(i as usize).unwrap().cb();
                for ctx in &cb.vtx {
                    for cs in &ctx.spends {
                        if cs.nf == nf {
                            return Some(cb.height);
                        }
                    }
                }
            }
        }

        None
    }

    pub async fn get_block_timestamp(&self, height: &BlockHeight) -> u32 {
        let height = u64::from(*height);
        self.wait_for_block(height).await;

        {
            let blocks = self.blocks.read().await;
            let pos = blocks.first().unwrap().height - height;
            blocks.get(pos as usize).unwrap().cb().time
        }
    }

    pub async fn get_note_witness(
        &self,
        height: BlockHeight,
        tx_num: usize,
        output_num: usize,
    ) -> IncrementalWitness<Node> {
        // Get the previous block's height, because that block's sapling tree is the tree state at the start
        // of the requested block.
        let prev_height = { u64::from(height) - 1 };

        let (cb, mut tree) = {
            // First, get the current compact block
            let cb = {
                let height = u64::from(height);
                self.wait_for_block(height).await;

                {
                    let blocks = self.blocks.read().await;

                    let pos = blocks.first().unwrap().height - height;
                    let bd = blocks.get(pos as usize).unwrap();

                    bd.cb()
                }
            };

            // Prev height could be in the existing blocks, too, so check those before checking the current blocks.
            let existing_blocks = self.existing_blocks.read().await;
            let tree = {
                if prev_height < self.sapling_activation_height {
                    CommitmentTree::empty()
                } else if !existing_blocks.is_empty() && existing_blocks.first().unwrap().height == prev_height {
                    existing_blocks.first().unwrap().tree.as_ref().unwrap().clone()
                } else {
                    self.wait_for_block(prev_height).await;

                    {
                        let blocks = self.blocks.read().await;

                        let prev_pos = blocks.first().unwrap().height - prev_height;
                        let prev_bd = blocks.get(prev_pos as usize).unwrap();
                        prev_bd.tree.as_ref().unwrap().clone()
                    }
                }
            };

            (cb, tree)
        };

        // Go over all the outputs. Remember that all the numbers are inclusive, i.e., we have to scan upto and including
        // block_height, tx_num and output_num
        for (t_num, ctx) in cb.vtx.iter().enumerate() {
            for (o_num, co) in ctx.outputs.iter().enumerate() {
                let node = Node::new(co.cmu().unwrap().into());
                tree.append(node).unwrap();
                if t_num == tx_num && o_num == output_num {
                    return IncrementalWitness::from_tree(&tree);
                }
            }
        }

        panic!("Not found!");
    }

    // Stream all the outputs start at the block till the highest block available.
    pub(crate) async fn update_witness_after_block(&self, witnesses: WitnessCache) -> WitnessCache {
        let height = witnesses.top_height + 1;

        // Check if we've already synced all the requested blocks
        if height > self.wait_for_first_block().await {
            return witnesses;
        }

        self.wait_for_block(height).await;

        let mut fsb = FixedSizeBuffer::new(MAX_REORG);

        let top_block = {
            let mut blocks = self.blocks.read().await;
            let top_block = blocks.first().unwrap().height;
            let pos = top_block - height;

            // Get the last witness, and then use that.
            let mut w = witnesses.last().unwrap().clone();
            witnesses.into_fsb(&mut fsb);

            for i in (0..pos + 1).rev() {
                let cb = &blocks.get(i as usize).unwrap().cb();
                for ctx in &cb.vtx {
                    for co in &ctx.outputs {
                        let node = Node::new(co.cmu().unwrap().into());
                        w.append(node).unwrap();
                    }
                }

                // At the end of every block, update the witness in the array
                fsb.push(w.clone());

                if i % 10_000 == 0 {
                    // Every 10k blocks, give up the lock, let other threads proceed and then re-acquire it
                    drop(blocks);
                    yield_now().await;
                    blocks = self.blocks.read().await;
                }
            }

            top_block
        };

        return WitnessCache::new(fsb.into_vec(), top_block);
    }

    pub(crate) async fn update_witness_after_pos(
        &self,
        height: &BlockHeight,
        txid: &TxId,
        output_num: u32,
        witnesses: WitnessCache,
    ) -> WitnessCache {
        let height = u64::from(*height);
        self.wait_for_block(height).await;

        // We'll update the rest of the block's witnesses here. Notice we pop the last witness, and we'll
        // add the updated one back into the array at the end of this function.
        let mut w = witnesses.last().unwrap().clone();

        {
            let blocks = self.blocks.read().await;
            let pos = blocks.first().unwrap().height - height;

            let mut txid_found = false;
            let mut output_found = false;

            let cb = &blocks.get(pos as usize).unwrap().cb();
            for ctx in &cb.vtx {
                if !txid_found && WalletTx::new_txid(&ctx.hash) == *txid {
                    txid_found = true;
                }
                for j in 0..ctx.outputs.len() as u32 {
                    // If we've already passed the txid and output_num, stream the results
                    if txid_found && output_found {
                        let co = ctx.outputs.get(j as usize).unwrap();
                        let node = Node::new(co.cmu().unwrap().into());
                        w.append(node).unwrap();
                    }

                    // Mark as found if we reach the txid and output_num. Starting with the next output,
                    // we'll stream all the data to the requester
                    if !output_found && txid_found && j == output_num {
                        output_found = true;
                    }
                }
            }

            if !txid_found || !output_found {
                panic!("Txid or output not found");
            }
        }

        // Replace the last witness in the vector with the newly computed one.
        let witnesses = WitnessCache::new(vec![w], height);

        return self.update_witness_after_block(witnesses).await;
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::sync::Arc;

    use futures::future::join_all;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use tokio::join;
    use tokio::sync::mpsc::UnboundedSender;
    use tokio::sync::oneshot::{self, Sender};
    use tokio::sync::RwLock;
    use tokio::{sync::mpsc::unbounded_channel, task::JoinHandle};
    use zcash_primitives::consensus::BlockHeight;
    use zcash_primitives::merkle_tree::IncrementalWitness;
    use zcash_primitives::{block::BlockHash, merkle_tree::CommitmentTree};

    use crate::blaze::sync_status::SyncStatus;
    use crate::blaze::test_utils::{incw_to_string, list_all_witness_nodes, tree_to_string};
    use crate::compact_formats::TreeState;
    use crate::lightwallet::data::{WalletTx, WitnessCache};
    use crate::lightwallet::wallet_txns::WalletTxns;
    use crate::{
        blaze::test_utils::{FakeCompactBlock, FakeCompactBlockList},
        lightclient::lightclient_config::LightClientConfig,
        lightwallet::data::BlockData,
    };

    use super::BlockAndWitnessData;

    #[tokio::test]
    async fn setup_finish_simple() {
        let mut nw = BlockAndWitnessData::new_with_batchsize(
            &LightClientConfig::create_unconnected("main".to_string(), None),
            25_000,
        );

        let cb = FakeCompactBlock::new(1, BlockHash([0u8; 32])).into_cb();
        let blks = vec![BlockData::new(cb)];

        nw.setup_sync(blks.clone()).await;
        let finished_blks = nw.finish_get_blocks(1).await;

        assert_eq!(blks[0].hash(), finished_blks[0].hash());
        assert_eq!(blks[0].height, finished_blks[0].height);
    }

    #[tokio::test]
    async fn setup_finish_large() {
        let mut nw = BlockAndWitnessData::new_with_batchsize(
            &LightClientConfig::create_unconnected("main".to_string(), None),
            25_000,
        );

        let existing_blocks = FakeCompactBlockList::new(200).into_blockdatas();
        nw.setup_sync(existing_blocks.clone()).await;
        let finished_blks = nw.finish_get_blocks(100).await;

        assert_eq!(finished_blks.len(), 100);

        for (i, finished_blk) in finished_blks.into_iter().enumerate() {
            assert_eq!(existing_blocks[i].hash(), finished_blk.hash());
            assert_eq!(existing_blocks[i].height, finished_blk.height);
        }
    }

    #[tokio::test]
    async fn from_sapling_genesis() {
        let mut config = LightClientConfig::create_unconnected("main".to_string(), None);
        config.sapling_activation_height = 1;

        let blocks = FakeCompactBlockList::new(200).into_blockdatas();

        // Blocks are in reverse order
        assert!(blocks.first().unwrap().height > blocks.last().unwrap().height);

        // Calculate the Witnesses manually, but do it reversed, because they have to be calculated from lowest height to tallest height
        let calc_witnesses: Vec<_> = blocks
            .iter()
            .rev()
            .scan(CommitmentTree::empty(), |witness, b| {
                for node in list_all_witness_nodes(&b.cb()) {
                    witness.append(node).unwrap();
                }

                Some((witness.clone(), b.height))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        let start_block = blocks.first().unwrap().height;
        let end_block = blocks.last().unwrap().height;

        let sync_status = Arc::new(RwLock::new(SyncStatus::default()));
        let mut nw = BlockAndWitnessData::new(&config, sync_status);
        nw.setup_sync(vec![]).await;

        let (uri_fetcher, mut uri_fetcher_rx) = unbounded_channel();
        let (reorg_tx, mut reorg_rx) = unbounded_channel();
        let uri_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            if let Some(_req) = uri_fetcher_rx.recv().await {
                return Err(format!("Should not have requested a TreeState from the URI fetcher!"));
            }

            Ok(())
        });

        let (h, cb_sender) = nw
            .start(
                start_block,
                end_block,
                Arc::new(RwLock::new(WalletTxns::new())),
                uri_fetcher,
                reorg_tx,
            )
            .await;

        let send_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            for block in blocks {
                cb_sender
                    .send(block.cb())
                    .map_err(|e| format!("Couldn't send block: {}", e))?;
            }
            if let Some(Some(_h)) = reorg_rx.recv().await {
                return Err(format!("Should not have requested a reorg!"));
            }
            Ok(())
        });

        assert_eq!(h.await.unwrap().unwrap(), end_block);

        join_all(vec![uri_h, send_h])
            .await
            .into_iter()
            .collect::<Result<Result<(), String>, _>>()
            .unwrap()
            .unwrap();

        // Make sure the witnesses are correct
        nw.blocks
            .read()
            .await
            .iter()
            .zip(calc_witnesses.into_iter())
            .for_each(|(bd, (w, w_h))| {
                assert_eq!(bd.height, w_h);
                assert_eq!(tree_to_string(bd.tree.as_ref().unwrap()), tree_to_string(&w));
            });
    }

    #[tokio::test]
    async fn with_existing_batched() {
        let mut config = LightClientConfig::create_unconnected("main".to_string(), None);
        config.sapling_activation_height = 1;

        let mut blocks = FakeCompactBlockList::new(200).into_blockdatas();

        // Blocks are in reverse order
        assert!(blocks.first().unwrap().height > blocks.last().unwrap().height);

        // Calculate the Witnesses manually, but do it reversed, because they have to be calculated from lowest height to tallest height
        let calc_witnesses: Vec<_> = blocks
            .iter()
            .rev()
            .scan(CommitmentTree::empty(), |witness, b| {
                for node in list_all_witness_nodes(&b.cb()) {
                    witness.append(node).unwrap();
                }

                Some((witness.clone(), b.height))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        // Use the first 50 blocks as "existing", and then sync the other 150 blocks.
        let mut existing_blocks = blocks.split_off(150);

        let start_block = blocks.first().unwrap().height;
        let end_block = blocks.last().unwrap().height;

        // We're expecting these blocks to be requested by the URI fetcher, since we're going to set the batch size to 25.
        let mut requested_block_trees: HashMap<_, _> = vec![50, 75, 100, 125, 150, 175]
            .into_iter()
            .map(|req_h| match calc_witnesses.iter().find(|(_, h)| *h == req_h as u64) {
                Some((t, _h)) => (req_h, t.clone()),
                None => panic!("Didn't find block {}", req_h),
            })
            .collect();

        // Put the tree that is going to be requested from the existing blocks
        let first_tree = requested_block_trees.remove(&50).unwrap();
        existing_blocks.first_mut().unwrap().tree = Some(first_tree);

        let mut nw = BlockAndWitnessData::new_with_batchsize(&config, 25);
        nw.setup_sync(existing_blocks).await;

        let (uri_fetcher, mut uri_fetcher_rx) =
            unbounded_channel::<(u64, oneshot::Sender<Result<TreeState, String>>)>();

        // Collect the hashes for the blocks, so we can look them up when returning from the uri fetcher.
        let mut hashes: HashMap<_, _> = requested_block_trees
            .iter()
            .map(|(h, _)| (*h, blocks.iter().find(|b| b.height == *h).unwrap().hash().clone()))
            .collect();

        let uri_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            while let Some((req_h, res_tx)) = uri_fetcher_rx.recv().await {
                assert!(requested_block_trees.contains_key(&req_h));

                let mut ts = TreeState::default();
                ts.height = req_h;
                ts.hash = hashes.remove(&req_h).unwrap();
                ts.tree = tree_to_string(&requested_block_trees.remove(&req_h).unwrap());

                res_tx.send(Ok(ts)).unwrap();
            }

            assert!(requested_block_trees.is_empty());
            assert!(hashes.is_empty());
            Ok(())
        });

        let (reorg_tx, mut reorg_rx) = unbounded_channel();

        let (h, cb_sender) = nw
            .start(
                start_block,
                end_block,
                Arc::new(RwLock::new(WalletTxns::new())),
                uri_fetcher,
                reorg_tx,
            )
            .await;

        let send_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            for block in blocks {
                cb_sender
                    .send(block.cb())
                    .map_err(|e| format!("Couldn't send block: {}", e))?;
            }
            if let Some(Some(_h)) = reorg_rx.recv().await {
                return Err(format!("Should not have requested a reorg!"));
            }
            Ok(())
        });

        assert_eq!(h.await.unwrap().unwrap(), end_block);

        join_all(vec![uri_h, send_h])
            .await
            .into_iter()
            .collect::<Result<Result<(), String>, _>>()
            .unwrap()
            .unwrap();

        // Make sure the witnesses are correct
        nw.blocks
            .read()
            .await
            .iter()
            .zip(calc_witnesses.into_iter().take(150)) // We're only expecting 150 blocks, since the first 50 are existing
            .for_each(|(bd, (w, w_h))| {
                assert_eq!(bd.height, w_h);
                assert_eq!(tree_to_string(bd.tree.as_ref().unwrap()), tree_to_string(&w));
            });

        let finished_blks = nw.finish_get_blocks(100).await;
        assert_eq!(finished_blks.len(), 100);
        assert_eq!(finished_blks.first().unwrap().height, start_block);
        assert_eq!(finished_blks.last().unwrap().height, start_block - 100 + 1);
    }

    #[tokio::test]
    async fn with_reorg() {
        let mut config = LightClientConfig::create_unconnected("main".to_string(), None);
        config.sapling_activation_height = 1;

        let mut blocks = FakeCompactBlockList::new(100).into_blockdatas();

        // Blocks are in reverse order
        assert!(blocks.first().unwrap().height > blocks.last().unwrap().height);

        // Calculate the Witnesses manually, but do it reversed, because they have to be calculated from lowest height to tallest height
        let calc_witnesses: Vec<_> = blocks
            .iter()
            .rev()
            .scan(CommitmentTree::empty(), |witness, b| {
                for node in list_all_witness_nodes(&b.cb()) {
                    witness.append(node).unwrap();
                }

                Some((witness.clone(), b.height))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        // Use the first 50 blocks as "existing", and then sync the other 50 blocks.
        let mut existing_blocks = blocks.split_off(50);

        // The first 5 blocks, blocks 46-50 will be reorg'd, so duplicate them
        let num_reorged = 5;
        let mut reorged_blocks = existing_blocks
            .iter()
            .take(num_reorged)
            .map(|b| b.clone())
            .collect::<Vec<_>>();

        // Reset the hashes
        for i in 0..num_reorged {
            let mut hash = [0u8; 32];
            OsRng.fill_bytes(&mut hash);

            if i == 0 {
                let mut cb = blocks.pop().unwrap().cb();
                cb.prev_hash = hash.to_vec();
                blocks.push(BlockData::new(cb));
            } else {
                let mut cb = reorged_blocks[i - 1].cb();
                cb.prev_hash = hash.to_vec();
                reorged_blocks[i - 1] = BlockData::new(cb);
            }

            let mut cb = reorged_blocks[i].cb();
            cb.hash = hash.to_vec();
            reorged_blocks[i] = BlockData::new(cb);
        }
        {
            let mut cb = reorged_blocks[4].cb();
            cb.prev_hash = existing_blocks
                .iter()
                .find(|b| b.height == 45)
                .unwrap()
                .cb()
                .hash
                .to_vec();
            reorged_blocks[4] = BlockData::new(cb);
        }

        let start_block = blocks.first().unwrap().height;
        let end_block = blocks.last().unwrap().height;

        // The sapling tree for block 45, which will be used after all the reorgs are done.
        let first_tree = calc_witnesses
            .iter()
            .find(|(_, h)| *h == 45)
            .map(|(t, _h)| t.clone())
            .unwrap();

        // Put the tree that is going to be requested from the existing blocks
        existing_blocks.iter_mut().find(|b| b.height == 45).unwrap().tree = Some(first_tree);

        let sync_status = Arc::new(RwLock::new(SyncStatus::default()));
        let mut nw = BlockAndWitnessData::new(&config, sync_status);
        nw.setup_sync(existing_blocks).await;

        let (uri_fetcher, mut uri_fetcher_rx) = unbounded_channel();
        let uri_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            if let Some(_req) = uri_fetcher_rx.recv().await {
                return Err(format!("Should not have requested a TreeState from the URI fetcher!"));
            }

            Ok(())
        });

        let (reorg_tx, mut reorg_rx) = unbounded_channel();

        let (h, cb_sender) = nw
            .start(
                start_block,
                end_block,
                Arc::new(RwLock::new(WalletTxns::new())),
                uri_fetcher,
                reorg_tx,
            )
            .await;

        let send_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            // Send the normal blocks
            for block in blocks {
                cb_sender
                    .send(block.cb())
                    .map_err(|e| format!("Couldn't send block: {}", e))?;
            }

            // Expect and send the reorg'd blocks
            let mut expecting_height = 50;
            let mut sent_ctr = 0;

            while let Some(Some(h)) = reorg_rx.recv().await {
                assert_eq!(h, expecting_height);

                expecting_height -= 1;
                sent_ctr += 1;

                cb_sender
                    .send(reorged_blocks.drain(0..1).next().unwrap().cb())
                    .map_err(|e| format!("Couldn't send block: {}", e))?;
            }

            assert_eq!(sent_ctr, num_reorged);
            assert!(reorged_blocks.is_empty());

            Ok(())
        });

        assert_eq!(h.await.unwrap().unwrap(), end_block - num_reorged as u64);

        join_all(vec![uri_h, send_h])
            .await
            .into_iter()
            .collect::<Result<Result<(), String>, _>>()
            .unwrap()
            .unwrap();

        // Make sure the witnesses are correct
        nw.blocks
            .read()
            .await
            .iter()
            .zip(calc_witnesses.into_iter().take(150)) // We're only expecting 150 blocks, since the first 50 are existing
            .for_each(|(bd, (w, w_h))| {
                assert_eq!(bd.height, w_h);
                assert_eq!(tree_to_string(bd.tree.as_ref().unwrap()), tree_to_string(&w));
            });

        let finished_blks = nw.finish_get_blocks(100).await;
        assert_eq!(finished_blks.len(), 100);
        assert_eq!(finished_blks.first().unwrap().height, start_block);
        assert_eq!(finished_blks.last().unwrap().height, start_block - 100 + 1);

        // Verify the hashes
        for i in 0..(finished_blks.len() - 1) {
            assert_eq!(finished_blks[i].cb().prev_hash, finished_blks[i + 1].cb().hash);
            assert_eq!(finished_blks[i].hash(), finished_blks[i].cb().hash().to_string());
        }
    }

    async fn setup_for_witness_tests(
        num_blocks: u64,
        uri_fetcher: UnboundedSender<(u64, Sender<Result<TreeState, String>>)>,
    ) -> (
        JoinHandle<Result<(), String>>,
        Vec<BlockData>,
        u64,
        u64,
        BlockAndWitnessData,
    ) {
        let mut config = LightClientConfig::create_unconnected("main".to_string(), None);
        config.sapling_activation_height = 1;

        let blocks = FakeCompactBlockList::new(num_blocks).into_blockdatas();

        let start_block = blocks.first().unwrap().height;
        let end_block = blocks.last().unwrap().height;

        let sync_status = Arc::new(RwLock::new(SyncStatus::default()));
        let mut nw = BlockAndWitnessData::new(&config, sync_status);
        nw.setup_sync(vec![]).await;

        let (reorg_tx, mut reorg_rx) = unbounded_channel();

        let (h0, cb_sender) = nw
            .start(
                start_block,
                end_block,
                Arc::new(RwLock::new(WalletTxns::new())),
                uri_fetcher,
                reorg_tx,
            )
            .await;

        let send_blocks = blocks.clone();
        let send_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            for block in send_blocks {
                cb_sender
                    .send(block.cb())
                    .map_err(|e| format!("Couldn't send block: {}", e))?;
            }
            if let Some(Some(_h)) = reorg_rx.recv().await {
                return Err(format!("Should not have requested a reorg!"));
            }
            Ok(())
        });

        let h = tokio::spawn(async move {
            let (r1, r2) = join!(h0, send_h);
            r1.map_err(|e| format!("{}", e))??;
            r2.map_err(|e| format!("{}", e))??;
            Ok(())
        });

        (h, blocks, start_block, end_block, nw)
    }

    #[tokio::test]
    async fn note_witness() {
        let (uri_fetcher, mut uri_fetcher_rx) = unbounded_channel();
        let uri_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            if let Some(_req) = uri_fetcher_rx.recv().await {
                return Err(format!("Should not have requested a TreeState from the URI fetcher!"));
            }

            Ok(())
        });

        let (send_h, blocks, _, _, nw) = setup_for_witness_tests(10, uri_fetcher).await;

        // Get note witness from the very first block
        let test_h = tokio::spawn(async move {
            // Calculate the Witnesses manually, but do it reversed, because they have to be calculated from lowest height to tallest height
            let calc_witnesses: Vec<_> = blocks
                .iter()
                .rev()
                .scan(CommitmentTree::empty(), |witness, b| {
                    for node in list_all_witness_nodes(&b.cb()) {
                        witness.append(node).unwrap();
                    }

                    Some((witness.clone(), b.height))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();

            // Test data is a triple of (block_height, tx_num and output_num). Note that block_height is the actual height
            // of the block, not the index in the blocks vec. tx_num and output_num are 0-indexed
            let test_data = vec![(1, 1, 1), (1, 0, 0), (10, 1, 1), (10, 0, 0), (5, 0, 1), (5, 1, 0)];

            for (block_height, tx_num, output_num) in test_data {
                let cb = blocks.iter().find(|b| b.height == block_height).unwrap().cb();

                // Get the previous block's tree or empty
                let prev_block_tree = calc_witnesses
                    .iter()
                    .find_map(|(w, h)| if *h == block_height - 1 { Some(w.clone()) } else { None })
                    .unwrap_or(CommitmentTree::empty());

                let expected_witness = list_all_witness_nodes(&cb)
                    .into_iter()
                    .take((tx_num) * 2 + output_num + 1)
                    .fold(prev_block_tree, |mut w, n| {
                        w.append(n).unwrap();
                        w
                    });

                assert_eq!(
                    incw_to_string(&IncrementalWitness::from_tree(&expected_witness)),
                    incw_to_string(
                        &nw.get_note_witness(BlockHeight::from_u32(block_height as u32), tx_num, output_num)
                            .await
                    )
                );
            }

            Ok(())
        });

        join_all(vec![uri_h, send_h, test_h])
            .await
            .into_iter()
            .collect::<Result<Result<(), String>, _>>()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn note_witness_updates() {
        let (uri_fetcher, mut uri_fetcher_rx) = unbounded_channel();
        let uri_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            if let Some(_req) = uri_fetcher_rx.recv().await {
                return Err(format!("Should not have requested a TreeState from the URI fetcher!"));
            }

            Ok(())
        });

        let (send_h, blocks, _, _, nw) = setup_for_witness_tests(10, uri_fetcher).await;

        let test_h = tokio::spawn(async move {
            let test_data = vec![(1, 1, 1), (1, 0, 0), (10, 1, 1), (10, 0, 0), (3, 0, 1), (5, 1, 0)];

            for (block_height, tx_num, output_num) in test_data {
                println!("Testing {}, {}, {}", block_height, tx_num, output_num);
                let cb = blocks.iter().find(|b| b.height == block_height).unwrap().cb();

                // Get the Incremental witness for the note
                let witness = nw
                    .get_note_witness(BlockHeight::from_u32(block_height as u32), tx_num, output_num)
                    .await;

                // Update till end of block
                let final_witness_1 = list_all_witness_nodes(&cb)
                    .into_iter()
                    .skip((tx_num) * 2 + output_num + 1)
                    .fold(witness.clone(), |mut w, n| {
                        w.append(n).unwrap();
                        w
                    });

                // Update all subsequent blocks
                let final_witness = blocks
                    .iter()
                    .rev()
                    .skip_while(|b| b.height <= block_height)
                    .flat_map(|b| list_all_witness_nodes(&b.cb()))
                    .fold(final_witness_1, |mut w, n| {
                        w.append(n).unwrap();
                        w
                    });

                let txid = cb
                    .vtx
                    .iter()
                    .enumerate()
                    .skip_while(|(i, _)| *i < tx_num)
                    .take(1)
                    .next()
                    .unwrap()
                    .1
                    .hash
                    .clone();

                let actual_final_witness = nw
                    .update_witness_after_pos(
                        &BlockHeight::from_u32(block_height as u32),
                        &WalletTx::new_txid(&txid),
                        output_num as u32,
                        WitnessCache::new(vec![witness], block_height),
                    )
                    .await
                    .last()
                    .unwrap()
                    .clone();

                assert_eq!(incw_to_string(&actual_final_witness), incw_to_string(&final_witness));
            }

            Ok(())
        });

        join_all(vec![uri_h, send_h, test_h])
            .await
            .into_iter()
            .collect::<Result<Result<(), String>, _>>()
            .unwrap()
            .unwrap();
    }
}
