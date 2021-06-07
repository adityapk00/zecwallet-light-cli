use std::mem;

use arr_macro::arr;

#[derive(PartialEq, PartialOrd)]
enum Node<T: PartialEq + Clone> {
    EmptyNode,
    SparseNode(SparseNode<T>),
    BranchNode(Box<BranchNode<T>>),
    LeafNode(LeafNode<T>),
}

#[derive(Debug)]
pub struct NodeCount {
    empty: u64,
    sparse: u64,
    branch: u64,
    leaf: u64,
}

impl NodeCount {
    pub fn new() -> Self {
        Self {
            empty: 0,
            sparse: 0,
            branch: 0,
            leaf: 0,
        }
    }
}

impl<T: PartialEq + Clone> Node<T> {
    fn depth(&self) -> u64 {
        match self {
            Node::EmptyNode => 0,
            Node::SparseNode(_) => 1,
            Node::BranchNode(bn) => bn.depth(),
            Node::LeafNode(_) => 1,
        }
    }

    fn count(&self, nc: &mut NodeCount) {
        match self {
            Node::EmptyNode => nc.empty += 0,
            Node::SparseNode(sn) => sn.count(nc),
            Node::BranchNode(bn) => {
                nc.branch += mem::size_of_val(bn) as u64;
                bn.count(nc);
            }
            Node::LeafNode(ln) => nc.leaf += mem::size_of_val(ln) as u64,
        }
    }
}

#[derive(PartialEq, PartialOrd)]
struct SparseNode<T: PartialEq + Clone> {
    path: Vec<u8>,
    leaf: LeafNode<T>,
}

impl<T: PartialEq + Clone> SparseNode<T> {
    fn new(path: Vec<u8>, data: T) -> Self {
        Self {
            path,
            leaf: LeafNode::new(data),
        }
    }

    fn into_branch_node(&self) -> Result<BranchNode<T>, SparseNullifierTreeError> {
        let mut bn = BranchNode::new();
        bn.insert(self.path.clone(), self.leaf.data.clone())?;

        Ok(bn)
    }

    fn lookup(&self, path: Vec<u8>) -> Option<T> {
        if self.path == path {
            Some(self.leaf.data.clone())
        } else {
            None
        }
    }

    fn count(&self, nc: &mut NodeCount) {
        nc.sparse += mem::size_of_val(self) as u64;
        nc.sparse += mem::size_of_val(&self.path) as u64;
    }
}

#[derive(PartialEq, PartialOrd)]
struct BranchNode<T: PartialEq + Clone> {
    nodes: [Node<T>; 16],
}

#[derive(Debug, PartialEq, PartialOrd)]
pub enum SparseNullifierTreeError {
    AlreadyExists,
    MismatchedTxid(String),
    WrongNodeInPosition(String),
}

impl<T: PartialEq + Clone> BranchNode<T> {
    fn new() -> Self {
        Self {
            nodes: arr![Node::EmptyNode; 16],
        }
    }

    fn insert(&mut self, path: Vec<u8>, data: T) -> Result<(), SparseNullifierTreeError> {
        // The first item in the path is the index
        let (first, path) = path.split_first().unwrap();
        let idx = usize::from(*first);

        if path.len() == 0 {
            match &mut self.nodes[idx] {
                Node::EmptyNode => {
                    self.nodes[idx] = Node::LeafNode(LeafNode::new(data));
                    Ok(())
                }
                Node::LeafNode(ln) => {
                    if ln.data != data {
                        Err(SparseNullifierTreeError::MismatchedTxid(format!(
                            "nullifier already has data"
                        )))
                    } else {
                        // Else, return that already exists
                        Err(SparseNullifierTreeError::AlreadyExists)
                    }
                }
                _ => Err(SparseNullifierTreeError::WrongNodeInPosition(format!(
                    "Can't have a SparseNode or BranchNode at the end!"
                ))),
            }
        } else {
            match &mut self.nodes[idx] {
                Node::EmptyNode => {
                    self.nodes[idx] = Node::SparseNode(SparseNode::new(path.to_vec(), data));
                    Ok(())
                }
                Node::SparseNode(sn) => {
                    // Make sure we are not inserting duplicates
                    if sn.path == path.to_vec() {
                        if sn.leaf.data == data {
                            Err(SparseNullifierTreeError::AlreadyExists)
                        } else {
                            Err(SparseNullifierTreeError::MismatchedTxid(format!(
                                "nullifier already has data"
                            )))
                        }
                    } else {
                        // We need to "upgrade" to a Branch Node
                        let mut newroot = sn.into_branch_node()?;
                        newroot.insert(path.to_vec(), data)?;

                        self.nodes[idx] = Node::BranchNode(Box::new(newroot));
                        Ok(())
                    }
                }
                Node::BranchNode(bn) => {
                    bn.insert(path.to_vec(), data)?;
                    Ok(())
                }
                Node::LeafNode(_) => Err(SparseNullifierTreeError::WrongNodeInPosition(format!(
                    "Tried to insert into leaf node, which should not be possible"
                ))),
            }
        }
    }

    fn lookup(&self, path: Vec<u8>) -> Option<T> {
        // The first item in the path is the index
        let (first, path) = path.split_first().unwrap();
        let idx = usize::from(*first);

        match &self.nodes[idx] {
            Node::EmptyNode => return None,
            Node::LeafNode(ln) => return Some(ln.data.clone()),
            Node::SparseNode(sn) => return sn.lookup(path.to_vec()),
            Node::BranchNode(bn) => return bn.lookup(path.to_vec()),
        }
    }

    fn depth(&self) -> u64 {
        1 + self.nodes.iter().map(|n| n.depth()).max().unwrap()
    }

    fn count(&self, nc: &mut NodeCount) {
        self.nodes.iter().for_each(|n| n.count(nc));
    }
}

#[derive(PartialEq, PartialOrd)]
struct LeafNode<T> {
    pub data: T,
}

impl<T> LeafNode<T> {
    fn new(data: T) -> Self {
        Self { data }
    }
}

pub struct SparseNullifierTree<T: PartialEq + Clone> {
    root: BranchNode<T>,
}

impl<T: PartialEq + Clone> SparseNullifierTree<T> {
    pub fn new() -> Self {
        SparseNullifierTree {
            root: BranchNode::new(),
        }
    }

    fn nullifier_to_path(nullifier: &Vec<u8>) -> Vec<u8> {
        nullifier
            .iter()
            .flat_map(|b| vec![(b >> 4) & 0xf, b & 0xf])
            .collect::<Vec<u8>>()
    }

    pub fn insert(&mut self, nullifier: &Vec<u8>, data: T) -> Result<(), SparseNullifierTreeError> {
        if nullifier.len() != 32 {
            panic!("Nullifier length is incorrect");
        }

        self.root
            .insert(SparseNullifierTree::<T>::nullifier_to_path(nullifier), data)
    }

    pub fn lookup(&self, nullifier: &Vec<u8>) -> Option<T> {
        if nullifier.len() != 32 {
            panic!("Nullifier length is incorrect");
        }

        self.root.lookup(SparseNullifierTree::<T>::nullifier_to_path(nullifier))
    }

    pub fn depth(&self) -> u64 {
        self.root.depth() - 1 // Don't count the root node as 1 depth
    }

    pub fn is_empty(&self) -> bool {
        self.depth() == 0
    }

    pub fn clear(&mut self) {
        self.root = BranchNode::new();
    }

    pub fn count(&self, nc: &mut NodeCount) {
        self.root.count(nc);
    }
}

#[cfg(test)]
mod test {
    use super::{NodeCount, SparseNode, SparseNullifierTree, SparseNullifierTreeError};
    use rand::Rng;
    use std::mem;
    use zcash_primitives::transaction::TxId;

    #[test]
    fn test_basic_insert_lookup() {
        let mut t = SparseNullifierTree::new();
        t.insert(&vec![0u8; 32], 5).expect("insert");

        assert_eq!(t.lookup(&[0u8; 32].to_vec()), Some(5));
        assert_eq!(t.lookup(&[1u8; 32].to_vec()), None);

        assert!(matches!(
            t.insert(&vec![0u8; 32], 5).err().unwrap(),
            SparseNullifierTreeError::AlreadyExists
        ));
        assert!(matches!(
            t.insert(&vec![0u8; 32], 3).err().unwrap(),
            SparseNullifierTreeError::MismatchedTxid(..)
        ));

        assert_eq!(t.depth(), 1);

        let mut nc = NodeCount::new();
        t.count(&mut nc);
        println!("{} / {}", nc.sparse, mem::size_of::<SparseNode<TxId>>() as u64);

        assert_eq!(nc.sparse / mem::size_of::<SparseNode<TxId>>() as u64, 1);
    }

    #[test]
    fn test_random_insert_lookup() {
        let mut tree = SparseNullifierTree::new();
        assert!(tree.is_empty());

        // Create data
        let size = 100_000;
        let mut nullifiers = (0..size)
            .map(|_| rand::thread_rng().gen::<[u8; 32]>().to_vec())
            .collect::<Vec<Vec<u8>>>();

        // There's a chance the random number generator will generate duplicate nullifiers which will cause problems,
        // so make sure to dedup just in case.
        nullifiers.sort();
        nullifiers.dedup();

        let txids = (0..nullifiers.len())
            .map(|_| TxId {
                0: rand::thread_rng().gen::<[u8; 32]>(),
            })
            .collect::<Vec<TxId>>();

        for (n, t) in nullifiers.iter().zip(txids.iter()) {
            tree.insert(n, *t).expect("insert");
        }
        assert!(!tree.is_empty());

        let mut nc = NodeCount::new();
        tree.count(&mut nc);
        println!("Count = {:#?}", nc);

        // Lookup forward
        for (n, t) in nullifiers.iter().zip(txids.iter()) {
            assert_eq!(tree.lookup(n), Some(*t));
        }

        // Lookup reverse
        for (n, t) in nullifiers.iter().rev().zip(txids.iter().rev()) {
            assert_eq!(tree.lookup(n), Some(*t));
        }
    }

    #[test]
    fn test_multiple_insert_lookup() {
        let mut tree = SparseNullifierTree::new();

        // Create data
        let size = 100_000;
        let mut nullifiers = (0..size)
            .map(|_| rand::thread_rng().gen::<[u8; 32]>().to_vec())
            .collect::<Vec<Vec<u8>>>();

        // There's a chance the random number generator will generate duplicate nullifiers which will cause problems,
        // so make sure to dedup just in case.
        nullifiers.sort();
        nullifiers.dedup();

        let txids = (0..nullifiers.len())
            .map(|_| TxId {
                0: rand::thread_rng().gen::<[u8; 32]>(),
            })
            .collect::<Vec<TxId>>();

        for (n, t) in nullifiers.iter().zip(txids.iter()) {
            tree.insert(n, *t).expect("insert");
        }

        // Try to reinsert the txids, they should all fail
        for (n, t) in nullifiers.iter().zip(txids.iter()) {
            assert!(matches!(
                tree.insert(n, *t).err().unwrap(),
                SparseNullifierTreeError::AlreadyExists
            ));
        }

        // Try to reinsert the txids reversed, they should all fail
        for (n, t) in nullifiers.iter().rev().zip(txids.iter().rev()) {
            assert!(matches!(
                tree.insert(n, *t).err().unwrap(),
                SparseNullifierTreeError::AlreadyExists
            ));
        }
    }
}
