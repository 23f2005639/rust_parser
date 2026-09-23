//! RFC 6962 Standard Merkle Tree implementation for Certificate Transparency & Log Auditing.
//!
//! Conforms strictly to RFC 6962 Section 2.1:
//! - Leaf Hash: `SHA256(0x00 || raw_log_bytes)`
//! - Internal Node Hash: `SHA256(0x01 || left_child_hash || right_child_hash)`
//! - Empty Tree Hash: `SHA256("")`
//! - Tree balancing: Split at largest power of 2 strictly less than N.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

/// Domain separation prefixes as mandated by RFC 6962 Section 2.1.
pub const LEAF_PREFIX: u8 = 0x00;
pub const NODE_PREFIX: u8 = 0x01;

/// A 256-bit cryptographic digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Hash(bytes))
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Hash::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Sibling position relative to the target branch in an audit path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    /// Sibling is on the left; hash calculation: `SHA256(0x01 || sibling || current)`
    Left,
    /// Sibling is on the right; hash calculation: `SHA256(0x01 || current || sibling)`
    Right,
}

/// Computes the leaf hash for data as per RFC 6962: `SHA256(0x00 || raw_data)`.
pub fn hash_leaf(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    Hash(hasher.finalize().into())
}

/// Computes the internal node hash for two children as per RFC 6962: `SHA256(0x01 || left || right)`.
pub fn hash_children(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left.0);
    hasher.update(right.0);
    Hash(hasher.finalize().into())
}

/// Computes the empty tree hash as per RFC 6962: `SHA256("")`.
pub fn empty_tree_hash() -> Hash {
    let hasher = Sha256::new();
    Hash(hasher.finalize().into())
}

/// Finds the largest power of two strictly smaller than `n` ($k < n \le 2k$).
#[inline]
pub fn largest_power_of_two_less_than(n: usize) -> usize {
    assert!(
        n > 1,
        "n must be > 1 to find largest power of two less than n"
    );
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("Index {index} is out of bounds for tree with {size} leaves")]
    IndexOutOfBounds { index: usize, size: usize },
    #[error("Cannot generate proof for an empty tree")]
    EmptyTree,
    #[error("Invalid previous size {prev_size} for tree with {size} leaves")]
    InvalidConsistencySize { prev_size: usize, size: usize },
}

/// Node representation in the RFC 6962 binary Merkle tree.
#[derive(Clone, Debug)]
enum TreeNode {
    Leaf {
        hash: Hash,
        _index: usize,
    },
    Internal {
        hash: Hash,
        size: usize,
        left: Box<TreeNode>,
        right: Box<TreeNode>,
    },
}

impl TreeNode {
    fn hash(&self) -> Hash {
        match self {
            TreeNode::Leaf { hash, .. } => *hash,
            TreeNode::Internal { hash, .. } => *hash,
        }
    }

    fn collect_audit_path(&self, target_idx: usize, path: &mut Vec<(Hash, Side)>) {
        match self {
            TreeNode::Leaf { .. } => {}
            TreeNode::Internal {
                size, left, right, ..
            } => {
                let k = largest_power_of_two_less_than(*size);
                if target_idx < k {
                    // Target is in left subtree; sibling is right subtree
                    left.collect_audit_path(target_idx, path);
                    path.push((right.hash(), Side::Right));
                } else {
                    // Target is in right subtree; sibling is left subtree
                    right.collect_audit_path(target_idx - k, path);
                    path.push((left.hash(), Side::Left));
                }
            }
        }
    }
}

/// An RFC 6962 Inclusion Proof (audit path) for proving that a leaf belongs to a tree.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionProof {
    pub leaf_index: usize,
    pub tree_size: usize,
    pub audit_path: Vec<(Hash, Side)>,
}

impl InclusionProof {
    /// Verifies this proof against the given raw log bytes and the expected Merkle root.
    pub fn verify(&self, raw_log: &[u8], expected_root: &Hash) -> bool {
        verify_inclusion_proof(
            raw_log,
            self.leaf_index,
            self.tree_size,
            &self.audit_path,
            expected_root,
        )
    }

    /// Verifies this proof against the pre-calculated leaf hash and the expected Merkle root.
    pub fn verify_hash(&self, leaf_hash: &Hash, expected_root: &Hash) -> bool {
        verify_inclusion_proof_by_hash(
            leaf_hash,
            self.leaf_index,
            self.tree_size,
            &self.audit_path,
            expected_root,
        )
    }
}

/// RFC 6962 Standard Merkle Tree.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    leaf_hashes: Vec<Hash>,
    root: Hash,
    root_node: Option<Box<TreeNode>>,
}

impl MerkleTree {
    /// Constructs an empty Merkle tree.
    pub fn empty() -> Self {
        Self {
            leaf_hashes: Vec::new(),
            root: empty_tree_hash(),
            root_node: None,
        }
    }

    /// Constructs a Merkle tree from an iterator of raw log entries.
    pub fn from_raw_logs<I, T>(logs: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let leaf_hashes: Vec<Hash> = logs
            .into_iter()
            .map(|item| hash_leaf(item.as_ref()))
            .collect();
        Self::from_leaf_hashes(leaf_hashes)
    }

    /// Constructs a Merkle tree from pre-computed leaf hashes.
    pub fn from_leaf_hashes(leaf_hashes: Vec<Hash>) -> Self {
        let n = leaf_hashes.len();
        if n == 0 {
            return Self::empty();
        }

        let root_node = Box::new(Self::build_subtree(&leaf_hashes, 0));
        let root = root_node.hash();

        Self {
            leaf_hashes,
            root,
            root_node: Some(root_node),
        }
    }

    fn build_subtree(leaves: &[Hash], offset: usize) -> TreeNode {
        let n = leaves.len();
        if n == 1 {
            TreeNode::Leaf {
                hash: leaves[0],
                _index: offset,
            }
        } else {
            let k = largest_power_of_two_less_than(n);
            let left = Self::build_subtree(&leaves[..k], offset);
            let right = Self::build_subtree(&leaves[k..], offset + k);
            let hash = hash_children(&left.hash(), &right.hash());
            TreeNode::Internal {
                hash,
                size: n,
                left: Box::new(left),
                right: Box::new(right),
            }
        }
    }

    /// Returns the Merkle root hash.
    pub fn root(&self) -> Hash {
        self.root
    }

    /// Returns the hex string representation of the Merkle root.
    pub fn root_hex(&self) -> String {
        self.root.to_hex()
    }

    /// Returns the number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.leaf_hashes.len()
    }

    /// Returns true if the tree contains zero leaves.
    pub fn is_empty(&self) -> bool {
        self.leaf_hashes.is_empty()
    }

    /// Returns the leaf hash at the specified index, if within bounds.
    pub fn leaf_hash(&self, index: usize) -> Option<Hash> {
        self.leaf_hashes.get(index).copied()
    }

    /// Returns all leaf hashes.
    pub fn leaf_hashes(&self) -> &[Hash] {
        &self.leaf_hashes
    }

    /// Generates an inclusion proof (audit path) for the leaf at `index`.
    /// Operates in $O(\log N)$ time.
    pub fn inclusion_proof(&self, index: usize) -> Result<InclusionProof, MerkleError> {
        let size = self.leaf_hashes.len();
        if size == 0 {
            return Err(MerkleError::EmptyTree);
        }
        if index >= size {
            return Err(MerkleError::IndexOutOfBounds { index, size });
        }

        let mut audit_path = Vec::new();
        if let Some(ref node) = self.root_node {
            node.collect_audit_path(index, &mut audit_path);
        }

        Ok(InclusionProof {
            leaf_index: index,
            tree_size: size,
            audit_path,
        })
    }

    /// Generates an RFC 6962 consistency proof proving that the tree at `prev_size`
    /// is a prefix of this tree.
    pub fn consistency_proof(&self, prev_size: usize) -> Result<Vec<Hash>, MerkleError> {
        let size = self.leaf_hashes.len();
        if prev_size == 0 || prev_size > size {
            return Err(MerkleError::InvalidConsistencySize { prev_size, size });
        }
        if prev_size == size {
            return Ok(Vec::new());
        }

        Ok(subproof(prev_size, &self.leaf_hashes, true))
    }
}

/// Recursive consistency proof generator (RFC 6962 Section 2.1.2).
fn subproof(m: usize, leaves: &[Hash], b: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        if b {
            Vec::new()
        } else {
            vec![MerkleTree::from_leaf_hashes(leaves.to_vec()).root()]
        }
    } else {
        let k = largest_power_of_two_less_than(n);
        if m <= k {
            let mut p = subproof(m, &leaves[..k], b);
            let right_mth = MerkleTree::from_leaf_hashes(leaves[k..].to_vec()).root();
            p.push(right_mth);
            p
        } else {
            let mut p = subproof(m - k, &leaves[k..], false);
            let left_mth = MerkleTree::from_leaf_hashes(leaves[..k].to_vec()).root();
            p.push(left_mth);
            p
        }
    }
}

/// Verifies an RFC 6962 Inclusion Proof given raw log bytes in $O(\log N)$ steps.
pub fn verify_inclusion_proof(
    raw_log: &[u8],
    leaf_index: usize,
    tree_size: usize,
    audit_path: &[(Hash, Side)],
    expected_root: &Hash,
) -> bool {
    let leaf_h = hash_leaf(raw_log);
    verify_inclusion_proof_by_hash(&leaf_h, leaf_index, tree_size, audit_path, expected_root)
}

/// Verifies an RFC 6962 Inclusion Proof given a pre-computed leaf hash in $O(\log N)$ steps.
pub fn verify_inclusion_proof_by_hash(
    leaf_hash: &Hash,
    leaf_index: usize,
    tree_size: usize,
    audit_path: &[(Hash, Side)],
    expected_root: &Hash,
) -> bool {
    if tree_size == 0 || leaf_index >= tree_size {
        return false;
    }

    if tree_size == 1 {
        return audit_path.is_empty() && leaf_index == 0 && leaf_hash == expected_root;
    }

    // Verify each step along the audit path
    let mut current_hash = *leaf_hash;
    for (sibling_hash, side) in audit_path {
        current_hash = match side {
            Side::Right => hash_children(&current_hash, sibling_hash),
            Side::Left => hash_children(sibling_hash, &current_hash),
        };
    }

    &current_hash == expected_root
}

/// Verifies an RFC 6962 Consistency Proof between two tree snapshots.
pub fn verify_consistency_proof(
    prev_size: usize,
    curr_size: usize,
    prev_root: &Hash,
    curr_root: &Hash,
    proof: &[Hash],
) -> bool {
    if prev_size == 0 || prev_size > curr_size {
        return false;
    }
    if prev_size == curr_size {
        return proof.is_empty() && prev_root == curr_root;
    }

    let mut proof_stack = proof.to_vec();
    match verify_consistency_internal(prev_size, curr_size, &mut proof_stack, prev_root) {
        Some(reconstructed_root) => proof_stack.is_empty() && &reconstructed_root == curr_root,
        None => false,
    }
}

fn verify_consistency_internal(
    m: usize,
    n: usize,
    proof: &mut Vec<Hash>,
    prev_root: &Hash,
) -> Option<Hash> {
    if m == n {
        Some(*prev_root)
    } else {
        let k = largest_power_of_two_less_than(n);
        if m <= k {
            let right_mth = proof.pop()?;
            let left_root = verify_consistency_internal(m, k, proof, prev_root)?;
            Some(hash_children(&left_root, &right_mth))
        } else {
            let left_mth = proof.pop()?;
            let (sub_m, sub_n) = verify_subproof_full(m - k, n - k, proof)?;
            let rec_m = hash_children(&left_mth, &sub_m);
            if &rec_m != prev_root {
                return None;
            }
            Some(hash_children(&left_mth, &sub_n))
        }
    }
}

fn verify_subproof_full(m: usize, n: usize, proof: &mut Vec<Hash>) -> Option<(Hash, Hash)> {
    if m == n {
        let h = proof.pop()?;
        Some((h, h))
    } else {
        let k = largest_power_of_two_less_than(n);
        if m <= k {
            let right_mth = proof.pop()?;
            let (sub_m, sub_k) = verify_subproof_full(m, k, proof)?;
            Some((sub_m, hash_children(&sub_k, &right_mth)))
        } else {
            let left_mth = proof.pop()?;
            let (sub_m, sub_n) = verify_subproof_full(m - k, n - k, proof)?;
            Some((
                hash_children(&left_mth, &sub_m),
                hash_children(&left_mth, &sub_n),
            ))
        }
    }
}
