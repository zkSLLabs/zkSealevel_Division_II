//! Real Merkle tree implementation for Solana account state

use blake3::Hasher;
use serde::{Deserialize, Serialize};

/// Merkle tree node
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct MerkleNode {
    pub hash: [u8; 32],
}

/// Merkle proof for a leaf
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub siblings: Vec<[u8; 32]>,
}

/// Real Merkle tree implementation
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct MerkleTree {
    /// Leaf layer values.
    leaves: Vec<[u8; 32]>,
    /// All tree levels bottom-up (nodes[level][index]).
    nodes: Vec<Vec<[u8; 32]>>, // nodes[level][index]
    /// Merkle root for the current tree.
    root: [u8; 32],
}

impl MerkleTree {
    /// Build real Merkle tree from leaf hashes
    pub fn new(mut leaves: Vec<[u8; 32]>) -> Self {
        if leaves.is_empty() {
            leaves.push([0u8; 32]); // Empty tree has zero leaf
        }
        
        // Pad to power of 2
        let target_size = leaves.len().next_power_of_two();
        while leaves.len() < target_size {
            leaves.push([0u8; 32]); // Pad with zeros
        }
        
        let mut nodes = vec![leaves.clone()];
        let mut current_level = leaves;
        
        // Build tree bottom-up
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { [0u8; 32] };
                let parent = Self::hash_pair(&left, &right);
                next_level.push(parent);
            }
            
            nodes.push(next_level.clone());
            current_level = next_level;
        }
        
        let root = current_level[0];
        
        Self {
            leaves: nodes[0].clone(),
            nodes,
            root,
        }
    }
    
    /// Hash two nodes to create parent
    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(left);
        hasher.update(right);
        *hasher.finalize().as_bytes()
    }
    
    /// Get Merkle root
    pub fn root(&self) -> [u8; 32] {
        self.root
    }
    
    /// Generate Merkle proof for a leaf
    #[allow(dead_code)]
    pub fn prove(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }
        
        let mut siblings = Vec::new();
        let mut idx = leaf_index;
        
        for level in 0..self.nodes.len() - 1 {
            let sibling_idx = idx ^ 1; // XOR with 1 to get sibling
            if sibling_idx < self.nodes[level].len() {
                siblings.push(self.nodes[level][sibling_idx]);
            } else {
                siblings.push([0u8; 32]);
            }
            idx /= 2;
        }
        
        Some(MerkleProof {
            leaf_index,
            siblings,
        })
    }
    
    /// Verify Merkle proof
    #[allow(dead_code)]
    pub fn verify(root: &[u8; 32], leaf: &[u8; 32], proof: &MerkleProof) -> bool {
        let mut current = *leaf;
        let mut idx = proof.leaf_index;
        
        for sibling in &proof.siblings {
            current = if idx % 2 == 0 {
                Self::hash_pair(&current, sibling)
            } else {
                Self::hash_pair(sibling, &current)
            };
            idx /= 2;
        }
        
        current == *root
    }
    
    /// Get number of leaves
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }
    
    /// Check if tree is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_merkle_tree_construction() {
        let leaves = vec![
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        ];
        
        let tree = MerkleTree::new(leaves.clone());
        assert_eq!(tree.len(), 4); // Padded to power of 2
        
        // Root should be deterministic
        let tree2 = MerkleTree::new(leaves);
        assert_eq!(tree.root(), tree2.root());
    }
    
    #[test]
    fn test_merkle_proof() {
        let leaves = vec![
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
        ];
        
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();
        
        // Prove and verify each leaf
        for i in 0..leaves.len() {
            let proof = tree.prove(i).unwrap();
            assert!(MerkleTree::verify(&root, &leaves[i], &proof));
        }
    }
    
    #[test]
    fn test_merkle_proof_invalid() {
        let leaves = vec![
            [1u8; 32],
            [2u8; 32],
        ];
        
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();
        let proof = tree.prove(0).unwrap();
        
        // Wrong leaf should fail verification
        let wrong_leaf = [99u8; 32];
        assert!(!MerkleTree::verify(&root, &wrong_leaf, &proof));
    }
}

