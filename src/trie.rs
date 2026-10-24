//! Merkle-Patricia trie root computation (Yellow Paper, appendix D).
//!
//! The interpreter keeps state in hash maps; this module only computes the
//! root commitment so post-states can be compared against `ethereum/tests`.
//! The trie is built bottom-up from the sorted key set in one pass:
//! O(n · k) for n keys of k nibbles.

use crate::crypto::keccak256;
use crate::rlp;
use crate::types::B256;

/// Root of the empty trie: `keccak256(rlp(""))`.
pub const EMPTY_ROOT: B256 = B256([
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e, 0x5b, 0x48, 0xe0,
    0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
]);

fn to_nibbles(key: &[u8]) -> Vec<u8> {
    key.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect()
}

/// Hex-prefix encoding of a nibble path.
fn hex_prefix(nibbles: &[u8], leaf: bool) -> Vec<u8> {
    let flag = if leaf { 2 } else { 0 };
    let mut out = Vec::with_capacity(nibbles.len() / 2 + 1);
    let mut rest = nibbles;
    if nibbles.len() % 2 == 1 {
        out.push(((flag + 1) << 4) | nibbles[0]);
        rest = &nibbles[1..];
    } else {
        out.push(flag << 4);
    }
    for pair in rest.chunks_exact(2) {
        out.push((pair[0] << 4) | pair[1]);
    }
    out
}

/// Reference to a child node inside its parent: inline if short, else hashed.
fn node_ref(node_rlp: Vec<u8>) -> Vec<u8> {
    if node_rlp.len() < 32 {
        node_rlp
    } else {
        rlp::encode_bytes(&keccak256(&node_rlp).0)
    }
}

/// Builds the RLP of the node covering `items` (sorted, unique keys) at `depth`.
fn build(items: &[(Vec<u8>, Vec<u8>)], depth: usize) -> Vec<u8> {
    match items {
        [] => rlp::encode_bytes(&[]),
        [(key, value)] => {
            rlp::encode_list(&[rlp::encode_bytes(&hex_prefix(&key[depth..], true)), rlp::encode_bytes(value)])
        }
        _ => {
            let first = &items[0].0;
            let last = &items[items.len() - 1].0;
            let common = first[depth..].iter().zip(&last[depth..]).take_while(|(a, b)| a == b).count();
            if common > 0 {
                let child = build_branch(items, depth + common);
                rlp::encode_list(&[
                    rlp::encode_bytes(&hex_prefix(&first[depth..depth + common], false)),
                    node_ref(child),
                ])
            } else {
                build_branch(items, depth)
            }
        }
    }
}

fn build_branch(items: &[(Vec<u8>, Vec<u8>)], depth: usize) -> Vec<u8> {
    let mut children: Vec<Vec<u8>> = Vec::with_capacity(17);
    let mut start = 0;
    for nibble in 0u8..16 {
        let end = start + items[start..].iter().take_while(|(k, _)| k[depth] == nibble).count();
        if end == start {
            children.push(rlp::encode_bytes(&[]));
        } else {
            children.push(node_ref(build(&items[start..end], depth + 1)));
        }
        start = end;
    }
    // Keys all have equal length, so no value terminates at a branch.
    children.push(rlp::encode_bytes(&[]));
    rlp::encode_list(&children)
}

/// Computes the trie root of `(key, value)` pairs. Keys must be unique and of
/// equal length; empty values must be filtered out by the caller.
pub fn trie_root(pairs: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>) -> B256 {
    let mut items: Vec<(Vec<u8>, Vec<u8>)> = pairs.into_iter().map(|(k, v)| (to_nibbles(&k), v)).collect();
    if items.is_empty() {
        return EMPTY_ROOT;
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    keccak256(&build(&items, 0))
}

/// Root of a "secure" trie, where every key is first hashed with Keccak-256.
pub fn secure_trie_root(pairs: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>) -> B256 {
    trie_root(pairs.into_iter().map(|(k, v)| (keccak256(&k).0.to_vec(), v)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_matches_constant() {
        assert_eq!(keccak256(&rlp::encode_bytes(&[])), EMPTY_ROOT);
        assert_eq!(trie_root(Vec::new()), EMPTY_ROOT);
    }

    #[test]
    fn hex_prefix_encoding() {
        assert_eq!(hex_prefix(&[1, 2, 3, 4, 5], false), vec![0x11, 0x23, 0x45]);
        assert_eq!(hex_prefix(&[0, 1, 2, 3, 4, 5], false), vec![0x00, 0x01, 0x23, 0x45]);
        assert_eq!(hex_prefix(&[0, 15, 1, 12, 11, 8], true), vec![0x20, 0x0f, 0x1c, 0xb8]);
        assert_eq!(hex_prefix(&[15, 1, 12, 11, 8], true), vec![0x3f, 0x1c, 0xb8]);
    }

    #[test]
    fn known_small_trie() {
        // Classic example from the Ethereum wiki ("doe"/"dog"/"dogglesworth"
        // need variable-length keys, which we do not support); instead check
        // a single-pair trie against a hand-computed leaf.
        let root = trie_root(vec![(vec![0xab], b"x".to_vec())]);
        let leaf = rlp::encode_list(&[rlp::encode_bytes(&[0x20, 0xab]), rlp::encode_bytes(b"x")]);
        assert_eq!(root, keccak256(&leaf));
    }

    #[test]
    fn order_independent() {
        let a = vec![(vec![1, 2], vec![9]), (vec![1, 3], vec![8]), (vec![0x41, 0], vec![7])];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(trie_root(a), trie_root(b));
    }
}
