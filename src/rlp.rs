//! Minimal RLP encoder (Ethereum Yellow Paper, appendix B).
//!
//! Only encoding is needed: for CREATE addresses, state/storage trie nodes and
//! the logs hash checked by `ethereum/tests`.

use crate::u256::U256;

fn length_prefix(len: usize, short_base: u8, long_base: u8, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(short_base + len as u8);
    } else {
        let be = (len as u64).to_be_bytes();
        let skip = be.iter().take_while(|&&b| b == 0).count();
        out.push(long_base + (8 - skip) as u8);
        out.extend_from_slice(&be[skip..]);
    }
}

/// Encodes a byte string.
pub fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return vec![bytes[0]];
    }
    let mut out = Vec::with_capacity(bytes.len() + 9);
    length_prefix(bytes.len(), 0x80, 0xb7, &mut out);
    out.extend_from_slice(bytes);
    out
}

/// Encodes an unsigned integer as its minimal big-endian byte string.
pub fn encode_u256(v: U256) -> Vec<u8> {
    encode_bytes(&v.to_be_bytes_trimmed())
}

/// Encodes a `u64` as its minimal big-endian byte string.
pub fn encode_u64(v: u64) -> Vec<u8> {
    encode_u256(U256::from_u64(v))
}

/// Encodes a list whose items are already RLP-encoded.
pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: usize = items.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(payload + 9);
    length_prefix(payload, 0xc0, 0xf7, &mut out);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yellow_paper_examples() {
        assert_eq!(encode_bytes(b"dog"), vec![0x83, b'd', b'o', b'g']);
        assert_eq!(encode_bytes(b""), vec![0x80]);
        assert_eq!(encode_u64(0), vec![0x80]);
        assert_eq!(encode_u64(15), vec![0x0f]);
        assert_eq!(encode_u64(1024), vec![0x82, 0x04, 0x00]);
        assert_eq!(encode_list(&[]), vec![0xc0]);
        assert_eq!(
            encode_list(&[encode_bytes(b"cat"), encode_bytes(b"dog")]),
            vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );
        let long = vec![b'a'; 56];
        let enc = encode_bytes(&long);
        assert_eq!(&enc[..2], &[0xb8, 56]);
        let big_list = encode_list(&vec![encode_bytes(&[0x01]); 60]);
        assert_eq!(&big_list[..2], &[0xf8, 60]);
    }
}
