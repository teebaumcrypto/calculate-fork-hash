
use crc::*;
use primitive_types::H256;
use hex_literal::hex;

/* 
thanks to RETH
https://github.com/paradigmxyz/reth/blob/dba6b24bde655bccc87a7b69ea9f53b2a4a58e13/crates/primitives/src/forkid.rs
 */

const CRC_32_IEEE: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

fn calculate_fork_hash(fork_blocks: &[u64]) -> u32 {

    const GENESIS_HASH: H256 = H256(hex!("0d21840abff46b96c84b2ac9e10e4f5cdaeb5693cb665db62a2f3b02d2d57b5b"));
     
    let mut prev_fork_hash = CRC_32_IEEE.checksum(&GENESIS_HASH[..]).to_be_bytes();


    for block_number in fork_blocks {
        let blob = block_number.to_be_bytes();
        let digest = CRC_32_IEEE.digest_with_initial(u32::from_be_bytes(prev_fork_hash));
        let value = digest.finalize();
        let mut digest = CRC_32_IEEE.digest_with_initial(value);
        digest.update(&blob);
        prev_fork_hash = digest.finalize().to_be_bytes();

    }
    println!("{:?}",prev_fork_hash);

    u32::from_be_bytes(prev_fork_hash)
}


fn main() {
    // List of block numbers for Ethereum mainnet hard forks
    // List of block numbers for Ethereum custom hard forks
    let ethereum_fork_blocks: &[u64] = &[
        // BSC HARDFORKS
        5184000,
        13082000,
        18907621,
        21962149,
        22107423,
        23846001,
        27281024,
    ];

    let fork_hash = calculate_fork_hash(ethereum_fork_blocks);
    println!("BSC fork hash: {:08x}", fork_hash);
    /*
    [249, 141, 16, 114]
    BSC fork hash: f98d1072
 */
}
