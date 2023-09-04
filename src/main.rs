
use crc::*;
use primitive_types::H256;
use hex_literal::hex;
use std::convert::TryInto;


/* 
thanks to RETH
https://github.com/paradigmxyz/reth/blob/dba6b24bde655bccc87a7b69ea9f53b2a4a58e13/crates/primitives/src/forkid.rs
 */

const CRC_32_IEEE: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

fn calculate_fork_hash(fork_blocks: &[u64]) -> Vec<u8> {

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
    prev_fork_hash.to_vec()
}

/*fn vec_to_array(input: Vec<u8>) -> Result<[u8; 4], String> {
    input.try_into()
        .map_err(|v: Vec<u8>| format!("Expected a Vec of length 4 but it was {}", v.len()))
}*/


fn main() {
    // List of block numbers for BSC mainnet hard forks
    let ethereum_fork_blocks: &[u64] = &[
        // BSC HARDFORKS
        5184000,
    ];

    let fork_hash = calculate_fork_hash(ethereum_fork_blocks);
    println!("ForkId {{ hash: ForkHash({:?}), next: 13082000u64}},", fork_hash);

    let ethereum_fork_blocks: &[u64] = &[
        // BSC HARDFORKS
        5184000,
        13082000,
    ];

    let fork_hash = calculate_fork_hash(ethereum_fork_blocks);
    println!("ForkId {{ hash: ForkHash({:?}), next: 18907621u64}},", fork_hash);

    let ethereum_fork_blocks: &[u64] = &[
        // BSC HARDFORKS
        5184000,
        13082000,
        18907621,
    ];

    let fork_hash = calculate_fork_hash(ethereum_fork_blocks);
    println!("ForkId {{ hash: ForkHash({:?}), next: 21962149u64}},", fork_hash);
    let ethereum_fork_blocks: &[u64] = &[
        // BSC HARDFORKS
        5184000,
        13082000,
        18907621,
        21962149,
    ];

    let fork_hash = calculate_fork_hash(ethereum_fork_blocks);
    println!("ForkId {{ hash: ForkHash({:?}), next: 22107423u64}},", fork_hash);

    let ethereum_fork_blocks: &[u64] = &[
        // BSC HARDFORKS
        5184000,
        13082000,
        18907621,
        21962149,
        22107423,
    ];

    let fork_hash = calculate_fork_hash(ethereum_fork_blocks);
    println!("ForkId {{ hash: ForkHash({:?}), next: 23846001u64}},", fork_hash);

    let ethereum_fork_blocks: &[u64] = &[
        // BSC HARDFORKS
        5184000,
        13082000,
        18907621,
        21962149,
        22107423,
        23846001,
    ];

    let fork_hash = calculate_fork_hash(ethereum_fork_blocks);
    println!("ForkId {{ hash: ForkHash({:?}), next: 27281024u64}},", fork_hash);

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
    println!("ForkId {{ hash: ForkHash({:?}), next: 29020050u64}},", fork_hash);

    let ethereum_fork_blocks: &[u64] = &[
        // BSC HARDFORKS
        5184000,
        13082000,
        18907621,
        21962149,
        22107423,
        23846001,
        27281024,
        29020050,
    ];

    let fork_hash = calculate_fork_hash(ethereum_fork_blocks);
    println!("ForkId {{ hash: ForkHash({:?}), next: 30720096u64}},", fork_hash);

    let ethereum_fork_blocks: &[u64] = &[
        // BSC HARDFORKS
        5184000,
        13082000,
        18907621,
        21962149,
        22107423,
        23846001,
        27281024,
        29020050,
        30720096,
    ];

    let fork_hash = calculate_fork_hash(ethereum_fork_blocks);
    println!("ForkId {{ hash: ForkHash({:?}), next: 31302048u64}},", fork_hash);

    /*
    let fork_hex = u32::from_be_bytes(vec_to_array(fork_hash.clone()).unwrap());
    println!("BSC fork hash hex: {:08x}", fork_hex);

    [249, 141, 16, 114]
    BSC fork hash: f98d1072
    */
    let ethereum_fork_blocks: &[u64] = &[
        // BSC HARDFORKS
        5184000,
        13082000,
        18907621,
        21962149,
        22107423,
        23846001,
        27281024,
        29020050,
        30720096,
        31302048,
    ];

    let fork_hash = calculate_fork_hash(ethereum_fork_blocks);
    println!("ForkId {{ hash: ForkHash({:?}), next: 0u64}},", fork_hash);
    
}
