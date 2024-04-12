#![allow(unused)]
use ethers_core::types::H256;
use revm_primitives::B256;
use std::fs::File;
use std::io::Write;

pub fn write_to_file(file_name: &str, content: String) -> Result<(), std::io::Error> {
    // Create the file (will overwrite if it exists)
    let mut file = File::create(file_name)?;
    // Write the data to the file
    file.write_all(content.as_bytes())?;
    Ok(())
}

pub fn decode_hex(data: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(data)
}

pub fn convert_hash(hash: B256) -> H256 {
    H256::from_slice(hash.as_slice())
}

pub fn from_hash(hash: H256) -> B256 {
    B256::from_slice(hash.as_bytes())
}
