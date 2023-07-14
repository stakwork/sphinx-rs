extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use anyhow::Error;
use anyhow::Result;
use rmp::{
    decode::{self, RmpRead},
    encode,
};

pub fn serialize_state_vec(
    buff: &mut encode::buffer::ByteBuf,
    v: &Vec<(String, (u64, Vec<u8>))>,
) -> Result<()> {
    encode::write_array_len(buff, v.len() as u32).map_err(Error::msg)?;
    for (x, (y, z)) in v {
        encode::write_array_len(buff, 2).map_err(Error::msg)?;
        serialize_state_element(buff, x, y, z)?;
    }
    Ok(())
}

pub fn deserialize_state_vec(
    bytes: &mut decode::bytes::Bytes,
) -> Result<Vec<(String, (u64, Vec<u8>))>> {
    let length =
        decode::read_array_len(bytes).map_err(|_| Error::msg("could not read array length"))?;
    let mut object: Vec<(String, (u64, Vec<u8>))> = Vec::with_capacity(length as usize);
    for _ in 0..length {
        let _ =
            decode::read_array_len(bytes).map_err(|_| Error::msg("could not read array length"))?;
        let (x, (y, z)) = deserialize_state_element(bytes)?;
        object.push((x, (y, z)));
    }
    Ok(object)
}

pub fn serialize_state_map(map: &BTreeMap<String, (u64, Vec<u8>)>) -> Result<Vec<u8>> {
    let mut buff = encode::buffer::ByteBuf::new();
    encode::write_map_len(&mut buff, map.len() as u32).map_err(Error::msg)?;
    for (x, (y, z)) in map {
        serialize_state_element(&mut buff, x, y, z)?;
    }
    Ok(buff.into_vec())
}

pub fn deserialize_state_map(b: &[u8]) -> Result<BTreeMap<String, (u64, Vec<u8>)>> {
    let mut bytes = decode::bytes::Bytes::new(b);
    let length =
        decode::read_map_len(&mut bytes).map_err(|_| Error::msg("could not read map length"))?;
    let mut object: BTreeMap<String, (u64, Vec<u8>)> = BTreeMap::new();
    for _ in 0..length {
        let (x, (y, z)) = deserialize_state_element(&mut bytes)?;
        object.insert(x, (y, z));
    }
    Ok(object)
}

fn serialize_state_element(
    buff: &mut encode::buffer::ByteBuf,
    x: &String,
    y: &u64,
    z: &Vec<u8>,
) -> Result<()> {
    encode::write_str(buff, x).map_err(Error::msg)?;
    encode::write_array_len(buff, 2).map_err(Error::msg)?;
    encode::write_uint(buff, *y).map_err(Error::msg)?;
    encode::write_bin(buff, &z).map_err(Error::msg)?;
    Ok(())
}

fn deserialize_state_element(bytes: &mut decode::bytes::Bytes) -> Result<(String, (u64, Vec<u8>))> {
    let mut temp = decode::bytes::Bytes::new(bytes.remaining_slice());
    let length =
        decode::read_str_len(&mut temp).map_err(|_| Error::msg("could not read str length"))?;
    let mut buff = vec![0u8; length as usize];
    decode::read_str(bytes, &mut buff).map_err(|_| Error::msg("could not read str"))?;
    let x = String::from_utf8(buff).map_err(Error::msg)?;
    let _ = decode::read_array_len(bytes).map_err(|_| Error::msg("could not read array length"))?;
    let y: u64 = decode::read_int(bytes).map_err(Error::msg)?;
    let length =
        decode::read_bin_len(bytes).map_err(|_| Error::msg("could not read bin length"))?;
    let mut z: Vec<u8> = vec![0u8; length as usize];
    bytes.read_exact_buf(&mut z).map_err(Error::msg)?;
    Ok((x, (y, z)))
}

#[test]
fn state_vec_serde() {
    let test = vec![
        ("aaaa".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
        ("bbbb".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
        ("cccc".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
    ];
    let mut buff = encode::buffer::ByteBuf::new();
    serialize_state_vec(&mut buff, &test).unwrap();
    let mut bytes = decode::bytes::Bytes::new(buff.as_slice());
    let object = deserialize_state_vec(&mut bytes).unwrap();
    assert_eq!(test, object);
}

#[test]
fn state_map_serde() {
    let mut test = BTreeMap::new();
    test.insert("aaaa".to_string(), (0, vec![u8::MAX, u8::MAX, u8::MAX]));
    test.insert("bbbb".to_string(), (0, vec![u8::MAX, u8::MAX, u8::MAX]));
    test.insert("cccc".to_string(), (0, vec![u8::MAX, u8::MAX, u8::MAX]));
    let bytes = serialize_state_map(&test).unwrap();
    let object = deserialize_state_map(&bytes).unwrap();
    assert_eq!(test, object);
}
