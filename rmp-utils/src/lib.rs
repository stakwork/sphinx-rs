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

pub mod blocks;
pub use blocks::*;
pub use rmp::decode::bytes::Bytes;
pub use rmp::encode::buffer::ByteBuf;

const TRACE: bool = false;

pub fn serialize_state_vec(
    buff: &mut encode::buffer::ByteBuf,
    field_name: Option<&str>,
    v: &Vec<(String, (u64, Vec<u8>))>,
) -> Result<()> {
    if TRACE {
        log::info!("serialize_state_vec: start");
    }
    blocks::serialize_field_name(buff, field_name)?;
    encode::write_array_len(buff, v.len() as u32).map_err(Error::msg)?;
    for (x, (y, z)) in v {
        encode::write_array_len(buff, 2).map_err(Error::msg)?;
        serialize_state_element(buff, x, y, z)?;
    }
    if TRACE {
        log::info!("serialize_state_vec: end");
    }
    Ok(())
}

pub fn serialize_velocity(vel: &(u64, Vec<u64>)) -> Result<Vec<u8>> {
    let mut buff = encode::buffer::ByteBuf::new();
    encode::write_array_len(&mut buff, 2).map_err(Error::msg)?;
    encode::write_u64(&mut buff, vel.0).map_err(Error::msg)?;
    encode::write_array_len(&mut buff, vel.1.len() as u32).map_err(Error::msg)?;
    for payment in vel.1.iter() {
        encode::write_u64(&mut buff, *payment).map_err(Error::msg)?;
    }
    Ok(buff.into_vec())
}

#[allow(clippy::type_complexity)]
pub fn deserialize_state_vec(
    bytes: &mut decode::bytes::Bytes,
    field_name: Option<&str>,
) -> Result<Vec<(String, (u64, Vec<u8>))>> {
    if TRACE {
        log::info!("deserialize_state_vec: start");
    }
    blocks::deserialize_field_name(bytes, field_name)?;
    let length =
        decode::read_array_len(bytes).map_err(|_| Error::msg("could not read array length"))?;
    let mut object: Vec<(String, (u64, Vec<u8>))> = Vec::with_capacity(length as usize);
    for _ in 0..length {
        let _ =
            decode::read_array_len(bytes).map_err(|_| Error::msg("could not read array length"))?;
        let (x, (y, z)) = deserialize_state_element(bytes)?;
        object.push((x, (y, z)));
    }
    if TRACE {
        log::info!("deserialize_state_vec: end");
    }
    Ok(object)
}

pub fn deserialize_velocity(b: &[u8]) -> Result<(u64, Vec<u64>)> {
    let mut bytes = decode::bytes::Bytes::new(b);
    let _ = decode::read_array_len(&mut bytes)
        .map_err(|_| Error::msg("could not read array length"))?;
    let bucket = decode::read_u64(&mut bytes).map_err(|_| Error::msg("could not read u64"))?;
    let len = decode::read_array_len(&mut bytes)
        .map_err(|_| Error::msg("could not read array length"))?;
    let mut pmts: Vec<u64> = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let x = decode::read_u64(&mut bytes).map_err(|_| Error::msg("could not read u64"))?;
        pmts.push(x);
    }
    Ok((bucket, pmts))
}

pub fn serialize_state_map(map: &BTreeMap<String, (u64, Vec<u8>)>) -> Result<Vec<u8>> {
    if TRACE {
        log::info!("serialize_state_map: start");
    }
    let mut buff = encode::buffer::ByteBuf::new();
    encode::write_map_len(&mut buff, map.len() as u32).map_err(Error::msg)?;
    for (x, (y, z)) in map {
        serialize_state_element(&mut buff, x, y, z)?;
    }
    if TRACE {
        log::info!("serialize_state_map: end");
    }
    Ok(buff.into_vec())
}

pub fn serialize_simple_state_map(map: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    let mut buff = encode::buffer::ByteBuf::new();
    encode::write_map_len(&mut buff, map.len() as u32).map_err(Error::msg)?;
    for (x, z) in map {
        serialize_simple_state_element(&mut buff, x, z)?;
    }
    Ok(buff.into_vec())
}

pub fn deserialize_state_map(b: &[u8]) -> Result<BTreeMap<String, (u64, Vec<u8>)>> {
    if TRACE {
        log::info!("deserialize_state_map: start");
    }
    let mut bytes = decode::bytes::Bytes::new(b);
    let length =
        decode::read_map_len(&mut bytes).map_err(|_| Error::msg("could not read map length"))?;
    let mut object: BTreeMap<String, (u64, Vec<u8>)> = BTreeMap::new();
    for _ in 0..length {
        let (x, (y, z)) = deserialize_state_element(&mut bytes)?;
        object.insert(x, (y, z));
    }
    if TRACE {
        log::info!("deserialize_state_map: end");
    }
    Ok(object)
}

pub fn deserialize_simple_state_map(b: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut bytes = decode::bytes::Bytes::new(b);
    let length =
        decode::read_map_len(&mut bytes).map_err(|_| Error::msg("could not read map length"))?;
    let mut object: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for _ in 0..length {
        let (x, z) = deserialize_simple_state_element(&mut bytes)?;
        object.insert(x, z);
    }
    Ok(object)
}

fn serialize_state_element(
    buff: &mut encode::buffer::ByteBuf,
    x: &str,
    y: &u64,
    z: &[u8],
) -> Result<()> {
    if TRACE {
        log::info!("serialize_state_element: start");
    }
    encode::write_str(buff, x).map_err(Error::msg)?;
    encode::write_array_len(buff, 2).map_err(Error::msg)?;
    encode::write_uint(buff, *y).map_err(Error::msg)?;
    encode::write_bin(buff, z).map_err(Error::msg)?;
    if TRACE {
        log::info!("serialize_state_element: end");
    }
    Ok(())
}

fn serialize_simple_state_element(
    buff: &mut encode::buffer::ByteBuf,
    x: &str,
    z: &[u8],
) -> Result<()> {
    encode::write_str(buff, x).map_err(Error::msg)?;
    encode::write_bin(buff, z).map_err(Error::msg)?;
    Ok(())
}

fn deserialize_state_element(bytes: &mut decode::bytes::Bytes) -> Result<(String, (u64, Vec<u8>))> {
    if TRACE {
        log::info!("deserialize_state_element: start");
    }
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
    if TRACE {
        log::info!("deserialize_state_element: Vec<u8> of size {}", length);
    }
    let mut z: Vec<u8> = vec![0u8; length as usize];
    bytes.read_exact_buf(&mut z).map_err(Error::msg)?;
    if TRACE {
        log::info!("deserialize_state_element: end");
    }
    Ok((x, (y, z)))
}

fn deserialize_simple_state_element(bytes: &mut decode::bytes::Bytes) -> Result<(String, Vec<u8>)> {
    let mut temp = decode::bytes::Bytes::new(bytes.remaining_slice());
    let length =
        decode::read_str_len(&mut temp).map_err(|_| Error::msg("could not read str length"))?;
    let mut buff = vec![0u8; length as usize];
    decode::read_str(bytes, &mut buff).map_err(|_| Error::msg("could not read str"))?;
    let x = String::from_utf8(buff).map_err(Error::msg)?;
    let length =
        decode::read_bin_len(bytes).map_err(|_| Error::msg("could not read bin length"))?;
    let mut z: Vec<u8> = vec![0u8; length as usize];
    bytes.read_exact_buf(&mut z).map_err(Error::msg)?;
    Ok((x, z))
}

#[test]
fn state_vec_serde() {
    let test = vec![
        ("aaaa".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
        ("bbbb".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
        ("cccc".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
    ];
    let mut buff = encode::buffer::ByteBuf::new();
    serialize_state_vec(&mut buff, None, &test).unwrap();
    let mut bytes = decode::bytes::Bytes::new(buff.as_slice());
    let object = deserialize_state_vec(&mut bytes, None).unwrap();
    assert_eq!(test, object);

    let test = Vec::new();
    let mut buff = encode::buffer::ByteBuf::new();
    serialize_state_vec(&mut buff, None, &test).unwrap();
    let mut bytes = decode::bytes::Bytes::new(buff.as_slice());
    let object = deserialize_state_vec(&mut bytes, None).unwrap();
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

#[test]
fn ser_velocity_test() {
    let vel = (1, vec![123, 456, 789]);
    let bytes = serialize_velocity(&vel).unwrap();
    let vel2 = deserialize_velocity(&bytes).unwrap();
    assert_eq!(vel, vel2);
}
