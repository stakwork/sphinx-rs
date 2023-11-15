use anyhow::{anyhow, Error, Result};
use rmp::{
    decode::{self, bytes::Bytes, RmpRead},
    encode::{self, buffer::ByteBuf, RmpWrite},
    Marker,
};

pub fn hello_world() {
    println!("Hello world!");
}

pub fn peek_byte(bytes: &mut Bytes, field_name: Option<&str>) -> Result<u8> {
    let mut temp = Bytes::new(bytes.remaining_slice());
    deserialize_field_name(&mut temp, field_name)?;
    let peek = temp.read_u8().map_err(Error::msg)?;
    Ok(peek)
}

pub fn peek_str_len(bytes: &mut Bytes) -> Result<usize> {
    let mut temp = Bytes::new(bytes.remaining_slice());
    let len =
        decode::read_str_len(&mut temp).map_err(|_| Error::msg("could not read str len"))? as usize;
    Ok(len)
}

fn null_marker_byte() -> u8 {
    Marker::Null.to_u8()
}

pub fn serialize_map_len(buff: &mut ByteBuf, len: u32) -> Result<()> {
    encode::write_map_len(buff, len).map_err(Error::msg)?;
    Ok(())
}

pub fn deserialize_map_len(bytes: &mut Bytes, expected_map_len: u32) -> Result<()> {
    let length =
        decode::read_map_len(bytes).map_err(|_| Error::msg("could not read map length"))?;
    if length != expected_map_len {
        Err(anyhow!("deserialize_map_len: unexpected map length"))
    } else {
        Ok(())
    }
}

pub fn serialize_array_len(buff: &mut ByteBuf, len: u32) -> Result<()> {
    encode::write_array_len(buff, len).map_err(Error::msg)?;
    Ok(())
}

pub fn deserialize_array_len(bytes: &mut Bytes) -> Result<u32> {
    let length =
        decode::read_array_len(bytes).map_err(|_| Error::msg("could not read map length"))?;
    Ok(length)
}

pub fn serialize_field_name(buff: &mut ByteBuf, field_name: Option<&str>) -> Result<()> {
    if let Some(name) = field_name {
        encode::write_str(buff, name).map_err(Error::msg)?;
    }
    Ok(())
}

pub fn deserialize_field_name(bytes: &mut Bytes, field_name: Option<&str>) -> Result<()> {
    if let Some(name) = field_name {
        let field_name_read = deserialize_raw_string(bytes)?;
        if field_name_read != name {
            return Err(anyhow!("deserialize_field_name: unexpected field name"));
        }
    }
    Ok(())
}

pub fn serialize_variant(buff: &mut ByteBuf, variant_name: &str) -> Result<()> {
    encode::write_str(buff, variant_name).map_err(Error::msg)?;
    Ok(())
}

pub fn deserialize_variant(bytes: &mut Bytes) -> Result<String> {
    let object = deserialize_raw_string(bytes)?;
    Ok(object)
}

pub fn serialize_string(buff: &mut ByteBuf, field_name: Option<&str>, object: &str) -> Result<()> {
    serialize_field_name(buff, field_name)?;
    encode::write_str(buff, object).map_err(Error::msg)?;
    Ok(())
}

pub fn deserialize_string(bytes: &mut Bytes, field_name: Option<&str>) -> Result<String> {
    deserialize_field_name(bytes, field_name)?;
    let object = deserialize_raw_string(bytes)?;
    Ok(object)
}

fn deserialize_raw_string(bytes: &mut Bytes) -> Result<String> {
    let len = peek_str_len(bytes)?;
    let mut buff = vec![0u8; len];
    let object = decode::read_str(bytes, &mut buff)
        .map_err(|_| Error::msg("could not read str"))?
        .to_string();
    Ok(object)
}

pub fn serialize_string_vec(
    buff: &mut ByteBuf,
    field_name: Option<&str>,
    object: &Vec<String>,
) -> Result<()> {
    serialize_field_name(buff, field_name)?;
    encode::write_array_len(buff, object.len() as u32).map_err(Error::msg)?;
    for e in object {
        encode::write_str(buff, e).map_err(Error::msg)?;
    }
    Ok(())
}

pub fn deserialize_string_vec(bytes: &mut Bytes, field_name: Option<&str>) -> Result<Vec<String>> {
    deserialize_field_name(bytes, field_name)?;
    let length =
        decode::read_array_len(bytes).map_err(|_| Error::msg("could not read array length"))?;
    let mut list: Vec<String> = Vec::with_capacity(length as usize);
    for _ in 0..length {
        let e = deserialize_raw_string(bytes)?;
        list.push(e);
    }
    Ok(list)
}

pub fn serialize_uint(buff: &mut ByteBuf, field_name: Option<&str>, object: u64) -> Result<()> {
    serialize_field_name(buff, field_name)?;
    encode::write_uint(buff, object).map_err(Error::msg)?;
    Ok(())
}

pub fn deserialize_uint(bytes: &mut Bytes, field_name: Option<&str>) -> Result<u64> {
    deserialize_field_name(bytes, field_name)?;
    let object = decode::read_int(bytes).map_err(|_| Error::msg("could not read uint"))?;
    Ok(object)
}

pub fn serialize_bin(buff: &mut ByteBuf, field_name: Option<&str>, object: &[u8]) -> Result<()> {
    serialize_field_name(buff, field_name)?;
    encode::write_bin(buff, object).map_err(Error::msg)?;
    Ok(())
}

pub fn deserialize_bin(
    bytes: &mut Bytes,
    field_name: Option<&str>,
    expected_bin_len: u32,
) -> Result<Vec<u8>> {
    deserialize_field_name(bytes, field_name)?;
    let length =
        decode::read_bin_len(bytes).map_err(|_| Error::msg("could not read bin length"))?;
    if length != expected_bin_len {
        return Err(anyhow!("deserialize_bin: unexpected binary length"));
    }
    let mut binary = vec![0u8; length as usize];
    bytes.read_exact_buf(&mut binary).map_err(Error::msg)?;
    Ok(binary)
}

pub fn peek_is_none(bytes: &mut Bytes, field_name: Option<&str>) -> Result<bool> {
    Ok(peek_byte(bytes, field_name)? == null_marker_byte())
}

pub fn serialize_none(buff: &mut ByteBuf, field_name: Option<&str>) -> Result<()> {
    serialize_field_name(buff, field_name)?;
    buff.write_u8(Marker::Null.to_u8()).map_err(Error::msg)?;
    Ok(())
}

pub fn deserialize_none(bytes: &mut Bytes, field_name: Option<&str>) -> Result<()> {
    deserialize_field_name(bytes, field_name)?;
    let byte = bytes.read_u8().map_err(Error::msg)?;
    if byte == null_marker_byte() {
        Ok(())
    } else {
        Err(anyhow!(
            "deserialize_none: byte is not the null marker byte"
        ))
    }
}
