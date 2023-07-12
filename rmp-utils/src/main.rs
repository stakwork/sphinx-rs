use std::collections::BTreeMap;

fn main() {
}

#[test]
fn vector_serialize_test() {
    let test = vec![
        ("aaaa", (15, vec![u8::MAX, u8::MAX, u8::MAX])),
        ("bbbb", (15, vec![u8::MAX, u8::MAX, u8::MAX])),
        ("cccc", (15, vec![u8::MAX, u8::MAX, u8::MAX])),
    ];
    let mut buff = rmp::encode::buffer::ByteBuf::new();
    rmp::encode::write_array_len(&mut buff, test.len() as u32).unwrap();
    test.iter().for_each(|(x, (y, z))| {
        rmp::encode::write_array_len(&mut buff, 2).unwrap();
        rmp::encode::write_str(&mut buff, x).unwrap();
        rmp::encode::write_array_len(&mut buff, 2).unwrap();
        rmp::encode::write_uint(&mut buff, *y).unwrap();
        rmp::encode::write_array_len(&mut buff, z.len() as u32).unwrap();
        z.iter().for_each(|x| {
            rmp::encode::write_uint(&mut buff, *x as u64).unwrap();
        });
    });
    let reference = rmp_serde::to_vec(&test).unwrap();
    // Test bytes equality
    assert_eq!(reference, *buff.as_vec());
    // Deserialize, and check both objects are the same
    let result: Vec<(&str, (u64, Vec<u8>))> = rmp_serde::from_slice(buff.as_slice()).unwrap();
    assert_eq!(test, result);
}

#[test]
fn btree_serialize_test() {
    let mut test = BTreeMap::new();
    test.insert("aaaa", (0, vec![u8::MAX, u8::MAX, u8::MAX]));
    test.insert("bbbb", (0, vec![u8::MAX, u8::MAX, u8::MAX]));
    test.insert("cccc", (0, vec![u8::MAX, u8::MAX, u8::MAX]));
    let mut buff = rmp::encode::buffer::ByteBuf::new();
    rmp::encode::write_map_len(&mut buff, test.len() as u32).unwrap();
    test.iter().for_each(|(x, (y, z))| {
        rmp::encode::write_str(&mut buff, x).unwrap();
        rmp::encode::write_array_len(&mut buff, 2).unwrap();
        rmp::encode::write_uint(&mut buff, *y).unwrap();
        rmp::encode::write_array_len(&mut buff, z.len() as u32).unwrap();
        z.iter().for_each(|x| {
            rmp::encode::write_uint(&mut buff, *x as u64).unwrap();
        });
    });
    let reference = rmp_serde::to_vec(&test).unwrap();
    // Test bytes equality
    assert_eq!(reference, *buff.as_vec());
    // Deserialize, and check both objects are the same
    let result: BTreeMap<&str, (u64, Vec<u8>)> = rmp_serde::from_slice(buff.as_slice()).unwrap();
    assert_eq!(test, result);
}
