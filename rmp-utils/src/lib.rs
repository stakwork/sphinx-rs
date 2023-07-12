use std::collections::BTreeMap;

pub fn serialize_vec(v: &Vec<(String, (u64, Vec<u8>))>) -> Vec<u8> {
    let mut buff = rmp::encode::buffer::ByteBuf::new();
    rmp::encode::write_array_len(&mut buff, v.len() as u32).unwrap();
    v.iter().for_each(|(x, (y, z))| {
        rmp::encode::write_array_len(&mut buff, 2).unwrap();
        rmp::encode::write_str(&mut buff, x).unwrap();
        rmp::encode::write_array_len(&mut buff, 2).unwrap();
        rmp::encode::write_uint(&mut buff, *y).unwrap();
        rmp::encode::write_array_len(&mut buff, z.len() as u32).unwrap();
        z.iter().for_each(|x| {
            rmp::encode::write_uint(&mut buff, *x as u64).unwrap();
        });
    });
    buff.into_vec()
}

pub fn serialize_map(map: &BTreeMap<String, (u64, Vec<u8>)>) -> Vec<u8> {
    let mut buff = rmp::encode::buffer::ByteBuf::new();
    rmp::encode::write_map_len(&mut buff, map.len() as u32).unwrap();
    map.iter().for_each(|(x, (y, z))| {
        rmp::encode::write_str(&mut buff, x).unwrap();
        rmp::encode::write_array_len(&mut buff, 2).unwrap();
        rmp::encode::write_uint(&mut buff, *y).unwrap();
        rmp::encode::write_array_len(&mut buff, z.len() as u32).unwrap();
        z.iter().for_each(|x| {
            rmp::encode::write_uint(&mut buff, *x as u64).unwrap();
        });
    });
    buff.into_vec()
}

#[test]
fn vector_serialize_test() {
    let test = vec![
        ("aaaa".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
        ("bbbb".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
        ("cccc".to_string(), (15, vec![u8::MAX, u8::MAX, u8::MAX])),
    ];
    let buff = serialize_vec(&test);
    let reference = rmp_serde::to_vec(&test).unwrap();
    // Test bytes equality
    assert_eq!(reference, buff);
    // Deserialize, and check both objects are the same
    let result: Vec<(String, (u64, Vec<u8>))> = rmp_serde::from_slice(buff.as_slice()).unwrap();
    assert_eq!(test, result);
}

#[test]
fn btree_serialize_test() {
    let mut test = BTreeMap::new();
    test.insert("aaaa".to_string(), (0, vec![u8::MAX, u8::MAX, u8::MAX]));
    test.insert("bbbb".to_string(), (0, vec![u8::MAX, u8::MAX, u8::MAX]));
    test.insert("cccc".to_string(), (0, vec![u8::MAX, u8::MAX, u8::MAX]));
    let buff = serialize_map(&test);
    let reference = rmp_serde::to_vec(&test).unwrap();
    // Test bytes equality
    assert_eq!(reference, buff);
    // Deserialize, and check both objects are the same
    let result: BTreeMap<String, (u64, Vec<u8>)> = rmp_serde::from_slice(buff.as_slice()).unwrap();
    assert_eq!(test, result);
}
