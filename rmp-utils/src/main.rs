use std::collections::BTreeMap;

fn main() {
    // A &str
    //println!("&str test");
    let test = "Hello world";
    let mut buff = rmp::encode::buffer::ByteBuf::new();
    rmp::encode::write_str(&mut buff, test).unwrap();
    let result: &str = rmp_serde::from_slice(buff.as_slice()).unwrap();
    println!("{}", test == result);

    // A Vec<u8>
    //println!("Vec<u8> test");
    let test = vec![0x01, 0x02, 0x03];
    let mut buff = rmp::encode::buffer::ByteBuf::new();
    rmp::encode::write_bin(&mut buff, &test).unwrap();
    let result: &[u8] = rmp_serde::from_slice(buff.as_slice()).unwrap();
    println!("{}", test == result);

    // A (u64, &[u8])
    //println!("(u64, &[u8]) test");
    let test = (
        u64::MAX,
        &vec![
            u8::MAX,
            u8::MAX - 1,
            u8::MAX - 2,
            u8::MAX - 3,
            u8::MAX - 4,
            u8::MAX - 5,
        ][..],
    );
    let mut buff = rmp::encode::buffer::ByteBuf::new();
    rmp::encode::write_array_len(&mut buff, 2).unwrap();
    rmp::encode::write_u64(&mut buff, test.0).unwrap();
    rmp::encode::write_bin(&mut buff, &test.1).unwrap();
    let result: (u64, &[u8]) = rmp_serde::from_slice(buff.as_slice()).unwrap();
    println!("{}", test == result);

    // A Vec<(&str, (u64, Vec<u8>))>
    //println!("Vec<(&str, (u64, Vec<u8>))> test");
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
    println!("{}", reference == *buff.as_vec());
    // Deserialize, and check both objects are the same
    let result: Vec<(&str, (u64, Vec<u8>))> = rmp_serde::from_slice(buff.as_slice()).unwrap();
    println!("{}", test == result);

    let mut test = BTreeMap::new();
    //println!("BTreeMap<&str, (u64, Vec<u8>)> test");
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
    println!("{}", reference == *buff.as_vec());
    // Deserialize, and check both objects are the same
    let result: BTreeMap<&str, (u64, Vec<u8>)> = rmp_serde::from_slice(buff.as_slice()).unwrap();
    println!("{}", test == result);
}
