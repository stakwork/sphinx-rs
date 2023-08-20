use rmp_utils::deserialize_simple_state_map;

fn main() {
    // Bytes taken from https://github.com/stakwork/sphinx-ios/issues/256
    let x = [
        129, 165, 77, 83, 71, 95, 49, 196, 56, 129, 164, 73, 110, 105, 116, 129, 173, 115, 101,
        114, 118, 101, 114, 95, 112, 117, 98, 107, 101, 121, 196, 33, 2, 116, 210, 87, 213, 129, 0,
        4, 177, 77, 39, 94, 32, 210, 198, 74, 84, 30, 183, 174, 1, 133, 51, 137, 69, 135, 160, 29,
        77, 74, 218, 206, 233,
    ];
    let y = deserialize_simple_state_map(&x);
    println!("{:?}", y);
}
