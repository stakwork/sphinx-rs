use lss_connector::msgs::*;
//use rmp_serde::encode::Error;
/*
use rand::{
    distributions::{Alphanumeric, DistString},
    Rng,
};
use vls_protocol_signer::lightning_signer::persist::Mutations;
*/

fn main() {
    //let mut std_rng = rand::thread_rng();

    let init = Msg::Init(Init {
        server_pubkey: [0u8; 33],
    });

    let _z = init.to_vec();

    /*
        let auth_token = vec![
            3, 1, 5, 6, 7, 3, 3, 2, 1, 5, 1, 2, 3, 4, 6, 1, 2, 3, 4, 5, 1, 2, 4, 5, 6, 7, 3, 4, 2, 1,
            3, 4,
        ];
        //println!("len: {}", auth_token.len());

        let init_response = Response::Init(InitResponse {
            client_id: [0u8; 33],
            auth_token,
            nonce: Some([0u8; 32]),
        });
        let _ = init_response.to_vec();

        let _z: Mutations = Mutations::from_vec(
            (0..std_rng.gen_range(100..200))
                .map(|_| {
                    (
                        Alphanumeric.sample_string(&mut rand::thread_rng(), std_rng.gen_range(10..20)),
                        (std_rng.gen(), vec![std_rng.gen(); std_rng.gen_range(0..10)]),
                    )
                })
                .collect(),
        );

    */
    //println!("{:?}", z);
}
