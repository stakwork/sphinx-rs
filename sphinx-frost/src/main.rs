use rand_chacha::ChaCha20Rng;
use schnorr_fun::{frost, Message};
use sha2::Sha256;
use std::ops::MulAssign;
use schnorr_fun::binonce::Nonce;
use secp256kfun::marker::Zero;

fn main() {
    let frost = frost::new_with_deterministic_nonces::<Sha256>();
    let mut rng = rand::thread_rng();
    let threshold = 2;

    // generate secret scalar polynomials we'll use in the key generation protocol
    let secret_poly_0 = frost::generate_scalar_poly(threshold, &mut rng);
    let public_poly_0 = frost::to_point_poly(&secret_poly_0);
    let secret_poly_1 = frost::generate_scalar_poly(threshold, &mut rng);
    let public_poly_1 = frost::to_point_poly(&secret_poly_1);
    let secret_poly_2 = frost::generate_scalar_poly(threshold, &mut rng);
    let public_poly_2 = frost::to_point_poly(&secret_poly_2);
    // share our public point poly, and receive the point polys from other participants
    let public_polys = vec![public_poly_0, public_poly_1, public_poly_2];

    // generate secret shares for others and proof-of-possession to protect against rogue key attacks.
    // ⚠ these shares and pops need to be shared encrypted
    let keygen = frost
        .new_keygen(public_polys)
        .expect("something wrong with what was provided by other parties");
    let (shares_0, pop_0) = frost.create_shares(&keygen, secret_poly_0);
    let (shares_1, pop_1) = frost.create_shares(&keygen, secret_poly_1);
    let (shares_2, pop_2) = frost.create_shares(&keygen, secret_poly_2);

    let received_shares_0 = vec![
        shares_0[0].clone(),
        shares_1[0].clone(),
        shares_2[0].clone(),
    ];
    let received_shares_2 = vec![
        shares_0[2].clone(),
        shares_1[2].clone(),
        shares_2[2].clone(),
    ];

    let proofs_of_possession_0 = vec![pop_0.clone(), pop_1.clone(), pop_2.clone()];
    let proofs_of_possession_2 = vec![pop_0, pop_1, pop_2];

    // finish keygen by verifying the shares we received, verifying all proofs-of-possession,
    // and calculate our long-lived secret share of the joint FROST key.
    let (secret_share_0, frost_key) = frost
        .finish_keygen(keygen.clone(), 0, received_shares_0, proofs_of_possession_0)
        .expect("finish_keygen failed");
    let (secret_share_2, _) = frost
        .finish_keygen(keygen, 2, received_shares_2, proofs_of_possession_2)
        .expect("finish_keygen failed");

    // we're ready to do some signing, so convert to xonly key
    let frost_key = frost_key.into_xonly_key();

    // ⚠ session_id must be different for every signing attempt
    let message = Message::plain("my-app", b"chancellor on brink of second bailout for banks");
    let session_id = b"signing-ominous-message-about-banks-attempt-1".as_slice();

    // generate public nonces for this signing session.
    let mut nonce_rng: ChaCha20Rng = frost.seed_nonce_rng(&frost_key, &secret_share_0, session_id);
    let nonce_0 = frost.gen_nonce(&mut nonce_rng);
    let mut nonce_rng: ChaCha20Rng = frost.seed_nonce_rng(&frost_key, &secret_share_2, session_id);
    let nonce_2 = frost.gen_nonce(&mut nonce_rng);

    // share the public nonces with the other signing participant(s)
    // receive public nonces from other signers
    let nonces = vec![(0, nonce_0.public()), (2, nonce_2.public())];

    let nonce_a = nonce_0.clone();
    let nonce_b = nonce_2.clone();
    let a_secret = nonce_a.secret();
    let b_secret = nonce_b.secret();
    let mut a_scalar = a_secret[0].clone();
    let b_scalar = b_secret[0].clone();

    a_scalar.mul_assign(b_scalar);

    //nonce_0.secret()[0].mul_assign(nonce_2.secret()[0]);

    // start a sign session with these nonces for a message
    let session = frost.start_sign_session(&frost_key, nonces.clone(), message);

    let x = session.agg_nonce;
    let y = x.to_bytes();

    let mut z = [0u8; 66];
    for i in 0..66 {
        z[i] = y[i%33];
    }
    Nonce::<Zero>::from_bytes(z);

    // create a partial signature using our secret share and secret nonce
    let sig_0 = frost.sign(&frost_key, &session, 0, &secret_share_0, nonce_0);
    let sig_2 = frost.sign(&frost_key, &session, 2, &secret_share_2, nonce_2);

    // receive the partial signature(s) from the other participant(s) and verify
    assert!(frost.verify_signature_share(&frost_key, &session, 2, sig_2));
    // combine signature shares into a single signature that is valid under the FROST key
    let combined_sig = frost.combine_signature_shares(&frost_key, &session, vec![sig_0, sig_2]);
    assert!(frost
        .schnorr
        .verify(&frost_key.public_key(), message, &combined_sig));
}
