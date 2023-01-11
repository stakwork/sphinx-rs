use rand_chacha::ChaCha20Rng;
use schnorr_fun::fun::Scalar;
use schnorr_fun::{musig, Message};
use sha2::Sha256;

fn main() {
    let musig = musig::new_with_deterministic_nonces::<Sha256>();

    let keypair_0 = musig.new_keypair(Scalar::random(&mut rand::thread_rng()));
    let public_key_0 = keypair_0.public_key();
    let keypair_1 = musig.new_keypair(Scalar::random(&mut rand::thread_rng()));
    let public_key_1 = keypair_1.public_key();
    let keypair_2 = musig.new_keypair(Scalar::random(&mut rand::thread_rng()));
    let public_key_2 = keypair_2.public_key();

    let agg_key = musig
        .new_agg_key(vec![public_key_0, public_key_1, public_key_2])
        .into_xonly_key();

    let session_id = b"signing-ominous-message-about-banks-attempt-1".as_slice();

    let mut nonce_rng_0: ChaCha20Rng =
        musig.seed_nonce_rng(&agg_key, &keypair_0.secret_key(), session_id);
    let nonce_0 = musig.gen_nonce(&mut nonce_rng_0);
    let public_nonce_0 = nonce_0.public();

    let mut nonce_rng_1: ChaCha20Rng =
        musig.seed_nonce_rng(&agg_key, &keypair_1.secret_key(), session_id);
    let nonce_1 = musig.gen_nonce(&mut nonce_rng_1);
    let public_nonce_1 = nonce_1.public();

    let mut nonce_rng_2: ChaCha20Rng =
        musig.seed_nonce_rng(&agg_key, &keypair_2.secret_key(), session_id);
    let nonce_2 = musig.gen_nonce(&mut nonce_rng_2);
    let public_nonce_2 = nonce_2.public();

    let nonces = vec![public_nonce_0, public_nonce_1, public_nonce_2];
    let message = Message::plain("my-app", b"chancellor on brink of second bailout for banks");

    let session = musig.start_sign_session(&agg_key, nonces, message);

    let sig_0 = musig.sign(&agg_key, &session, 0, &keypair_0, nonce_0);
    let sig_1 = musig.sign(&agg_key, &session, 1, &keypair_1, nonce_1);
    let sig_2 = musig.sign(&agg_key, &session, 2, &keypair_2, nonce_2);

    assert!(musig.verify_partial_signature(&agg_key, &session, 1, sig_1));
    assert!(musig.verify_partial_signature(&agg_key, &session, 2, sig_2));

    let sig = musig.combine_partial_signatures(&agg_key, &session, [sig_0, sig_1, sig_2]);
    assert!(musig
        .schnorr
        .verify(&agg_key.agg_public_key(), message, &sig));
}
