use paillier::*;
use curv::BigInt;
use curv::arithmetic::traits::Converter;
use curv::arithmetic::Zero;
use curv::arithmetic::Samplable;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
fn mta_2(
    alice_secret: &Scalar<Secp256k1>,
    bob_secret: &Scalar<Secp256k1>, 
    r1: &BigInt,
    r2: &BigInt,
    ek: &EncryptionKey,
    dk: &DecryptionKey,
) -> (Scalar<Secp256k1>, Scalar<Secp256k1>) {
    // Generate Paillier key pair
    let (ek, dk) = Paillier::keypair().keys();


    // Alice's secret shares
    let a1 = &alice_secret.to_bigint();
    

    // Bob's secret shares
    
    let a2 = &bob_secret.to_bigint();

    // 1. Alice computes CA = EncryptA(a1)
    let c_alice = Paillier::encrypt(&ek, RawPlaintext::from(&a1.clone()));

    // 2. Alice computes CR1 = EncryptA(r1)
    let c_r1 = Paillier::encrypt(&ek, RawPlaintext::from(r1.clone()));


    // 3. Send CA and CR1 to Bob
    // (Simulation: omitted as it's not part of the protocol logic)

    // 4. Bob selects β' <- ZN
    let beta_prime = BigInt::sample_below(&ek.n);
    // 5. Bob computes CB = (r2 * CA) + (a2 * CR1) + EncryptA(β')
    let r2_mul_c_alice =  Paillier::mul(&ek, RawPlaintext::from(r2.clone()), c_alice.clone());
    let a2_mul_c_r1 = Paillier::mul(&ek, RawPlaintext::from(a2.clone()), c_r1.clone());
    let enc_beta_prime = Paillier::encrypt(&ek, RawPlaintext::from(beta_prime.clone()));
    let c_bob = Paillier::add(&ek, r2_mul_c_alice.clone(), a2_mul_c_r1.clone());
    let c_bob = Paillier::add(&ek, c_bob.clone(), enc_beta_prime.clone());

    // 6. Bob sets additive share δ2 = -β′ mod q
    let delta_2 = Scalar::from((BigInt::zero() - &beta_prime) % &ek.n);

    // 7. Send CB to Alice
    // (Simulation: omitted as it's not part of the protocol)

    // 8. Alice decrypts α' = dec(CB)
    let dec_alice = Paillier::decrypt(&dk, &c_bob);

    // 9. Alice sets δ 1 = α' mod q
    let delta_1 = Scalar::from(BigInt::from(dec_alice) % &ek.n);

    (delta_1, delta_2)
}

fn mta(a: &Scalar<Secp256k1>, b: &Scalar<Secp256k1>) -> (Scalar<Secp256k1>, Scalar<Secp256k1>){
    let (ek, dk) = Paillier::keypair().keys();

    // Alice's input
    let alice_input= a;
    // Bob's input
    let bob_input= b;

    // Alice computes cA = EncryptA(a)
    let c_alice = Paillier::encrypt(&ek, RawPlaintext::from(&alice_input.to_bigint()));

    // Bob selects Beta Tag <– Z(N) -> where n is ek.n 
    let beta_tag: BigInt = BigInt::sample_below(&ek.n);

    // Compute Encrypt(BetaTag) using key of A
    let enc_betatag = Paillier::encrypt(&ek, RawPlaintext::from(&beta_tag));

    // Compute cB = b * cA + EncryptA(BetaTag) = EncryptA(ab+Tag)
    // Compute b * CA
    let b_mul_c_alice = Paillier::mul(&ek, RawPlaintext::from(&bob_input.to_bigint()), c_alice.clone());

    // Compute cB
    let c_bob = Paillier::add(&ek, b_mul_c_alice.clone(), enc_betatag.clone());

    // Bob sets additive share Beta = -BetaTag mod n
    let beta = Scalar::<Secp256k1>::from(&(&BigInt::zero() - &beta_tag) % &ek.n);

    // Alice decrypts = dec(cB)
    let dec_alice = Paillier::decrypt(&dk, &c_bob);

    // Alice sets alpha = dec_alice mod n
    let alpha = Scalar::<Secp256k1>::from(BigInt::from(dec_alice.clone()) % &ek.n);
    (alpha, beta)
}

fn main() {
    let alice_input = Scalar::<Secp256k1>::random();
    let bob_input = Scalar::<Secp256k1>::random();
    let (ek, dk) = Paillier::keypair().keys();
    let r1 = BigInt::sample_below(&ek.n);
    let r2 = BigInt::sample_below(&ek.n);
    let (delta_1, delta_2) = mta_2(&alice_input, &bob_input, &r1, &r2, &ek, &dk);

    let left = &delta_1.to_bigint() + &delta_2.to_bigint();
    // dbg!(&left);
    let right = (&alice_input.to_bigint()*&r2) + (&bob_input.to_bigint()*&r1);
    // dbg!(&right);
    assert_eq!(left, right, "Verification failed: Left side ({}) is not equal to right side ({})", left, right);

    println!("MTA Test Satisfied");
    // Verify
    // let left = (&alpha + &beta).to_bigint();
    // dbg!(&left);
    // let right = (&alice_input * &bob_input).to_bigint();
    // dbg!(&right);
    // assert_eq!(left, right, "Verification failed: Left side ({}) is not equal to right side ({})", left, right);

    // println!("MTA Test Satisfied");


}
