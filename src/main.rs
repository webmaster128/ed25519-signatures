fn main() {
    println!("Hello, hack0r! Please use `cargo test` to run the demo.");
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signature;
    use ed25519_dalek::{ExpandedSecretKey, Keypair, PublicKey};
    use rand::rngs::OsRng;

    #[test]
    fn multiple_signatues_can_be_generated() {
        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let public_key: PublicKey = keypair.public;

        let message: &[u8] = b"Make love.";

        // Baseline signature using the higher level API
        let signature_default: Signature = keypair.sign(message);
        assert!(public_key.verify(message, &signature_default).is_ok());

        // The 32 bytes `a` and the 32 bytes `RH` as seen in https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/
        // We manipulate the RH to get different signatures under the same pubkey.
        let mut a_and_rh = ExpandedSecretKey::from(&keypair.secret).to_bytes().to_vec();
        println!("a || RH = {}", hex::encode(&a_and_rh));
        let expanded0 = ExpandedSecretKey::from_bytes(&a_and_rh).unwrap();
        a_and_rh[63] += 1;
        println!("a || RH = {}", hex::encode(&a_and_rh));
        let expanded1 = ExpandedSecretKey::from_bytes(&a_and_rh).unwrap();
        a_and_rh[63] += 1;
        println!("a || RH = {}", hex::encode(&a_and_rh));
        let expanded2 = ExpandedSecretKey::from_bytes(&a_and_rh).unwrap();
        a_and_rh[63] += 1;
        println!("a || RH = {}", hex::encode(&a_and_rh));
        let expanded3 = ExpandedSecretKey::from_bytes(&a_and_rh).unwrap();
        a_and_rh[63] += 1;
        println!("a || RH = {}", hex::encode(&a_and_rh));
        let expanded4 = ExpandedSecretKey::from_bytes(&a_and_rh).unwrap();
        a_and_rh[63] += 1;

        // Generate 5 different signatures for the same message and public key
        let sig0 = expanded0.sign(message, &public_key);
        let sig1 = expanded1.sign(message, &public_key);
        let sig2 = expanded2.sign(message, &public_key);
        let sig3 = expanded3.sign(message, &public_key);
        let sig4 = expanded4.sign(message, &public_key);
        println!("sig0 = {}", hex::encode(&sig0.to_bytes() as &[u8]));
        println!("sig1 = {}", hex::encode(&sig1.to_bytes() as &[u8]));
        println!("sig2 = {}", hex::encode(&sig2.to_bytes() as &[u8]));
        println!("sig3 = {}", hex::encode(&sig3.to_bytes() as &[u8]));
        println!("sig4 = {}", hex::encode(&sig4.to_bytes() as &[u8]));

        // All signatures are valid for the same pubkey
        assert!(public_key.verify(message, &sig0).is_ok());
        assert!(public_key.verify(message, &sig1).is_ok());
        assert!(public_key.verify(message, &sig2).is_ok());
        assert!(public_key.verify(message, &sig3).is_ok());
        assert!(public_key.verify(message, &sig4).is_ok());

        // Signature 0 is the same as generated from the higher level API
        assert_eq!(sig0, signature_default);

        // All signatures are different
        assert_ne!(sig0, sig1);
        assert_ne!(sig0, sig2);
        assert_ne!(sig0, sig3);
        assert_ne!(sig0, sig4);
        assert_ne!(sig1, sig2);
        assert_ne!(sig1, sig3);
        assert_ne!(sig1, sig4);
        assert_ne!(sig2, sig3);
        assert_ne!(sig2, sig4);
        assert_ne!(sig3, sig4);
    }
}
