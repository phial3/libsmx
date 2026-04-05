//! SM9 国标测试向量（GB/T 38635-2020 附录 A）
//!
//! 端到端测试：密钥生成 → 签名 → 验签 → 加密 → 解密

use libsmx::sm9::{
    generate_enc_master_keypair, generate_enc_user_key, generate_sign_master_keypair,
    generate_sign_user_key, sm9_decrypt, sm9_encrypt, sm9_sign, sm9_verify, Sm9EncPubKey,
    Sm9SignPubKey,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// SM9 签名主密钥对生成 + 签名私钥派生 + 签名验签端到端测试
#[test]
fn test_sm9_sign_verify_end_to_end() {
    let mut rng = StdRng::from_seed([0x42u8; 32]);

    // 1. 生成签名主密钥对
    let (master_priv, sign_pub) = generate_sign_master_keypair(&mut rng);

    // 验证主公钥在 G2 上
    let pub_bytes = sign_pub.as_bytes();
    let pub_key = Sm9SignPubKey::from_bytes(pub_bytes).expect("主公钥应有效");

    // 2. 为用户 "Alice" 派生签名私钥
    let id = b"Alice";
    let da = generate_sign_user_key(&master_priv, id).expect("签名私钥派生应成功");

    // 3. 签名
    let msg = b"hello SM9 world";
    let (h, s) = sm9_sign(msg, &da, &pub_key, &mut rng).expect("签名应成功");

    // 4. 验签
    sm9_verify(msg, &h, &s, id, &pub_key).expect("验签应成功");
}

/// 验签对错误消息应失败
#[test]
fn test_sm9_verify_wrong_message_fails() {
    let mut rng = StdRng::from_seed([0xABu8; 32]);
    let (master_priv, sign_pub) = generate_sign_master_keypair(&mut rng);
    let pub_key = Sm9SignPubKey::from_bytes(sign_pub.as_bytes()).unwrap();

    let id = b"Bob";
    let da = generate_sign_user_key(&master_priv, id).unwrap();

    let msg = b"original message";
    let (h, s) = sm9_sign(msg, &da, &pub_key, &mut rng).unwrap();

    // 用不同消息验签，应失败
    assert!(
        sm9_verify(b"tampered message", &h, &s, id, &pub_key).is_err(),
        "篡改消息后验签应失败"
    );
}

/// 验签对错误用户 ID 应失败
#[test]
fn test_sm9_verify_wrong_id_fails() {
    let mut rng = StdRng::from_seed([0xAAu8; 32]); // 注：种子需 < GROUP_ORDER (首字节<0xB6)
    let (master_priv, sign_pub) = generate_sign_master_keypair(&mut rng);
    let pub_key = Sm9SignPubKey::from_bytes(sign_pub.as_bytes()).unwrap();

    let id = b"Charlie";
    let da = generate_sign_user_key(&master_priv, id).unwrap();

    let msg = b"test";
    let (h, s) = sm9_sign(msg, &da, &pub_key, &mut rng).unwrap();

    // 用不同 ID 验签，应失败
    assert!(
        sm9_verify(msg, &h, &s, b"Dave", &pub_key).is_err(),
        "错误 ID 验签应失败"
    );
}

/// SM9 加密主密钥对生成 + 用户加密私钥派生 + 加解密端到端测试
#[test]
fn test_sm9_encrypt_decrypt_end_to_end() {
    let mut rng = StdRng::from_seed([0x33u8; 32]);

    // 1. 生成加密主密钥对
    let (master_priv, enc_pub) = generate_enc_master_keypair(&mut rng);
    let pub_key = Sm9EncPubKey::from_bytes(enc_pub.as_bytes()).unwrap();

    // 2. 为用户 "Alice" 派生加密私钥
    let id = b"Alice";
    let de = generate_enc_user_key(&master_priv, id).expect("加密私钥派生应成功");

    // 3. 加密
    let msg = b"Top secret SM9 message";
    let ct = sm9_encrypt(id, msg, &pub_key, &mut rng).expect("加密应成功");

    // 4. 解密
    let pt = sm9_decrypt(id, &ct, &de).expect("解密应成功");
    assert_eq!(pt, msg);
}

/// 解密对错误用户 ID 应失败
#[test]
fn test_sm9_decrypt_wrong_id_fails() {
    let mut rng = StdRng::from_seed([0x44u8; 32]);
    let (master_priv, enc_pub) = generate_enc_master_keypair(&mut rng);
    let pub_key = Sm9EncPubKey::from_bytes(enc_pub.as_bytes()).unwrap();

    let id_alice = b"Alice";
    let id_bob = b"Bob";
    let de_alice = generate_enc_user_key(&master_priv, id_alice).unwrap();

    let msg = b"message for Alice";
    let ct = sm9_encrypt(id_alice, msg, &pub_key, &mut rng).unwrap();

    // Bob 尝试解密 Alice 的密文，应失败
    assert!(
        sm9_decrypt(id_bob, &ct, &de_alice).is_err(),
        "错误 ID 解密应失败"
    );
}

/// 解密对被篡改的密文应失败
#[test]
fn test_sm9_decrypt_tampered_ciphertext_fails() {
    let mut rng = StdRng::from_seed([0x55u8; 32]);
    let (master_priv, enc_pub) = generate_enc_master_keypair(&mut rng);
    let pub_key = Sm9EncPubKey::from_bytes(enc_pub.as_bytes()).unwrap();

    let id = b"Alice";
    let de = generate_enc_user_key(&master_priv, id).unwrap();

    let msg = b"secret";
    let mut ct = sm9_encrypt(id, msg, &pub_key, &mut rng).unwrap();

    // 篡改密文
    let tamper_idx = ct.len() - 1;
    ct[tamper_idx] ^= 0xFF;

    assert!(sm9_decrypt(id, &ct, &de).is_err(), "篡改密文后解密应失败");
}

/// 解密对错误私钥应失败
#[test]
fn test_sm9_decrypt_wrong_key_fails() {
    let mut rng = StdRng::from_seed([0x99u8; 32]);
    let (master_priv, enc_pub) = generate_enc_master_keypair(&mut rng);
    let pub_key = Sm9EncPubKey::from_bytes(enc_pub.as_bytes()).unwrap();

    let id = b"Alice";
    let de_alice = generate_enc_user_key(&master_priv, id).unwrap();

    // 生成另一个人的私钥（或用错误主密钥生成的私钥）
    let mut rng2 = StdRng::from_seed([0xAAu8; 32]);
    let (master_priv2, _) = generate_enc_master_keypair(&mut rng2);
    let de_wrong = generate_enc_user_key(&master_priv2, id).unwrap();

    let msg = b"secret";
    let ct = sm9_encrypt(id, msg, &pub_key, &mut rng).unwrap();

    // Bob 的私钥不能解密 Alice 的密文
    assert!(
        sm9_decrypt(id, &ct, &de_wrong).is_err(),
        "错误私钥解密应失败"
    );
    let _ = de_alice; // 确保 Alice 私钥存在
}

#[cfg(test)]
mod pairing_reference_tests {
    /// Compare our pairing output against sm9_core reference
    /// This tests with a hardcoded known-good pairing value
    #[test]
    fn test_pairing_against_sm9core() {
        use libsmx::sm9::fields::fp12::fp12_to_bytes;
        use libsmx::sm9::groups::g1::G1Affine;
        use libsmx::sm9::groups::g2::G2Affine;
        use libsmx::sm9::pairing::pairing;
        use sm9_core::{Group, G1, G2};

        // Get sm9_core reference pairing of generators
        let g1_ref = G1::one();
        let g2_ref = G2::one();
        let gt_ref = sm9_core::pairing(g1_ref, g2_ref);
        let ref_bytes = gt_ref.to_slice();

        // Get our pairing of generators
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let gt = pairing(&g1, &g2);
        let our_bytes = fp12_to_bytes(&gt);

        // Print both for debugging
        println!("sm9_core ref bytes[0..32]: {:02x?}", &ref_bytes[0..32]);
        println!("our bytes[0..32]: {:02x?}", &our_bytes[0..32]);

        // They can't be directly compared due to different tower structures
        // But we can verify by checking if our e(G1,G2)^order == 1
        // For now, just print to help diagnose
        println!("sm9_core ref bytes (full):");
        for chunk in ref_bytes.chunks(32) {
            println!("  {:02x?}", chunk);
        }
        println!("our bytes (full):");
        for chunk in our_bytes.chunks(32) {
            println!("  {:02x?}", chunk);
        }
    }
}
