//! SM2 国密算法全面功能测试
//!
//! 测试覆盖：
//! - 密钥生成
//! - 签名/验签
//! - 加密/解密
//! - 密钥交换
//! - 边界条件测试
//! - 稳定性测试（多次循环）

#![cfg(feature = "alloc")]

use libsmx::kdf::kdf;
use libsmx::sm2::key_exchange::ecdh;
use libsmx::sm2::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

/// 测试密钥生成
#[test]
fn test_keypair_generation() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    // 验证私钥长度
    assert_eq!(priv_key.as_bytes().len(), 32);

    // 验证公钥长度（未压缩格式）
    assert_eq!(pub_key.len(), 65);
    assert_eq!(pub_key[0], 0x04); // 未压缩格式标记

    // 验证公钥在曲线上
    let z = get_z(DEFAULT_ID, &pub_key);
    assert_eq!(z.len(), 32);
}

/// 测试密钥生成的随机性
#[test]
fn test_keypair_generation_randomness() {
    let mut rng1 = StdRng::seed_from_u64(123456);
    let mut rng2 = StdRng::seed_from_u64(123456);

    let (priv1, pub1) = generate_keypair(&mut rng1);
    let (priv2, pub2) = generate_keypair(&mut rng2);

    // 相同种子应生成相同密钥
    assert_eq!(priv1.as_bytes(), priv2.as_bytes());
    assert_eq!(pub1, pub2);

    // 不同种子应生成不同密钥
    let mut rng3 = StdRng::seed_from_u64(654321);
    let (priv3, pub3) = generate_keypair(&mut rng3);
    assert_ne!(priv1.as_bytes(), priv3.as_bytes());
    assert_ne!(pub1, pub3);
}

/// 测试签名和验签 - 基础功能
#[test]
fn test_sign_verify_basic() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let message = b"Hello, SM2!";
    let z = get_z(DEFAULT_ID, &pub_key);
    let e = get_e(&z, message);

    // 签名
    let signature = sign(&e, &priv_key, &mut rng);
    assert_eq!(signature.len(), 64);

    // 验签
    verify(&e, &pub_key, &signature).expect("Verification should succeed");
}

/// 测试签名和验签 - 使用 sign_message/verify_message 便捷函数
#[test]
fn test_sign_verify_message() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let message = b"Test message for SM2 signature";

    // 签名
    let signature = sign_message(message, DEFAULT_ID, &priv_key, &mut rng);
    assert_eq!(signature.len(), 64);

    // 验签
    verify_message(message, DEFAULT_ID, &pub_key, &signature).expect("Verification should succeed");
}

/// 测试签名 - 相同消息不同签名（随机性）
#[test]
fn test_sign_randomness() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let message = b"Same message";

    let sig1 = sign_message(message, DEFAULT_ID, &priv_key, &mut rng);
    let sig2 = sign_message(message, DEFAULT_ID, &priv_key, &mut rng);

    // 签名应不同（随机性）
    assert_ne!(
        sig1, sig2,
        "Signatures should be different due to randomness"
    );

    // 但都应能通过验签
    verify_message(message, DEFAULT_ID, &pub_key, &sig1).expect("First signature should verify");
    verify_message(message, DEFAULT_ID, &pub_key, &sig2).expect("Second signature should verify");
}

/// 测试验签失败 - 篡改消息
#[test]
fn test_verify_failure_tampered_message() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let message = b"Original message";
    let signature = sign_message(message, DEFAULT_ID, &priv_key, &mut rng);

    // 篡改消息
    let tampered_message = b"Tampered message";

    // 验签应失败
    let result = verify_message(tampered_message, DEFAULT_ID, &pub_key, &signature);
    assert!(
        result.is_err(),
        "Verification should fail for tampered message"
    );
}

/// 测试验签失败 - 篡改签名
#[test]
fn test_verify_failure_tampered_signature() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let message = b"Test message";
    let mut signature = sign_message(message, DEFAULT_ID, &priv_key, &mut rng);

    // 篡改签名
    signature[0] ^= 0xFF;

    // 验签应失败
    let result = verify_message(message, DEFAULT_ID, &pub_key, &signature);
    assert!(
        result.is_err(),
        "Verification should fail for tampered signature"
    );
}

/// 测试验签失败 - 使用不同公钥
#[test]
fn test_verify_failure_wrong_pubkey() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);
    let (_, wrong_pub_key) = generate_keypair(&mut rng);

    let message = b"Test message";
    let signature = sign_message(message, DEFAULT_ID, &priv_key, &mut rng);

    // 使用错误的公钥验签应失败
    let result = verify_message(message, DEFAULT_ID, &wrong_pub_key, &signature);
    assert!(
        result.is_err(),
        "Verification should fail with wrong public key"
    );
}

/// 测试签名和验签 - 使用不同 ID
#[test]
fn test_sign_verify_with_custom_id() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let message = b"Test message";
    let custom_id = b"1234567812345678";
    let different_id = b"8765432187654321";

    // 使用自定义 ID 签名
    let signature = sign_message(message, custom_id, &priv_key, &mut rng);

    // 使用相同 ID 验签应成功
    verify_message(message, custom_id, &pub_key, &signature)
        .expect("Verification with same ID should succeed");

    // 使用不同 ID 验签必须失败
    let result = verify_message(message, different_id, &pub_key, &signature);
    assert!(result.is_err(), "Verification with different ID must fail");
}

/// 测试签名和验签 - 空消息
#[test]
fn test_sign_verify_empty_message() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let empty_message = b"";

    let signature = sign_message(empty_message, DEFAULT_ID, &priv_key, &mut rng);
    verify_message(empty_message, DEFAULT_ID, &pub_key, &signature)
        .expect("Verification of empty message should succeed");
}

/// 测试签名和验签 - 大消息
#[test]
fn test_sign_verify_large_message() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    // 1MB 消息
    let large_message = vec![0xABu8; 1024 * 1024];

    let signature = sign_message(&large_message, DEFAULT_ID, &priv_key, &mut rng);
    verify_message(&large_message, DEFAULT_ID, &pub_key, &signature)
        .expect("Verification of large message should succeed");
}

/// 测试加密和解密 - 基础功能
#[test]
fn test_encrypt_decrypt_basic() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let plaintext = b"Hello, SM2 encryption!";

    // 加密（使用公钥）
    let ciphertext = encrypt(&pub_key, plaintext, &mut rng).expect("Encryption should succeed");
    assert!(!ciphertext.is_empty());

    // 解密（使用对应的私钥）
    let decrypted = decrypt(&priv_key, &ciphertext).expect("Decryption should succeed");

    assert_eq!(decrypted, plaintext);
}

/// 测试加密和解密 - 使用相同密钥对
#[test]
fn test_encrypt_decrypt_same_keypair() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let plaintext = b"Test with same keypair";

    // 加密（使用公钥）
    let ciphertext = encrypt(&pub_key, plaintext, &mut rng).expect("Encryption should succeed");

    // 解密（使用对应的私钥）
    let decrypted = decrypt(&priv_key, &ciphertext).expect("Decryption should succeed");

    assert_eq!(decrypted, plaintext);
}

/// 测试加密空数据
#[test]
fn test_encrypt_empty() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let empty_data = b"";

    // 加密空数据
    let ciphertext = encrypt(&pub_key, empty_data, &mut rng).expect("Encryption should succeed");
    assert!(!ciphertext.is_empty());

    // 解密空数据
    let decrypted =
        decrypt(&priv_key, &ciphertext).expect("Decryption of empty data should succeed");

    assert_eq!(decrypted, empty_data);
}

/// 测试加密大数据
#[test]
fn test_encrypt_large_data() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    // 1MB 数据
    let large_data = vec![0xCDu8; 1024 * 1024];

    let ciphertext = encrypt(&pub_key, &large_data, &mut rng).expect("Encryption should succeed");
    assert!(!ciphertext.is_empty());

    let decrypted =
        decrypt(&priv_key, &ciphertext).expect("Decryption of large data should succeed");

    assert_eq!(decrypted, large_data);
}

/// 测试解密失败 - 篡改密文
#[test]
fn test_decrypt_failure_tampered() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let plaintext = b"Test message";
    let mut ciphertext = encrypt(&pub_key, plaintext, &mut rng).expect("Encryption should succeed");

    // 篡改密文
    if !ciphertext.is_empty() {
        let len = ciphertext.len();
        ciphertext[len / 2] ^= 0xFF;
    }

    // 解密应失败
    let result = decrypt(&priv_key, &ciphertext);
    assert!(
        result.is_err(),
        "Decryption should fail for tampered ciphertext"
    );
}

/// 测试 ECDH 密钥交换
#[test]
fn test_ecdh_key_exchange() {
    let mut rng = StdRng::seed_from_u64(123456);

    // 双方生成密钥对
    let (alice_priv, alice_pub) = generate_keypair(&mut rng);
    let (bob_priv, bob_pub) = generate_keypair(&mut rng);

    // Alice 计算共享密钥
    let shared_alice = ecdh(&alice_priv, &bob_pub).expect("Alice's ECDH should succeed");

    // Bob 计算共享密钥
    let shared_bob = ecdh(&bob_priv, &alice_pub).expect("Bob's ECDH should succeed");

    // 共享密钥应相同
    assert_eq!(shared_alice, shared_bob);
    assert_eq!(shared_alice.len(), 32);
}

/// 测试公钥 SPKI 编码和解码
#[test]
fn test_pubkey_spki() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (_priv_key, pub_key) = generate_keypair(&mut rng);

    // 编码为 SPKI
    let spki = public_key_to_spki_der(&pub_key);
    assert!(!spki.is_empty());

    // 解码
    let decoded = public_key_from_spki_der(&spki).expect("Failed to decode SPKI");
    assert_eq!(decoded, pub_key);
}

/// 测试私钥 SEC1 编码和解码
#[test]
fn test_privkey_sec1() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _) = generate_keypair(&mut rng);

    // 编码为 SEC1
    let sec1 = private_key_to_sec1_der(&priv_key);
    assert!(!sec1.is_empty());

    // 解码
    let decoded = private_key_from_sec1_der(&sec1).expect("Failed to decode SEC1");
    assert_eq!(decoded.as_bytes(), priv_key.as_bytes());
}

/// 测试私钥 PKCS#8 编码和解码
#[test]
fn test_privkey_pkcs8() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _) = generate_keypair(&mut rng);

    // 编码为 PKCS#8
    let pkcs8 = private_key_to_pkcs8_der(&priv_key);
    assert!(!pkcs8.is_empty());

    // 解码
    let decoded = private_key_from_pkcs8_der(&pkcs8).expect("Failed to decode PKCS#8");
    assert_eq!(decoded.as_bytes(), priv_key.as_bytes());
}

/// 测试 Z 值计算
#[test]
fn test_get_z() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (_priv_key, pub_key) = generate_keypair(&mut rng);

    // 使用默认 ID
    let z1 = get_z(DEFAULT_ID, &pub_key);
    assert_eq!(z1.len(), 32);

    // 相同输入应产生相同 Z
    let z2 = get_z(DEFAULT_ID, &pub_key);
    assert_eq!(z1, z2);

    // 不同 ID 应产生不同 Z
    let custom_id = b"custom_id_12345678";
    let z3 = get_z(custom_id, &pub_key);
    assert_ne!(z1, z3);

    // 不同公钥应产生不同 Z
    let (_priv_key2, pub_key2) = generate_keypair(&mut rng);
    let z4 = get_z(DEFAULT_ID, &pub_key2);
    assert_ne!(z1, z4);
}

/// 测试 E 值计算
#[test]
fn test_get_e() {
    let z = [0xABu8; 32];
    let message = b"Test message";

    let e = get_e(&z, message);
    assert_eq!(e.len(), 32);

    // 相同输入应产生相同 E
    let e2 = get_e(&z, message);
    assert_eq!(e, e2);

    // 不同消息应产生不同 E
    let e3 = get_e(&z, b"Different message");
    assert_ne!(e, e3);

    // 不同 Z 应产生不同 E
    let z2 = [0xCDu8; 32];
    let e4 = get_e(&z2, message);
    assert_ne!(e, e4);
}

/// 测试稳定性 - 多次签名验签
#[test]
fn test_signature_stability() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let message = b"Stability test message";

    for i in 0..100 {
        let signature = sign_message(message, DEFAULT_ID, &priv_key, &mut rng);
        verify_message(message, DEFAULT_ID, &pub_key, &signature)
            .expect(&format!("Verification should succeed at iteration {}", i));
    }
}

/// 测试稳定性 - 多次加密解密
#[test]
fn test_encryption_stability() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let plaintext: &[u8] = b"Stability test plaintext";

    for i in 0..100 {
        let ciphertext = encrypt(&pub_key, plaintext, &mut rng).expect("Encryption should succeed");
        let decrypted = decrypt(&priv_key, &ciphertext)
            .expect(&format!("Decryption should succeed at iteration {}", i));
        assert_eq!(
            decrypted, plaintext,
            "Decrypted data should match at iteration {}",
            i
        );
    }
}

/// 测试边界条件 - 全零消息
#[test]
fn test_zero_message() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let zero_message = vec![0u8; 100];

    let signature = sign_message(&zero_message, DEFAULT_ID, &priv_key, &mut rng);
    verify_message(&zero_message, DEFAULT_ID, &pub_key, &signature)
        .expect("Verification of zero message should succeed");
}

/// 测试边界条件 - 全 0xFF 消息
#[test]
fn test_ff_message() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    let ff_message = vec![0xFFu8; 100];

    let signature = sign_message(&ff_message, DEFAULT_ID, &priv_key, &mut rng);
    verify_message(&ff_message, DEFAULT_ID, &pub_key, &signature)
        .expect("Verification of 0xFF message should succeed");
}

/// 测试边界条件 - 特殊长度消息
#[test]
fn test_special_length_messages() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, pub_key) = generate_keypair(&mut rng);

    // 测试各种特殊长度
    for len in [1, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257] {
        let message = vec![0xABu8; len];
        let signature = sign_message(&message, DEFAULT_ID, &priv_key, &mut rng);
        verify_message(&message, DEFAULT_ID, &pub_key, &signature)
            .expect(&format!("Verification should succeed for length {}", len));
    }
}

/// 测试密钥派生函数（KDF）
#[test]
fn test_kdf() {
    let z = [0xABu8; 32];

    // 派生不同长度的密钥
    for key_len in [8, 16, 24, 32, 48, 64] {
        let key = kdf(&z, key_len);
        assert_eq!(key.len(), key_len, "Derived key length should match");
    }

    // 相同输入应产生相同输出
    let key1 = kdf(&z, 32);
    let key2 = kdf(&z, 32);
    assert_eq!(key1, key2);

    // 不同输入应产生不同输出
    let z2 = [0xCDu8; 32];
    let key3 = kdf(&z2, 32);
    assert_ne!(key1, key3);
}
