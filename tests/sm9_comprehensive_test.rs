//! SM9 国密算法全面功能测试
//!
//! 测试覆盖：
//! - 基础签名验签
//! - 加密解密
//! - 不同ID的使用
//! - 边界条件测试
//! - 稳定性测试

#![cfg(feature = "alloc")]

use libsmx::sm9::{
    generate_enc_master_keypair, generate_enc_user_key, generate_sign_master_keypair,
    generate_sign_user_key, sm9_decrypt, sm9_encrypt, sm9_sign, sm9_verify,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// 测试 SM9 签名验签基本功能
#[test]
fn test_sign_verify_basic() {
    let mut rng = StdRng::seed_from_u64(42);

    // 生成签名主密钥对
    let (sign_master_priv, sign_master_pub) = generate_sign_master_keypair(&mut rng);

    // 生成用户签名密钥
    let sign_user_key = generate_sign_user_key(&sign_master_priv, b"Alice").unwrap();

    // 待签名消息
    let message = b"Hello, SM9 signature!";

    // 签名
    let (h, s) = sm9_sign(message, &sign_user_key, &sign_master_pub, &mut rng).unwrap();

    // 验签
    let result = sm9_verify(message, &h, &s, b"Alice", &sign_master_pub);
    assert!(result.is_ok());
}

/// 测试 SM9 加密解密基本功能
#[test]
fn test_encrypt_decrypt_basic() {
    let mut rng = StdRng::seed_from_u64(42);

    // 生成加密主密钥对
    let (enc_master_priv, enc_master_pub) = generate_enc_master_keypair(&mut rng);

    // 生成用户加密密钥
    let enc_user_key = generate_enc_user_key(&enc_master_priv, b"Bob").unwrap();

    // 待加密消息
    let message = b"Hello, SM9 encryption!";

    // 加密
    let ciphertext = sm9_encrypt(b"Bob", message, &enc_master_pub, &mut rng).unwrap();

    // 解密
    let plaintext = sm9_decrypt(b"Bob", &ciphertext, &enc_user_key).unwrap();
    assert_eq!(plaintext, message);
}

/// 测试 SM9 不同 ID 的签名验签
#[test]
fn test_sign_verify_different_ids() {
    let mut rng = StdRng::seed_from_u64(42);

    // 生成签名主密钥对
    let (sign_master_priv, sign_master_pub) = generate_sign_master_keypair(&mut rng);

    // 生成不同用户的签名密钥
    let sign_key_alice = generate_sign_user_key(&sign_master_priv, b"Alice").unwrap();
    let _sign_key_bob = generate_sign_user_key(&sign_master_priv, b"Bob").unwrap();

    // 待签名消息
    let message = b"Hello, SM9 signature!";

    // 使用 Alice 的密钥签名
    let (h, s) = sm9_sign(message,  &sign_key_alice, &sign_master_pub, &mut rng).unwrap();

    // 使用 Alice 的 ID 验签应成功
    let result1 = sm9_verify(message, &h, &s, b"Alice", &sign_master_pub);
    assert!(result1.is_ok());

    // 使用 Bob 的 ID 验签应失败
    let result2 = sm9_verify(message,  &h, &s, b"Bob", &sign_master_pub);
    assert!(result2.is_err());
}

/// 测试 SM9 不同 ID 的加密解密
#[test]
fn test_encrypt_decrypt_different_ids() {
    let mut rng = StdRng::seed_from_u64(42);

    // 生成加密主密钥对
    let (enc_master_priv, enc_master_pub) = generate_enc_master_keypair(&mut rng);

    // 生成不同用户的加密密钥
    let enc_key_alice = generate_enc_user_key(&enc_master_priv, b"Alice").unwrap();
    let enc_key_bob = generate_enc_user_key(&enc_master_priv, b"Bob").unwrap();

    // 待加密消息
    let message = b"Hello, SM9 encryption!";

    // 使用 Bob 的 ID 加密
    let ciphertext = sm9_encrypt(b"Bob", message, &enc_master_pub, &mut rng).unwrap();

    // 使用 Bob 的密钥解密应成功
    let plaintext1 = sm9_decrypt(b"Bob", &ciphertext, &enc_key_bob).unwrap();
    assert_eq!(plaintext1, message);

    // 使用 Alice 的密钥解密应失败
    let result2 = sm9_decrypt(b"Bob", &ciphertext, &enc_key_alice);
    assert!(result2.is_err());
}

/// 测试 SM9 签名验签稳定性
#[test]
fn test_sign_verify_stability() {
    let mut rng = StdRng::seed_from_u64(42);

    // 生成签名主密钥对
    let (sign_master_priv, sign_master_pub) = generate_sign_master_keypair(&mut rng);

    // 生成用户签名密钥
    let sign_user_key = generate_sign_user_key(&sign_master_priv, b"Alice").unwrap();

    // 待签名消息
    let message = b"Stability test message";

    // 多次签名验签
    for i in 0..100 {
        let (h, s) = sm9_sign(message,  &sign_user_key, &sign_master_pub, &mut rng).unwrap();
        let result = sm9_verify(message, &h, &s, b"Alice", &sign_master_pub);
        assert!(result.is_ok(), "Failed at iteration {}", i);
    }
}

/// 测试 SM9 加密解密稳定性
#[test]
fn test_encrypt_decrypt_stability() {
    let mut rng = StdRng::seed_from_u64(42);

    // 生成加密主密钥对
    let (enc_master_priv, enc_master_pub) = generate_enc_master_keypair(&mut rng);

    // 生成用户加密密钥
    let enc_user_key = generate_enc_user_key(&enc_master_priv, b"Bob").unwrap();

    // 待加密消息
    let message = b"Stability test message";

    // 多次加密解密
    for i in 0..100 {
        let ciphertext = sm9_encrypt(b"Bob", message, &enc_master_pub, &mut rng).unwrap();
        let plaintext = sm9_decrypt(b"Bob", &ciphertext, &enc_user_key).unwrap();
        assert_eq!(plaintext, message, "Failed at iteration {}", i);
    }
}

/// 测试 SM9 签名验签失败情况
#[test]
fn test_sign_verify_failure() {
    let mut rng = StdRng::seed_from_u64(42);

    // 生成签名主密钥对
    let (sign_master_priv, sign_master_pub) = generate_sign_master_keypair(&mut rng);

    // 生成用户签名密钥
    let sign_user_key = generate_sign_user_key(&sign_master_priv, b"Alice").unwrap();

    // 待签名消息
    let message = b"Hello, SM9 signature!";

    // 签名
    let (mut h, s) = sm9_sign(message, &sign_user_key, &sign_master_pub, &mut rng).unwrap();

    // 篡改签名
    h[0] ^= 0xFF;

    // 验签应失败
    let result = sm9_verify(message, &h, &s, b"Alice", &sign_master_pub);
    assert!(result.is_err());
}

/// 测试 SM9 加密解密失败情况
#[test]
fn test_encrypt_decrypt_failure() {
    let mut rng = StdRng::seed_from_u64(42);

    // 生成加密主密钥对
    let (enc_master_priv, enc_master_pub) = generate_enc_master_keypair(&mut rng);

    // 生成用户加密密钥
    let enc_user_key = generate_enc_user_key(&enc_master_priv, b"Bob").unwrap();

    // 待加密消息
    let message = b"Hello, SM9 encryption!";

    // 加密
    let mut ciphertext = sm9_encrypt(b"Bob", message, &enc_master_pub, &mut rng).unwrap();

    // 篡改密文
    ciphertext[0] ^= 0xFF;

    // 解密应失败
    let result = sm9_decrypt(b"Bob", &ciphertext, &enc_user_key);
    assert!(result.is_err());
}
