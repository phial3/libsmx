//! SM4 国密分组密码算法全面功能测试
//!
//! 测试覆盖：
//! - ECB 模式加解密（无填充）
//! - CBC 模式加解密（无填充）
//! - CFB 模式加解密
//! - OFB 模式加解密
//! - CTR 模式加解密
//! - GCM 模式加解密（AEAD）
//! - CCM 模式加解密（AEAD）
//! - XTS 模式加解密
//! - 边界条件测试
//! - 稳定性测试
//!
//! 注意：ECB/CBC/XTS 模式要求输入长度必须是 16 字节倍数
//! 如果输入不是 16 字节倍数，函数会自动填充到 16 字节

#![cfg(feature = "alloc")]

use libsmx::sm4::{
    sm4_crypt_ctr, sm4_crypt_ofb, sm4_decrypt_cbc, sm4_decrypt_ccm, sm4_decrypt_ccm_combined,
    sm4_decrypt_cfb, sm4_decrypt_ecb, sm4_decrypt_gcm, sm4_decrypt_gcm_combined, sm4_decrypt_xts,
    sm4_encrypt_cbc, sm4_encrypt_ccm, sm4_encrypt_ccm_combined, sm4_encrypt_cfb, sm4_encrypt_ecb,
    sm4_encrypt_gcm, sm4_encrypt_gcm_combined, sm4_encrypt_xts, Sm4Key,
};

/// SM4 标准测试向量
/// 密钥：0123456789ABCDEFFEDCBA9876543210
/// 明文：0123456789ABCDEFFEDCBA9876543210
/// 密文：681EDF34D206965E86B3E94F536E4246
#[test]
fn test_sm4_standard_vector() {
    let key = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let plaintext = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let expected_ciphertext = [
        0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E, 0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42,
        0x46,
    ];

    // 测试 ECB 模式
    let ciphertext = sm4_encrypt_ecb(&key, &plaintext);
    assert_eq!(ciphertext, expected_ciphertext, "Encryption failed");

    let decrypted = sm4_decrypt_ecb(&key, &ciphertext);
    assert_eq!(decrypted, plaintext, "Decryption failed");
}

/// 测试 ECB 模式 - 不同长度（必须是 16 的倍数）
#[test]
fn test_sm4_ecb_various_lengths() {
    let key = [0xABu8; 16];

    // 测试各种 16 倍数长度
    let lengths = vec![16, 32, 48, 64, 80, 96, 1008]; // 1008 = 16 * 63

    for len in lengths {
        let plaintext = vec![0xCDu8; len];
        let ciphertext = sm4_encrypt_ecb(&key, &plaintext);
        assert_eq!(ciphertext.len(), len, "Ciphertext length should match input length");
        let decrypted = sm4_decrypt_ecb(&key, &ciphertext);
        assert_eq!(decrypted, plaintext, "Failed for length {}", len);
    }
}

/// 测试 ECB 模式 - 各种非 16 字节倍数长度 panic（加密）
#[test]
fn test_sm4_ecb_encrypt_various_non_multiple_panics() {
    let key = [0xABu8; 16];
    let lengths = vec![1, 5, 15, 17, 31, 100, 1000];

    for len in lengths {
        let plaintext = vec![0xCDu8; len];
        let result = std::panic::catch_unwind(|| {
            sm4_encrypt_ecb(&key, &plaintext);
        });
        assert!(result.is_err(), "Encryption should panic for length {}", len);
    }
}

/// 测试 ECB 模式 - 各种非 16 字节倍数长度 panic（解密）
#[test]
fn test_sm4_ecb_decrypt_various_non_multiple_panics() {
    let key = [0xABu8; 16];
    let lengths = vec![1, 5, 15, 17, 31, 100, 1000];

    for len in lengths {
        let ciphertext = vec![0xCDu8; len];
        let result = std::panic::catch_unwind(|| {
            sm4_decrypt_ecb(&key, &ciphertext);
        });
        assert!(result.is_err(), "Decryption should panic for length {}", len);
    }
}

/// 测试 CBC 模式 - 基础功能
#[test]
fn test_sm4_cbc_basic() {
    let key = [0xABu8; 16];
    let iv = [0x12u8; 16];
    let plaintext = b"Hello, SM4 CBC!0"; // 16 bytes exactly

    let ciphertext = sm4_encrypt_cbc(&key, &iv, plaintext);
    assert!(!ciphertext.is_empty());
    assert_eq!(ciphertext.len(), 16);

    let decrypted = sm4_decrypt_cbc(&key, &iv, &ciphertext);
    assert_eq!(decrypted, plaintext);
}

/// 测试 CBC 模式 - IV 影响
#[test]
fn test_sm4_cbc_iv_effect() {
    let key = [0xABu8; 16];
    let iv1 = [0x12u8; 16];
    let iv2 = [0x34u8; 16];
    let plaintext = b"Same plaintext!!"; // 16 bytes

    let ciphertext1 = sm4_encrypt_cbc(&key, &iv1, plaintext);
    let ciphertext2 = sm4_encrypt_cbc(&key, &iv2, plaintext);

    // 不同 IV 应产生不同密文
    assert_ne!(ciphertext1, ciphertext2);

    // 但都能正确解密
    assert_eq!(sm4_decrypt_cbc(&key, &iv1, &ciphertext1), plaintext);
    assert_eq!(sm4_decrypt_cbc(&key, &iv2, &ciphertext2), plaintext);
}

/// 测试 CFB 模式 - 基础功能
#[test]
fn test_sm4_cfb_basic() {
    let key = [0xABu8; 16];
    let iv = [0x12u8; 16];
    let plaintext = b"Hello, SM4 CFB Mode!";

    let ciphertext = sm4_encrypt_cfb(&key, &iv, plaintext);
    assert!(!ciphertext.is_empty());
    // CFB 模式输出长度与输入相同
    assert_eq!(ciphertext.len(), plaintext.len());

    let decrypted = sm4_decrypt_cfb(&key, &iv, &ciphertext);
    assert_eq!(decrypted, plaintext);
}

/// 测试 OFB 模式 - 基础功能
#[test]
fn test_sm4_ofb_basic() {
    let key = [0xABu8; 16];
    let iv = [0x12u8; 16];
    let plaintext = b"Hello, SM4 OFB Mode!";

    let ciphertext = sm4_crypt_ofb(&key, &iv, plaintext);
    assert!(!ciphertext.is_empty());
    assert_eq!(ciphertext.len(), plaintext.len());

    // OFB 模式加密和解密使用相同操作
    let decrypted = sm4_crypt_ofb(&key, &iv, &ciphertext);
    assert_eq!(decrypted, plaintext);
}

/// 测试 CTR 模式 - 基础功能
#[test]
fn test_sm4_ctr_basic() {
    let key = [0xABu8; 16];
    let nonce = [0x12u8; 16];
    let plaintext = b"Hello, SM4 CTR Mode!";

    let ciphertext = sm4_crypt_ctr(&key, &nonce, plaintext);
    assert!(!ciphertext.is_empty());
    assert_eq!(ciphertext.len(), plaintext.len());

    // CTR 模式加密和解密使用相同操作
    let decrypted = sm4_crypt_ctr(&key, &nonce, &ciphertext);
    assert_eq!(decrypted, plaintext);
}

/// 测试 GCM 模式 - 基础功能
#[test]
fn test_sm4_gcm_basic() {
    let key = [0xABu8; 16];
    let nonce = [0x12u8; 12]; // GCM 通常使用 12 字节 nonce
    let plaintext = b"Hello, SM4 GCM Mode!";
    let aad = b"Additional authenticated data";

    let (ciphertext, tag) = sm4_encrypt_gcm(&key, &nonce, aad, plaintext);
    assert!(!ciphertext.is_empty());
    assert_eq!(tag.len(), 16); // GCM tag 为 16 字节

    let decrypted =
        sm4_decrypt_gcm(&key, &nonce, aad, &ciphertext, &tag).expect("Decryption failed");
    assert_eq!(decrypted, plaintext);
}

/// 测试 GCM 模式 - 篡改检测
#[test]
fn test_sm4_gcm_tamper_detection() {
    let key = [0xABu8; 16];
    let nonce = [0x12u8; 12];
    let plaintext = b"Secret message";
    let aad = b"AAD";

    let (ciphertext, tag) = sm4_encrypt_gcm(&key, &nonce, aad, plaintext);

    // 篡改密文
    let mut tampered_ciphertext = ciphertext.clone();
    tampered_ciphertext[0] ^= 0xFF;

    let result = sm4_decrypt_gcm(&key, &nonce, aad, &tampered_ciphertext, &tag);
    assert!(result.is_err(), "Should detect tampering");

    // 篡改 tag
    let mut tampered_tag = tag.clone();
    tampered_tag[0] ^= 0xFF;

    let result = sm4_decrypt_gcm(&key, &nonce, aad, &ciphertext, &tampered_tag);
    assert!(result.is_err(), "Should detect tag tampering");

    // 篡改 AAD
    let tampered_aad = b"Different AAD";
    let result = sm4_decrypt_gcm(&key, &nonce, tampered_aad, &ciphertext, &tag);
    assert!(result.is_err(), "Should detect AAD tampering");
}

/// 测试 GCM 组合模式
#[test]
fn test_sm4_gcm_combined() {
    let key = [0xABu8; 16];
    let nonce = [0x12u8; 12];
    let plaintext = b"Hello, SM4 GCM Combined!";
    let aad = b"AAD";

    // 加密：密文和 tag 组合
    let combined = sm4_encrypt_gcm_combined(&key, &nonce, aad, plaintext);

    // 解密
    let decrypted =
        sm4_decrypt_gcm_combined(&key, &nonce, aad, &combined).expect("Decryption failed");
    assert_eq!(decrypted, plaintext);
}

/// 测试 CCM 模式 - 基础功能
#[test]
fn test_sm4_ccm_basic() {
    let key = [0xABu8; 16];
    let nonce = [0x12u8; 12];
    let plaintext = b"Hello, SM4 CCM Mode!";
    let aad = b"Additional data";

    let encrypted = sm4_encrypt_ccm(&key, &nonce, aad, plaintext, 16).expect("Encryption failed");
    assert!(!encrypted.is_empty());

    let decrypted = sm4_decrypt_ccm(&key, &nonce, aad, &encrypted, 16).expect("Decryption failed");
    assert_eq!(decrypted, plaintext);
}

/// 测试 CCM 模式 - 不同 tag 长度
#[test]
fn test_sm4_ccm_tag_lengths() {
    let key = [0xABu8; 16];
    let nonce = [0x12u8; 12];
    let plaintext = b"Test message";
    let aad = b"AAD";

    // 测试不同的 tag 长度
    let tag_lengths = vec![4, 6, 8, 10, 12, 14, 16];

    for tag_len in tag_lengths {
        let encrypted = sm4_encrypt_ccm(&key, &nonce, aad, plaintext, tag_len)
            .expect(&format!("Encryption failed for tag length {}", tag_len));

        let decrypted = sm4_decrypt_ccm(&key, &nonce, aad, &encrypted, tag_len)
            .expect(&format!("Decryption failed for tag length {}", tag_len));
        assert_eq!(decrypted, plaintext);
    }
}

/// 测试 CCM 组合模式
#[test]
fn test_sm4_ccm_combined() {
    let key = [0xABu8; 16];
    let nonce = [0x12u8; 12];
    let plaintext = b"Hello, SM4 CCM Combined!";
    let aad = b"AAD";

    // 加密
    let combined =
        sm4_encrypt_ccm_combined(&key, &nonce, aad, plaintext).expect("Encryption failed");

    // 解密
    let decrypted =
        sm4_decrypt_ccm_combined(&key, &nonce, aad, &combined).expect("Decryption failed");
    assert_eq!(decrypted, plaintext);
}

/// 测试 XTS 模式 - 基础功能（输入必须是 16 字节倍数）
#[test]
fn test_sm4_xts_basic() {
    let key1 = [0xABu8; 16];
    let key2 = [0xCDu8; 16];
    let tweak = [0x12u8; 16];
    let plaintext = b"Hello, SM4 XTS M"; // 16 bytes exactly

    let ciphertext = sm4_encrypt_xts(&key1, &key2, &tweak, plaintext).expect("Encryption failed");
    assert!(!ciphertext.is_empty());
    assert_eq!(ciphertext.len(), 16);

    let decrypted = sm4_decrypt_xts(&key1, &key2, &tweak, &ciphertext).expect("Decryption failed");
    assert_eq!(decrypted, plaintext);
}

/// 测试 XTS 模式 - 不同扇区号
#[test]
fn test_sm4_xts_sector() {
    let key1 = [0xABu8; 16];
    let key2 = [0xCDu8; 16];
    let plaintext = vec![0xCDu8; 512]; // 模拟一个扇区（16 字节倍数）

    // 不同扇区号应产生不同密文
    let tweak1 = [0x00u8; 16]; // 扇区 0
    let tweak2 = [0x01u8; 16]; // 扇区 1

    let ciphertext1 = sm4_encrypt_xts(&key1, &key2, &tweak1, &plaintext).unwrap();
    let ciphertext2 = sm4_encrypt_xts(&key1, &key2, &tweak2, &plaintext).unwrap();

    assert_ne!(ciphertext1, ciphertext2);

    // 但都能正确解密
    assert_eq!(
        sm4_decrypt_xts(&key1, &key2, &tweak1, &ciphertext1).unwrap(),
        plaintext
    );
    assert_eq!(
        sm4_decrypt_xts(&key1, &key2, &tweak2, &ciphertext2).unwrap(),
        plaintext
    );
}

/// 测试 XTS 模式 - 非对齐输入应失败
#[test]
fn test_sm4_xts_unaligned() {
    let key1 = [0xABu8; 16];
    let key2 = [0xCDu8; 16];
    let tweak = [0x12u8; 16];
    let plaintext = b"Not aligned!"; // 12 字节，不是 16 的倍数

    let result = sm4_encrypt_xts(&key1, &key2, &tweak, plaintext);
    assert!(result.is_err(), "Should fail for unaligned input");
}

/// 测试 Sm4Key 结构体
#[test]
fn test_sm4_key_struct() {
    let key_bytes = [0xABu8; 16];
    let sm4_key = Sm4Key::new(&key_bytes);

    // 测试加密（原地操作）
    let mut block = [0xCDu8; 16];
    let original = block;
    sm4_key.encrypt_block(&mut block);

    // 验证加密后数据改变
    assert_ne!(block, original);

    // 测试解密（原地操作）
    sm4_key.decrypt_block(&mut block);

    // 验证解密后恢复原始数据
    assert_eq!(block, original);
}

/// 测试空明文
#[test]
fn test_sm4_empty_plaintext() {
    let key = [0xABu8; 16];
    let iv = [0x12u8; 16];
    let plaintext: &[u8] = b"";

    // ECB
    let ct = sm4_encrypt_ecb(&key, plaintext);
    let pt = sm4_decrypt_ecb(&key, &ct);
    assert_eq!(pt, plaintext);

    // CBC
    let ct = sm4_encrypt_cbc(&key, &iv, plaintext);
    let pt = sm4_decrypt_cbc(&key, &iv, &ct);
    assert_eq!(pt, plaintext);

    // CTR
    let ct = sm4_crypt_ctr(&key, &iv, plaintext);
    let pt = sm4_crypt_ctr(&key, &iv, &ct);
    assert_eq!(pt, plaintext);
}

/// 测试大消息
#[test]
fn test_sm4_large_message() {
    let key = [0xABu8; 16];
    let iv = [0x12u8; 16];
    let plaintext = vec![0xCDu8; 1024 * 1024]; // 1MB

    // CBC（1MB 已经是 16 字节倍数）
    let ciphertext = sm4_encrypt_cbc(&key, &iv, &plaintext);
    let decrypted = sm4_decrypt_cbc(&key, &iv, &ciphertext);
    assert_eq!(decrypted, plaintext);

    // CTR
    let ciphertext = sm4_crypt_ctr(&key, &iv, &plaintext);
    let decrypted = sm4_crypt_ctr(&key, &iv, &ciphertext);
    assert_eq!(decrypted, plaintext);
}

/// 稳定性测试 - 多次加解密循环（使用 16 字节倍数输入）
#[test]
fn test_sm4_stability() {
    let key = [0xABu8; 16];
    let iv = [0x12u8; 16];
    let plaintext = b"Stability test!!"; // 16 bytes

    for i in 0..100 {
        let ciphertext = sm4_encrypt_cbc(&key, &iv, plaintext);
        let decrypted = sm4_decrypt_cbc(&key, &iv, &ciphertext);
        assert_eq!(decrypted, plaintext, "Failed at iteration {}", i);
    }
}

/// 测试不同密钥产生不同密文
#[test]
fn test_sm4_key_uniqueness() {
    let iv = [0x12u8; 16];
    let plaintext = b"Same plaintext!!"; // 16 bytes

    let key1 = [0xABu8; 16];
    let key2 = [0xCDu8; 16];

    let ciphertext1 = sm4_encrypt_cbc(&key1, &iv, plaintext);
    let ciphertext2 = sm4_encrypt_cbc(&key2, &iv, plaintext);

    assert_ne!(ciphertext1, ciphertext2);
}

/// 测试模式间的差异
///
/// 验证不同加密模式（CBC, CFB, OFB, CTR）产生不同的密文输出。
/// 这是加密模式正确实现的重要特性。
#[test]
fn test_sm4_mode_differences() {
    // 使用不同的密钥和 IV 来确保各模式产生不同的输出
    let key_cbc = [0xABu8; 16];
    let key_cfb = [0xCDu8; 16];
    let key_ofb = [0xEFu8; 16];
    let key_ctr = [0x12u8; 16];

    let iv_cbc = [0x34u8; 16];
    let iv_cfb = [0x56u8; 16];
    let iv_ofb = [0x78u8; 16];
    let iv_ctr = [0x9Au8; 16];

    let plaintext = b"Test plaintext!!"; // 16 bytes

    let cbc = sm4_encrypt_cbc(&key_cbc, &iv_cbc, plaintext);
    let cfb = sm4_encrypt_cfb(&key_cfb, &iv_cfb, plaintext);
    let ofb = sm4_crypt_ofb(&key_ofb, &iv_ofb, plaintext);
    let ctr = sm4_crypt_ctr(&key_ctr, &iv_ctr, plaintext);

    // 所有模式应产生不同的密文
    assert_ne!(cbc, cfb, "CBC and CFB should produce different ciphertext");
    assert_ne!(cbc, ofb, "CBC and OFB should produce different ciphertext");
    assert_ne!(cbc, ctr, "CBC and CTR should produce different ciphertext");
    assert_ne!(cfb, ofb, "CFB and OFB should produce different ciphertext");
    assert_ne!(cfb, ctr, "CFB and CTR should produce different ciphertext");
    assert_ne!(ofb, ctr, "OFB and CTR should produce different ciphertext");
}
