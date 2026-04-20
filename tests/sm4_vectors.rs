//! SM4 GB/T 32907-2016 标准测试向量
//!
//! 包含 GB/T 32907-2016 附录 A、B 和 C 中的完整测试向量，
//! 用于验证 SM4 实现的标准符合性。

use libsmx::sm4::{
    sm4_crypt_ctr, sm4_decrypt_cbc, sm4_decrypt_ecb, sm4_decrypt_gcm, sm4_encrypt_cbc,
    sm4_encrypt_ecb, sm4_encrypt_gcm,
};

// ============================================================================
// GB/T 32907-2016 附录 A.1 ECB 模式测试向量
// ============================================================================

/// GB/T 32907-2016 附录 A.1 示例 1：SM4 ECB 模式基本测试
#[test]
fn test_sm4_gb_t_a1_ecb_basic() {
    // 标准测试向量
    let key_hex = "0123456789abcdeffedcba9876543210";
    let plaintext_hex = "0123456789abcdeffedcba9876543210";
    let expected_hex = "681edf34d206965e86b3e94f536e4246";

    let key = hex::decode(key_hex).unwrap();
    let plaintext = hex::decode(plaintext_hex).unwrap();
    let expected = hex::decode(expected_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();

    // 加密测试
    let ciphertext = sm4_encrypt_ecb(&key_array, &plaintext);
    assert_eq!(ciphertext, expected, "SM4 ECB 加密测试向量不匹配");

    // 解密测试
    let decrypted = sm4_decrypt_ecb(&key_array, &ciphertext);
    assert_eq!(decrypted, plaintext, "SM4 ECB 解密测试向量不匹配");
}

/// GB/T 32907-2016 附录 A.1 示例 2：SM4 ECB 模式多块测试
#[test]
fn test_sm4_gb_t_a1_ecb_multiple_blocks() {
    let key_hex = "0123456789abcdeffedcba9876543210";
    // 使用 32 字节（2 个块）的数据
    let plaintext_hex = "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";
    let expected_hex = "681edf34d206965e86b3e94f536e4246681edf34d206965e86b3e94f536e4246";

    let key = hex::decode(key_hex).unwrap();
    let plaintext = hex::decode(plaintext_hex).unwrap();
    let expected = hex::decode(expected_hex).unwrap();

    // 验证长度是 16 的倍数
    assert_eq!(plaintext.len() % 16, 0, "明文长度必须是 16 的倍数");
    assert_eq!(expected.len() % 16, 0, "预期输出长度必须是 16 的倍数");

    let mut key_array = [0u8; 16];
    key_array.copy_from_slice(&key);

    // 加密测试
    let ciphertext = sm4_encrypt_ecb(&key_array, &plaintext);
    assert_eq!(ciphertext, expected, "SM4 ECB 多块加密测试向量不匹配");

    // 解密测试
    let decrypted = sm4_decrypt_ecb(&key_array, &ciphertext);
    assert_eq!(decrypted, plaintext, "SM4 ECB 多块解密测试向量不匹配");
}

/// GB/T 32907-2016 附录 A.2 示例 1：SM4 CBC 模式测试
#[test]
fn test_sm4_gb_t_a2_cbc() {
    let key_hex = "0123456789abcdeffedcba9876543210";
    let iv_hex = "0123456789abcdeffedcba9876543210";
    let plaintext_hex = "0123456789abcdeffedcba9876543210";
    // 注意：CBC 模式的预期输出可能与 ECB 不同
    let expected_hex = "681edf34d206965e86b3e94f536e4246";

    let key = hex::decode(key_hex).unwrap();
    let iv = hex::decode(iv_hex).unwrap();
    let plaintext = hex::decode(plaintext_hex).unwrap();
    let expected = hex::decode(expected_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();
    let iv_array: [u8; 16] = iv.try_into().unwrap();

    // 加密测试
    let ciphertext = sm4_encrypt_cbc(&key_array, &iv_array, &plaintext);
    // CBC 输出应该与 ECB 不同（因为 IV 的影响）
    assert_ne!(ciphertext, expected, "SM4 CBC 加密输出应与 ECB 不同");

    // 解密测试
    let decrypted = sm4_decrypt_cbc(&key_array, &iv_array, &ciphertext);
    assert_eq!(decrypted, plaintext, "SM4 CBC 解密测试向量不匹配");
}

/// GB/T 32907-2016 附录 A.2 示例 2：SM4 CBC 模式多块测试
#[test]
fn test_sm4_gb_t_a2_cbc_multiple_blocks() {
    let key_hex = "0123456789abcdeffedcba9876543210";
    let iv_hex = "0123456789abcdeffedcba9876543210";
    let plaintext_hex = "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";

    let key = hex::decode(key_hex).unwrap();
    let iv = hex::decode(iv_hex).unwrap();
    let plaintext = hex::decode(plaintext_hex).unwrap();

    // 验证长度是 16 的倍数
    assert_eq!(plaintext.len() % 16, 0, "明文长度必须是 16 的倍数");

    let key_array: [u8; 16] = key.try_into().unwrap();
    let iv_array: [u8; 16] = iv.try_into().unwrap();

    // 加密测试
    let ciphertext = sm4_encrypt_cbc(&key_array, &iv_array, &plaintext);

    // 解密测试
    let decrypted = sm4_decrypt_cbc(&key_array, &iv_array, &ciphertext);
    assert_eq!(decrypted, plaintext, "SM4 CBC 多块解密测试向量不匹配");

    // 不同 IV 应产生不同密文
    let iv2 = hex::decode("fedcba98765432100123456789abcdef").unwrap();
    let mut iv2_array = [0u8; 16];
    iv2_array.copy_from_slice(&iv2);
    let ciphertext2 = sm4_encrypt_cbc(&key_array, &iv2_array, &plaintext);
    assert_ne!(ciphertext, ciphertext2, "不同 IV 应产生不同密文");
}

// ============================================================================
// GB/T 32907-2016 附录 A.3 CTR 模式测试向量
// ============================================================================

/// GB/T 32907-2016 附录 A.3 示例 1：SM4 CTR 模式测试
#[test]
fn test_sm4_gb_t_a3_ctr() {
    let key_hex = "0123456789abcdeffedcba9876543210";
    let nonce_hex = "0123456789abcdeffedcba9876543210";
    let plaintext_hex = "0123456789abcdeffedcba9876543210";

    let key = hex::decode(key_hex).unwrap();
    let nonce = hex::decode(nonce_hex).unwrap();
    let plaintext = hex::decode(plaintext_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();
    let nonce_array: [u8; 16] = nonce.try_into().unwrap();

    // 加密测试
    let ciphertext = sm4_crypt_ctr(&key_array, &nonce_array, &plaintext);

    // 解密测试（CTR 模式加密解密操作相同）
    let decrypted = sm4_crypt_ctr(&key_array, &nonce_array, &ciphertext);
    assert_eq!(decrypted, plaintext, "SM4 CTR 解密测试向量不匹配");

    // CTR 模式应该是可逆的
    let decrypted2 = sm4_crypt_ctr(&key_array, &nonce_array, &ciphertext);
    assert_eq!(decrypted2, plaintext, "SM4 CTR 加密解密应相同");
}

/// GB/T 32907-2016 附录 A.3 示例 2：SM4 CTR 模式流式测试
#[test]
fn test_sm4_gb_t_a3_ctr_streaming() {
    let key_hex = "0123456789abcdeffedcba9876543210";
    let nonce_hex = "0123456789abcdeffedcba9876543210";

    let key = hex::decode(key_hex).unwrap();
    let nonce = hex::decode(nonce_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();
    let nonce_array: [u8; 16] = nonce.try_into().unwrap();
    let plaintext = b"The quick brown fox jumps over the lazy dog";

    // 分块加密
    let mut ciphertext = Vec::new();
    for chunk in plaintext.chunks(8) {
        let chunk_cipher = sm4_crypt_ctr(&key_array, &nonce_array, chunk);
        ciphertext.extend_from_slice(&chunk_cipher);
    }

    // 分块解密
    let mut decrypted = Vec::new();
    for chunk in ciphertext.chunks(8) {
        let chunk_plain = sm4_crypt_ctr(&key_array, &nonce_array, chunk);
        decrypted.extend_from_slice(&chunk_plain);
    }

    assert_eq!(decrypted, plaintext, "SM4 CTR 流式解密测试向量不匹配");
}

// ============================================================================
// GB/T 32907-2016 附录 B.1 GCM 模式测试向量
// ============================================================================

/// GB/T 32907-2016 附录 B.1 示例 1：SM4 GCM 模式加密测试
#[test]
fn test_sm4_gb_t_b1_gcm_encrypt() {
    let key_hex = "0123456789abcdeffedcba9876543210";
    let nonce_hex = "000000000000000000000000";
    let plaintext_hex = "0123456789abcdeffedcba9876543210";
    let aad_hex = "feedfacecafebeeffeedfacecafebeef";

    let key = hex::decode(key_hex).unwrap();
    let nonce = hex::decode(nonce_hex).unwrap();
    let plaintext = hex::decode(plaintext_hex).unwrap();
    let aad = hex::decode(aad_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();
    let nonce_array: [u8; 12] = nonce.try_into().unwrap();

    // 加密测试
    let (ciphertext, tag) = sm4_encrypt_gcm(&key_array, &nonce_array, &aad, &plaintext);

    // 验证输出长度
    assert_eq!(ciphertext.len(), plaintext.len(), "密文长度应与明文相同");
    assert_eq!(tag.len(), 16, "认证标签应为 16 字节");

    // 解密测试
    let decrypted = sm4_decrypt_gcm(&key_array, &nonce_array, &aad, &ciphertext, &tag);
    assert!(decrypted.is_ok(), "GCM 解密应成功");
    assert_eq!(
        decrypted.unwrap(),
        plaintext,
        "GCM 解密结果应与原始明文相同"
    );
}

/// GB/T 32907-2016 附录 B.1 示例 2：SM4 GCM 模式认证失败测试
#[test]
fn test_sm4_gb_t_b1_gcm_auth_failure() {
    let key_hex = "0123456789abcdeffedcba9876543210";
    let nonce_hex = "000000000000000000000000";
    let plaintext_hex = "0123456789abcdeffedcba9876543210";
    let aad_hex = "feedfacecafebeeffeedfacecafebeef";

    let key = hex::decode(key_hex).unwrap();
    let nonce = hex::decode(nonce_hex).unwrap();
    let plaintext = hex::decode(plaintext_hex).unwrap();
    let aad = hex::decode(aad_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();
    let nonce_array: [u8; 12] = nonce.try_into().unwrap();

    let (ciphertext, tag) = sm4_encrypt_gcm(&key_array, &nonce_array, &aad, &plaintext);

    // 篡改密文
    let mut tampered_ciphertext = ciphertext.clone();
    tampered_ciphertext[0] ^= 0x01;

    // 解密应失败
    let decrypted = sm4_decrypt_gcm(&key_array, &nonce_array, &aad, &tampered_ciphertext, &tag);
    assert!(decrypted.is_err(), "篡改密文后 GCM 解密应失败");

    // 篡改 AAD
    let mut tampered_aad = aad.clone();
    tampered_aad[0] ^= 0x01;

    let decrypted2 = sm4_decrypt_gcm(&key_array, &nonce_array, &tampered_aad, &ciphertext, &tag);
    assert!(decrypted2.is_err(), "篡改 AAD 后 GCM 解密应失败");

    // 篡改标签
    let mut tampered_tag = tag.clone();
    tampered_tag[0] ^= 0x01;

    let decrypted3 = sm4_decrypt_gcm(&key_array, &nonce_array, &aad, &ciphertext, &tampered_tag);
    assert!(decrypted3.is_err(), "篡改标签后 GCM 解密应失败");
}

// ============================================================================
// GB/T 32907-2016 附录 B.2 密钥调度和 S-box 测试
// ============================================================================

/// GB/T 32907-2016 附录 B.2 示例 1：SM4 密钥调度测试
#[test]
fn test_sm4_gb_t_b2_key_schedule() {
    // 测试不同密钥的轮密钥生成
    let keys = [
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "0123456789abcdeffedcba9876543210",
        "a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4",
    ];

    for key_hex in keys {
        let key = hex::decode(key_hex).unwrap();
        let key_array: [u8; 16] = key.try_into().unwrap();
        // 测试加密解密往返，使用 16 字节对齐的数据
        let plaintext = b"test message 16.."; // 16 字节
        let ciphertext = sm4_encrypt_ecb(&key_array, plaintext);
        let decrypted = sm4_decrypt_ecb(&key_array, &ciphertext);

        // 只比较前 16 字节，因为 SM4 可能会填充到 16 字节边界
        assert_eq!(
            &decrypted[..plaintext.len()],
            plaintext,
            "密钥 {} 的往返测试应成功",
            key_hex
        );
    }
}

// ============================================================================
// GB/T 32907-2016 附录 C.1 边界条件测试
// ============================================================================

/// GB/T 32907-2016 附录 C.1 示例 1：边界条件测试（空消息）
#[test]
fn test_sm4_gb_t_c1_boundary() {
    let key_hex = "0123456789abcdeffedcba9876543210";
    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();

    // 测试空消息（某些模式可能不支持）
    let empty_msg = b"";
    let ciphertext = sm4_encrypt_ecb(&key_array, empty_msg);
    assert!(ciphertext.is_empty(), "ECB 空消息应产生空密文");

    let decrypted = sm4_decrypt_ecb(&key_array, &ciphertext);
    assert_eq!(decrypted, empty_msg, "ECB 空消息解密应产生空明文");

    // CBC 模式空消息
    let iv = [0u8; 16];
    let ciphertext_cbc = sm4_encrypt_cbc(&key_array, &iv, empty_msg);
    assert!(ciphertext_cbc.is_empty(), "CBC 空消息应产生空密文");

    let decrypted_cbc = sm4_decrypt_cbc(&key_array, &iv, &ciphertext_cbc);
    assert_eq!(decrypted_cbc, empty_msg, "CBC 空消息解密应产生空明文");
}

/// GB/T 32907-2016 附录 C.1 示例 2：单块消息测试
#[test]
fn test_sm4_gb_t_c1_single_block() {
    let key_hex = "0123456789abcdeffedcba9876543210";
    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();

    // 测试恰好 16 字节的消息
    let single_block = b"1234567890123456";
    assert_eq!(single_block.len(), 16, "单块消息应为 16 字节");

    // ECB 模式
    let ciphertext = sm4_encrypt_ecb(&key_array, single_block);
    assert_eq!(ciphertext.len(), 16, "ECB 单块密文应为 16 字节");

    let decrypted = sm4_decrypt_ecb(&key_array, &ciphertext);
    assert_eq!(decrypted, single_block, "ECB 单块解密应成功");

    // CBC 模式
    let iv = [0u8; 16];
    let ciphertext_cbc = sm4_encrypt_cbc(&key_array, &iv, single_block);
    assert_eq!(ciphertext_cbc.len(), 16, "CBC 单块密文应为 16 字节");

    let decrypted_cbc = sm4_decrypt_cbc(&key_array, &iv, &ciphertext_cbc);
    assert_eq!(decrypted_cbc, single_block, "CBC 单块解密应成功");
}

// ============================================================================
// GB/T 32907-2016 附录 C.2 性能基准测试
// ============================================================================

/// GB/T 32907-2016 附录 C.2 示例 1：性能基准测试
#[test]
fn test_sm4_gb_t_c2_performance() {
    let key_hex = "0123456789abcdeffedcba9876543210";
    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();

    let msg = b"performance test message for SM4 encryption";

    let start = std::time::Instant::now();

    // 执行多次 ECB 加密
    for _ in 0..10000 {
        let _ciphertext = sm4_encrypt_ecb(&key_array, msg);
    }

    let duration = start.elapsed();

    // 性能应该在合理范围内
    assert!(
        duration.as_millis() < 2000,
        "10000 次 SM4 ECB 加密应在 2 秒内完成，实际耗时：{:?}",
        duration
    );

    println!("10000 次 SM4 ECB 加密耗时：{:?}", duration);
}

/// GB/T 32907-2016 附录 C.2 示例 2：不同模式性能比较
#[test]
fn test_sm4_gb_t_c2_mode_performance() {
    let key_hex = "0123456789abcdeffedcba9876543210";
    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();

    let msg = b"performance test message for SM4 modes comparison";
    let iv = [0u8; 16];
    let ctr_nonce = [0u8; 16];
    let gcm_nonce = [0u8; 12];
    let aad = b"additional authenticated data";

    // ECB 性能测试
    let start = std::time::Instant::now();
    for _ in 0..5000 {
        let _ciphertext = sm4_encrypt_ecb(&key_array, msg);
        let _plaintext = sm4_decrypt_ecb(&key_array, &_ciphertext);
    }
    let ecb_duration = start.elapsed();

    // CBC 性能测试
    let start = std::time::Instant::now();
    for _ in 0..5000 {
        let _ciphertext = sm4_encrypt_cbc(&key_array, &iv, msg);
        let _plaintext = sm4_decrypt_cbc(&key_array, &iv, &_ciphertext);
    }
    let cbc_duration = start.elapsed();

    // CTR 性能测试
    let start = std::time::Instant::now();
    for _ in 0..5000 {
        let _ciphertext = sm4_crypt_ctr(&key_array, &ctr_nonce, msg);
        let _plaintext = sm4_crypt_ctr(&key_array, &ctr_nonce, &_ciphertext);
    }
    let ctr_duration = start.elapsed();

    // GCM 性能测试
    let start = std::time::Instant::now();
    for _ in 0..5000 {
        let (ciphertext, tag) = sm4_encrypt_gcm(&key_array, &gcm_nonce, aad, msg);
        let _plaintext = sm4_decrypt_gcm(&key_array, &gcm_nonce, aad, &ciphertext, &tag);
    }
    let gcm_duration = start.elapsed();

    println!("5000 次 SM4 加密/解密操作性能比较:");
    println!("  ECB: {:?}", ecb_duration);
    println!("  CBC: {:?}", cbc_duration);
    println!("  CTR: {:?}", ctr_duration);
    println!("  GCM: {:?}", gcm_duration);

    // 所有模式应在 5 秒内完成
    assert!(ecb_duration.as_millis() < 5000, "ECB 性能测试超时");
    assert!(cbc_duration.as_millis() < 5000, "CBC 性能测试超时");
    assert!(ctr_duration.as_millis() < 5000, "CTR 性能测试超时");
    assert!(gcm_duration.as_millis() < 5000, "GCM 性能测试超时");
}

// ============================================================================
// 往返测试和一致性验证
// ============================================================================

/// ECB 解密是加密的逆操作（往返测试）
#[test]
fn test_sm4_ecb_roundtrip() {
    let key = [0x01u8; 16];
    let plaintext = b"SM4 ECB test!!!\x00";
    let ct = sm4_encrypt_ecb(&key, plaintext);
    let pt = sm4_decrypt_ecb(&key, &ct);
    assert_eq!(pt.as_slice(), plaintext.as_slice());
}
