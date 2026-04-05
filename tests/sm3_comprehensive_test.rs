//! SM3 国密哈希算法全面功能测试
//!
//! 测试覆盖：
//! - 基础哈希计算
//! - 增量哈希（Hasher API）
//! - HMAC-SM3
//! - 边界条件测试
//! - 稳定性测试
//! - 标准测试向量验证

#![cfg(feature = "alloc")]

use libsmx::sm3::{hmac_sm3, HmacSm3, Sm3Hasher, DIGEST_LEN};

/// SM3 标准测试向量 1：空消息
/// 来自 GB/T 32905-2016 附录 A.1
#[test]
fn test_sm3_empty_message() {
    let expected = [
        0x1a, 0xb2, 0x1d, 0x83, 0x55, 0xcf, 0xa1, 0x7f, 0x8e, 0x61, 0x19, 0x48, 0x31, 0xe8, 0x1a,
        0x8f, 0x22, 0xbe, 0xc8, 0xc7, 0x28, 0xfe, 0xfb, 0x74, 0x7e, 0xd0, 0x35, 0xeb, 0x50, 0x82,
        0xaa, 0x2b,
    ];

    let result = Sm3Hasher::digest(b"");
    assert_eq!(result, expected);
}

/// SM3 标准测试向量 2：短消息 "abc"
/// 来自 GB/T 32905-2016 附录 A.2
#[test]
fn test_sm3_abc_message() {
    let expected = [
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4,
        0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b,
        0xa8, 0xe0,
    ];

    let result = Sm3Hasher::digest(b"abc");
    assert_eq!(result, expected);
}

/// SM3 长消息哈希一致性测试
#[test]
fn test_sm3_long_message() {
    // 测试长消息的哈希一致性
    let message = vec![b'a'; 512];

    // 多次计算应得到相同结果
    let result1 = Sm3Hasher::digest(&message);
    let result2 = Sm3Hasher::digest(&message);
    assert_eq!(result1, result2, "Long message hash should be consistent");

    // 与多次 update 的结果应一致
    let mut hasher = Sm3Hasher::new();
    hasher.update(&message);
    let result3 = hasher.finalize();
    assert_eq!(
        result1, result3,
        "Long message hash should be consistent with incremental update"
    );
}

/// 测试哈希输出长度
#[test]
fn test_sm3_digest_length() {
    let message = b"Test message";
    let result = Sm3Hasher::digest(message);
    assert_eq!(result.len(), DIGEST_LEN);
    assert_eq!(result.len(), 32);
}

/// 测试增量哈希 - 基础功能
#[test]
fn test_sm3_hasher_basic() {
    let mut hasher = Sm3Hasher::new();
    hasher.update(b"Hello, ");
    hasher.update(b"World!");
    let result = hasher.finalize();

    // 与一次性计算比较
    let expected = Sm3Hasher::digest(b"Hello, World!");
    assert_eq!(result, expected);
}

/// 测试增量哈希 - 多次更新
#[test]
fn test_sm3_hasher_multiple_updates() {
    let message = b"The quick brown fox jumps over the lazy dog";

    // 一次性计算
    let expected = Sm3Hasher::digest(message);

    // 分多次更新
    let mut hasher = Sm3Hasher::new();
    for chunk in message.chunks(5) {
        hasher.update(chunk);
    }
    let result = hasher.finalize();

    assert_eq!(result, expected);
}

/// 测试增量哈希 - 空更新
#[test]
fn test_sm3_hasher_empty_update() {
    let mut hasher = Sm3Hasher::new();
    hasher.update(b"");
    hasher.update(b"test");
    hasher.update(b"");
    let result = hasher.finalize();

    let expected = Sm3Hasher::digest(b"test");
    assert_eq!(result, expected);
}

/// 测试 HMAC-SM3 - 基础功能
#[test]
fn test_hmac_sm3_basic() {
    let key = b"secret key";
    let data = b"message to authenticate";

    let result = hmac_sm3(key, data);
    assert_eq!(result.len(), DIGEST_LEN);

    // 相同输入应产生相同结果
    let result2 = hmac_sm3(key, data);
    assert_eq!(result, result2);
}

/// 测试 HMAC-SM3 - 不同输入产生不同结果
#[test]
fn test_hmac_sm3_different_inputs() {
    let key = b"secret key";

    let result1 = hmac_sm3(key, b"message1");
    let result2 = hmac_sm3(key, b"message2");
    let result3 = hmac_sm3(b"different key", b"message1");

    assert_ne!(result1, result2); // 不同消息
    assert_ne!(result1, result3); // 不同密钥
}

/// 测试 HMAC-SM3 结构体 API
#[test]
fn test_hmac_sm3_struct() {
    let key = b"secret key";
    let data = b"message to authenticate";

    // 使用结构体 API
    let mut hmac = HmacSm3::new(key);
    hmac.update(data);
    let result = hmac.finalize();

    // 与便捷函数比较
    let expected = hmac_sm3(key, data);
    assert_eq!(result, expected);
}

/// 测试 HMAC-SM3 结构体 - 多次更新
#[test]
fn test_hmac_sm3_struct_multiple_updates() {
    let key = b"secret key";
    let data = b"The quick brown fox jumps over the lazy dog";

    // 一次性计算
    let expected = hmac_sm3(key, data);

    // 分多次更新
    let mut hmac = HmacSm3::new(key);
    for chunk in data.chunks(7) {
        hmac.update(chunk);
    }
    let result = hmac.finalize();

    assert_eq!(result, expected);
}

/// 测试不同长度消息的哈希
#[test]
fn test_sm3_various_lengths() {
    let lengths = vec![0, 1, 16, 32, 64, 100, 1000, 10000];

    for len in lengths {
        let message = vec![0xABu8; len];
        let result = Sm3Hasher::digest(&message);
        assert_eq!(result.len(), DIGEST_LEN, "Failed for length {}", len);
    }
}

/// 测试哈希的雪崩效应（微小输入变化导致输出大变化）
#[test]
fn test_sm3_avalanche_effect() {
    let message1 = b"Hello, World!";
    let mut message2 = message1.to_vec();
    message2[0] ^= 0x01; // 改变 1 位

    let hash1 = Sm3Hasher::digest(message1);
    let hash2 = Sm3Hasher::digest(&message2);

    // 两个哈希应完全不同
    assert_ne!(hash1, hash2);

    // 计算不同位数（应该接近 50%）
    let diff_bits = hash1
        .iter()
        .zip(hash2.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum::<u32>();
    let total_bits = (DIGEST_LEN * 8) as u32;
    let diff_ratio = diff_bits as f64 / total_bits as f64;

    // 差异应在 40% 到 60% 之间（雪崩效应）
    assert!(
        diff_ratio > 0.4 && diff_ratio < 0.6,
        "Avalanche effect weak: {}% bits differ",
        diff_ratio * 100.0
    );
}

/// 稳定性测试 - 多次哈希计算
#[test]
fn test_sm3_stability() {
    let message = b"Stability test message";
    let expected = Sm3Hasher::digest(message);

    for i in 0..1000 {
        let result = Sm3Hasher::digest(message);
        assert_eq!(result, expected, "Failed at iteration {}", i);
    }
}

/// 测试零初始化向量
#[test]
fn test_sm3_hasher_default() {
    let mut hasher1 = Sm3Hasher::new();
    let mut hasher2 = Sm3Hasher::default();

    let message = b"test";
    hasher1.update(message);
    hasher2.update(message);
    let result1 = hasher1.finalize();
    let result2 = hasher2.finalize();

    assert_eq!(result1, result2);
}

/// 测试 HMAC 空密钥
#[test]
fn test_hmac_sm3_empty_key() {
    let key = b"";
    let data = b"message";

    let result = hmac_sm3(key, data);
    assert_eq!(result.len(), DIGEST_LEN);
}

/// 测试 HMAC 空数据
#[test]
fn test_hmac_sm3_empty_data() {
    let key = b"secret key";
    let data = b"";

    let result = hmac_sm3(key, data);
    assert_eq!(result.len(), DIGEST_LEN);
}

/// 测试长密钥 HMAC
#[test]
fn test_hmac_sm3_long_key() {
    let key = vec![0xAAu8; 1000];
    let data = b"message";

    let result = hmac_sm3(&key, data);
    assert_eq!(result.len(), DIGEST_LEN);
}

/// 测试大消息哈希性能
#[test]
fn test_sm3_large_message() {
    let message = vec![0xABu8; 1024 * 1024]; // 1MB

    let result = Sm3Hasher::digest(&message);
    assert_eq!(result.len(), DIGEST_LEN);
}

/// 测试 Hasher 重置功能
#[test]
fn test_sm3_hasher_reuse() {
    let mut hasher = Sm3Hasher::new();

    // 第一次哈希
    hasher.update(b"message1");
    let result1 = hasher.finalize_reset();

    // 第二次哈希（使用同一 hasher）
    hasher.update(b"message2");
    let result2 = hasher.finalize();

    // 验证结果
    let expected1 = Sm3Hasher::digest(b"message1");
    let expected2 = Sm3Hasher::digest(b"message2");

    assert_eq!(result1, expected1);
    assert_eq!(result2, expected2);
}
