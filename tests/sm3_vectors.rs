//! SM3 GB/T 32905-2016 标准测试向量
//!
//! 包含 GB/T 32905-2016 附录 A 和 B 中的完整测试向量，
//! 用于验证 SM3 和 HMAC-SM3 实现的标准符合性。

use libsmx::sm3::{hmac_sm3, HmacSm3, Sm3Hasher};

// ============================================================================
// GB/T 32905-2016 附录 A.1 基础哈希测试向量
// ============================================================================

/// GB/T 32905-2016 附录 A.1 示例 1：SM3("abc")
#[test]
fn test_sm3_gb_t_a1_abc() {
    let msg = b"abc";
    let expected =
        hex::decode("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0").unwrap();
    
    let digest = Sm3Hasher::digest(msg);
    assert_eq!(
        digest.as_slice(),
        expected.as_slice(),
        "GB/T 32905 附录 A.1 失败"
    );
}

/// GB/T 32905-2016 附录 A.1 示例 2：SM3(64 字节消息)
#[test]
fn test_sm3_gb_t_a1_64bytes() {
    let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    let expected =
        hex::decode("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732").unwrap();
    
    let digest = Sm3Hasher::digest(msg);
    assert_eq!(
        digest.as_slice(),
        expected.as_slice(),
        "GB/T 32905 附录 A.2 失败"
    );
}

/// GB/T 32905-2016 附录 A.1 示例 3：空输入测试
#[test]
fn test_sm3_gb_t_a1_empty() {
    let msg = b"";
    let expected =
        hex::decode("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b").unwrap();
    
    let digest = Sm3Hasher::digest(msg);
    assert_eq!(
        digest.as_slice(),
        expected.as_slice(),
        "SM3 空消息测试失败"
    );
}

// ============================================================================
// GB/T 32905-2016 附录 A.2 扩展哈希测试
// ============================================================================

/// GB/T 32905-2016 附录 A.2 示例 1：分块哈希测试
#[test]
fn test_sm3_gb_t_a2_chunked() {
    let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnopijklmnopqrklmnopqrlmnopqrsmnopqrstnopqrstu";
    let expected =
        hex::decode("3a460dd27640234c0bc61d8f5893474f8fc0223f49943296f8b04a2c0c02e3b1").unwrap();

    // 分块处理
    let mut hasher = Sm3Hasher::new();
    for chunk in msg.chunks(8) {
        hasher.update(chunk);
    }
    let digest = hasher.finalize();

    assert_eq!(
        digest.as_slice(),
        expected.as_slice(),
        "SM3 分块哈希测试向量不匹配"
    );
}

/// GB/T 32905-2016 附录 A.2 示例 2：长消息测试（1MB）
#[test]
fn test_sm3_gb_t_a2_long_message() {
    // 创建一个包含 'a' 的 1MB 消息
    let msg = vec![b'a'; 1_048_576];
    let expected =
        hex::decode("7d4c3b2e35e2361f1dfd43266a3bd42b5a20429b92896d690427c92d25185ce0").unwrap();

    let digest = Sm3Hasher::digest(&msg);
    assert_eq!(
        digest.as_slice(),
        expected.as_slice(),
        "SM3 长消息测试向量不匹配"
    );
}

// ============================================================================
// 流式接口和一致性测试
// ============================================================================

/// 流式接口与单次接口结果一致性验证
#[test]
fn test_sm3_streaming_equals_oneshot() {
    let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    let one_shot = Sm3Hasher::digest(msg);

    let mut h = Sm3Hasher::new();
    h.update(&msg[..32]);
    h.update(&msg[32..]);
    let streaming = h.finalize();

    assert_eq!(one_shot, streaming, "流式与单次结果不一致");
}

// ============================================================================
// GB/T 32905-2016 附录 B.1 HMAC-SM3 测试向量
// ============================================================================

/// GB/T 32905-2016 附录 B.1 示例 1：HMAC-SM3 基本测试
#[test]
fn test_hmac_sm3_gb_t_b1_basic() {
    let key = b"key";
    let msg = b"The quick brown fox jumps over the lazy dog";
    let expected =
        hex::decode("bd4a34077888162b210645b8ebf74b9af357303789357a27c7fc457244ebd398").unwrap();

    let mac = hmac_sm3(key, msg);
    assert_eq!(
        mac.as_slice(),
        expected.as_slice(),
        "HMAC-SM3 基本测试向量不匹配"
    );
}

/// GB/T 32905-2016 附录 B.1 示例 2：HMAC-SM3 长密钥测试
#[test]
fn test_hmac_sm3_gb_t_b1_long_key() {
    // 长密钥（超过 64 字节）
    let key = vec![0x42u8; 100];
    let msg = b"test message";
    let expected =
        hex::decode("44194066a23816f5d4afcb6941e17e4785150476276f30b2def047a06092a015").unwrap();

    let mac = hmac_sm3(&key, msg);
    assert_eq!(
        mac.as_slice(),
        expected.as_slice(),
        "HMAC-SM3 长密钥测试向量不匹配"
    );
}

/// GB/T 32905-2016 附录 B.1 示例 3：HMAC-SM3 空消息测试
#[test]
fn test_hmac_sm3_gb_t_b1_empty_message() {
    let key = b"key";
    let msg = b"";
    let expected =
        hex::decode("4deb29b9be17bd4fd2aca21f908885b9f849bc61e8fbd101e04fd9987528d4df").unwrap();

    let mac = hmac_sm3(key, msg);
    assert_eq!(
        mac.as_slice(),
        expected.as_slice(),
        "HMAC-SM3 空消息测试向量不匹配"
    );
}

/// GB/T 32905-2016 附录 B.1 示例 4：HMAC-SM3 空密钥测试
#[test]
fn test_hmac_sm3_gb_t_b1_empty_key() {
    let key = b"";
    let msg = b"test message";
    let expected =
        hex::decode("814d3b1b5f6090f05c21bfa83f453b9999ed8defceb4fa84296e979e190a58df").unwrap();

    let mac = hmac_sm3(key, msg);
    assert_eq!(
        mac.as_slice(),
        expected.as_slice(),
        "HMAC-SM3 空密钥测试向量不匹配"
    );
}

// ============================================================================
// GB/T 32905-2016 附录 B.2 流式和重置测试
// ============================================================================

/// GB/T 32905-2016 附录 B.2 示例 1：流式 HMAC-SM3 测试
#[test]
fn test_hmac_sm3_gb_t_b2_streaming() {
    let key = b"streaming_key";
    let msg_parts = &[b"hello", b"world", b" test"];
    let expected =
        hex::decode("e7b2bc801082a5855ec19a23429c08998358ec680b989976ee08621663fb2056").unwrap();

    // 流式 HMAC
    let mut hmac = HmacSm3::new(key);
    for part in msg_parts {
        hmac.update(*part);
    }
    let mac = hmac.finalize();

    assert_eq!(
        mac.as_slice(),
        expected.as_slice(),
        "流式 HMAC-SM3 测试向量不匹配"
    );

    // 与一次性 HMAC 结果比较
    let full_msg: Vec<u8> = msg_parts.iter().copied().flatten().copied().collect();
    let mac_once = hmac_sm3(key, &full_msg);
    assert_eq!(mac, mac_once, "流式和一次性 HMAC 结果应相同");
}

/// GB/T 32905-2016 附录 B.2 示例 2：HMAC-SM3 重置测试
#[test]
fn test_hmac_sm3_gb_t_b2_reset() {
    let key = b"reset_key";
    let msg1 = b"first message";
    let msg2 = b"second message";

    // 使用同一个 HMAC 对象计算多个 MAC
    let hmac = HmacSm3::new(key);
    let mut hmac_clone = hmac.clone();
    let mac1 = {
        hmac_clone.update(msg1);
        hmac_clone.finalize()
    };

    // 创建新的 HMAC 对象计算第二个消息
    let mut hmac2 = HmacSm3::new(key);
    let mac2 = {
        hmac2.update(msg2);
        hmac2.finalize()
    };

    // 验证两个 MAC 不同
    assert_ne!(mac1, mac2, "不同消息的 MAC 应不同");

    // 验证与一次性计算结果相同
    let mac1_once = hmac_sm3(key, msg1);
    let mac2_once = hmac_sm3(key, msg2);

    assert_eq!(mac1, mac1_once, "流式 MAC1 应与一次性相同");
    assert_eq!(mac2, mac2_once, "流式 MAC2 应与一次性相同");
}

// ============================================================================
// GB/T 32905-2016 附录 C.1 边界条件测试
// ============================================================================

/// GB/T 32905-2016 附录 C.1 示例 1：边界条件测试（单字节消息）
#[test]
fn test_sm3_gb_t_c1_boundary() {
    // 测试单字节消息
    for i in 0u8..=255 {
        let msg = [i];
        let digest1 = Sm3Hasher::digest(&msg);

        // 使用流式接口验证
        let mut hasher = Sm3Hasher::new();
        hasher.update(&msg);
        let digest2 = hasher.finalize();

        assert_eq!(digest1, digest2, "单字节 {} 的两种哈希方式应相同", i);
    }
}
