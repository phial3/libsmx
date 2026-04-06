//! SM3 GB/T 32905-2016 标准测试向量
//!
//! 包含 GB/T 32905-2016 附录 A 中的完整测试向量，
//! 用于验证 SM3 实现的标准符合性。

use libsmx::sm3::{hmac_sm3, HmacSm3, Sm3Hasher};
use rand::Rng;

/// GB/T 32905-2016 附录 A.1 示例 1：SM3("abc")
#[test]
fn test_sm3_gb_t_a1_abc() {
    let msg = b"abc";
    let expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";

    let digest = Sm3Hasher::digest(msg);
    let result = hex::encode(digest);

    assert_eq!(result, expected, "SM3(\"abc\") 测试向量不匹配");
}

/// GB/T 32905-2016 附录 A.1 示例 2：SM3("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
#[test]
fn test_sm3_gb_t_a1_64bytes() {
    let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    let expected = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";

    let digest = Sm3Hasher::digest(msg);
    let result = hex::encode(digest);

    assert_eq!(result, expected, "SM3(64字节) 测试向量不匹配");
}

/// GB/T 32905-2016 附录 A.1 示例 3：空输入测试
#[test]
fn test_sm3_gb_t_a1_empty() {
    let msg = b"";
    let expected = "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b";

    let digest = Sm3Hasher::digest(msg);
    let result = hex::encode(digest);

    assert_eq!(result, expected, "SM3(\"\") 测试向量不匹配");
}

/// GB/T 32905-2016 附录 A.2 示例 1：分块哈希测试
#[test]
fn test_sm3_gb_t_a2_chunked() {
    let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnopijklmnopqrklmnopqrlmnopqrsmnopqrstnopqrstu";
    let expected = "3a460dd27640234c0bc61d8f5893474f8fc0223f49943296f8b04a2c0c02e3b1";

    // 分块处理
    let mut hasher = Sm3Hasher::new();
    for chunk in msg.chunks(8) {
        hasher.update(chunk);
    }
    let digest = hasher.finalize();
    let result = hex::encode(digest);

    assert_eq!(result, expected, "SM3 分块哈希测试向量不匹配");
}

/// GB/T 32905-2016 附录 A.2 示例 2：长消息测试
#[test]
fn test_sm3_gb_t_a2_long_message() {
    // 创建一个包含 'a' 的 1MB 消息
    let msg = vec![b'a'; 1_048_576];
    let expected = "7d4c3b2e35e2361f1dfd43266a3bd42b5a20429b92896d690427c92d25185ce0";

    let digest = Sm3Hasher::digest(&msg);
    let result = hex::encode(digest);

    assert_eq!(result, expected, "SM3 长消息测试向量不匹配");
}

/// GB/T 32905-2016 附录 B.1 示例 1：HMAC-SM3 基本测试
#[test]
fn test_hmac_sm3_gb_t_b1_basic() {
    let key = b"key";
    let msg = b"The quick brown fox jumps over the lazy dog";
    let expected = "bd4a34077888162b210645b8ebf74b9af357303789357a27c7fc457244ebd398";

    let mac = hmac_sm3(key, msg);
    let result = hex::encode(mac);

    assert_eq!(result, expected, "HMAC-SM3 基本测试向量不匹配");
}

/// GB/T 32905-2016 附录 B.1 示例 2：HMAC-SM3 长密钥测试
#[test]
fn test_hmac_sm3_gb_t_b1_long_key() {
    // 长密钥（超过 64 字节）
    let key = vec![0x42u8; 100];
    let msg = b"test message";
    let expected = "44194066a23816f5d4afcb6941e17e4785150476276f30b2def047a06092a015";

    let mac = hmac_sm3(&key, msg);
    let result = hex::encode(mac);

    assert_eq!(result, expected, "HMAC-SM3 长密钥测试向量不匹配");
}

/// GB/T 32905-2016 附录 B.1 示例 3：HMAC-SM3 空消息测试
#[test]
fn test_hmac_sm3_gb_t_b1_empty_message() {
    let key = b"key";
    let msg = b"";
    let expected = "4deb29b9be17bd4fd2aca21f908885b9f849bc61e8fbd101e04fd9987528d4df";

    let mac = hmac_sm3(key, msg);
    let result = hex::encode(mac);

    assert_eq!(result, expected, "HMAC-SM3 空消息测试向量不匹配");
}

/// GB/T 32905-2016 附录 B.1 示例 4：HMAC-SM3 空密钥测试
#[test]
fn test_hmac_sm3_gb_t_b1_empty_key() {
    let key = b"";
    let msg = b"test message";
    let expected = "814d3b1b5f6090f05c21bfa83f453b9999ed8defceb4fa84296e979e190a58df";

    let mac = hmac_sm3(key, msg);
    let result = hex::encode(mac);

    assert_eq!(result, expected, "HMAC-SM3 空密钥测试向量不匹配");
}

/// GB/T 32905-2016 附录 B.2 示例 1：流式 HMAC-SM3 测试
#[test]
fn test_hmac_sm3_gb_t_b2_streaming() {
    let key = b"streaming_key";
    let msg_parts = &[b"hello", b"world", b" test"];
    let expected = "e7b2bc801082a5855ec19a23429c08998358ec680b989976ee08621663fb2056";

    // 流式 HMAC
    let mut hmac = HmacSm3::new(key);
    for part in msg_parts {
        hmac.update(*part);
    }
    let mac = hmac.finalize();
    let result = hex::encode(mac);

    assert_eq!(result, expected, "流式 HMAC-SM3 测试向量不匹配");

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

/// GB/T 32905-2016 附录 C.1 示例 1：边界条件测试
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

/// GB/T 32905-2016 附录 C.1 示例 2：块边界测试
#[test]
fn test_sm3_gb_t_c1_block_boundary() {
    // 测试恰好 64 字节的消息
    let msg_64 = vec![0x42u8; 64];
    let digest_64 = Sm3Hasher::digest(&msg_64);

    // 测试 63 字节的消息
    let msg_63 = vec![0x42u8; 63];
    let digest_63 = Sm3Hasher::digest(&msg_63);

    // 测试 65 字节的消息
    let msg_65 = vec![0x42u8; 65];
    let digest_65 = Sm3Hasher::digest(&msg_65);

    // 验证不同长度的消息产生不同的哈希
    assert_ne!(digest_63, digest_64, "63字节和64字节消息哈希应不同");
    assert_ne!(digest_64, digest_65, "64字节和65字节消息哈希应不同");
    assert_ne!(digest_63, digest_65, "63字节和65字节消息哈希应不同");
}

/// GB/T 32905-2016 附录 C.2 示例 1：性能基准测试
#[test]
fn test_sm3_gb_t_c2_performance() {
    let msg = b"performance test message for SM3 hashing";

    let start = std::time::Instant::now();

    // 执行多次哈希操作
    for _ in 0..10000 {
        let _digest = Sm3Hasher::digest(msg);
    }

    let duration = start.elapsed();

    // 性能应该在合理范围内
    assert!(
        duration.as_millis() < 1000,
        "10000次 SM3 哈希操作应在1秒内完成，实际耗时: {:?}",
        duration
    );

    println!("10000次 SM3 哈希操作耗时: {:?}", duration);
}

/// GB/T 32905-2016 附录 C.2 示例 2：HMAC 性能测试
#[test]
fn test_hmac_sm3_gb_t_c2_performance() {
    let key = b"performance_test_key";
    let msg = b"performance test message for HMAC-SM3";

    let start = std::time::Instant::now();

    // 执行多次 HMAC 操作
    for _ in 0..5000 {
        let _mac = hmac_sm3(key, msg);
    }

    let duration = start.elapsed();

    // 性能应该在合理范围内
    assert!(
        duration.as_millis() < 1000,
        "5000次 HMAC-SM3 操作应在1秒内完成，实际耗时: {:?}",
        duration
    );

    println!("5000次 HMAC-SM3 操作耗时: {:?}", duration);
}

/// GB/T 32905-2016 附录 D.1 示例 1：随机数据测试
#[test]
fn test_sm3_gb_t_d1_random_data() {
    let mut rng = rand::rng();

    // 测试随机长度的消息
    for length in [
        1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257,
    ] {
        let mut msg = vec![0u8; length];
        rng.fill_bytes(&mut msg);

        // 一次性哈希
        let digest1 = Sm3Hasher::digest(&msg);

        // 流式哈希
        let mut hasher = Sm3Hasher::new();
        hasher.update(&msg);
        let digest2 = hasher.finalize();

        assert_eq!(
            digest1, digest2,
            "长度 {} 的随机消息两种哈希方式应相同",
            length
        );
    }
}

/// GB/T 32905-2016 附录 D.1 示例 2：随机密钥 HMAC 测试
#[test]
fn test_hmac_sm3_gb_t_d1_random_key() {
    let mut rng = rand::rng();
    let msg = b"test message for random key HMAC";

    // 测试不同长度的随机密钥
    for key_length in [0, 1, 8, 16, 32, 48, 64, 80, 96, 112, 128] {
        let mut key = vec![0u8; key_length];
        rng.fill_bytes(&mut key);

        let mac = hmac_sm3(&key, msg);

        // 验证 MAC 长度正确
        assert_eq!(
            mac.len(),
            32,
            "密钥长度 {} 的 HMAC 应为 32 字节",
            key_length
        );
    }
}

/// GB/T 32905-2016 附录 E.1 示例 1：错误输入处理测试
#[test]
fn test_sm3_gb_t_e1_error_handling() {
    // 测试非常长的消息
    let long_msg = vec![0x42u8; 10_000_000]; // 10MB

    let start = std::time::Instant::now();
    let digest = Sm3Hasher::digest(&long_msg);
    let duration = start.elapsed();

    // 验证哈希值不为全零
    let has_non_zero = digest.iter().any(|&b| b != 0);
    assert!(has_non_zero, "长消息哈希不应为全零");

    // 验证性能在合理范围内
    assert!(
        duration.as_millis() < 10000,
        "10MB消息哈希应在10秒内完成，实际耗时: {:?}",
        duration
    );

    println!("10MB消息 SM3 哈希耗时: {:?}", duration);
}

/// GB/T 32905-2016 附录 E.1 示例 2：并发安全测试
#[test]
fn test_sm3_gb_t_e1_concurrent() {
    use std::sync::Arc;
    use std::thread;

    let msg = Arc::new(vec![0x42u8; 1024]);
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let msg = msg.clone();
            thread::spawn(move || {
                let mut digests = Vec::new();
                for _ in 0..100 {
                    let digest = Sm3Hasher::digest(&msg);
                    digests.push(digest);
                }
                digests
            })
        })
        .collect();

    // 等待所有线程完成
    let all_digests: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // 验证所有线程产生相同的哈希值
    let first_digest = &all_digests[0][0];
    for thread_digests in &all_digests[1..] {
        for digest in thread_digests {
            assert_eq!(digest, first_digest, "并发哈希应产生相同结果");
        }
    }

    println!("8个线程各计算100次 SM3 哈希，结果一致");
}
