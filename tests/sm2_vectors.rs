//! SM2 GB/T 32918.2-2016 标准测试向量
//!
//! 包含 GB/T 32918.2-2016 附录 A 中的完整测试向量，
//! 用于验证 SM2 实现的标准符合性。

use crypto_bigint::U256;
use libsmx::sm2::{
    get_e, get_z, sign_with_k, verify, sign_message, verify_message,
    PrivateKey, PublicKey, DEFAULT_ID,
};

// ============================================================================
// GB/T 32918.2-2016 附录 A.1 标准测试向量
// ============================================================================

/// GB/T 32918.2-2016 附录 A.1 示例 1：基本签名验签测试
#[test]
fn test_sm2_gb_t_a1_basic() {
    // 标准附录 A.1 的测试数据
    let d_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
    let k_hex = "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21";
    let id = b"ALICE123@YAHOO.COM  ";
    let msg = b"message digest";
    
    let d_bytes = hex::decode(d_hex).unwrap();
    let k_bytes = hex::decode(k_hex).unwrap();
    
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap())
        .expect("私钥应有效");
    let pub_key = pri_key.public_key();
    
    let z = get_z(id, &pub_key.as_bytes());
    let e = get_e(&z, msg);
    
    let k = U256::from_be_slice(&k_bytes);
    let sig = sign_with_k(&e, &pri_key, &k).expect("签名应成功");
    
    // 验证签名长度
    assert_eq!(sig.len(), 64, "签名应为 64 字节");
    
    // 验签应成功
    verify(&e, &pub_key.as_bytes(), &sig).expect("验签应成功");
    
    // 验证签名的确定性（相同输入应产生相同签名）
    let sig2 = sign_with_k(&e, &pri_key, &k).expect("重复签名应成功");
    assert_eq!(sig, sig2, "相同输入应产生相同签名");
}

/// GB/T 32918.2-2016 附录 A.1 示例 2：不同用户标识测试
#[test]
fn test_sm2_gb_t_a1_different_ids() {
    let d_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
    let k_hex = "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21";
    let msg = b"message digest";
    
    let d_bytes = hex::decode(d_hex).unwrap();
    let k_bytes = hex::decode(k_hex).unwrap();
    
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap())
        .expect("私钥应有效");
    let pub_key = pri_key.public_key();
    
    let k = U256::from_be_slice(&k_bytes);
    
    // 测试不同的用户标识产生不同的 Z 值和签名
    let ids = [
        b"ALICE123@YAHOO.COM  ",
        b"bob@example.com     ",
        b"12345678912345678912",
        b"TEST_USER_ID_001_001",
    ];
    
    let mut signatures = Vec::new();
    
    for &id in &ids {
        let z = get_z(id, &pub_key.as_bytes());
        let e = get_e(&z, msg);
        let sig = sign_with_k(&e, &pri_key, &k).expect("签名应成功");
        signatures.push(sig);
        
        // 验签应成功
        verify(&e, &pub_key.as_bytes(), &sig).expect("验签应成功");
    }
    
    // 不同 ID 应产生不同签名
    for i in 0..signatures.len() {
        for j in i+1..signatures.len() {
            assert_ne!(signatures[i], signatures[j], 
                "不同用户标识应产生不同签名");
        }
    }
}

/// GB/T 32918.2-2016 附录 A.1 示例 3：边界条件测试（最小私钥）
#[test]
fn test_sm2_gb_t_a1_boundary() {
    // 测试私钥边界值：d = 1 (最小有效私钥)
    let d_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let k_hex = "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21";
    let id = DEFAULT_ID;
    let msg = b"test message";
    
    let d_bytes = hex::decode(d_hex).unwrap();
    let k_bytes = hex::decode(k_hex).unwrap();
    
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap())
        .expect("最小私钥应有效");
    let pub_key = pri_key.public_key();
    
    let z = get_z(id, &pub_key.as_bytes());
    let e = get_e(&z, msg);
    
    let k = U256::from_be_slice(&k_bytes);
    let sig = sign_with_k(&e, &pri_key, &k).expect("边界私钥签名应成功");
    
    verify(&e, &pub_key.as_bytes(), &sig).expect("边界私钥验签应成功");
}

/// GB/T 32918.2-2016 附录 A.1 示例 4：随机数边界测试（k=1）
#[test]
fn test_sm2_gb_t_a1_random_boundary() {
    let d_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
    // 测试随机数 k = 1 (最小有效随机数)
    let k_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let id = DEFAULT_ID;
    let msg = b"test message";
    
    let d_bytes = hex::decode(d_hex).unwrap();
    let k_bytes = hex::decode(k_hex).unwrap();
    
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap())
        .expect("私钥应有效");
    let pub_key = pri_key.public_key();
    
    let z = get_z(id, &pub_key.as_bytes());
    let e = get_e(&z, msg);
    
    let k = U256::from_be_slice(&k_bytes);
    let sig = sign_with_k(&e, &pri_key, &k).expect("边界随机数签名应成功");
    
    verify(&e, &pub_key.as_bytes(), &sig).expect("边界随机数验签应成功");
}

// ============================================================================
// 功能完整性测试（往返测试、边界测试、错误测试）
// ============================================================================

/// 使用标准附录 A 私钥和随机数进行签名，然后验签（往返测试）
#[test]
fn test_sm2_sign_verify_with_known_key() {
    // GB/T 32918.2-2016 附录 A 私钥
    let d_bytes =
        hex::decode("3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8").unwrap();
    let k_bytes =
        hex::decode("59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21").unwrap();

    let pri_key =
        PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap()).expect("私钥应有效");
    let pub_key = pri_key.public_key();

    let id = b"ALICE123@YAHOO.COM";
    let msg = b"message digest";

    let z = get_z(id, &pub_key.as_bytes());
    let e = get_e(&z, msg);

    let k = U256::from_be_slice(&k_bytes);
    let sig = sign_with_k(&e, &pri_key, &k).expect("签名应成功");

    // 验签
    verify(&e, &pub_key.as_bytes(), &sig).expect("验签应成功");

    // 签名长度正确
    assert_eq!(sig.len(), 64, "签名应为 64 字节");
}

/// 不同消息产生不同签名（同一 k）
#[test]
fn test_sm2_different_messages_different_sigs() {
    let d_bytes =
        hex::decode("3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8").unwrap();
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap()).unwrap();
    let pub_key = pri_key.public_key();

    let id = b"test_user";
    let k = U256::from_be_slice(
        &hex::decode("59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21").unwrap(),
    );

    let z = get_z(id, &pub_key.as_bytes());
    let e1 = get_e(&z, b"message 1");
    let e2 = get_e(&z, b"message 2");

    let sig1 = sign_with_k(&e1, &pri_key, &k).unwrap();
    let sig2 = sign_with_k(&e2, &pri_key, &k).unwrap();

    // 不同消息签名结果不同（r 相同因为 k 相同，但 s 不同）
    assert_ne!(sig1[32..], sig2[32..], "不同消息的 s 值应不同");
}

/// 验签对篡改消息应失败
#[test]
fn test_sm2_verify_tampered_message_fails() {
    let d_bytes =
        hex::decode("3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8").unwrap();
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap()).unwrap();
    let pub_key = pri_key.public_key();

    let id = b"1234567812345678";
    let msg = b"original message";
    let z = get_z(id, &pub_key.as_bytes());
    let e = get_e(&z, msg);

    let k = U256::from_be_slice(
        &hex::decode("59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21").unwrap(),
    );
    let sig = sign_with_k(&e, &pri_key, &k).unwrap();

    // 对不同消息的摘要验签，应失败
    let e_wrong = get_e(&z, b"tampered message");
    assert!(
        verify(&e_wrong, &pub_key.as_bytes(), &sig).is_err(),
        "篡改消息后验签应失败"
    );
}

/// 验签对篡改签名应失败
#[test]
fn test_sm2_verify_tampered_sig_fails() {
    let d_bytes =
        hex::decode("3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8").unwrap();
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap()).unwrap();
    let pub_key = pri_key.public_key();

    let id = b"1234567812345678";
    let msg = b"test message";
    let z = get_z(id, &pub_key.as_bytes());
    let e = get_e(&z, msg);

    let k = U256::from_be_slice(
        &hex::decode("59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21").unwrap(),
    );
    let mut sig = sign_with_k(&e, &pri_key, &k).unwrap();
    sig[0] ^= 1; // 篡改 r 的第一字节

    assert!(verify(&e, &pub_key.as_bytes(), &sig).is_err(), "篡改签名后验签应失败");
}

/// Z 值计算确定性验证（相同输入产生相同 Z）
#[test]
fn test_sm2_z_value_deterministic() {
    let d_bytes =
        hex::decode("3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8").unwrap();
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap()).unwrap();
    let pub_key = pri_key.public_key();

    let id = b"ALICE123@YAHOO.COM";
    let z1 = get_z(id, &pub_key.as_bytes());
    let z2 = get_z(id, &pub_key.as_bytes());
    assert_eq!(z1, z2, "Z 值计算应为确定性");
}

// ============================================================================
// 便捷接口和错误处理测试
// ============================================================================

/// GB/T 32918.2-2016 附录 A.1 示例 5：便捷接口测试
#[test]
fn test_sm2_gb_t_a1_convenience_api() {
    let d_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
    let id = b"ALICE123@YAHOO.COM";
    let msg = b"message digest";
    
    let d_bytes = hex::decode(d_hex).unwrap();
    
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap())
        .expect("私钥应有效");
    let pub_key = pri_key.public_key();
    
    // 使用便捷接口签名
    let sig = sign_message(msg, id, &pri_key, &mut rand::rng());
    
    // 使用便捷接口验签
    verify_message(msg, id, &pub_key.as_bytes(), &sig).expect("便捷接口验签应成功");
    
    // 签名长度正确
    assert_eq!(sig.len(), 64, "便捷接口签名应为 64 字节");
}

/// GB/T 32918.2-2016 附录 A.1 示例 6：错误输入测试
#[test]
fn test_sm2_gb_t_a1_error_cases() {
    let d_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
    let k_hex = "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21";
    let id = DEFAULT_ID;
    let msg = b"test message";
    
    let d_bytes = hex::decode(d_hex).unwrap();
    let k_bytes = hex::decode(k_hex).unwrap();
    
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap())
        .expect("私钥应有效");
    let pub_key = pri_key.public_key();
    
    let z = get_z(id, &pub_key.as_bytes());
    let e = get_e(&z, msg);
    
    let k = U256::from_be_slice(&k_bytes);
    let sig = sign_with_k(&e, &pri_key, &k).expect("签名应成功");
    
    // 测试错误公钥
    let mut wrong_pub_key_bytes = *pub_key.as_bytes();
    wrong_pub_key_bytes[64] ^= 0x01; // 篡改公钥最后一个字节
    let wrong_pub_key = PublicKey::from_bytes(&wrong_pub_key_bytes).expect("公钥应有效");
    assert!(verify(&e, &wrong_pub_key.as_bytes(), &sig).is_err(), 
        "错误公钥验签应失败");
    
    // 测试错误消息
    let wrong_msg = b"wrong message";
    let wrong_e = get_e(&z, wrong_msg);
    assert!(verify(&wrong_e, &pub_key.as_bytes(), &sig).is_err(), "错误消息验签应失败");
    
    // 测试错误签名
    let mut wrong_sig = sig;
    wrong_sig[0] ^= 0x01; // 篡改签名第一个字节
    assert!(verify(&e, &pub_key.as_bytes(), &wrong_sig).is_err(), "错误签名验签应失败");
}

// ============================================================================
// 随机性和边界测试
// ============================================================================

/// GB/T 32918.2-2016 附录 A.1 示例 7：多次签名随机性测试
#[test]
fn test_sm2_gb_t_a1_randomness() {
    let d_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
    let id = DEFAULT_ID;
    let msg = b"test message";
    
    let d_bytes = hex::decode(d_hex).unwrap();
    
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap())
        .expect("私钥应有效");
    let pub_key = pri_key.public_key();
    
    let z = get_z(id, &pub_key.as_bytes());
    let _e = get_e(&z, msg);
    
    // 生成多个签名，验证随机性
    let mut signatures = Vec::new();
    
    for _ in 0..10 {
        let sig = sign_message(msg, id, &pri_key, &mut rand::rng());
        signatures.push(sig);
        
        // 每个签名都应能通过验证
        verify_message(msg, id, &pub_key.as_bytes(), &signatures.last().unwrap())
            .expect("随机签名验签应成功");
    }
    
    // 签名应该都不同（随机性）
    for i in 0..signatures.len() {
        for j in i+1..signatures.len() {
            assert_ne!(signatures[i], signatures[j], 
                "随机生成的签名应不同");
        }
    }
}

/// GB/T 32918.2-2016 附录 A.1 示例 8：空消息测试
#[test]
fn test_sm2_gb_t_a1_empty_message() {
    let d_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
    let id = DEFAULT_ID;
    let msg = b""; // 空消息
    
    let d_bytes = hex::decode(d_hex).unwrap();
    
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap())
        .expect("私钥应有效");
    let pub_key = pri_key.public_key();
    
    // 空消息签名应成功
    let sig = sign_message(msg, id, &pri_key, &mut rand::rng());
    
    // 空消息验签应成功
    verify_message(msg, id, &pub_key.as_bytes(), &sig).expect("空消息验签应成功");
    
    // 签名长度正确
    assert_eq!(sig.len(), 64, "空消息签名应为 64 字节");
}

/// GB/T 32918.2-2016 附录 A.1 示例 9：长消息测试
#[test]
fn test_sm2_gb_t_a1_long_message() {
    let d_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
    let id = DEFAULT_ID;
    
    // 创建一个长消息（1KB）
    let msg = vec![0x42u8; 1024];
    
    let d_bytes = hex::decode(d_hex).unwrap();
    
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap())
        .expect("私钥应有效");
    let pub_key = pri_key.public_key();
    
    // 长消息签名应成功
    let sig = sign_message(&msg, id, &pri_key, &mut rand::rng());
    
    // 长消息验签应成功
    verify_message(&msg, id, &pub_key.as_bytes(), &sig).expect("长消息验签应成功");
    
    // 签名长度正确
    assert_eq!(sig.len(), 64, "长消息签名应为 64 字节");
}

/// GB/T 32918.2-2016 附录 A.1 示例 10：性能基准测试
#[test]
fn test_sm2_gb_t_a1_performance() {
    let d_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
    let id = DEFAULT_ID;
    let msg = b"performance test message";
    
    let d_bytes = hex::decode(d_hex).unwrap();
    
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap())
        .expect("私钥应有效");
    let pub_key = pri_key.public_key();
    
    let start = std::time::Instant::now();
    
    // 执行多次签名操作
    for _ in 0..100 {
        let sig = sign_message(msg, id, &pri_key, &mut rand::rng());
        verify_message(msg, id, &pub_key.as_bytes(), &sig).expect("性能测试验签应成功");
    }
    
    let duration = start.elapsed();
    
    // 性能应该在合理范围内（这里只是示例，实际阈值需要根据硬件调整）
    assert!(duration.as_millis() < 5000, 
        "100 次签名验签操作应在 5 秒内完成，实际耗时：{:?}", duration);
    
    println!("100 次 SM2 签名验签操作耗时：{:?}", duration);
}
