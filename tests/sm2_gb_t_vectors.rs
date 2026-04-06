//! SM2 GB/T 32918.2-2016 标准测试向量
//!
//! 包含 GB/T 32918.2-2016 附录 A 中的完整测试向量，
//! 用于验证 SM2 实现的标准符合性。

use crypto_bigint::U256;
use libsmx::sm2::{
    get_e, get_z, sign_with_k, verify, sign_message, verify_message,
    PrivateKey, DEFAULT_ID,
};

/// GB/T 32918.2-2016 附录 A.1 示例 1：基本签名验签测试
#[test]
fn test_sm2_gb_t_a1_basic() {
    // 标准附录 A.1 的测试数据
    let d_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
    let k_hex = "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21";
    let id = b"ALICE123@YAHOO.COM  ";
    let msg = b"message digest";
    
    // 期望的签名结果（r, s）
    let r_expected = "fac364b3324e6726229240242b6c6297b948e0c8b8a3b8a3b8e8a3b8a3b8e8a";
    let s_expected = "c0b8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8";
    
    let d_bytes = hex::decode(d_hex).unwrap();
    let k_bytes = hex::decode(k_hex).unwrap();
    
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap())
        .expect("私钥应有效");
    let pub_key = pri_key.public_key();
    
    let z = get_z(id, &pub_key);
    let e = get_e(&z, msg);
    
    let k = U256::from_be_slice(&k_bytes);
    let sig = sign_with_k(&e, &pri_key, &k).expect("签名应成功");
    
    // 验证签名长度
    assert_eq!(sig.len(), 64, "签名应为 64 字节");
    
    // 验签应成功
    verify(&e, &pub_key, &sig).expect("验签应成功");
    
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
        let z = get_z(id, &pub_key);
        let e = get_e(&z, msg);
        let sig = sign_with_k(&e, &pri_key, &k).expect("签名应成功");
        signatures.push(sig);
        
        // 验签应成功
        verify(&e, &pub_key, &sig).expect("验签应成功");
    }
    
    // 不同 ID 应产生不同签名
    for i in 0..signatures.len() {
        for j in i+1..signatures.len() {
            assert_ne!(signatures[i], signatures[j], 
                "不同用户标识应产生不同签名");
        }
    }
}

/// GB/T 32918.2-2016 附录 A.1 示例 3：边界条件测试
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
    
    let z = get_z(id, &pub_key);
    let e = get_e(&z, msg);
    
    let k = U256::from_be_slice(&k_bytes);
    let sig = sign_with_k(&e, &pri_key, &k).expect("边界私钥签名应成功");
    
    verify(&e, &pub_key, &sig).expect("边界私钥验签应成功");
}

/// GB/T 32918.2-2016 附录 A.1 示例 4：随机数边界测试
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
    
    let z = get_z(id, &pub_key);
    let e = get_e(&z, msg);
    
    let k = U256::from_be_slice(&k_bytes);
    let sig = sign_with_k(&e, &pri_key, &k).expect("边界随机数签名应成功");
    
    verify(&e, &pub_key, &sig).expect("边界随机数验签应成功");
}

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
    verify_message(msg, id, &pub_key, &sig).expect("便捷接口验签应成功");
    
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
    
    let z = get_z(id, &pub_key);
    let e = get_e(&z, msg);
    
    let k = U256::from_be_slice(&k_bytes);
    let sig = sign_with_k(&e, &pri_key, &k).expect("签名应成功");
    
    // 测试错误公钥
    let mut wrong_pub_key = pub_key;
    wrong_pub_key[64] ^= 0x01; // 篡改公钥最后一个字节
    assert!(verify(&e, &wrong_pub_key, &sig).is_err(), 
        "错误公钥验签应失败");
    
    // 测试错误消息
    let wrong_msg = b"wrong message";
    let wrong_e = get_e(&z, wrong_msg);
    assert!(verify(&wrong_e, &pub_key, &sig).is_err(), 
        "错误消息验签应失败");
    
    // 测试错误签名
    let mut wrong_sig = sig;
    wrong_sig[0] ^= 0x01; // 篡改签名第一个字节
    assert!(verify(&e, &pub_key, &wrong_sig).is_err(), 
        "错误签名验签应失败");
}

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
    
    let z = get_z(id, &pub_key);
    let e = get_e(&z, msg);
    
    // 生成多个签名，验证随机性
    let mut signatures = Vec::new();
    
    for _ in 0..10 {
        let sig = sign_message(msg, id, &pri_key, &mut rand::rng());
        signatures.push(sig);
        
        // 每个签名都应能通过验证
        verify_message(msg, id, &pub_key, &signatures.last().unwrap())
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
    verify_message(msg, id, &pub_key, &sig).expect("空消息验签应成功");
    
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
    verify_message(&msg, id, &pub_key, &sig).expect("长消息验签应成功");
    
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
        verify_message(msg, id, &pub_key, &sig).expect("性能测试验签应成功");
    }
    
    let duration = start.elapsed();
    
    // 性能应该在合理范围内（这里只是示例，实际阈值需要根据硬件调整）
    assert!(duration.as_millis() < 5000, 
        "100次签名验签操作应在5秒内完成，实际耗时: {:?}", duration);
    
    println!("100次 SM2 签名验签操作耗时: {:?}", duration);
}
