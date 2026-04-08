//! 国密电子签章功能测试
//!
//! 测试使用 `cms` 包提供的类型定义实现完整的电子签章创建和验证功能。

#![cfg(feature = "std")]

use libsmx::sm2::cert::generate_self_signed_cert;
use libsmx::sm2::cms;
use libsmx::sm2::{generate_keypair, DEFAULT_ID};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn test_create_and_verify_signature() {
    let mut rng = StdRng::seed_from_u64(123456);
    
    // 生成密钥对
    let (priv_key, _pub_key) = generate_keypair(&mut rng);
    
    // 生成自签名证书
    let cert = generate_self_signed_cert(
        &priv_key,
        b"Test User",
        b"250101000000Z300101000000Z", // 有效期：2025-01-01 到 2030-01-01
        b"01", // 序列号
        DEFAULT_ID,
        None, // 无扩展
        &mut rng,
    ).unwrap();
    
    println!("GmCertificate created");
    println!("  Serial: {:02x?}", &cert.serial_number);
    println!("  Issuer len: {}", cert.issuer.len());
    println!("  Subject len: {}", cert.subject.len());
    
    let cert_der = cert.to_der();
    println!("  DER encoded: {} bytes", cert_der.len());
    println!("  DER first 30 bytes: {:02x?}", &cert_der[..30]);
    
    // 测试数据
    let data = b"Hello, World!";
    
    // 创建电子签章
    let signature = cms::create_digital_signature(
        data,
        &priv_key,
        &cert,
        DEFAULT_ID,
        &mut rng,
        true, // 包含时间戳
    ).expect("Failed to create signature");
    
    println!("Signature created successfully, length: {} bytes", signature.len());
    
    // 验证电子签章
    let result = cms::verify_digital_signature(&signature, DEFAULT_ID)
        .expect("Failed to verify signature");
    
    assert!(result.is_valid, "Signature verification should succeed");
    assert_eq!(result.signer_results.len(), 1, "Should have one signer");
    assert_eq!(result.content, data.to_vec(), "Content should match");
    assert!(result.all_errors().is_empty(), "Should have no errors");
    
    println!("Signature verified successfully!");
}

#[test]
fn test_signature_without_time() {
    let mut rng = StdRng::seed_from_u64(789012);
    
    // 生成密钥对
    let (priv_key, _pub_key) = generate_keypair(&mut rng);
    
    // 生成自签名证书
    let cert = generate_self_signed_cert(
        &priv_key,
        b"Test User 2",
        b"250101000000Z300101000000Z",
        b"02",
        DEFAULT_ID,
        None,
        &mut rng,
    ).unwrap();
    
    // 测试数据
    let data = b"Test data without timestamp";
    
    // 创建电子签章（不包含时间戳）
    let signature = cms::create_digital_signature(
        data,
        &priv_key,
        &cert,
        DEFAULT_ID,
        &mut rng,
        false, // 不包含时间戳
    ).expect("Failed to create signature");
    
    println!("Signature without time created, length: {} bytes", signature.len());
    
    // 验证电子签章
    let result = cms::verify_digital_signature(&signature, DEFAULT_ID)
        .expect("Failed to verify signature");
    
    assert!(result.is_valid, "Signature verification should succeed");
    assert_eq!(result.signer_results.len(), 1, "Should have one signer");
    
    println!("Signature without time verified successfully!");
}

#[test]
fn test_signature_verification_fails_with_wrong_data() {
    let mut rng = StdRng::seed_from_u64(345678);
    
    // 生成密钥对
    let (priv_key, _pub_key) = generate_keypair(&mut rng);
    
    // 生成自签名证书
    let cert = generate_self_signed_cert(
        &priv_key,
        b"Test User 3",
        b"250101000000Z300101000000Z",
        b"03",
        DEFAULT_ID,
        None,
        &mut rng,
    ).unwrap();
    
    // 测试数据
    let original_data = b"Original data";
    let tampered_data = b"Tampered data";
    
    // 创建电子签章
    let signature = cms::create_digital_signature(
        original_data,
        &priv_key,
        &cert,
        DEFAULT_ID,
        &mut rng,
        true,
    ).expect("Failed to create signature");
    
    // 使用错误的数据验证应该失败
    let result = cms::verify_digital_signature(&signature, DEFAULT_ID)
        .expect("Failed to verify signature");
    
    assert!(!result.is_valid, "Signature verification should fail with wrong data");
    
    println!("Signature verification correctly failed with tampered data!");
}

#[test]
fn test_signature_with_large_data() {
    let mut rng = StdRng::seed_from_u64(901234);
    
    // 生成密钥对
    let (priv_key, _pub_key) = generate_keypair(&mut rng);
    
    // 生成自签名证书
    let cert = generate_self_signed_cert(
        &priv_key,
        b"Test User 4",
        b"250101000000Z300101000000Z",
        b"04",
        DEFAULT_ID,
        None,
        &mut rng,
    ).unwrap();
    
    // 测试大数据（1MB）
    let data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    
    // 创建电子签章
    let signature = cms::create_digital_signature(
        &data,
        &priv_key,
        &cert,
        DEFAULT_ID,
        &mut rng,
        true,
    ).expect("Failed to create signature");
    
    println!("Signature for large data created, length: {} bytes", signature.len());
    
    // 验证电子签章
    let result = cms::verify_digital_signature(&signature, DEFAULT_ID)
        .expect("Failed to verify signature");
    
    assert!(result.is_valid, "Signature verification should succeed for large data");
    assert_eq!(result.signer_results.len(), 1, "Should have one signer");
    assert_eq!(result.content, data, "Content should match");
    
    println!("Signature for large data verified successfully!");
}

#[test]
fn test_signature_with_empty_data() {
    let mut rng = StdRng::seed_from_u64(567890);
    
    // 生成密钥对
    let (priv_key, _pub_key) = generate_keypair(&mut rng);
    
    // 生成自签名证书
    let cert = generate_self_signed_cert(
        &priv_key,
        b"Test User 5",
        b"250101000000Z300101000000Z",
        b"05",
        DEFAULT_ID,
        None,
        &mut rng,
    ).unwrap();
    
    // 测试空数据
    let data = b"";
    
    // 创建电子签章
    let signature = cms::create_digital_signature(
        data,
        &priv_key,
        &cert,
        DEFAULT_ID,
        &mut rng,
        true,
    ).expect("Failed to create signature");
    
    println!("Signature for empty data created, length: {} bytes", signature.len());
    
    // 验证电子签章
    let result = cms::verify_digital_signature(&signature, DEFAULT_ID)
        .expect("Failed to verify signature");
    
    assert!(result.is_valid, "Signature verification should succeed for empty data");
    assert_eq!(result.signer_results.len(), 1, "Should have one signer");
    assert_eq!(result.content, data, "Content should match");
    
    println!("Signature for empty data verified successfully!");
}
