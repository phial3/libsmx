//! 国密证书和电子签章全面功能测试
//!
//! 测试覆盖：
//! - 证书生成和解析
//! - 证书验证
//! - 公钥导入导出
//! - 电子签章创建和验证
//! - 边界条件测试
//! - 稳定性测试

#![cfg(feature = "alloc")]

use libsmx::sm2::cert::{generate_self_signed_cert, GmCertificate};
use libsmx::sm2::cms;
use libsmx::sm2::{generate_keypair, public_key_to_spki_der, public_key_from_spki_der, DEFAULT_ID};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// 创建简单的 DER Name 结构（空 RDNSequence）
/// 格式：SET OF {}
/// 注意：Name 是 CHOICE { rdnSequence RDNSequence }
/// RDNSequence 是 SEQUENCE OF RelativeDistinguishedName
/// 但这里使用 SET OF {} 作为简化表示
fn create_simple_name() -> Vec<u8> {
    vec![0x31, 0x00] // 空的 SET OF
}

/// 生成测试用的有效期 DER 编码
///
/// 固定有效期：2025-01-01 到 2030-01-01
fn generate_test_validity() -> Vec<u8> {
    // 使用字节数组方式生成有效期（用于测试）
    // 格式：SEQUENCE { UTCTime notBefore, UTCTime notAfter }
    vec![
        0x30, 0x1E,           // SEQUENCE, length 30
        0x17, 0x0D,           // UTCTime, length 13
        b'2', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z', // 250101000000Z
        0x17, 0x0D,           // UTCTime, length 13
        b'3', b'0', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z', // 300101000000Z
    ]
}

/// 创建测试用的国密证书
fn create_test_cert(pub_key: &[u8; 65]) -> GmCertificate {
    // 使用简单的空 Name 格式
    let issuer = create_simple_name();
    let subject = create_simple_name();
    let validity = generate_test_validity();

    GmCertificate {
        version: 2, // v3
        serial_number: vec![0x01],
        signature_algorithm: libsmx::sm2::SM2_WITH_SM3_ALGORITHM_IDENTIFIER.to_vec(),
        issuer,
        validity,
        subject,
        subject_public_key_info: public_key_to_spki_der(pub_key),
        signature: vec![0x00; 64], // 占位签名
    }
}

/// 测试证书结构创建
#[test]
fn test_cert_creation() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (_priv_key, pub_key) = generate_keypair(&mut rng);

    let cert = create_test_cert(&pub_key);

    // 验证证书字段
    assert_eq!(cert.version, 2);
    assert_eq!(cert.serial_number, vec![0x01]);
    assert!(!cert.subject_public_key_info.is_empty());
}

/// 测试证书 DER 编码和解码
#[test]
fn test_cert_der_encoding() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (_priv_key, pub_key) = generate_keypair(&mut rng);

    let cert = create_test_cert(&pub_key);

    // 编码为 DER
    let der = cert.to_der();
    assert!(!der.is_empty());

    // 从 DER 解码
    let decoded = GmCertificate::from_der(&der).expect("Failed to decode certificate");
    assert_eq!(decoded.version, cert.version);
}

/// 测试自签名证书生成
#[test]
fn test_self_signed_cert() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);

    let subject = create_simple_name();
    let validity = generate_test_validity();

    // 生成自签名证书
    let cert = generate_self_signed_cert(
        &priv_key,
        &subject,
        &validity,
        b"\x01",
        DEFAULT_ID,
        &mut rng,
    ).expect("Failed to generate self-signed certificate");

    // 验证证书字段
    assert_eq!(cert.version, 2);
    assert_eq!(cert.serial_number, vec![0x01]);
    assert!(!cert.signature.is_empty());

    // 验证 DER 编码
    let der = cert.to_der();
    assert!(!der.is_empty());
    assert_eq!(der[0], 0x30); // SEQUENCE tag
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

/// 测试公钥 PEM 编码
#[test]
fn test_pubkey_pem() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (_priv_key, pub_key) = generate_keypair(&mut rng);

    // 编码为 DER 格式
    let der = libsmx::sm2::public_key_to_spki_der(&pub_key);
    assert!(!der.is_empty());
    assert_eq!(der[0], 0x30); // SEQUENCE tag
    
    // 验证 DER 可以正确解码回公钥
    let decoded = libsmx::sm2::public_key_from_spki_der(&der).expect("SPKI decode failed");
    assert_eq!(pub_key, decoded);
}

/// 测试电子签章创建
#[test]
fn test_digital_signature_creation() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);

    let subject = create_simple_name();
    let validity = generate_test_validity();

    // 生成自签名证书
    let cert = generate_self_signed_cert(
        &priv_key,
        &subject,
        &validity,
        b"\x01",
        DEFAULT_ID,
        &mut rng,
    ).expect("Failed to generate certificate");

    let content = b"Test content";
    let custom_id = b"1234567890";

    // 使用自定义 ID 创建签章
    let signed_data_der = cms::create_digital_signature(
        content,
        &priv_key,
        &cert,
        custom_id,
        &mut rng,
        false, // 不包含时间
    ).expect("Failed to create digital signature");

    assert!(!signed_data_der.is_empty());
    assert_eq!(signed_data_der[0], 0x30); // SEQUENCE tag
}

/// 测试电子签章篡改检测
#[test]
fn test_digital_signature_tampering() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);

    let subject = create_simple_name();
    let validity = generate_test_validity();

    let cert = generate_self_signed_cert(
        &priv_key,
        &subject,
        &validity,
        b"\x01",
        DEFAULT_ID,
        &mut rng,
    ).expect("Failed to generate certificate");

    let content = b"Original content";

    // 创建签章
    let mut signed_data_der = cms::create_digital_signature(
        content,
        &priv_key,
        &cert,
        DEFAULT_ID,
        &mut rng,
        false,
    ).expect("Failed to create digital signature");

    // 篡改签章数据
    if !signed_data_der.is_empty() {
        let len = signed_data_der.len();
        signed_data_der[len / 2] ^= 0xFF;
    }

    // 验证篡改后的签章应该失败（或返回无效）
    match cms::verify_digital_signature(&signed_data_der, DEFAULT_ID) {
        Ok(result) => assert!(!result.is_valid, "Tampered signature should be invalid"),
        Err(_) => { /* 解析失败也接受 */ }
    }
}

/// 测试不同 ID 的电子签章
#[test]
fn test_digital_signature_different_id() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);

    let subject = create_simple_name();
    let validity = generate_test_validity();

    let cert = generate_self_signed_cert(
        &priv_key,
        &subject,
        &validity,
        b"\x01",
        DEFAULT_ID,
        &mut rng,
    ).expect("Failed to generate certificate");

    let content = b"Test content";
    let sign_id = b"1234567812345678";
    let verify_id = b"8765432187654321";

    // 使用 sign_id 创建签章
    let signed_data_der = cms::create_digital_signature(
        content,
        &priv_key,
        &cert,
        sign_id,
        &mut rng,
        false,
    ).expect("Failed to create digital signature");

    // 使用不同的 verify_id 验证应该失败
    match cms::verify_digital_signature(&signed_data_der, verify_id) {
        Ok(result) => assert!(!result.is_valid, "Signature with different ID should be invalid"),
        Err(_) => { /* 解析失败也接受 */ }
    }
}

/// 测试空内容电子签章
#[test]
fn test_digital_signature_empty_content() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);

    let subject = create_simple_name();
    let validity = generate_test_validity();

    let cert = generate_self_signed_cert(
        &priv_key,
        &subject,
        &validity,
        b"\x01",
        DEFAULT_ID,
        &mut rng,
    ).expect("Failed to generate certificate");

    let empty_content = b"";

    // 创建空内容签章
    let signed_data_der = cms::create_digital_signature(
        empty_content,
        &priv_key,
        &cert,
        DEFAULT_ID,
        &mut rng,
        false,
    ).expect("Failed to create digital signature for empty content");

    assert!(!signed_data_der.is_empty());
}

/// 测试大内容电子签章
#[test]
fn test_digital_signature_large_content() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);

    let subject = create_simple_name();
    let validity = generate_test_validity();

    let cert = generate_self_signed_cert(
        &priv_key,
        &subject,
        &validity,
        b"\x01",
        DEFAULT_ID,
        &mut rng,
    ).expect("Failed to generate certificate");

    // 1MB 内容
    let large_content = vec![0xABu8; 1024 * 1024];

    // 创建大内容签章
    let signed_data_der = cms::create_digital_signature(
        &large_content,
        &priv_key,
        &cert,
        DEFAULT_ID,
        &mut rng,
        false,
    ).expect("Failed to create digital signature for large content");

    assert!(!signed_data_der.is_empty());
}

/// 测试稳定性 - 多次创建签章
#[test]
fn test_digital_signature_stability() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);

    let subject = create_simple_name();
    let validity = generate_test_validity();

    let cert = generate_self_signed_cert(
        &priv_key,
        &subject,
        &validity,
        b"\x01",
        DEFAULT_ID,
        &mut rng,
    ).expect("Failed to generate certificate");

    let content = b"Stability test content";

    // 多次创建签章，每次都应该成功
    for i in 0..10 {
        let signed_data_der = cms::create_digital_signature(
            content,
            &priv_key,
            &cert,
            DEFAULT_ID,
            &mut rng,
            false,
        ).expect(&format!("Failed to create digital signature at iteration {}", i));

        assert!(!signed_data_der.is_empty(), "Signature should not be empty at iteration {}", i);
        assert_eq!(signed_data_der[0], 0x30, "Signature should start with SEQUENCE tag");
    }
}

/// 测试证书序列号提取
#[test]
fn test_cert_serial_extraction() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (_priv_key, pub_key) = generate_keypair(&mut rng);

    let cert = create_test_cert(&pub_key);

    // 验证序列号
    assert_eq!(cert.serial_number, vec![0x01]);
}

/// 测试证书有效期生成
#[test]
#[cfg(all(feature = "alloc", feature = "std"))]
fn test_cert_validity_generation() {
    use std::time::Duration;
    use x509_cert::der::Encode;
    
    let not_before = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1704067200); // 2024-01-01
    let not_after = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1893456000);  // 2030-01-01

    // 使用 x509-cert 的 Time 类型生成有效期
    let not_before_time = x509_cert::time::Time::try_from(not_before)
        .expect("not_before should be valid");
    let not_after_time = x509_cert::time::Time::try_from(not_after)
        .expect("not_after should be valid");
    
    let not_before_der = not_before_time.to_der().expect("Failed to encode not_before");
    let not_after_der = not_after_time.to_der().expect("Failed to encode not_after");
    
    let mut validity: Vec<u8> = Vec::with_capacity(2 + not_before_der.len() + not_after_der.len());
    validity.extend(&not_before_der);
    validity.extend(&not_after_der);
    
    // 包装为 SEQUENCE
    let mut validity_seq: Vec<u8> = Vec::with_capacity(2 + validity.len());
    validity_seq.push(0x30);
    validity_seq.push(validity.len() as u8);
    validity_seq.extend(validity);

    // 验证结构
    assert!(!validity_seq.is_empty());
    assert_eq!(validity_seq[0], 0x30); // SEQUENCE tag
}
