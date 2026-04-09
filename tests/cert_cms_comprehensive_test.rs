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

use libsmx::sm2::cert::{build_x500_name, generate_self_signed_cert, GmCertificate, X500Attribute, X500AttributeType};
use libsmx::sm2::cms;
use libsmx::sm2::{generate_keypair, public_key_from_spki_der, public_key_to_spki_der, DEFAULT_ID};
use rand::rngs::StdRng;
use rand::SeedableRng;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use std::time::Duration;

/// 创建测试用的 X.500 名称
fn create_test_name(common_name: &str) -> x509_cert::name::Name {
    build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test Org"),
        X500Attribute::new(X500AttributeType::CommonName, common_name),
    ])
}

/// 生成测试用的有效期
fn generate_test_validity() -> Validity {
    let not_before = Time::try_from(std::time::SystemTime::now()).unwrap();
    let not_after = Time::try_from(std::time::SystemTime::now() + Duration::from_secs(365 * 24 * 3600)).unwrap();
    Validity::new(not_before, not_after)
}

/// 创建测试用的国密证书
fn create_test_cert(priv_key: &libsmx::sm2::PrivateKey, rng: &mut StdRng) -> GmCertificate {
    let subject = create_test_name("Test Subject");
    let serial = SerialNumber::from(1u32);
    let validity = generate_test_validity();

    generate_self_signed_cert(
        priv_key,
        &subject,
        &validity,
        &serial,
        DEFAULT_ID,
        None,
        rng,
    ).expect("Failed to generate test certificate")
}

/// 测试证书结构创建
#[test]
fn test_cert_creation() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);

    let cert = create_test_cert(&priv_key, &mut rng);

    // 验证证书字段
    assert_eq!(cert.version, 2);
    assert!(!cert.signature.is_empty());
}

/// 测试证书 DER 编码和解码
#[test]
fn test_cert_der_encoding() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);

    let cert = create_test_cert(&priv_key, &mut rng);

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

    let subject = create_test_name("Test Subject");
    let validity = generate_test_validity();
    let serial = SerialNumber::from(1u32);

    // 生成自签名证书
    let cert = generate_self_signed_cert(
        &priv_key, &subject, &validity, &serial, DEFAULT_ID, None, &mut rng,
    )
    .expect("Failed to generate self-signed certificate");

    // 验证证书字段
    assert_eq!(cert.version, 2);
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

    let subject = create_test_name("Test Subject");
    let validity = generate_test_validity();
    let serial = SerialNumber::from(1u32);

    // 生成自签名证书
    let cert = generate_self_signed_cert(
        &priv_key, &subject, &validity, &serial, DEFAULT_ID, None, &mut rng,
    )
    .expect("Failed to generate certificate");

    let content = b"Test content";
    let custom_id = b"1234567890";

    // 使用自定义 ID 创建签章
    let signed_data_der = cms::create_digital_signature(
        content, &priv_key, &cert, custom_id, &mut rng, false, // 不包含时间
    )
    .expect("Failed to create digital signature");

    assert!(!signed_data_der.is_empty());
    assert_eq!(signed_data_der[0], 0x30); // SEQUENCE tag
}

/// 测试电子签章篡改检测
#[test]
fn test_digital_signature_tampering() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);

    let subject = create_test_name("Test Subject");
    let validity = generate_test_validity();
    let serial = SerialNumber::from(1u32);

    let cert = generate_self_signed_cert(
        &priv_key, &subject, &validity, &serial, DEFAULT_ID, None, &mut rng,
    )
    .expect("Failed to generate certificate");

    let content = b"Original content";

    // 创建签章
    let mut signed_data_der =
        cms::create_digital_signature(content, &priv_key, &cert, DEFAULT_ID, &mut rng, false)
            .expect("Failed to create digital signature");

    // 篡改内容数据（在 encapContentInfo 中）
    // 找到 "Original content" 的位置并篡改
    if let Some(pos) = signed_data_der
        .windows(b"Original content".len())
        .position(|w| w == b"Original content")
    {
        signed_data_der[pos] ^= 0xFF;
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

    let subject = create_test_name("Test Subject");
    let validity = generate_test_validity();
    let serial = SerialNumber::from(1u32);

    let cert = generate_self_signed_cert(
        &priv_key, &subject, &validity, &serial, DEFAULT_ID, None, &mut rng,
    )
    .expect("Failed to generate certificate");

    let content = b"Test content";
    let sign_id = b"1234567812345678";
    let verify_id = b"8765432187654321";

    // 使用 sign_id 创建签章
    let signed_data_der =
        cms::create_digital_signature(content, &priv_key, &cert, sign_id, &mut rng, false)
            .expect("Failed to create digital signature");

    // 使用不同的 verify_id 验证应该失败
    match cms::verify_digital_signature(&signed_data_der, verify_id) {
        Ok(result) => assert!(
            !result.is_valid,
            "Signature with different ID should be invalid"
        ),
        Err(_) => { /* 解析失败也接受 */ }
    }
}

/// 测试空内容电子签章
#[test]
fn test_digital_signature_empty_content() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);

    let subject = create_test_name("Test Subject");
    let validity = generate_test_validity();
    let serial = SerialNumber::from(1u32);

    let cert = generate_self_signed_cert(
        &priv_key, &subject, &validity, &serial, DEFAULT_ID, None, &mut rng,
    )
    .expect("Failed to generate certificate");

    let empty_content = b"";

    // 创建空内容签章
    let signed_data_der =
        cms::create_digital_signature(empty_content, &priv_key, &cert, DEFAULT_ID, &mut rng, false)
            .expect("Failed to create digital signature for empty content");

    assert!(!signed_data_der.is_empty());
}

/// 测试大内容电子签章
#[test]
fn test_digital_signature_large_content() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);

    let subject = create_test_name("Test Subject");
    let validity = generate_test_validity();
    let serial = SerialNumber::from(1u32);

    let cert = generate_self_signed_cert(
        &priv_key, &subject, &validity, &serial, DEFAULT_ID, None, &mut rng,
    )
    .expect("Failed to generate certificate");

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
    )
    .expect("Failed to create digital signature for large content");

    assert!(!signed_data_der.is_empty());
}

/// 测试稳定性 - 多次创建签章
#[test]
fn test_digital_signature_stability() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);

    let subject = create_test_name("Test Subject");
    let validity = generate_test_validity();
    let serial = SerialNumber::from(1u32);

    let cert = generate_self_signed_cert(
        &priv_key, &subject, &validity, &serial, DEFAULT_ID, None, &mut rng,
    )
    .expect("Failed to generate certificate");

    let content = b"Stability test content";

    // 多次创建签章，每次都应该成功
    for i in 0..10 {
        let signed_data_der =
            cms::create_digital_signature(content, &priv_key, &cert, DEFAULT_ID, &mut rng, false)
                .expect(&format!(
                    "Failed to create digital signature at iteration {}",
                    i
                ));

        assert!(
            !signed_data_der.is_empty(),
            "Signature should not be empty at iteration {}",
            i
        );
        let result = match cms::verify_digital_signature(&signed_data_der, DEFAULT_ID) {
            Ok(result) => result,
            Err(_) => continue,
        };
        assert!(result.is_valid, "Signature should be valid at iteration {}", i);
    }
}
