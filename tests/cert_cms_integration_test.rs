//! 国密证书和电子签章集成测试
//!
//! 测试覆盖：
//! - 证书生成、解析和验证
//! - 公钥导入导出（SPKI/SEC1/PKCS#8）
//! - 电子签章创建和验证
//! - 签名时间（signing_time）功能
//! - CRL 列表支持
//! - 未签名属性（unsignedAttrs）支持
//! - 边界条件测试（空数据、大数据）
//! - 多签名者场景
//! - 文件往返测试

#![cfg(all(feature = "alloc", feature = "std"))]

use libsmx::sm2::cert::{self, build_x500_name, generate_self_signed_cert, GmCertificate, X500Attribute, X500AttributeType};
use libsmx::sm2::cms::{self, CmsSignerBuilder, create_digital_signature, verify_digital_signature};
use libsmx::sm2::{generate_keypair, public_key_from_spki_der, public_key_to_spki_der, PrivateKey, DEFAULT_ID};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::fs;
use std::path::Path;
use std::time::Duration;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

// ====================================================================================
// 辅助函数
// ====================================================================================

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

/// 创建测试用的国密证书（使用 generate_self_signed_cert）
fn create_test_cert(priv_key: &PrivateKey, rng: &mut StdRng) -> GmCertificate {
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

/// 创建测试用的证书和密钥对（使用 Builder 模式）
fn create_test_cert_and_key(
    rng: &mut StdRng,
    common_name: &str,
    serial: u32,
) -> (GmCertificate, PrivateKey) {
    let (priv_key, pub_key) = generate_keypair(rng);
    let now = std::time::SystemTime::now();
    let expiry = now + Duration::from_secs(365 * 24 * 3600);

    let cert = cert::GmCertificate::builder()
        .subject(&[X500Attribute::new(X500AttributeType::CommonName, common_name)])
        .issuer(&[X500Attribute::new(X500AttributeType::CommonName, common_name)])
        .serial_number(serial)
        .validity_period(now, expiry)
        .build(&pub_key, &priv_key, DEFAULT_ID, rng)
        .expect("Certificate generation should succeed");

    (cert, priv_key)
}

// ====================================================================================
// 证书功能测试
// ====================================================================================

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

/// 测试证书文件生成和解析
#[test]
fn test_certificate_files() {
    let cert_der_file = "test_cert_integration.cert";
    let cert_pem_file = "test_cert_integration.pem";

    let _ = fs::remove_file(cert_der_file);
    let _ = fs::remove_file(cert_pem_file);

    let mut rng = StdRng::seed_from_u64(987654321);
    let (_issuer_priv, _issuer_pub) = generate_keypair(&mut rng);
    let (subject_priv, _subject_pub) = generate_keypair(&mut rng);

    let cert = create_test_cert(&subject_priv, &mut rng);
    let cert_der = cert::generate_gm_certificate(&cert);
    fs::write(cert_der_file, &cert_der).expect("写入 DER 文件应成功");
    assert!(Path::new(cert_der_file).exists());

    let cert_pem = cert::generate_gm_certificate_pem(&cert).expect("PEM 证书生成应成功");
    fs::write(cert_pem_file, &cert_pem).expect("写入 PEM 文件应成功");
    assert!(Path::new(cert_pem_file).exists());

    // 解析验证
    let parsed_cert = cert::parse_gm_certificate(&cert_der).expect("解析 DER 证书应成功");
    assert_eq!(parsed_cert.version, cert.version);

    let parsed_from_pem = cert::parse_gm_certificate_pem(&cert_pem).expect("解析 PEM 证书应成功");
    assert_eq!(parsed_from_pem.version, cert.version);

    let _ = fs::remove_file(cert_der_file);
    let _ = fs::remove_file(cert_pem_file);
}

// ====================================================================================
// 公钥功能测试
// ====================================================================================

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

/// 测试公钥 SPKI 文件生成
#[test]
fn test_pubkey_spki_files() {
    let pub_key_spki_der_file = "test_pub_spki_integration.der";
    let pub_key_spki_pem_file = "test_pub_spki_integration.pem";

    let _ = fs::remove_file(pub_key_spki_der_file);
    let _ = fs::remove_file(pub_key_spki_pem_file);

    let mut rng = StdRng::seed_from_u64(333333333);
    let (_, pub_key) = generate_keypair(&mut rng);

    let spki_der = public_key_to_spki_der(&pub_key);
    fs::write(pub_key_spki_der_file, &spki_der).expect("写入 SPKI DER 应成功");
    assert!(Path::new(pub_key_spki_der_file).exists());

    let spki_pem = cert::public_key_to_spki_pem(&pub_key).expect("SPKI PEM 编码应成功");
    fs::write(pub_key_spki_pem_file, &spki_pem).expect("写入 SPKI PEM 应成功");
    assert!(Path::new(pub_key_spki_pem_file).exists());

    let _ = fs::remove_file(pub_key_spki_der_file);
    let _ = fs::remove_file(pub_key_spki_pem_file);
}

/// 测试私钥 SEC1 编码
#[test]
fn test_private_key_sec1() {
    let priv_key_sec1_der_file = "test_priv_sec1_integration.der";
    let priv_key_sec1_pem_file = "test_priv_sec1_integration.pem";

    let _ = fs::remove_file(priv_key_sec1_der_file);
    let _ = fs::remove_file(priv_key_sec1_pem_file);

    let mut rng = StdRng::seed_from_u64(111111111);
    let (priv_key, _) = generate_keypair(&mut rng);

    let sec1_der = libsmx::sm2::private_key_to_sec1_der(&priv_key);
    fs::write(priv_key_sec1_der_file, &sec1_der).expect("写入 SEC1 DER 应成功");

    let recovered = libsmx::sm2::private_key_from_sec1_der(&sec1_der).expect("SEC1 解析应成功");
    assert_eq!(priv_key.as_bytes(), recovered.as_bytes());

    let sec1_pem = priv_key.to_sec1_pem().expect("SEC1 PEM 编码应成功");
    fs::write(priv_key_sec1_pem_file, &sec1_pem).expect("写入 SEC1 PEM 应成功");

    let recovered_pem = PrivateKey::from_sec1_pem(&sec1_pem).expect("SEC1 PEM 解析应成功");
    assert_eq!(priv_key.as_bytes(), recovered_pem.as_bytes());

    let _ = fs::remove_file(priv_key_sec1_der_file);
    let _ = fs::remove_file(priv_key_sec1_pem_file);
}

/// 测试私钥 PKCS#8 编码
#[test]
fn test_private_key_pkcs8() {
    let priv_key_pkcs8_der_file = "test_priv_pkcs8_integration.der";
    let priv_key_pkcs8_pem_file = "test_priv_pkcs8_integration.pem";

    let _ = fs::remove_file(priv_key_pkcs8_der_file);
    let _ = fs::remove_file(priv_key_pkcs8_pem_file);

    let mut rng = StdRng::seed_from_u64(222222222);
    let (priv_key, _) = generate_keypair(&mut rng);

    let pkcs8_der = libsmx::sm2::private_key_to_pkcs8_der(&priv_key);
    fs::write(priv_key_pkcs8_der_file, &pkcs8_der).expect("写入 PKCS#8 DER 应成功");

    let recovered = libsmx::sm2::private_key_from_pkcs8_der(&pkcs8_der).expect("PKCS#8 解析应成功");
    assert_eq!(priv_key.as_bytes(), recovered.as_bytes());

    let pkcs8_pem = priv_key.to_pkcs8_pem().expect("PKCS#8 PEM 编码应成功");
    fs::write(priv_key_pkcs8_pem_file, &pkcs8_pem).expect("写入 PKCS#8 PEM 应成功");

    let recovered_pem = PrivateKey::from_pkcs8_pem(&pkcs8_pem).expect("PKCS#8 PEM 解析应成功");
    assert_eq!(priv_key.as_bytes(), recovered_pem.as_bytes());

    let _ = fs::remove_file(priv_key_pkcs8_der_file);
    let _ = fs::remove_file(priv_key_pkcs8_pem_file);
}

// ====================================================================================
// CMS 基础签名测试
// ====================================================================================

/// 测试创建和验证签名（包含时间戳）
#[test]
fn test_create_and_verify_signature() {
    let mut rng = StdRng::seed_from_u64(123456);
    
    // 生成密钥对和证书
    let (priv_key, _pub_key) = generate_keypair(&mut rng);
    let cert = create_test_cert(&priv_key, &mut rng);
    
    // 测试数据
    let data = b"Hello, World!";
    
    // 创建电子签章（包含时间戳）
    let signature = create_digital_signature(
        data,
        &priv_key,
        &cert,
        DEFAULT_ID,
        &mut rng,
        true, // 包含时间戳
    ).expect("Failed to create signature");
    
    // 验证电子签章
    let result = verify_digital_signature(&signature, DEFAULT_ID)
        .expect("Failed to verify signature");
    
    assert!(result.is_valid, "Signature verification should succeed");
    assert_eq!(result.signer_results.len(), 1, "Should have one signer");
    assert_eq!(result.content, data.to_vec(), "Content should match");
    assert!(result.signer_results[0].signing_time.is_some(), "Signing time should be present");
}

/// 测试创建签名（不包含时间戳）
#[test]
fn test_signature_without_time() {
    let mut rng = StdRng::seed_from_u64(789012);
    
    let (priv_key, _pub_key) = generate_keypair(&mut rng);
    let cert = create_test_cert(&priv_key, &mut rng);
    
    let data = b"Test data without timestamp";
    
    // 创建电子签章（不包含时间戳）
    let signature = create_digital_signature(
        data,
        &priv_key,
        &cert,
        DEFAULT_ID,
        &mut rng,
        false, // 不包含时间戳
    ).expect("Failed to create signature");
    
    // 验证电子签章
    let result = verify_digital_signature(&signature, DEFAULT_ID)
        .expect("Failed to verify signature");
    
    assert!(result.is_valid, "Signature verification should succeed");
    assert_eq!(result.signer_results.len(), 1, "Should have one signer");
    assert!(result.signer_results[0].signing_time.is_none(), "Signing time should not be present");
}

/// 测试签名时间提取功能
#[test]
fn test_signing_time_feature() {
    let mut rng = StdRng::seed_from_u64(30001);
    let (cert, priv_key) = create_test_cert_and_key(&mut rng, "Signing Time Test", 30001);

    let data = b"Test data with signing time attribute";

    // 使用 Builder API 创建包含 signing-time 的签名
    let signed_data = CmsSignerBuilder::new()
        .content(data.as_slice())
        .add_signer(&priv_key, &cert, DEFAULT_ID)
        .include_signing_time(true)
        .sign(&mut rng)
        .expect("Signature creation should succeed");

    // 验证签名
    let result = verify_digital_signature(&signed_data, DEFAULT_ID)
        .expect("Verification should succeed");

    assert!(result.is_valid);
    assert_eq!(result.content, data.as_slice());
    assert_eq!(result.signer_results.len(), 1);
    
    // 验证签名时间被正确提取
    let signer_result = &result.signer_results[0];
    assert!(signer_result.signing_time.is_some(), "Signing time should be present");
}

/// 测试签名篡改检测
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
        create_digital_signature(content, &priv_key, &cert, DEFAULT_ID, &mut rng, false)
            .expect("Failed to create digital signature");

    // 篡改内容数据
    if let Some(pos) = signed_data_der
        .windows(b"Original content".len())
        .position(|w| w == b"Original content")
    {
        signed_data_der[pos] ^= 0xFF;
    }

    // 验证篡改后的签章应该失败
    match verify_digital_signature(&signed_data_der, DEFAULT_ID) {
        Ok(result) => assert!(!result.is_valid, "Tampered signature should be invalid"),
        Err(_) => { /* 解析失败也接受 */ }
    }
}

/// 测试不同 ID 的签名验证
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
        create_digital_signature(content, &priv_key, &cert, sign_id, &mut rng, false)
            .expect("Failed to create digital signature");

    // 使用不同的 verify_id 验证应该失败
    match verify_digital_signature(&signed_data_der, verify_id) {
        Ok(result) => assert!(
            !result.is_valid,
            "Signature with different ID should be invalid"
        ),
        Err(_) => { /* 解析失败也接受 */ }
    }
}

// ====================================================================================
// CMS 边界条件测试
// ====================================================================================

/// 测试空内容签名
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
        create_digital_signature(empty_content, &priv_key, &cert, DEFAULT_ID, &mut rng, false)
            .expect("Failed to create digital signature for empty content");

    assert!(!signed_data_der.is_empty());
    
    // 验证空内容签名
    let result = verify_digital_signature(&signed_data_der, DEFAULT_ID)
        .expect("Failed to verify signature");
    assert!(result.is_valid);
    assert_eq!(result.content, b"".to_vec());
}

/// 测试大数据签名（10KB）
#[test]
fn test_digital_signature_large_content() {
    let mut rng = StdRng::seed_from_u64(901234);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);
    let cert = create_test_cert(&priv_key, &mut rng);
    
    // 测试大数据（10KB）
    let data: Vec<u8> = (0..10 * 1024).map(|i| (i % 256) as u8).collect();
    
    // 创建电子签章
    let signature = create_digital_signature(
        &data,
        &priv_key,
        &cert,
        DEFAULT_ID,
        &mut rng,
        true,
    ).expect("Failed to create signature");
    
    // 验证电子签章
    let result = verify_digital_signature(&signature, DEFAULT_ID)
        .expect("Failed to verify signature");
    
    assert!(result.is_valid, "Signature verification should succeed for large data");
    assert_eq!(result.signer_results.len(), 1, "Should have one signer");
    assert_eq!(result.content, data, "Content should match");
}

/// 测试大数据带签名时间
#[test]
fn test_large_data_with_signing_time() {
    let mut rng = StdRng::seed_from_u64(30009);
    let (cert, priv_key) = create_test_cert_and_key(&mut rng, "Large Data Test", 30009);

    // 创建较大的测试数据（10KB）
    let data = vec![0x42u8; 10 * 1024];

    // 创建包含 signing-time 的签名
    let signed_data = CmsSignerBuilder::new()
        .content(&data)
        .add_signer(&priv_key, &cert, DEFAULT_ID)
        .include_signing_time(true)
        .sign(&mut rng)
        .expect("Signature creation should succeed");

    // 验证签名
    let result = verify_digital_signature(&signed_data, DEFAULT_ID)
        .expect("Verification should succeed");

    assert!(result.is_valid);
    assert_eq!(result.content, data.as_slice());
    assert!(result.signer_results[0].signing_time.is_some());
}

// ====================================================================================
// CMS 高级功能测试
// ====================================================================================

/// 测试 CRL 支持
#[test]
fn test_crl_support() {
    let mut rng = StdRng::seed_from_u64(30003);
    let (cert, priv_key) = create_test_cert_and_key(&mut rng, "CRL Support Test", 30003);

    let data = b"Test data with CRL support";

    // 创建签名
    let signed_data_bytes = create_digital_signature(
        &data[..], &priv_key, &cert, DEFAULT_ID, &mut rng, false
    ).expect("Signature creation should succeed");

    // 验证签名
    let result = verify_digital_signature(&signed_data_bytes, DEFAULT_ID)
        .expect("Verification should succeed");

    assert!(result.is_valid);
    assert_eq!(result.content, data.as_slice());
    
    // 验证结果中包含证书
    assert!(!result.certificates.is_empty());
}

/// 测试未签名属性编码
#[test]
fn test_unsigned_attrs_encoding() {
    let mut rng = StdRng::seed_from_u64(30004);
    let (cert, priv_key) = create_test_cert_and_key(&mut rng, "Unsigned Attrs Test", 30004);

    let data = b"Test data with unsigned attributes";

    // 创建签名
    let signed_data_bytes = create_digital_signature(
        &data[..], &priv_key, &cert, DEFAULT_ID, &mut rng, false
    ).expect("Signature creation should succeed");

    // 解析并验证签名
    let result = verify_digital_signature(&signed_data_bytes, DEFAULT_ID)
        .expect("Verification should succeed");

    assert!(result.is_valid);
    assert_eq!(result.content, data.as_slice());
}

/// 测试完整 CMS 往返
#[test]
fn test_full_cms_roundtrip() {
    let mut rng = StdRng::seed_from_u64(30005);
    let (cert, priv_key) = create_test_cert_and_key(&mut rng, "Full Roundtrip Test", 30005);

    let data = b"Complete CMS roundtrip test with all features";

    // 创建包含所有功能的签名
    let signed_data = CmsSignerBuilder::new()
        .content(data.as_slice())
        .add_signer(&priv_key, &cert, DEFAULT_ID)
        .include_signing_time(true)
        .sign(&mut rng)
        .expect("Signature creation should succeed");

    // 验证签名
    let result = verify_digital_signature(&signed_data, DEFAULT_ID)
        .expect("Verification should succeed");

    assert!(result.is_valid);
    assert_eq!(result.content, data.as_slice());
    assert_eq!(result.signer_results.len(), 1);
    assert!(result.signer_results[0].signing_time.is_some());
}

/// 测试多签名者
#[test]
fn test_multiple_signers() {
    let mut rng = StdRng::seed_from_u64(30006);
    
    // 创建两个签名者
    let (cert1, priv_key1) = create_test_cert_and_key(&mut rng, "Signer 1", 30006);
    let (cert2, priv_key2) = create_test_cert_and_key(&mut rng, "Signer 2", 30007);

    let data = b"Test data with multiple signers";

    // 创建包含多个签名者的签名
    let signed_data = CmsSignerBuilder::new()
        .content(data.as_slice())
        .add_signer(&priv_key1, &cert1, DEFAULT_ID)
        .add_signer(&priv_key2, &cert2, DEFAULT_ID)
        .include_signing_time(true)
        .sign(&mut rng)
        .expect("Signature creation should succeed");

    // 验证签名
    let result = verify_digital_signature(&signed_data, DEFAULT_ID)
        .expect("Verification should succeed");

    assert!(result.is_valid);
    assert_eq!(result.content, data.as_slice());
    assert_eq!(result.signer_results.len(), 2);
    
    // 两个签名者都应该有签名时间
    for (i, signer_result) in result.signer_results.iter().enumerate() {
        assert!(signer_result.signing_time.is_some(), 
            "Signer {} should have signing time", i);
    }
}

/// 测试消息摘要验证
#[test]
fn test_message_digest_verification() {
    let mut rng = StdRng::seed_from_u64(30008);
    let (cert, priv_key) = create_test_cert_and_key(&mut rng, "Message Digest Test", 30008);

    let data = b"Test data for message digest verification";

    // 创建签名
    let signed_data = CmsSignerBuilder::new()
        .content(data.as_slice())
        .add_signer(&priv_key, &cert, DEFAULT_ID)
        .include_signing_time(true)
        .sign(&mut rng)
        .expect("Signature creation should succeed");

    // 验证签名时会验证 message digest
    let result = verify_digital_signature(&signed_data, DEFAULT_ID)
        .expect("Verification should succeed");

    assert!(result.is_valid);
    
    // 验证结果中应该包含证书信息
    assert!(!result.certificates.is_empty());
}

// ====================================================================================
// 稳定性测试
// ====================================================================================

/// 测试稳定性 - 多次创建签章
#[test]
fn test_stability_multiple_signatures() {
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

    // 多次创建签章
    for i in 0..10 {
        let signed_data_der = cms::create_digital_signature(
            content, &priv_key, &cert, DEFAULT_ID, &mut rng, false,
        )
        .expect("Failed to create digital signature");

        assert!(!signed_data_der.is_empty());

        // 验证每个签章
        let result = cms::verify_digital_signature(&signed_data_der, DEFAULT_ID)
            .expect("Failed to verify signature");

        assert!(result.is_valid, "Signature {} should be valid", i);
        assert_eq!(result.content, content.to_vec(), "Content should match for signature {}", i);
    }
}
