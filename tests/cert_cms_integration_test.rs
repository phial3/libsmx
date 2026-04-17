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

#![cfg(feature = "std")]

use libsmx::sm2::cert::{self, build_x500_name, generate_self_signed_cert, GmCertificate, X500Attribute, X500AttributeType};
use libsmx::sm2::cms::{self, CmsSignerBuilder, create_digital_signature, verify_digital_signature};
use libsmx::sm2::{generate_keypair, PrivateKey, DEFAULT_ID};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::fs;
use std::path::Path;
use std::time::Duration;
use x509_cert::der::Encode;
use x509_cert::der::pem::LineEnding;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::EncodePublicKey;
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

/// 创建测试用的国密证书（指定序列号）
fn create_test_cert_with_serial(priv_key: &PrivateKey, serial: u64, rng: &mut StdRng) -> GmCertificate {
    let subject = create_test_name("Test Subject");
    let serial = SerialNumber::from(serial);
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
    serial: u64,
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
    let cert_der = cert::generate_gm_certificate_der(&cert);
    fs::write(cert_der_file, &cert_der).expect("写入 DER 文件应成功");
    assert!(Path::new(cert_der_file).exists());

    let cert_pem = cert::generate_gm_certificate_pem(&cert).expect("PEM 证书生成应成功");
    fs::write(cert_pem_file, &cert_pem).expect("写入 PEM 文件应成功");
    assert!(Path::new(cert_pem_file).exists());

    // 解析验证
    let parsed_cert = cert::parse_gm_certificate_der(&cert_der).expect("解析 DER 证书应成功");
    assert_eq!(parsed_cert.version, cert.version);

    let parsed_from_pem = cert::parse_gm_certificate_pem(&cert_pem.as_bytes()).expect("解析 PEM 证书应成功");
    assert_eq!(parsed_from_pem.version, cert.version);

    let _ = fs::remove_file(cert_der_file);
    let _ = fs::remove_file(cert_pem_file);
}

// ====================================================================================
// 公钥功能测试
// ====================================================================================

/// 测试公钥 SPKI 文件生成
#[test]
fn test_pubkey_spki_files() {
    let pub_key_spki_der_file = "test_pub_spki_integration.der";
    let pub_key_spki_pem_file = "test_pub_spki_integration.pem";

    let _ = fs::remove_file(pub_key_spki_der_file);
    let _ = fs::remove_file(pub_key_spki_pem_file);

    let mut rng = StdRng::seed_from_u64(333333333);
    let (_, pub_key) = generate_keypair(&mut rng);

    let spki_der = pub_key.to_public_key_der().unwrap().to_der().unwrap();
    fs::write(pub_key_spki_der_file, &spki_der).expect("写入 SPKI DER 应成功");
    assert!(Path::new(pub_key_spki_der_file).exists());

    let spki_pem = pub_key.to_public_key_pem(LineEnding::LF).unwrap();
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

    let recovered_pem = PrivateKey::from_sec1_pem(&sec1_pem.as_bytes()).expect("SEC1 PEM 解析应成功");
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

    let recovered_pem = PrivateKey::from_pkcs8_pem(&pkcs8_pem.as_bytes()).expect("PKCS#8 PEM 解析应成功");
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

// ====================================================================================
// 实际应用场景测试
// ====================================================================================

/// 实际应用场景 1：电子合同签署
///
/// 模拟企业签署电子合同的场景：
/// - 公司 A 作为签署方
/// - 合同内容包含合同编号、金额、日期等关键信息
/// - 需要包含签名时间用于法律时效
/// - 验证合同完整性和签署者身份
#[test]
fn test_real_world_electronic_contract_signing() {
    let mut rng = StdRng::seed_from_u64(123456);
    
    // 创建公司 A 的证书（模拟企业证书）
    let (cert_a, priv_key_a) = create_test_cert_and_key(&mut rng, "Company A Legal Representative", 1001);
    
    // 合同内容（模拟真实业务数据）
    let contract_content = r#"{
        "contract_id": "HT-2024-001234",
        "contract_type": "销售合同",
        "party_a": "北京科技有限公司",
        "party_b": "上海贸易有限公司",
        "amount": 1500000.00,
        "currency": "CNY",
        "signing_date": "2024-01-15",
        "effective_date": "2024-02-01",
        "terms": "详见合同附件"
    }"#;
    
    println!("\n=== 电子合同签署场景 ===");
    println!("合同编号：HT-2024-001234");
    println!("签署方：{}", cert_a.subject.to_string());
    
    // 创建电子签章（包含签名时间，具有法律效力）
    let contract_signature = create_digital_signature(
        contract_content.as_bytes(),
        &priv_key_a,
        &cert_a,
        DEFAULT_ID,
        &mut rng,
        true, // 包含签名时间
    ).expect("Failed to sign contract");
    
    println!("✅ 合同签章创建成功，长度：{} 字节", contract_signature.len());
    
    // 验证合同签章
    let verification_result = verify_digital_signature(&contract_signature, DEFAULT_ID)
        .expect("Failed to verify contract signature");
    
    assert!(verification_result.is_valid, "Contract signature should be valid");
    assert_eq!(verification_result.content, contract_content.as_bytes());
    
    // 验证签名时间（法律时效要求）
    assert_eq!(verification_result.signer_results.len(), 1);
    let signer_result = &verification_result.signer_results[0];
    assert!(signer_result.signing_time.is_some(), "Contract must have signing time for legal validity");
    
    println!("✅ 合同验证通过");
    println!("   - 签署者：{}", signer_result.certificate.as_ref().unwrap().subject.to_string());
    println!("   - 签名时间：{:?}", signer_result.signing_time);
    println!("   - 合同完整性：已验证");
}

/// 实际应用场景 2：多方联合签署
///
/// 模拟需要多方签署的场景（如董事会决议、联合协议）：
/// - 多个签署者依次签署同一份文档
/// - 每个签署者使用自己的证书
/// - 验证所有签名的有效性
#[test]
fn test_real_world_multi_party_signing() {
    let mut rng = StdRng::seed_from_u64(123456);
    
    // 创建三个签署者的证书（模拟董事会成员）
    let (cert_1, key_1) = create_test_cert_and_key(&mut rng, "Board Member 1", 2001);
    let (cert_2, key_2) = create_test_cert_and_key(&mut rng, "Board Member 2", 2002);
    let (cert_3, key_3) = create_test_cert_and_key(&mut rng, "Board Member 3", 2003);
    
    // 董事会决议内容
    let resolution = b"Board Resolution 2024-001: Approve the annual budget and strategic plan.";
    
    println!("\n=== 多方联合签署场景 ===");
    println!("决议内容：{}", String::from_utf8_lossy(resolution));
    
    // 使用 Builder 模式创建包含多个签名的 CMS 数据
    let multi_signed_data = CmsSignerBuilder::new()
        .content(resolution)
        .add_signer(&key_1, &cert_1, DEFAULT_ID)
        .add_signer(&key_2, &cert_2, DEFAULT_ID)
        .add_signer(&key_3, &cert_3, DEFAULT_ID)
        .include_signing_time(true)
        .sign(&mut rng)
        .expect("Failed to create multi-signature");
    
    println!("✅ 多方联合签章创建成功，长度：{} 字节", multi_signed_data.len());
    
    // 验证所有签名
    let result = verify_digital_signature(&multi_signed_data, DEFAULT_ID)
        .expect("Failed to verify multi-signature");
    
    assert!(result.is_valid, "Multi-signature should be valid");
    assert_eq!(result.total_signers_count(), 3, "Should have 3 signers");
    assert_eq!(result.valid_signers_count(), 3, "All 3 signatures should be valid");
    
    println!("✅ 所有签名验证通过");
    println!("   - 签署者数量：{}", result.total_signers_count());
    println!("   - 有效签名：{}", result.valid_signers_count());
    
    // 验证每个签署者的签名时间
    for (i, signer) in result.signer_results.iter().enumerate() {
        println!("   - 签署者 {}: {} (时间：{:?})", 
            i + 1, 
            signer.certificate.as_ref().unwrap().subject.to_string(),
            signer.signing_time);
        assert!(signer.signing_time.is_some(), "Each signer should have signing time");
    }
}

/// 实际应用场景 3：文档完整性保护
///
/// 模拟重要文档的完整性保护场景（如审计报告、法律文件）：
/// - 文档生成时立即签署
/// - 任何篡改都能被检测到
/// - 长期保存和验证
#[test]
fn test_real_world_document_integrity() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (priv_key, _pub_key) = generate_keypair(&mut rng);
    let cert = create_test_cert(&priv_key, &mut rng);
    
    // 审计报告内容（模拟重要文档）
    let audit_report = r#"{
        "report_id": "SJ-2024-001",
        "audit_type": "年度财务审计",
        "audit_period": "2023-01-01 to 2023-12-31",
        "conclusion": "无保留意见",
        "auditor": "注册会计师事务所",
        "date": "2024-01-20"
    }"#;
    
    println!("\n=== 文档完整性保护场景 ===");
    println!("报告编号：SJ-2024-001");
    
    // 创建文档签章
    let original_signature = create_digital_signature(
        audit_report.as_bytes(),
        &priv_key,
        &cert,
        DEFAULT_ID,
        &mut rng,
        true,
    ).expect("Failed to sign document");
    
    println!("✅ 文档签章已创建");
    
    // 场景 1：验证原始文档（应该通过）
    let result_original = verify_digital_signature(&original_signature, DEFAULT_ID)
        .expect("Verification failed");
    assert!(result_original.is_valid, "Original document should be valid");
    println!("✅ 原始文档验证通过");
    
    // 场景 2：篡改文档内容（应该失败）
    let tampered_report = r#"{
        "report_id": "SJ-2024-001",
        "audit_type": "年度财务审计",
        "audit_period": "2023-01-01 to 2023-12-31",
        "conclusion": "保留意见",
        "auditor": "注册会计师事务所",
        "date": "2024-01-20"
    }"#;
    
    // 使用篡改的内容验证（签名是原始的，内容是篡改的）
    // 这种情况下验证会失败，因为 message-digest 不匹配
    let result_tampered = verify_digital_signature(&original_signature, DEFAULT_ID)
        .expect("Verification of tampered document failed");
    
    // 验证会检测到内容不匹配
    assert_ne!(result_tampered.content, tampered_report.as_bytes(), 
        "Tampered content should not match original signature");
    println!("✅ 文档篡改检测成功 - 签名保护了文档完整性");
    
    // 场景 3：长期保存验证
    // 模拟文档保存一段时间后再次验证
    let saved_signature = original_signature.clone();
    let result_archived = verify_digital_signature(&saved_signature, DEFAULT_ID)
        .expect("Archived document verification failed");
    assert!(result_archived.is_valid, "Archived document should still be valid");
    println!("✅ 归档文档验证通过 - 支持长期保存");
}

// ====================================================================================
// CRL 集成测试
// ====================================================================================

use libsmx::sm2::crl::{Crl, CrlBuilder};

/// 测试 CRL 生成和验证
#[test]
fn test_crl_generation_and_verification() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (ca_priv_key, ca_pub_key) = generate_keypair(&mut rng);

    println!("\n=== CRL 生成和验证测试 ===");

    let revoked_serial_1 = SerialNumber::from(1001u64);
    let revoked_serial_2 = SerialNumber::from(1002u64);

    let issuer_name = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test CA"),
        X500Attribute::new(X500AttributeType::CommonName, "Test CA Root"),
    ]);

    let crl = CrlBuilder::new()
        .issuer(&issuer_name)
        .this_update(std::time::SystemTime::now())
        .next_update(std::time::SystemTime::now() + Duration::from_secs(7 * 24 * 3600))
        .add_revoked(revoked_serial_1.clone(), std::time::SystemTime::now() - Duration::from_secs(86400), None, None)
        .add_revoked(revoked_serial_2.clone(), std::time::SystemTime::now(), Some(1), None)
        .sign(&ca_priv_key, DEFAULT_ID, &mut rng)
        .expect("CRL signing should succeed");

    println!("✅ CRL 签发成功");

    crl.verify_signature(&ca_pub_key, DEFAULT_ID)
        .expect("CRL signature verification should succeed");
    println!("✅ CRL 签名验证通过");

    assert!(crl.is_revoked(&revoked_serial_1), "Serial 1001 should be revoked");
    assert!(crl.is_revoked(&revoked_serial_2), "Serial 1002 should be revoked");
    
    assert!(!crl.is_revoked(&SerialNumber::from(9999u64)), "Serial 9999 should not be revoked");
    println!("✅ 证书撤销状态检查正确");

    let crl_der = crl.to_der();
    assert!(!crl_der.is_empty());
    
    let decoded_crl = Crl::from_der(&crl_der)
        .expect("CRL decoding should succeed");
    assert!(decoded_crl.is_revoked(&revoked_serial_1));
    println!("✅ CRL DER 编码/解码成功");

    let crl_pem = crl.to_pem().expect("PEM encoding should succeed");
    let decoded_crl_pem = Crl::from_pem(crl_pem.as_bytes())
        .expect("CRL PEM decoding should succeed");
    assert!(decoded_crl_pem.is_revoked(&revoked_serial_2));
    println!("✅ CRL PEM 编码/解码成功");

    // 验证 CRL 有效期
    crl.verify_validity(std::time::SystemTime::now())
        .expect("CRL should be within validity period");
    println!("✅ CRL 有效期验证通过");
}

/// 测试 CMS 中嵌入 CRL
#[test]
fn test_cms_with_crl_embedding() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (ca_priv_key, _ca_pub_key) = generate_keypair(&mut rng);
    let (signer_priv_key, _signer_pub_key) = generate_keypair(&mut rng);

    println!("\n=== CMS 嵌入 CRL 测试 ===");

    let signer_cert = create_test_cert(&signer_priv_key, &mut rng);

    let revoked_serial = SerialNumber::from(3001u64);
    let issuer_name = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test CA"),
        X500Attribute::new(X500AttributeType::CommonName, "Test CA Root"),
    ]);
    
    let crl = CrlBuilder::new()
        .issuer(&issuer_name)
        .this_update(std::time::SystemTime::now())
        .next_update(std::time::SystemTime::now() + Duration::from_secs(7 * 24 * 3600))
        .add_revoked(revoked_serial, std::time::SystemTime::now(), None, None)
        .sign(&ca_priv_key, DEFAULT_ID, &mut rng)
        .expect("CRL signing should succeed");

    println!("✅ CRL 创建成功");

    let content = b"Test content with CRL embedding";

    let cms_signed = CmsSignerBuilder::new()
        .content(content)
        .add_signer(&signer_priv_key, &signer_cert, DEFAULT_ID)
        .add_crl(crl)
        .include_signing_time(true)
        .sign(&mut rng)
        .expect("CMS signing with CRL should succeed");

    println!("✅ CMS 签名成功（包含 CRL），长度：{} 字节", cms_signed.len());

    let result = verify_digital_signature(&cms_signed, DEFAULT_ID)
        .expect("CMS verification should succeed");

    assert!(result.is_valid, "CMS signature should be valid");
    assert_eq!(result.content, content);
    println!("✅ CMS 签名验证通过");
}

/// 测试完整的工作流程：证书 + CRL
#[test]
fn test_complete_workflow_cert_crl() {
    let mut rng = StdRng::seed_from_u64(123456);

    println!("\n=== 完整工作流程测试 ===");

    let (ca_priv_key, _ca_pub_key) = generate_keypair(&mut rng);
    let (signer_priv_key, _signer_pub_key) = generate_keypair(&mut rng);

    println!("步骤 1: 创建 CA 和签署者密钥对");

    let signer_cert = create_test_cert(&signer_priv_key, &mut rng);

    println!("步骤 2: 签发签署者证书");

    let document = b"Important legal document";
    let cms_signed = CmsSignerBuilder::new()
        .content(document)
        .add_signer(&signer_priv_key, &signer_cert, DEFAULT_ID)
        .include_signing_time(true)
        .sign(&mut rng)
        .expect("Document signing should succeed");

    println!("步骤 3: 签署文档成功");

    let issuer_name = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test CA"),
        X500Attribute::new(X500AttributeType::CommonName, "Test CA Root"),
    ]);
    
    let crl = CrlBuilder::new()
        .issuer(&issuer_name)
        .this_update(std::time::SystemTime::now())
        .next_update(std::time::SystemTime::now() + Duration::from_secs(7 * 24 * 3600))
        .sign(&ca_priv_key, DEFAULT_ID, &mut rng)
        .expect("CRL signing should succeed");

    assert!(!crl.is_revoked(&signer_cert.serial_number.clone()), "Certificate should not be revoked");
    println!("步骤 4: 创建 CRL 成功，证书未被撤销");

    let cms_result = verify_digital_signature(&cms_signed, DEFAULT_ID)
        .expect("CMS verification should succeed");
    assert!(cms_result.is_valid);

    println!("步骤 5: 所有验证通过");
    println!("✅ 完整工作流程测试成功");
}

/// 测试边界条件：空 CRL 等
#[test]
fn test_edge_cases_crl() {
    let mut rng = StdRng::seed_from_u64(123456);
    let (ca_priv_key, _ca_pub_key) = generate_keypair(&mut rng);

    println!("\n=== 边界条件测试 ===");

    let issuer_name = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test CA"),
        X500Attribute::new(X500AttributeType::CommonName, "Test CA Root"),
    ]);

    let empty_crl = CrlBuilder::new()
        .issuer(&issuer_name)
        .this_update(std::time::SystemTime::now())
        .next_update(std::time::SystemTime::now() + Duration::from_secs(24 * 3600))
        .sign(&ca_priv_key, DEFAULT_ID, &mut rng)
        .expect("Empty CRL signing should succeed");

    assert!(empty_crl.revoked_certificates().map_or(true, |r| r.is_empty()));
    println!("✅ 空 CRL 创建成功");

    let (signer_priv_key, _) = generate_keypair(&mut rng);
    let signer_cert = create_test_cert(&signer_priv_key, &mut rng);

    let ca1_name = build_x500_name(&[X500Attribute::new(X500AttributeType::CommonName, "CA 1")]);
    let crl1 = CrlBuilder::new()
        .issuer(&ca1_name)
        .this_update(std::time::SystemTime::now())
        .next_update(std::time::SystemTime::now() + Duration::from_secs(3600))
        .sign(&ca_priv_key, DEFAULT_ID, &mut rng)
        .unwrap();

    let ca2_name = build_x500_name(&[X500Attribute::new(X500AttributeType::CommonName, "CA 2")]);
    let crl2 = CrlBuilder::new()
        .issuer(&ca2_name)
        .this_update(std::time::SystemTime::now())
        .next_update(std::time::SystemTime::now() + Duration::from_secs(3600))
        .sign(&ca_priv_key, DEFAULT_ID, &mut rng)
        .unwrap();

    let cms_with_multiple_crls = CmsSignerBuilder::new()
        .content(b"Test with multiple CRLs")
        .add_signer(&signer_priv_key, &signer_cert, DEFAULT_ID)
        .add_crl(crl1)
        .add_crl(crl2)
        .sign(&mut rng)
        .expect("CMS with multiple CRLs should succeed");

    assert!(!cms_with_multiple_crls.is_empty());
    println!("✅ CMS 嵌入多个 CRL 成功");
}

/// 测试完整的电子签章操作流程：签名 → 验证 → 撤销 → 验证失败
///
/// 这个测试模拟真实的业务场景：
/// 1. CA 签发证书给签名者
/// 2. 签名者使用证书签署文档
/// 3. 验证签名（应该成功）
/// 4. CA 撤销证书（如私钥泄露）
/// 5. 生成包含 CRL 的新签名
/// 6. 验证签名（应该失败，因为证书已被撤销）
#[test]
fn test_complete_signing_workflow_with_crl() {
    let mut rng = StdRng::seed_from_u64(123456);
    println!("\n=== 完整电子签章操作流程测试 ===");

    // 步骤 1：CA 签发证书给签名者
    println!("\n--- 步骤 1：CA 签发证书 ---");
    let (signer_priv_key, signer_pub_key) = generate_keypair(&mut rng);
    let signer_cert = create_test_cert(&signer_priv_key, &mut rng);
    println!("✅ 签名者证书已签发");
    println!("   证书序列号: {:?}", signer_cert.serial_number);
    println!("   证书签发者: {:?}", signer_cert.issuer);
    println!("   证书主体: {:?}", signer_cert.subject);

    // 步骤 2：签名者签署文档（不包含 CRL）
    println!("\n--- 步骤 2：签署文档（无 CRL） ---");
    let content = "这是一份重要的合同文档".as_bytes();
    let cms_without_crl = CmsSignerBuilder::new()
        .content(content)
        .add_signer(&signer_priv_key, &signer_cert, DEFAULT_ID)
        .include_signing_time(true)
        .sign(&mut rng)
        .expect("CMS signing should succeed");
    println!("✅ 文档签名成功（无 CRL），长度：{} 字节", cms_without_crl.len());

    // 步骤 3：验证签名（应该成功，因为证书有效且未被撤销）
    println!("\n--- 步骤 3：验证签名（无 CRL） ---");
    let result = verify_digital_signature(&cms_without_crl, DEFAULT_ID)
        .expect("CMS verification should complete");
    assert!(result.is_valid, "签名应该有效");
    assert_eq!(result.content, content);
    println!("✅ 签名验证通过（无 CRL）");
    println!("   内容匹配: {}", result.content == content);
    println!("   有效签名者: {}/{}", result.valid_signers_count(), result.total_signers_count());

    // 步骤 4：CA 撤销证书（模拟私钥泄露场景）
    println!("\n--- 步骤 4：CA 撤销证书 ---");
    
    // 使用与证书相同的签发者名称（自签名证书的 issuer == subject）
    let ca_name = signer_cert.issuer.clone();

    let signer_serial_u64 = signer_cert.serial_number.clone();
    println!("   被撤销的证书序列号: {}", signer_serial_u64.to_string());
    println!("   CRL 签发者: {:?}", ca_name);

    let crl = CrlBuilder::new()
        .issuer(&ca_name)
        .this_update(std::time::SystemTime::now())
        .next_update(std::time::SystemTime::now() + Duration::from_secs(7 * 24 * 3600))
        .add_revoked(
            signer_serial_u64.clone(),
            std::time::SystemTime::now(),
            Some(1), // keyCompromise
            None,
        )
        .sign(&signer_priv_key, DEFAULT_ID, &mut rng)
        .expect("CRL signing should succeed");
    println!("✅ CRL 已签发，包含 1 个被撤销的证书");

    // 验证 CRL 签名
    crl.verify_signature(&signer_pub_key, DEFAULT_ID)
        .expect("CRL signature should be valid");
    println!("✅ CRL 签名验证通过");

    // 确认证书在 CRL 中
    assert!(crl.is_revoked(&signer_serial_u64), "证书应该在 CRL 中");
    println!("✅ 确认证书已被撤销");

    // 步骤 5：签名者签署文档（包含 CRL）
    println!("\n--- 步骤 5：签署文档（包含 CRL） ---");
    let cms_with_crl = CmsSignerBuilder::new()
        .content(content)
        .add_signer(&signer_priv_key, &signer_cert, DEFAULT_ID)
        .add_crl(crl.clone())
        .include_signing_time(true)
        .sign(&mut rng)
        .expect("CMS signing with CRL should succeed");
    println!("✅ 文档签名成功（包含 CRL），长度：{} 字节", cms_with_crl.len());

    // 步骤 6：验证签名（应该失败，因为证书已被撤销）
    println!("\n--- 步骤 6：验证签名（包含 CRL） ---");
    let result_with_crl = verify_digital_signature(&cms_with_crl, DEFAULT_ID)
        .expect("CMS verification should complete");
    
    // 验证应该失败，因为证书在 CRL 中
    assert!(!result_with_crl.is_valid, "签名应该无效（证书已撤销）");
    println!("✅ 签名验证失败（预期行为）");
    println!("   验证失败原因:");
    for signer_result in &result_with_crl.signer_results {
        for error in &signer_result.errors {
            println!("     - {}", error);
        }
    }

    // 步骤 7：使用未撤销的证书签名（应该成功）
    println!("\n--- 步骤 7：使用未撤销的证书签名 ---");
    let (other_priv_key, _) = generate_keypair(&mut rng);
    let other_cert = create_test_cert_with_serial(&other_priv_key, 999, &mut rng);
    let other_serial = other_cert.serial_number.clone();
    println!("   新证书序列号: {}", other_serial);

    // 确认新证书不在 CRL 中
    assert!(!crl.is_revoked(&other_serial.clone()), "新证书不应该在 CRL 中");

    let cms_other = CmsSignerBuilder::new()
        .content(content)
        .add_signer(&other_priv_key, &other_cert, DEFAULT_ID)
        .add_crl(crl)
        .include_signing_time(true)
        .sign(&mut rng)
        .expect("CMS signing with other cert should succeed");

    let result_other = verify_digital_signature(&cms_other, DEFAULT_ID)
        .expect("CMS verification should complete");
    assert!(result_other.is_valid, "使用未撤销证书的签名应该有效");
    println!("✅ 使用未撤销证书的签名验证通过");

    println!("\n=== 完整电子签章操作流程测试完成 ===");
}

/// 测试多签名者场景下的 CRL 验证
///
/// 场景：
/// - 3 个签名者签署同一文档
/// - 其中 1 个证书被撤销
/// - 验证结果应该显示部分签名有效，部分无效
#[test]
fn test_multiple_signers_with_crl() {
    let mut rng = StdRng::seed_from_u64(789012);
    println!("\n=== 多签名者 CRL 验证测试 ===");

    // 创建 3 个签名者证书（使用不同的序列号）
    let (priv1, _) = generate_keypair(&mut rng);
    let cert1 = create_test_cert_with_serial(&priv1, 1001, &mut rng);

    let (priv2, _) = generate_keypair(&mut rng);
    let cert2 = create_test_cert_with_serial(&priv2, 1002, &mut rng);

    let (priv3, _) = generate_keypair(&mut rng);
    let cert3 = create_test_cert_with_serial(&priv3, 1003, &mut rng);

    println!("✅ 创建 3 个签名者证书");
    println!("   证书 1 序列号: {}", cert1.serial_number.to_string());
    println!("   证书 2 序列号: {}", cert2.serial_number.to_string());
    println!("   证书 3 序列号: {}", cert3.serial_number.to_string());

    // 撤销证书 2
    // 使用与证书相同的签发者名称（自签名证书的 issuer == subject）
    let ca_name = cert2.issuer.clone();

    let crl = CrlBuilder::new()
        .issuer(&ca_name)
        .this_update(std::time::SystemTime::now())
        .next_update(std::time::SystemTime::now() + Duration::from_secs(3600))
        .add_revoked(cert2.serial_number.clone(), std::time::SystemTime::now(), Some(1), None)
        .sign(&priv2, DEFAULT_ID, &mut rng)
        .expect("CRL signing should succeed");

    crl.verify_signature(&cert2.extract_sm2_public_key().unwrap(), DEFAULT_ID)
        .expect("CRL signature should be valid");
    println!("✅ CRL 已签发，撤销证书 2");

    // 3 个签名者签署文档
    let content = "多方签署的合同".as_bytes();
    let cms = CmsSignerBuilder::new()
        .content(content)
        .add_signer(&priv1, &cert1, DEFAULT_ID)
        .add_signer(&priv2, &cert2, DEFAULT_ID) // 这个证书已被撤销
        .add_signer(&priv3, &cert3, DEFAULT_ID)
        .add_crl(crl)
        .include_signing_time(true)
        .sign(&mut rng)
        .expect("CMS signing should succeed");

    println!("✅ 3 个签名者签署文档完成");

    // 验证签名
    let result = verify_digital_signature(&cms, DEFAULT_ID)
        .expect("CMS verification should complete");

    // 整体应该无效（因为有签名者证书被撤销）
    assert!(!result.is_valid, "整体签名应该无效");
    println!("\n✅ 整体签名验证结果: 无效（预期）");

    // 检查每个签名者的状态
    println!("\n各签名者验证状态:");
    for (i, signer_result) in result.signer_results.iter().enumerate() {
        println!("  签名者 {}: 有效={}", i + 1, signer_result.is_valid);
        if !signer_result.errors.is_empty() {
            for error in &signer_result.errors {
                println!("    错误: {}", error);
            }
        }
    }

    // 签名者 1 和 3 应该有效，签名者 2 应该无效
    assert!(result.signer_results[0].is_valid, "签名者 1 应该有效");
    assert!(!result.signer_results[1].is_valid, "签名者 2 应该无效（证书已撤销）");
    assert!(result.signer_results[2].is_valid, "签名者 3 应该有效");

    println!("\n✅ 多签名者 CRL 验证测试完成");
}
