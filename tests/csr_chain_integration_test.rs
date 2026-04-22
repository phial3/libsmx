//! CSR 和证书链验证集成测试
//!
//! 测试覆盖：
//! - CSR 创建、验证、编码/解码
//! - 证书链验证
//! - 边界条件和错误处理

#![cfg(feature = "std")]

use core::str::FromStr;
use libsmx::sm2::cert::{
    build_x500_name, generate_self_signed_cert, issue_certificate, X500Attribute, X500AttributeType,
};
use libsmx::sm2::csr::{issue_certificate_from_csr, CertificateChain, CertificateSigningRequest};
use libsmx::sm2::{generate_keypair, DEFAULT_ID};
use rand::rngs::StdRng;
use rand::SeedableRng;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

fn build_test_validity() -> Validity {
    let not_before = Time::from_str("2024-01-01T00:00:00Z").unwrap();
    let not_after = Time::from_str("2030-01-01T00:00:00Z").unwrap();
    Validity::new(not_before, not_after)
}

// ====================================================================================
// CSR 集成测试
// ====================================================================================

/// 测试 CSR 创建和验证
#[test]
fn test_csr_create_verify_integration() {
    let mut rng = StdRng::seed_from_u64(12345);
    let (priv_key, pub_key) = generate_keypair(&mut rng);
    let subject = build_x500_name(&[
        X500Attribute::new(X500AttributeType::CommonName, "test.example.com"),
        X500Attribute::new(X500AttributeType::Organization, "Test Org"),
    ]);

    let csr = CertificateSigningRequest::create(&priv_key, &subject, DEFAULT_ID, &mut rng)
        .expect("Failed to create CSR");

    csr.verify().expect("CSR signature verification failed");

    let csr_pub_key = csr.public_key().expect("Failed to get public key from CSR");
    assert_eq!(csr_pub_key.as_bytes(), pub_key.as_bytes());
}

/// 测试 CSR DER 编码/解码
#[test]
fn test_csr_der_integration() {
    let mut rng = StdRng::seed_from_u64(12345);
    let (priv_key, _) = generate_keypair(&mut rng);
    let subject = build_x500_name(&[X500Attribute::new(
        X500AttributeType::CommonName,
        "test.example.com",
    )]);

    let csr = CertificateSigningRequest::create(&priv_key, &subject, DEFAULT_ID, &mut rng)
        .expect("Failed to create CSR");

    let der = csr.to_der().expect("Failed to encode CSR to DER");
    assert!(!der.is_empty());

    let csr_decoded =
        CertificateSigningRequest::from_der(&der).expect("Failed to decode CSR from DER");

    assert_eq!(csr.subject(), csr_decoded.subject());
    csr_decoded
        .verify()
        .expect("Decoded CSR signature verification failed");
}

/// 测试 CSR PEM 编码/解码
#[test]
fn test_csr_pem_integration() {
    let mut rng = StdRng::seed_from_u64(12345);
    let (priv_key, _) = generate_keypair(&mut rng);
    let subject = build_x500_name(&[X500Attribute::new(
        X500AttributeType::CommonName,
        "test.example.com",
    )]);

    let csr = CertificateSigningRequest::create(&priv_key, &subject, DEFAULT_ID, &mut rng)
        .expect("Failed to create CSR");

    let pem = csr.to_pem().expect("Failed to encode CSR to PEM");
    assert!(pem.contains("CERTIFICATE REQUEST"));

    let csr_decoded =
        CertificateSigningRequest::from_pem(&pem).expect("Failed to decode CSR from PEM");

    assert_eq!(csr.subject(), csr_decoded.subject());
    csr_decoded
        .verify()
        .expect("Decoded CSR signature verification failed");
}

/// 测试 CSR 验证失败 - 篡改签名
#[test]
fn test_csr_verify_failure_tampered_signature() {
    let mut rng = StdRng::seed_from_u64(12345);
    let (priv_key, _) = generate_keypair(&mut rng);
    let subject = build_x500_name(&[X500Attribute::new(
        X500AttributeType::CommonName,
        "test.example.com",
    )]);

    let mut csr = CertificateSigningRequest::create(&priv_key, &subject, DEFAULT_ID, &mut rng)
        .expect("Failed to create CSR");

    csr.signature =
        x509_cert::der::asn1::BitString::new(0, &[0u8; 64]).expect("Failed to create bit string");

    assert!(
        csr.verify().is_err(),
        "Verification should fail for tampered signature"
    );
}

// ====================================================================================
// 证书链验证集成测试
// ====================================================================================

/// 测试完整证书链验证（根 CA -> 中间 CA -> 终端证书）
#[test]
fn test_full_certificate_chain_integration() {
    let mut rng = StdRng::seed_from_u64(12345);

    // 创建根 CA
    let (root_priv_key, _) = generate_keypair(&mut rng);
    let root_subject = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test Root CA"),
        X500Attribute::new(X500AttributeType::CommonName, "Root CA"),
    ]);
    let root_serial = SerialNumber::from(1u64);
    let root_validity = build_test_validity();
    let root_cert = generate_self_signed_cert(
        &root_priv_key,
        &root_subject,
        &root_validity,
        &root_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to generate root CA certificate");

    // 创建中间 CA
    let (intermediate_priv_key, _) = generate_keypair(&mut rng);
    let intermediate_subject = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test Intermediate CA"),
        X500Attribute::new(X500AttributeType::CommonName, "Intermediate CA"),
    ]);
    let intermediate_serial = SerialNumber::from(2u64);
    let intermediate_validity = build_test_validity();
    let intermediate_cert = issue_certificate(
        &root_cert,
        &root_priv_key,
        &intermediate_subject,
        &intermediate_priv_key.public_key(),
        &intermediate_validity,
        &intermediate_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to generate intermediate CA certificate");

    // 创建终端证书
    let (end_priv_key, _) = generate_keypair(&mut rng);
    let end_subject = build_x500_name(&[X500Attribute::new(
        X500AttributeType::CommonName,
        "test.example.com",
    )]);
    let end_serial = SerialNumber::from(3u64);
    let end_validity = build_test_validity();
    let end_cert = issue_certificate(
        &intermediate_cert,
        &intermediate_priv_key,
        &end_subject,
        &end_priv_key.public_key(),
        &end_validity,
        &end_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to generate end certificate");

    // 验证证书链
    let mut chain = CertificateChain::new();
    chain.add_certificate(end_cert);
    chain.add_certificate(intermediate_cert);

    let mut trust_anchors = Vec::new();
    trust_anchors.push(root_cert);

    let result = chain.verify(&trust_anchors);
    assert!(
        result.is_valid,
        "Certificate chain verification should succeed: {:?}",
        result.errors
    );
    assert_eq!(result.chain.len(), 3, "Chain should contain 3 certificates");
}

/// 测试证书链验证失败 - 缺少信任锚
#[test]
fn test_chain_verification_missing_trust_anchor() {
    let mut rng = StdRng::seed_from_u64(12345);

    // 创建根 CA
    let (root_priv_key, _) = generate_keypair(&mut rng);
    let root_subject = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test CA"),
        X500Attribute::new(X500AttributeType::CommonName, "Root CA"),
    ]);
    let root_serial = SerialNumber::from(1u64);
    let root_validity = build_test_validity();
    let root_cert = generate_self_signed_cert(
        &root_priv_key,
        &root_subject,
        &root_validity,
        &root_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to generate CA certificate");

    // 创建终端证书
    let (end_priv_key, _) = generate_keypair(&mut rng);
    let end_subject = build_x500_name(&[X500Attribute::new(
        X500AttributeType::CommonName,
        "test.example.com",
    )]);
    let end_serial = SerialNumber::from(100u64);
    let end_validity = build_test_validity();
    let end_cert = issue_certificate(
        &root_cert,
        &root_priv_key,
        &end_subject,
        &end_priv_key.public_key(),
        &end_validity,
        &end_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to generate end certificate");

    // 验证证书链（不提供信任锚）
    let mut chain = CertificateChain::new();
    chain.add_certificate(end_cert);

    let trust_anchors = Vec::new();
    let result = chain.verify(&trust_anchors);
    assert!(
        !result.is_valid,
        "Certificate chain verification should fail without trust anchor"
    );
}

/// 测试空证书链验证
#[test]
fn test_empty_chain_verification() {
    let chain = CertificateChain::new();
    let trust_anchors = Vec::new();

    let result = chain.verify(&trust_anchors);
    assert!(
        !result.is_valid,
        "Empty certificate chain should fail verification"
    );
}

/// 测试自签名证书验证
#[test]
fn test_self_signed_certificate_verification() {
    let mut rng = StdRng::seed_from_u64(12345);

    // 创建自签名证书
    let (priv_key, _) = generate_keypair(&mut rng);
    let subject = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test Org"),
        X500Attribute::new(X500AttributeType::CommonName, "Self Signed"),
    ]);
    let serial = SerialNumber::from(1u64);
    let validity = build_test_validity();
    let cert = generate_self_signed_cert(
        &priv_key, &subject, &validity, &serial, DEFAULT_ID, None, &mut rng,
    )
    .expect("Failed to generate self-signed certificate");

    // 验证自签名证书
    let mut chain = CertificateChain::new();
    chain.add_certificate(cert.clone());

    let mut trust_anchors = Vec::new();
    trust_anchors.push(cert);

    let result = chain.verify(&trust_anchors);
    assert!(
        result.is_valid,
        "Self-signed certificate verification should succeed: {:?}",
        result.errors
    );
}

/// 测试证书链长度
#[test]
fn test_chain_length() {
    let mut chain = CertificateChain::new();
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);

    let mut rng = StdRng::seed_from_u64(12345);
    let (priv_key, _) = generate_keypair(&mut rng);
    let subject = build_x500_name(&[X500Attribute::new(X500AttributeType::CommonName, "Test")]);
    let serial = SerialNumber::from(1u64);
    let validity = build_test_validity();
    let cert = generate_self_signed_cert(
        &priv_key, &subject, &validity, &serial, DEFAULT_ID, None, &mut rng,
    )
    .expect("Failed to generate certificate");

    chain.add_certificate(cert);
    assert!(!chain.is_empty());
    assert_eq!(chain.len(), 1);
}

// ====================================================================================
// CSR 到 CA 颁发证书完整流程集成测试
// ====================================================================================

/// 测试完整的 CSR 到证书颁发流程
#[test]
fn test_csr_to_certificate_full_workflow_integration() {
    let mut rng = StdRng::seed_from_u64(12345);

    // 步骤 1: 创建 CA
    let (ca_priv_key, _ca_pub_key) = generate_keypair(&mut rng);
    let ca_subject = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test CA"),
        X500Attribute::new(X500AttributeType::CommonName, "Root CA"),
    ]);
    let ca_serial = SerialNumber::from(1u64);
    let ca_validity = build_test_validity();
    let ca_cert = generate_self_signed_cert(
        &ca_priv_key,
        &ca_subject,
        &ca_validity,
        &ca_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to generate CA certificate");

    // 步骤 2: 申请者创建密钥对和 CSR
    let (applicant_priv_key, applicant_pub_key) = generate_keypair(&mut rng);
    let applicant_subject = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test Org"),
        X500Attribute::new(X500AttributeType::CommonName, "test.example.com"),
    ]);

    let csr = CertificateSigningRequest::create(
        &applicant_priv_key,
        &applicant_subject,
        DEFAULT_ID,
        &mut rng,
    )
    .expect("Failed to create CSR");

    // 步骤 3: 验证 CSR 签名
    csr.verify().expect("CSR signature verification failed");

    // 步骤 4: CA 从 CSR 颁发证书
    let cert_serial = SerialNumber::from(100u64);
    let cert_validity = build_test_validity();
    let issued_cert = issue_certificate_from_csr(
        &csr,
        &ca_cert,
        &ca_priv_key,
        &cert_validity,
        &cert_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to issue certificate from CSR");

    // 步骤 5: 验证颁发的证书
    assert_eq!(issued_cert.subject, applicant_subject);
    assert_eq!(issued_cert.issuer, ca_subject);
    assert_eq!(issued_cert.serial_number, cert_serial);

    // 步骤 6: 验证证书中的公钥与申请者公钥匹配
    assert_eq!(
        issued_cert.subject_public_key_info.subject_public_key.raw_bytes(),
        applicant_pub_key.as_bytes()
    );

    // 步骤 7: 证书链验证
    let mut chain = CertificateChain::new();
    chain.add_certificate(issued_cert);

    let mut trust_anchors = Vec::new();
    trust_anchors.push(ca_cert);

    let result = chain.verify(&trust_anchors);
    assert!(
        result.is_valid,
        "Certificate chain verification should succeed: {:?}",
        result.errors
    );
}

/// 测试 CSR DER 编码/解码后颁发证书
#[test]
fn test_csr_der_roundtrip_and_issue_certificate() {
    let mut rng = StdRng::seed_from_u64(12345);

    // 创建 CA
    let (ca_priv_key, _) = generate_keypair(&mut rng);
    let ca_subject = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test CA"),
        X500Attribute::new(X500AttributeType::CommonName, "Root CA"),
    ]);
    let ca_serial = SerialNumber::from(1u64);
    let ca_validity = build_test_validity();
    let ca_cert = generate_self_signed_cert(
        &ca_priv_key,
        &ca_subject,
        &ca_validity,
        &ca_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to generate CA certificate");

    // 申请者创建 CSR
    let (applicant_priv_key, _) = generate_keypair(&mut rng);
    let applicant_subject = build_x500_name(&[X500Attribute::new(
        X500AttributeType::CommonName,
        "test.example.com",
    )]);

    let csr = CertificateSigningRequest::create(
        &applicant_priv_key,
        &applicant_subject,
        DEFAULT_ID,
        &mut rng,
    )
    .expect("Failed to create CSR");

    // CSR DER 编码/解码
    let csr_der = csr.to_der().expect("Failed to encode CSR to DER");
    let csr_decoded =
        CertificateSigningRequest::from_der(&csr_der).expect("Failed to decode CSR from DER");

    // 验证解码后的 CSR
    csr_decoded
        .verify()
        .expect("Decoded CSR signature verification failed");

    // CA 从解码后的 CSR 颁发证书
    let cert_serial = SerialNumber::from(200u64);
    let cert_validity = build_test_validity();
    let issued_cert = issue_certificate_from_csr(
        &csr_decoded,
        &ca_cert,
        &ca_priv_key,
        &cert_validity,
        &cert_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to issue certificate from decoded CSR");

    // 验证颁发的证书
    assert_eq!(issued_cert.subject, applicant_subject);
}

/// 测试 CSR PEM 编码/解码后颁发证书
#[test]
fn test_csr_pem_roundtrip_and_issue_certificate() {
    let mut rng = StdRng::seed_from_u64(12345);

    // 创建 CA
    let (ca_priv_key, _) = generate_keypair(&mut rng);
    let ca_subject = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test CA"),
        X500Attribute::new(X500AttributeType::CommonName, "Root CA"),
    ]);
    let ca_serial = SerialNumber::from(1u64);
    let ca_validity = build_test_validity();
    let ca_cert = generate_self_signed_cert(
        &ca_priv_key,
        &ca_subject,
        &ca_validity,
        &ca_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to generate CA certificate");

    // 申请者创建 CSR
    let (applicant_priv_key, _) = generate_keypair(&mut rng);
    let applicant_subject = build_x500_name(&[X500Attribute::new(
        X500AttributeType::CommonName,
        "test.example.com",
    )]);

    let csr = CertificateSigningRequest::create(
        &applicant_priv_key,
        &applicant_subject,
        DEFAULT_ID,
        &mut rng,
    )
    .expect("Failed to create CSR");

    // CSR PEM 编码/解码
    let csr_pem = csr.to_pem().expect("Failed to encode CSR to PEM");
    assert!(csr_pem.contains("-----BEGIN CERTIFICATE REQUEST-----"));
    assert!(csr_pem.contains("-----END CERTIFICATE REQUEST-----"));

    let csr_decoded =
        CertificateSigningRequest::from_pem(&csr_pem).expect("Failed to decode CSR from PEM");

    // 验证解码后的 CSR
    csr_decoded
        .verify()
        .expect("Decoded CSR signature verification failed");

    // CA 从解码后的 CSR 颁发证书
    let cert_serial = SerialNumber::from(300u64);
    let cert_validity = build_test_validity();
    let issued_cert = issue_certificate_from_csr(
        &csr_decoded,
        &ca_cert,
        &ca_priv_key,
        &cert_validity,
        &cert_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to issue certificate from decoded CSR");

    // 验证颁发的证书
    assert_eq!(issued_cert.subject, applicant_subject);
}

/// 测试篡改 CSR 签名后 CA 拒绝颁发证书
#[test]
fn test_tampered_csr_rejected_by_ca() {
    let mut rng = StdRng::seed_from_u64(12345);

    // 创建 CA
    let (ca_priv_key, _) = generate_keypair(&mut rng);
    let ca_subject = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test CA"),
        X500Attribute::new(X500AttributeType::CommonName, "Root CA"),
    ]);
    let ca_serial = SerialNumber::from(1u64);
    let ca_validity = build_test_validity();
    let ca_cert = generate_self_signed_cert(
        &ca_priv_key,
        &ca_subject,
        &ca_validity,
        &ca_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to generate CA certificate");

    // 申请者创建 CSR
    let (applicant_priv_key, _) = generate_keypair(&mut rng);
    let applicant_subject = build_x500_name(&[X500Attribute::new(
        X500AttributeType::CommonName,
        "test.example.com",
    )]);

    let mut csr = CertificateSigningRequest::create(
        &applicant_priv_key,
        &applicant_subject,
        DEFAULT_ID,
        &mut rng,
    )
    .expect("Failed to create CSR");

    // 篡改 CSR 签名
    csr.signature =
        x509_cert::der::asn1::BitString::new(0, &[0u8; 64]).expect("Failed to create bit string");

    // CA 拒绝颁发证书（CSR 签名无效）
    let cert_serial = SerialNumber::from(400u64);
    let cert_validity = build_test_validity();
    let result = issue_certificate_from_csr(
        &csr,
        &ca_cert,
        &ca_priv_key,
        &cert_validity,
        &cert_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    );

    assert!(
        result.is_err(),
        "Certificate issuance should fail with invalid CSR signature"
    );
}

/// 测试多级证书链使用 CSR 颁发
#[test]
fn test_multi_level_chain_with_csr_integration() {
    let mut rng = StdRng::seed_from_u64(12345);

    // 步骤 1: 创建根 CA
    let (root_priv_key, _) = generate_keypair(&mut rng);
    let root_subject = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test Root CA"),
        X500Attribute::new(X500AttributeType::CommonName, "Root CA"),
    ]);
    let root_serial = SerialNumber::from(1u64);
    let root_validity = build_test_validity();
    let root_cert = generate_self_signed_cert(
        &root_priv_key,
        &root_subject,
        &root_validity,
        &root_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to generate root CA certificate");

    // 步骤 2: 中间 CA 创建 CSR
    let (intermediate_priv_key, _) = generate_keypair(&mut rng);
    let intermediate_subject = build_x500_name(&[
        X500Attribute::new(X500AttributeType::Organization, "Test Intermediate CA"),
        X500Attribute::new(X500AttributeType::CommonName, "Intermediate CA"),
    ]);

    let intermediate_csr = CertificateSigningRequest::create(
        &intermediate_priv_key,
        &intermediate_subject,
        DEFAULT_ID,
        &mut rng,
    )
    .expect("Failed to create intermediate CA CSR");

    // 根 CA 为中间 CA 颁发证书
    let intermediate_cert_serial = SerialNumber::from(2u64);
    let intermediate_cert_validity = build_test_validity();
    let intermediate_cert = issue_certificate_from_csr(
        &intermediate_csr,
        &root_cert,
        &root_priv_key,
        &intermediate_cert_validity,
        &intermediate_cert_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to issue intermediate CA certificate");

    // 步骤 3: 终端实体创建 CSR
    let (end_priv_key, _) = generate_keypair(&mut rng);
    let end_subject = build_x500_name(&[X500Attribute::new(
        X500AttributeType::CommonName,
        "test.example.com",
    )]);

    let end_csr = CertificateSigningRequest::create(
        &end_priv_key,
        &end_subject,
        DEFAULT_ID,
        &mut rng,
    )
    .expect("Failed to create end entity CSR");

    // 中间 CA 为终端实体颁发证书
    let end_cert_serial = SerialNumber::from(3u64);
    let end_cert_validity = build_test_validity();
    let end_cert = issue_certificate_from_csr(
        &end_csr,
        &intermediate_cert,
        &intermediate_priv_key,
        &end_cert_validity,
        &end_cert_serial,
        DEFAULT_ID,
        None,
        &mut rng,
    )
    .expect("Failed to issue end entity certificate");

    // 步骤 4: 验证完整证书链
    let mut chain = CertificateChain::new();
    chain.add_certificate(end_cert);
    chain.add_certificate(intermediate_cert);

    let mut trust_anchors = Vec::new();
    trust_anchors.push(root_cert);

    let result = chain.verify(&trust_anchors);
    assert!(
        result.is_valid,
        "Multi-level certificate chain verification should succeed: {:?}",
        result.errors
    );
    assert_eq!(result.chain.len(), 3, "Chain should contain 3 certificates");
}
