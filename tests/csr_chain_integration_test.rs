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
use libsmx::sm2::csr::{CertificateChain, CertificateSigningRequest};
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
