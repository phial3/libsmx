#![cfg(all(feature = "alloc", feature = "std"))]

//! 使用 data 目录中的真实证书和密钥测试 CMS 电子签章功能

use libsmx::sm2::cert::GmCertificate;
use libsmx::sm2::cms;
use libsmx::sm2::PrivateKey;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::fs;

#[test]
fn test_cms_digital_signature_with_real_cert() {
    // 加载证书和私钥
    let cert_pem = fs::read("data/certification.cer").expect("读取证书失败");
    let key_pem = fs::read("data/privatekey.key").expect("读取私钥失败");

    let cert = GmCertificate::from_pem(&cert_pem).expect("解析证书失败");
    let priv_key = PrivateKey::from_pkcs8_pem(&key_pem).expect("解析私钥失败");

    // 验证证书和私钥匹配
    let cert_pub_key = cert.extract_sm2_public_key().expect("提取公钥失败");
    let priv_pub_key = priv_key.public_key();
    assert_eq!(cert_pub_key, priv_pub_key, "证书和私钥不匹配");

    // 测试数据
    let test_data = b"Test data for CMS signature with real certificate";
    let id = b"1234567812345678";
    let mut rng = StdRng::seed_from_u64(123456);

    // 创建电子签名
    let signature_der = cms::create_digital_signature(
        test_data,
        &priv_key,
        &cert,
        id,
        &mut rng,
        false,
    ).expect("CMS 签名创建失败");

    // 验证电子签名
    let result = cms::verify_digital_signature(&signature_der, id)
        .expect("CMS 签名验证出错");

    assert!(result.is_valid, "签名验证应该成功");
    assert_eq!(result.signer_count, 1, "应该有 1 个签名者");
    assert_eq!(result.content, test_data, "恢复的内容应该匹配原始数据");
}

#[test]
fn test_cms_signature_tampering_detection() {
    // 加载证书和私钥
    let cert_pem = fs::read("data/certification.cer").expect("读取证书失败");
    let key_pem = fs::read("data/privatekey.key").expect("读取私钥失败");

    let cert = GmCertificate::from_pem(&cert_pem).expect("解析证书失败");
    let priv_key = PrivateKey::from_pkcs8_pem(&key_pem).expect("解析私钥失败");

    let test_data = b"Original content";
    let id = b"1234567812345678";
    let mut rng = StdRng::seed_from_u64(123456);

    // 创建电子签名
    let mut signature_der = cms::create_digital_signature(
        test_data,
        &priv_key,
        &cert,
        id,
        &mut rng,
        false,
    ).expect("CMS 签名创建失败");

    // 篡改内容数据
    if let Some(pos) = signature_der.windows(b"Original content".len()).position(|w| w == b"Original content") {
        signature_der[pos] ^= 0xFF;
    }

    // 验证应该失败
    match cms::verify_digital_signature(&signature_der, id) {
        Ok(result) => assert!(!result.is_valid, "篡改后的签名应该无效"),
        Err(_) => (), // 解析失败也接受
    }
}
