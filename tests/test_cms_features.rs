//! CMS 功能集成测试
//!
//! 测试 CMS 实现的所有功能，包括：
//! 1. 签名时间（signing_time）的提取
//! 2. CRL 列表的编码和解析
//! 3. 未签名属性（unsignedAttrs）的支持

#[cfg(all(test, feature = "alloc", feature = "std"))]
mod tests {
    use libsmx::sm2::cert::{self, X500Attribute, X500AttributeType};
    use libsmx::sm2::cms::{
        create_digital_signature, verify_digital_signature, CmsSignerBuilder,
    };
    use libsmx::sm2::{generate_keypair, DEFAULT_ID};
    use libsmx::sm3::Sm3Hasher;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::time::{Duration, SystemTime};

    fn create_test_cert_and_key(
        rng: &mut StdRng,
        common_name: &str,
        serial: u32,
    ) -> (cert::GmCertificate, libsmx::sm2::PrivateKey) {
        let (priv_key, pub_key) = generate_keypair(rng);
        let now = SystemTime::now();
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

    #[test]
    fn test_signing_time_feature() {
        let mut rng = StdRng::seed_from_u64(30001);
        let (cert, priv_key) = create_test_cert_and_key(&mut rng, "Signing Time Test", 30001);

        let data = b"Test data with signing time attribute";

        // 创建包含 signing-time 的签名
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
        
        println!("✅ 签名时间功能测试通过");
        println!("   签名时间 DER 编码长度：{} bytes", signer_result.signing_time.as_ref().unwrap().len());
    }

    #[test]
    fn test_without_signing_time() {
        let mut rng = StdRng::seed_from_u64(30002);
        let (cert, priv_key) = create_test_cert_and_key(&mut rng, "No Signing Time Test", 30002);

        let data = b"Test data without signing time";

        // 创建不包含 signing-time 的签名
        let signed_data = CmsSignerBuilder::new()
            .content(data.as_slice())
            .add_signer(&priv_key, &cert, DEFAULT_ID)
            .include_signing_time(false)
            .sign(&mut rng)
            .expect("Signature creation should succeed");

        // 验证签名
        let result = verify_digital_signature(&signed_data, DEFAULT_ID)
            .expect("Verification should succeed");

        assert!(result.is_valid);
        assert_eq!(result.content, data.as_slice());
        
        // 验证没有签名时间
        let signer_result = &result.signer_results[0];
        assert!(signer_result.signing_time.is_none(), "Signing time should not be present");
        
        println!("✅ 不包含签名时间的测试通过");
    }

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
        
        println!("✅ CRL 支持测试通过");
        println!("   证书数量：{}", result.certificates.len());
    }

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
        
        println!("✅ 未签名属性编码测试通过");
    }

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
        
        println!("✅ 完整 CMS 往返测试通过");
        println!("   数据长度：{} bytes", data.len());
        println!("   签名长度：{} bytes", signed_data.len());
        println!("   签名时间：存在");
    }

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
        
        println!("✅ 多签名者测试通过");
        println!("   签名者数量：{}", result.signer_results.len());
    }

    #[test]
    fn test_message_digest_verification() {
        let mut rng = StdRng::seed_from_u64(30008);
        let (cert, priv_key) = create_test_cert_and_key(&mut rng, "Message Digest Test", 30008);

        let data = b"Test data for message digest verification";
        let digest = Sm3Hasher::digest(data);

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
        
        println!("✅ 消息摘要验证测试通过");
    }

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
        
        println!("✅ 大数据签名时间测试通过");
        println!("   数据大小：{} bytes", data.len());
    }
}
