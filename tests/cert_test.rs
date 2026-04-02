#[cfg(all(test, feature = "alloc"))]
mod tests {
    use libsmx::sm2::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::fs;
    use std::path::Path;

    /// 构建 X.500 Name (RelativeDistinguishedName)
    ///
    /// 生成包含单个属性（如 commonName）的 X.500 Name DER 编码。
    /// Name ::= CHOICE { rdnSequence  RDNSequence }
    /// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    /// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
    fn build_name(oid: &[u8], value: &str) -> Vec<u8> {
        let value_bytes = value.as_bytes();
        let mut name = Vec::with_capacity(32);

        // SET
        name.push(0x31);
        name.push((2 + oid.len() + 2 + value_bytes.len()) as u8);

        // SEQUENCE
        name.push(0x30);
        name.push((oid.len() + 2 + value_bytes.len()) as u8);

        // OID
        name.extend_from_slice(oid);

        // PrintableString (简化处理，假设所有字符都可打印)
        name.push(0x13);
        name.push(value_bytes.len() as u8);
        name.extend_from_slice(value_bytes);

        name
    }

    /// commonName OID (2.5.4.3)
    const OID_COMMON_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];

    /// SM2withSM3 签名算法 OID (1.2.156.10197.1.501)
    const OID_SM2_WITH_SM3: &[u8] = &[0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D];

    /// 创建 SM2withSM3 签名算法标识符 (AlgorithmIdentifier)
    /// SEQUENCE { OID, NULL }
    fn sm2_with_sm3_algorithm() -> Vec<u8> {
        let mut alg = Vec::with_capacity(2 + OID_SM2_WITH_SM3.len() + 2);
        alg.push(0x30); // SEQUENCE
        alg.push((OID_SM2_WITH_SM3.len() + 2) as u8);
        alg.extend_from_slice(OID_SM2_WITH_SM3);
        alg.extend_from_slice(&[0x05, 0x00]); // NULL
        alg
    }

    /// 创建测试用的国密证书
    ///
    /// 使用辅助函数构建证书字段，避免直接操作字节。
    /// 证书有效期为 2001-01-01 到 2030-01-01。
    fn create_test_cert(pub_key: &[u8; 65]) -> cert::GmCertificate {
        // 使用辅助函数构建颁发者和主体名称
        let issuer = build_name(OID_COMMON_NAME, "TestCA");
        let subject = build_name(OID_COMMON_NAME, "TestUser");

        // 使用 UTCTime 字符串生成有效期（200101000000Z 到 300101000000Z）
        let validity = cert::generate_validity(b"010101000000Z", b"300101000000Z");

        cert::GmCertificate {
            version: 2, // v3
            serial_number: vec![0x01, 0x02, 0x03],
            signature_algorithm: sm2_with_sm3_algorithm(),
            issuer,
            validity,
            subject,
            subject_public_key_info: public_key_to_spki_der(pub_key),
            signature: vec![0x00; 64], // 占位签名（SM2 签名为 64 字节）
        }
    }

    #[test]
    fn test_generate_keypair() {
        let mut rng = StdRng::seed_from_u64(123456789);
        let (priv_key, pub_key) = generate_keypair(&mut rng);
        
        assert_eq!(priv_key.as_bytes().len(), 32);
        assert_eq!(pub_key.len(), 65);
        println!("✅ 测试 1：生成密钥对 - 通过");
    }

    #[test]
    fn test_generate_certificate_files() {
        let cert_der_file = "test_cert_gen.cert";
        let cert_pem_file = "test_cert_gen.pem";
        
        let _ = fs::remove_file(cert_der_file);
        let _ = fs::remove_file(cert_pem_file);
        
        let mut rng = StdRng::seed_from_u64(987654321);
        
        let (_issuer_priv, _issuer_pub) = generate_keypair(&mut rng);
        let (_subject_priv, subject_pub) = generate_keypair(&mut rng);
        
        let cert = create_test_cert(&subject_pub);
        let cert_der = cert::generate_gm_certificate(&cert);
        fs::write(cert_der_file, &cert_der).expect("写入 DER 文件应成功");
        assert!(Path::new(cert_der_file).exists());
        println!("✅ 测试 2.1：生成 DER 证书文件 - 通过 ({} 字节)", cert_der.len());
        
        let cert_pem = cert::generate_gm_certificate_pem(&cert).expect("PEM 证书生成应成功");
        fs::write(cert_pem_file, &cert_pem).expect("写入 PEM 文件应成功");
        assert!(Path::new(cert_pem_file).exists());
        println!("✅ 测试 2.2：生成 PEM 证书文件 - 通过");
        
        let _ = fs::remove_file(cert_der_file);
        let _ = fs::remove_file(cert_pem_file);
    }

    #[test]
    fn test_parse_certificate_files() {
        let mut rng = StdRng::seed_from_u64(1234567890);
        
        let (_priv_key, pub_key) = generate_keypair(&mut rng);
        let cert = create_test_cert(&pub_key);
        let cert_der = cert::generate_gm_certificate(&cert);
        
        let parsed_cert = cert::parse_gm_certificate(&cert_der).expect("解析 DER 证书应成功");
        assert_eq!(parsed_cert.version, cert.version);
        assert_eq!(parsed_cert.serial_number, cert.serial_number);
        println!("✅ 测试 3.1：解析 DER 证书 - 通过");
        
        let extracted_pub_key = cert::extract_sm2_public_key(&parsed_cert).expect("提取公钥应成功");
        assert_eq!(extracted_pub_key, pub_key);
        println!("✅ 测试 3.2：从证书提取公钥 - 通过");
        
        let cert_pem = cert::generate_gm_certificate_pem(&cert).expect("生成 PEM 应成功");
        let parsed_from_pem = cert::parse_gm_certificate_pem(&cert_pem).expect("解析 PEM 证书应成功");
        assert_eq!(parsed_from_pem.version, cert.version);
        println!("✅ 测试 3.3：解析 PEM 证书 - 通过");
    }

    #[test]
    fn test_private_key_sec1() {
        let priv_key_sec1_der_file = "test_priv_sec1_key.der";
        let priv_key_sec1_pem_file = "test_priv_sec1_key.pem";
        
        let _ = fs::remove_file(priv_key_sec1_der_file);
        let _ = fs::remove_file(priv_key_sec1_pem_file);
        
        let mut rng = StdRng::seed_from_u64(111111111);
        let (priv_key, _) = generate_keypair(&mut rng);
        
        let sec1_der = private_key_to_sec1_der(&priv_key);
        fs::write(priv_key_sec1_der_file, &sec1_der).expect("写入 SEC1 DER 应成功");
        assert!(Path::new(priv_key_sec1_der_file).exists());
        println!("✅ 测试 4.1：私钥 SEC1 DER - 通过 ({} 字节)", sec1_der.len());
        
        let recovered = private_key_from_sec1_der(&sec1_der)
            .expect("SEC1 解析应成功");
        assert_eq!(priv_key.as_bytes(), recovered.as_bytes());
        println!("✅ 测试 4.2：私钥 SEC1 DER 往返 - 通过");
        
        let sec1_pem = priv_key.to_sec1_pem()
            .expect("SEC1 PEM 编码应成功");
        fs::write(priv_key_sec1_pem_file, &sec1_pem).expect("写入 SEC1 PEM 应成功");
        assert!(Path::new(priv_key_sec1_pem_file).exists());
        println!("✅ 测试 4.3：私钥 SEC1 PEM - 通过");
        
        let recovered_pem = PrivateKey::from_sec1_pem(&sec1_pem)
            .expect("SEC1 PEM 解析应成功");
        assert_eq!(priv_key.as_bytes(), recovered_pem.as_bytes());
        println!("✅ 测试 4.4：私钥 SEC1 PEM 往返 - 通过");
        
        let _ = fs::remove_file(priv_key_sec1_der_file);
        let _ = fs::remove_file(priv_key_sec1_pem_file);
    }

    #[test]
    fn test_private_key_pkcs8() {
        let priv_key_pkcs8_der_file = "test_priv_pkcs8_key.der";
        let priv_key_pkcs8_pem_file = "test_priv_pkcs8_key.pem";
        
        let _ = fs::remove_file(priv_key_pkcs8_der_file);
        let _ = fs::remove_file(priv_key_pkcs8_pem_file);
        
        let mut rng = StdRng::seed_from_u64(222222222);
        let (priv_key, _) = generate_keypair(&mut rng);
        
        let pkcs8_der = private_key_to_pkcs8_der(&priv_key);
        fs::write(priv_key_pkcs8_der_file, &pkcs8_der).expect("写入 PKCS#8 DER 应成功");
        assert!(Path::new(priv_key_pkcs8_der_file).exists());
        println!("✅ 测试 5.1：私钥 PKCS#8 DER - 通过 ({} 字节)", pkcs8_der.len());
        
        let recovered = private_key_from_pkcs8_der(&pkcs8_der)
            .expect("PKCS#8 解析应成功");
        assert_eq!(priv_key.as_bytes(), recovered.as_bytes());
        println!("✅ 测试 5.2：私钥 PKCS#8 DER 往返 - 通过");
        
        let pkcs8_pem = priv_key.to_pkcs8_pem()
            .expect("PKCS#8 PEM 编码应成功");
        fs::write(priv_key_pkcs8_pem_file, &pkcs8_pem).expect("写入 PKCS#8 PEM 应成功");
        assert!(Path::new(priv_key_pkcs8_pem_file).exists());
        println!("✅ 测试 5.3：私钥 PKCS#8 PEM - 通过");
        
        let recovered_pem = PrivateKey::from_pkcs8_pem(&pkcs8_pem)
            .expect("PKCS#8 PEM 解析应成功");
        assert_eq!(priv_key.as_bytes(), recovered_pem.as_bytes());
        println!("✅ 测试 5.4：私钥 PKCS#8 PEM 往返 - 通过");
        
        let _ = fs::remove_file(priv_key_pkcs8_der_file);
        let _ = fs::remove_file(priv_key_pkcs8_pem_file);
    }

    #[test]
    fn test_public_key_spki() {
        let pub_key_spki_der_file = "test_pub_spki_key.der";
        let pub_key_spki_pem_file = "test_pub_spki_key.pem";
        
        let _ = fs::remove_file(pub_key_spki_der_file);
        let _ = fs::remove_file(pub_key_spki_pem_file);
        
        let mut rng = StdRng::seed_from_u64(333333333);
        let (_, pub_key) = generate_keypair(&mut rng);
        
        let spki_der = public_key_to_spki_der(&pub_key);
        fs::write(pub_key_spki_der_file, &spki_der).expect("写入 SPKI DER 应成功");
        assert!(Path::new(pub_key_spki_der_file).exists());
        println!("✅ 测试 6.1：公钥 SPKI DER - 通过 ({} 字节)", spki_der.len());
        
        let spki_pem = cert::public_key_to_spki_pem(&pub_key)
            .expect("SPKI PEM 编码应成功");
        fs::write(pub_key_spki_pem_file, &spki_pem).expect("写入 SPKI PEM 应成功");
        assert!(Path::new(pub_key_spki_pem_file).exists());
        println!("✅ 测试 6.2：公钥 SPKI PEM - 通过");
        
        let _ = fs::remove_file(pub_key_spki_der_file);
        let _ = fs::remove_file(pub_key_spki_pem_file);
    }

    #[test]
    fn test_certificate_signing_and_verification() {
        let signature_file = "test_signature_cert.bin";
        
        let _ = fs::remove_file(signature_file);
        
        let mut rng = StdRng::seed_from_u64(444444444);
        let (priv_key, pub_key) = generate_keypair(&mut rng);
        let test_data = b"Test data for certificate signing and verification";
        let id = DEFAULT_ID;
        
        let signature = cert::sign_certificate_data(test_data, &priv_key, id, &mut rng)
            .expect("签名应成功");
        fs::write(signature_file, &signature).expect("写入签名应成功");
        assert!(Path::new(signature_file).exists());
        assert_eq!(signature.len(), 64);
        println!("✅ 测试 7.1：证书签名 - 通过 (64 字节)");
        
        cert::verify_certificate_data(test_data, &signature, &pub_key, id)
            .expect("验证应成功");
        println!("✅ 测试 7.2：证书签名验证 - 通过");
        
        let tampered_data = b"Tampered test data";
        assert!(cert::verify_certificate_data(tampered_data, &signature, &pub_key, id).is_err());
        println!("✅ 测试 7.3：篡改数据检测 - 通过");
        
        let _ = fs::remove_file(signature_file);
    }

    #[test]
    fn test_file_roundtrip() {
        let cert_der_file = "test_cert_roundtrip.cert";
        let cert_pem_file = "test_cert_roundtrip.pem";
        let priv_key_sec1_der_file = "test_priv_sec1_roundtrip.der";
        let priv_key_sec1_pem_file = "test_priv_sec1_roundtrip.pem";
        let priv_key_pkcs8_der_file = "test_priv_pkcs8_roundtrip.der";
        let priv_key_pkcs8_pem_file = "test_priv_pkcs8_roundtrip.pem";
        let pub_key_spki_der_file = "test_pub_spki_roundtrip.der";
        let pub_key_spki_pem_file = "test_pub_spki_roundtrip.pem";
        let signature_file = "test_signature_roundtrip.bin";
        
        let _ = fs::remove_file(cert_der_file);
        let _ = fs::remove_file(cert_pem_file);
        let _ = fs::remove_file(priv_key_sec1_der_file);
        let _ = fs::remove_file(priv_key_sec1_pem_file);
        let _ = fs::remove_file(priv_key_pkcs8_der_file);
        let _ = fs::remove_file(priv_key_pkcs8_pem_file);
        let _ = fs::remove_file(pub_key_spki_der_file);
        let _ = fs::remove_file(pub_key_spki_pem_file);
        let _ = fs::remove_file(signature_file);
        
        let mut rng = StdRng::seed_from_u64(555555555);
        
        let (issuer_priv, issuer_pub) = generate_keypair(&mut rng);
        let (_subject_priv, subject_pub) = generate_keypair(&mut rng);
        
        let cert = create_test_cert(&subject_pub);
        let cert_der = cert::generate_gm_certificate(&cert);
        fs::write(cert_der_file, &cert_der).expect("写入 DER 文件应成功");
        
        let cert_pem = cert::generate_gm_certificate_pem(&cert).expect("PEM 证书生成应成功");
        fs::write(cert_pem_file, &cert_pem).expect("写入 PEM 文件应成功");
        
        let priv_sec1_der = private_key_to_sec1_der(&issuer_priv);
        fs::write(priv_key_sec1_der_file, &priv_sec1_der).expect("写入 SEC1 DER 应成功");
        
        let priv_sec1_pem = issuer_priv.to_sec1_pem()
            .expect("SEC1 PEM 编码应成功");
        fs::write(priv_key_sec1_pem_file, &priv_sec1_pem).expect("写入 SEC1 PEM 应成功");
        
        let priv_pkcs8_der = private_key_to_pkcs8_der(&issuer_priv);
        fs::write(priv_key_pkcs8_der_file, &priv_pkcs8_der).expect("写入 PKCS#8 DER 应成功");
        
        let priv_pkcs8_pem = issuer_priv.to_pkcs8_pem()
            .expect("PKCS#8 PEM 编码应成功");
        fs::write(priv_key_pkcs8_pem_file, &priv_pkcs8_pem).expect("写入 PKCS#8 PEM 应成功");
        
        let pub_spki_der = public_key_to_spki_der(&issuer_pub);
        fs::write(pub_key_spki_der_file, &pub_spki_der).expect("写入 SPKI DER 应成功");
        
        let pub_spki_pem = cert::public_key_to_spki_pem(&issuer_pub)
            .expect("SPKI PEM 编码应成功");
        fs::write(pub_key_spki_pem_file, &pub_spki_pem).expect("写入 SPKI PEM 应成功");
        
        let test_data = b"Test data for roundtrip";
        let id = DEFAULT_ID;
        let signature = cert::sign_certificate_data(test_data, &issuer_priv, id, &mut rng)
            .expect("签名应成功");
        fs::write(signature_file, &signature).expect("写入签名应成功");
        
        let loaded_cert_der = fs::read(cert_der_file).expect("读取 DER 证书应成功");
        let loaded_cert_pem = fs::read(cert_pem_file).expect("读取 PEM 证书应成功");
        let loaded_priv_sec1_der = fs::read(priv_key_sec1_der_file).expect("读取 SEC1 DER 应成功");
        let loaded_priv_sec1_pem = fs::read(priv_key_sec1_pem_file).expect("读取 SEC1 PEM 应成功");
        let loaded_priv_pkcs8_der = fs::read(priv_key_pkcs8_der_file).expect("读取 PKCS#8 DER 应成功");
        let loaded_priv_pkcs8_pem = fs::read(priv_key_pkcs8_pem_file).expect("读取 PKCS#8 PEM 应成功");
        let loaded_pub_spki_der = fs::read(pub_key_spki_der_file).expect("读取 SPKI DER 应成功");
        let loaded_pub_spki_pem = fs::read(pub_key_spki_pem_file).expect("读取 SPKI PEM 应成功");
        let loaded_signature = fs::read(signature_file).expect("读取签名应成功");
        
        assert_eq!(loaded_cert_der, cert_der);
        assert_eq!(loaded_cert_pem, cert_pem);
        assert_eq!(loaded_priv_sec1_der, priv_sec1_der);
        assert_eq!(loaded_priv_sec1_pem, priv_sec1_pem);
        assert_eq!(loaded_priv_pkcs8_der, priv_pkcs8_der);
        assert_eq!(loaded_priv_pkcs8_pem, priv_pkcs8_pem);
        assert_eq!(loaded_pub_spki_der, pub_spki_der);
        assert_eq!(loaded_pub_spki_pem, pub_spki_pem);
        assert_eq!(loaded_signature, signature);
        println!("✅ 测试 8：文件往返验证 - 通过");
        
        let _ = fs::remove_file(cert_der_file);
        let _ = fs::remove_file(cert_pem_file);
        let _ = fs::remove_file(priv_key_sec1_der_file);
        let _ = fs::remove_file(priv_key_sec1_pem_file);
        let _ = fs::remove_file(priv_key_pkcs8_der_file);
        let _ = fs::remove_file(priv_key_pkcs8_pem_file);
        let _ = fs::remove_file(pub_key_spki_der_file);
        let _ = fs::remove_file(pub_key_spki_pem_file);
        let _ = fs::remove_file(signature_file);
    }

    #[test]
    fn test_verify_certificate_validity() {
        let mut rng = StdRng::seed_from_u64(123456789);
        let (_priv_key, pub_key) = generate_keypair(&mut rng);
        let cert = create_test_cert(&pub_key);

        // 测试在有效期内 (2001-01-01 到 2030-01-01)
        let valid_time = 1609459200u64; // 2021-01-01 00:00:00 UTC
        cert.verify_validity(valid_time).expect("证书应在有效期内");
        println!("✅ 测试 9.1：证书有效期验证 - 通过");

        // 测试过期前
        let before_valid = 946684800u64; // 2000-01-01 00:00:00 UTC (证书生效前)
        assert!(cert.verify_validity(before_valid).is_err());
        println!("✅ 测试 9.2：证书生效前验证 - 通过");

        // 测试过期后 (证书在 2030-01-01 00:00:00 UTC 过期)
        let after_expired = 1893456001u64; // 2030-01-01 00:00:01 UTC (过期后 1 秒)
        assert!(cert.verify_validity(after_expired).is_err());
        println!("✅ 测试 9.3：证书过期后验证 - 通过");

        // 验证刚好在过期时间点 (应该仍然有效，因为是 <= not_after)
        let at_expiration = 1893456000u64; // 2030-01-01 00:00:00 UTC
        assert!(cert.verify_validity(at_expiration).is_ok());
        println!("✅ 测试 9.4：证书在过期时间点验证 - 通过");
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_verify_certificate_validity_system_time() {
        use std::time::{SystemTime, Duration};

        let mut rng = StdRng::seed_from_u64(123456789);
        let (_priv_key, pub_key) = generate_keypair(&mut rng);
        let cert = create_test_cert(&pub_key);

        // 使用 SystemTime 验证 (2001-01-01 到 2030-01-01)
        // 创建一个在有效期内的 SystemTime (2021-01-01)
        let valid_system_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1609459200);
        cert.verify_validity_system_time(valid_system_time).expect("证书应在有效期内");
        println!("✅ 测试 10.1：SystemTime 证书有效期验证 - 通过");

        // 测试过期前
        let before_valid = SystemTime::UNIX_EPOCH + Duration::from_secs(946684800);
        assert!(cert.verify_validity_system_time(before_valid).is_err());
        println!("✅ 测试 10.2：SystemTime 证书生效前验证 - 通过");

        // 测试过期后 (证书在 2030-01-01 00:00:00 UTC 过期)
        let after_expired = SystemTime::UNIX_EPOCH + Duration::from_secs(1893456001); // 过期后 1 秒
        assert!(cert.verify_validity_system_time(after_expired).is_err());
        println!("✅ 测试 10.3：SystemTime 证书过期后验证 - 通过");

        // 验证刚好在过期时间点 (应该仍然有效，因为是 <= not_after)
        let at_expiration = SystemTime::UNIX_EPOCH + Duration::from_secs(1893456000);
        assert!(cert.verify_validity_system_time(at_expiration).is_ok());
        println!("✅ 测试 10.4：SystemTime 证书在过期时间点验证 - 通过");
    }

    #[test]
    fn test_generate_validity_from_times() {
        use x509_cert::time::Time;
        use std::time::{SystemTime, Duration};

        // 创建两个时间点
        let not_before_sys = SystemTime::UNIX_EPOCH + Duration::from_secs(1609459200); // 2021-01-01
        let not_after_sys = SystemTime::UNIX_EPOCH + Duration::from_secs(1640995200);  // 2022-01-01

        let not_before = Time::try_from(not_before_sys).expect("转换时间应成功");
        let not_after = Time::try_from(not_after_sys).expect("转换时间应成功");

        // 生成有效期 DER
        let validity_der = cert::generate_validity_from_times(not_before, not_after);

        // 验证 DER 结构
        assert_eq!(validity_der[0], 0x30); // SEQUENCE tag
        assert!(validity_der.len() > 2);
        println!("✅ 测试 11：从 Time 生成有效期 DER - 通过 ({} 字节)", validity_der.len());

        // 验证包含两个时间字段
        // 解析 SEQUENCE 长度
        let seq_len = validity_der[1] as usize;
        assert!(seq_len > 0);

        // 验证第一个时间字段 (UTCTime 0x17 或 GeneralizedTime 0x18)
        let first_tag = validity_der[2];
        assert!(first_tag == 0x17 || first_tag == 0x18);

        // 验证第二个时间字段
        let first_time_len = validity_der[3] as usize;
        let second_tag_pos = 2 + 2 + first_time_len; // tag + len + content
        let second_tag = validity_der[second_tag_pos];
        assert!(second_tag == 0x17 || second_tag == 0x18);

        println!("✅ 测试 11.1：有效期 DER 结构验证 - 通过");
    }
}
