#[cfg(all(test, feature = "alloc"))]
mod tests {
    use libsmx::sm2::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::fs;
    use std::path::Path;

    fn create_test_cert(pub_key: &[u8; 65]) -> cert::GmCertificate {
        cert::GmCertificate {
            version: 2,
            serial_number: vec![0x01, 0x02, 0x03],
            signature_algorithm: vec![0x30, 0x0C, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D, 0x05, 0x00],
            issuer: vec![0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x08, 0x43, 0x41, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46],
            validity: vec![
                0x30, 0x1e,  // SEQUENCE, length 30
                0x17, 0x0d, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x5a,  // UTCTime
                0x17, 0x0d, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x5a,  // UTCTime
            ],
            subject: vec![0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x08, 0x55, 0x73, 0x65, 0x72, 0x4E, 0x61, 0x6D, 0x65],
            subject_public_key_info: cert::public_key_to_spki_der(pub_key),
            signature: vec![0x00, 0x01, 0x02, 0x03],
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
        
        let sec1_der = cert::private_key_to_sec1_der(&priv_key);
        fs::write(priv_key_sec1_der_file, &sec1_der).expect("写入 SEC1 DER 应成功");
        assert!(Path::new(priv_key_sec1_der_file).exists());
        println!("✅ 测试 4.1：私钥 SEC1 DER - 通过 ({} 字节)", sec1_der.len());
        
        let recovered = cert::private_key_from_sec1_der(&sec1_der)
            .expect("SEC1 解析应成功");
        assert_eq!(priv_key.as_bytes(), recovered.as_bytes());
        println!("✅ 测试 4.2：私钥 SEC1 DER 往返 - 通过");
        
        let sec1_pem = cert::private_key_to_sec1_pem(&priv_key)
            .expect("SEC1 PEM 编码应成功");
        fs::write(priv_key_sec1_pem_file, &sec1_pem).expect("写入 SEC1 PEM 应成功");
        assert!(Path::new(priv_key_sec1_pem_file).exists());
        println!("✅ 测试 4.3：私钥 SEC1 PEM - 通过");
        
        let recovered_pem = cert::private_key_from_sec1_pem(&sec1_pem)
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
        
        let pkcs8_der = cert::private_key_to_pkcs8_der(&priv_key);
        fs::write(priv_key_pkcs8_der_file, &pkcs8_der).expect("写入 PKCS#8 DER 应成功");
        assert!(Path::new(priv_key_pkcs8_der_file).exists());
        println!("✅ 测试 5.1：私钥 PKCS#8 DER - 通过 ({} 字节)", pkcs8_der.len());
        
        let recovered = cert::private_key_from_pkcs8_der(&pkcs8_der)
            .expect("PKCS#8 解析应成功");
        assert_eq!(priv_key.as_bytes(), recovered.as_bytes());
        println!("✅ 测试 5.2：私钥 PKCS#8 DER 往返 - 通过");
        
        let pkcs8_pem = cert::private_key_to_pkcs8_pem(&priv_key)
            .expect("PKCS#8 PEM 编码应成功");
        fs::write(priv_key_pkcs8_pem_file, &pkcs8_pem).expect("写入 PKCS#8 PEM 应成功");
        assert!(Path::new(priv_key_pkcs8_pem_file).exists());
        println!("✅ 测试 5.3：私钥 PKCS#8 PEM - 通过");
        
        let recovered_pem = cert::private_key_from_pkcs8_pem(&pkcs8_pem)
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
        
        let spki_der = cert::public_key_to_spki_der(&pub_key);
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
        
        let priv_sec1_der = cert::private_key_to_sec1_der(&issuer_priv);
        fs::write(priv_key_sec1_der_file, &priv_sec1_der).expect("写入 SEC1 DER 应成功");
        
        let priv_sec1_pem = cert::private_key_to_sec1_pem(&issuer_priv)
            .expect("SEC1 PEM 编码应成功");
        fs::write(priv_key_sec1_pem_file, &priv_sec1_pem).expect("写入 SEC1 PEM 应成功");
        
        let priv_pkcs8_der = cert::private_key_to_pkcs8_der(&issuer_priv);
        fs::write(priv_key_pkcs8_der_file, &priv_pkcs8_der).expect("写入 PKCS#8 DER 应成功");
        
        let priv_pkcs8_pem = cert::private_key_to_pkcs8_pem(&issuer_priv)
            .expect("PKCS#8 PEM 编码应成功");
        fs::write(priv_key_pkcs8_pem_file, &priv_pkcs8_pem).expect("写入 PKCS#8 PEM 应成功");
        
        let pub_spki_der = cert::public_key_to_spki_der(&issuer_pub);
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
}
