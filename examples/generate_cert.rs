use libsmx::sm2::{generate_keypair, DEFAULT_ID};
use libsmx::sm2::cert::{
    self, 
    X500Attribute, 
    X500AttributeType,
    build_x500_name,
    create_basic_constraints_extension,
    create_key_usage_extension,
    create_extended_key_usage_extension,
    key_usage_presets,
    generate_gm_certificate_pem,
    parse_gm_certificate_pem,
    public_key_to_spki_pem,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::fs;
use std::path::Path;

/// 构建 CA 主体名称
fn build_ca_subject() -> Vec<u8> {
    build_x500_name(&[
        X500Attribute::new(X500AttributeType::Country, "CN"),
        X500Attribute::new(X500AttributeType::State, "Beijing"),
        X500Attribute::new(X500AttributeType::Locality, "Beijing"),
        X500Attribute::new(X500AttributeType::Organization, "Test Org"),
        X500Attribute::new(X500AttributeType::OrganizationalUnit, "IT Department"),
        X500Attribute::new(X500AttributeType::CommonName, "Test CA"),
    ])
}

/// 构建终端实体主体名称
fn build_ee_subject(common_name: &str) -> Vec<u8> {
    build_x500_name(&[
        X500Attribute::new(X500AttributeType::Country, "CN"),
        X500Attribute::new(X500AttributeType::State, "Beijing"),
        X500Attribute::new(X500AttributeType::Locality, "Beijing"),
        X500Attribute::new(X500AttributeType::Organization, "Test Org"),
        X500Attribute::new(X500AttributeType::CommonName, common_name),
    ])
}

/// 构建有效期（2025-01-01 到 2030-01-01）
fn build_validity(not_before: &str, not_after: &str) -> Vec<u8> {
    // 构建 UTCTime DER 编码 (tag 0x17)
    // 格式：YYYYMMDDHHMMSSZ
    let encode_utctime = |time_str: &str| -> Vec<u8> {
        let mut encoded = vec![0x17, time_str.len() as u8];
        encoded.extend_from_slice(time_str.as_bytes());
        encoded
    };

    let not_before_der = encode_utctime(not_before);
    let not_after_der = encode_utctime(not_after);

    // 构建 Validity SEQUENCE
    let mut validity = Vec::with_capacity(2 + not_before_der.len() + not_after_der.len());
    validity.push(0x30); // SEQUENCE tag
    validity.push((not_before_der.len() + not_after_der.len()) as u8);
    validity.extend(not_before_der);
    validity.extend(not_after_der);
    validity
}

/// 构建序列号
fn build_serial(serial: u64) -> Vec<u8> {
    let bytes = serial.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}

fn main() {
    let output_dir = Path::new("data/www_test4_com");
    fs::create_dir_all(output_dir).expect("Failed to create output directory");
    
    println!("🔐 生成国密证书和密钥到 {:?}", output_dir);
    
    let mut rng = StdRng::seed_from_u64(123456);
    let validity = build_validity("250101000000Z", "300101000000Z");
    
    // ==================== 生成 CA 证书 ====================
    println!("\n1️⃣  生成 CA 密钥对和证书...");
    let (ca_priv_key, _ca_pub_key) = generate_keypair(&mut rng);
    let ca_subject = build_ca_subject();
    let ca_serial = build_serial(1);
    
    // CA 证书扩展
    let mut ca_extensions = Vec::new();
    ca_extensions.push(create_basic_constraints_extension(true, Some(0)));
    ca_extensions.push(create_key_usage_extension(key_usage_presets::ca_basic()));
    
    let ca_cert = cert::generate_self_signed_cert(
        &ca_priv_key,
        &ca_subject,
        &validity,
        &ca_serial,
        DEFAULT_ID,
        Some(ca_extensions),
        &mut rng,
    ).expect("CA certificate generation failed");
    
    println!("   ✅ CA 证书生成成功");
    
    // ==================== 生成服务器证书 ====================
    println!("\n2️⃣  生成服务器密钥对和证书...");
    let (server_priv_key, server_pub_key) = generate_keypair(&mut rng);
    let server_subject = build_ee_subject("www.test4.com");
    let server_serial = build_serial(2);
    
    // 服务器证书扩展
    let mut server_extensions = Vec::new();
    server_extensions.push(create_key_usage_extension(key_usage_presets::both_basic()));
    server_extensions.push(create_extended_key_usage_extension(&[
        libsmx::sm2::ID_KP_SERVER_AUTH,
        libsmx::sm2::ID_KP_CLIENT_AUTH
    ]));
    
    let server_cert = cert::issue_certificate(
        &ca_cert,
        &ca_priv_key,
        &server_subject,
        &server_pub_key,
        &validity,
        &server_serial,
        DEFAULT_ID,
        Some(server_extensions),
        &mut rng,
    ).expect("Server certificate issuance failed");
    
    println!("   ✅ 服务器证书生成成功");
    
    // ==================== 生成客户端证书 ====================
    println!("\n3️⃣  生成客户端密钥对和证书...");
    let (client_priv_key, client_pub_key) = generate_keypair(&mut rng);
    let client_subject = build_ee_subject("client@test4.com");
    let client_serial = build_serial(3);
    
    // 客户端证书扩展
    let mut client_extensions = Vec::new();
    client_extensions.push(create_key_usage_extension(key_usage_presets::both_basic()));
    client_extensions.push(create_extended_key_usage_extension(&[
        libsmx::sm2::ID_KP_CLIENT_AUTH
    ]));
    
    let client_cert = cert::issue_certificate(
        &ca_cert,
        &ca_priv_key,
        &client_subject,
        &client_pub_key,
        &validity,
        &client_serial,
        DEFAULT_ID,
        Some(client_extensions),
        &mut rng,
    ).expect("Client certificate issuance failed");
    
    println!("   ✅ 客户端证书生成成功");
    
    // ==================== 保存文件 ====================
    println!("\n4️⃣  保存证书和密钥到文件...");
    
    // CA 证书
    let ca_cert_pem = generate_gm_certificate_pem(&ca_cert)
        .expect("CA cert PEM encoding failed");
    fs::write(output_dir.join("ca_cert.pem"), &ca_cert_pem)
        .expect("Failed to write CA cert");
    println!("   ✅ 保存 ca_cert.pem");
    
    // CA 私钥
    let ca_key_pem = ca_priv_key.to_pkcs8_pem()
        .expect("CA key PEM encoding failed");
    fs::write(output_dir.join("ca_key.pem"), &ca_key_pem)
        .expect("Failed to write CA key");
    println!("   ✅ 保存 ca_key.pem");
    
    // 服务器证书
    let server_cert_pem = generate_gm_certificate_pem(&server_cert)
        .expect("Server cert PEM encoding failed");
    fs::write(output_dir.join("server_cert.pem"), &server_cert_pem)
        .expect("Failed to write server cert");
    println!("   ✅ 保存 server_cert.pem");
    
    // 服务器私钥
    let server_key_pem = server_priv_key.to_pkcs8_pem()
        .expect("Server key PEM encoding failed");
    fs::write(output_dir.join("server_key.pem"), &server_key_pem)
        .expect("Failed to write server key");
    println!("   ✅ 保存 server_key.pem");
    
    // 服务器公钥
    let server_pub_pem = public_key_to_spki_pem(&server_pub_key)
        .expect("Server pub PEM encoding failed");
    fs::write(output_dir.join("server_pub.pem"), &server_pub_pem)
        .expect("Failed to write server pub");
    println!("   ✅ 保存 server_pub.pem");
    
    // 客户端证书
    let client_cert_pem = generate_gm_certificate_pem(&client_cert)
        .expect("Client cert PEM encoding failed");
    fs::write(output_dir.join("client_cert.pem"), &client_cert_pem)
        .expect("Failed to write client cert");
    println!("   ✅ 保存 client_cert.pem");
    
    // 客户端私钥
    let client_key_pem = client_priv_key.to_pkcs8_pem()
        .expect("Client key PEM encoding failed");
    fs::write(output_dir.join("client_key.pem"), &client_key_pem)
        .expect("Failed to write client key");
    println!("   ✅ 保存 client_key.pem");
    
    // ==================== 验证证书链 ====================
    println!("\n5️⃣  验证证书链...");
    
    // 验证 CA 证书
    assert_eq!(ca_cert.issuer, ca_cert.subject, "CA 证书应该是自签名的");
    println!("   ✅ CA 证书是自签名的");
    
    // 验证服务器证书的签发者
    assert_eq!(server_cert.issuer, ca_cert.subject, "服务器证书的签发者应该是 CA");
    println!("   ✅ 服务器证书由 CA 签发");
    
    // 验证客户端证书的签发者
    assert_eq!(client_cert.issuer, ca_cert.subject, "客户端证书的签发者应该是 CA");
    println!("   ✅ 客户端证书由 CA 签发");
    
    // 验证服务器证书签名
    assert!(server_cert.verify_signature_with_ca(&ca_cert, DEFAULT_ID).is_ok(), 
            "服务器证书签名验证应该通过");
    println!("   ✅ 服务器证书签名验证通过");
    
    // 验证客户端证书签名
    assert!(client_cert.verify_signature_with_ca(&ca_cert, DEFAULT_ID).is_ok(), 
            "客户端证书签名验证应该通过");
    println!("   ✅ 客户端证书签名验证通过");
    
    // ==================== 验证 PEM 编解码 ====================
    println!("\n6️⃣  验证 PEM 编解码...");
    
    let parsed_ca_cert = parse_gm_certificate_pem(&ca_cert_pem)
        .expect("Failed to parse CA cert PEM");
    assert_eq!(ca_cert.serial_number, parsed_ca_cert.serial_number);
    println!("   ✅ CA 证书 PEM 编解码验证通过");
    
    let parsed_server_cert = parse_gm_certificate_pem(&server_cert_pem)
        .expect("Failed to parse server cert PEM");
    assert_eq!(server_cert.serial_number, parsed_server_cert.serial_number);
    println!("   ✅ 服务器证书 PEM 编解码验证通过");
    
    let parsed_client_cert = parse_gm_certificate_pem(&client_cert_pem)
        .expect("Failed to parse client cert PEM");
    assert_eq!(client_cert.serial_number, parsed_client_cert.serial_number);
    println!("   ✅ 客户端证书 PEM 编解码验证通过");
    
    println!("\n✅ 所有证书和密钥生成成功！");
    println!("\n📁 生成的文件:");
    println!("   - ca_cert.pem       (CA 证书)");
    println!("   - ca_key.pem        (CA 私钥)");
    println!("   - server_cert.pem   (服务器证书)");
    println!("   - server_key.pem    (服务器私钥)");
    println!("   - server_pub.pem    (服务器公钥)");
    println!("   - client_cert.pem   (客户端证书)");
    println!("   - client_key.pem    (客户端私钥)");
}
