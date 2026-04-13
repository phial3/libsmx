use libsmx::sm2::cert::{
    self, build_x500_name, create_authority_key_identifier_extension,
    create_basic_constraints_extension, create_extended_key_usage_extension,
    create_key_usage_extension, create_subject_alternative_name_extension,
    create_subject_key_identifier_extension, generate_gm_certificate_pem, key_usage_presets,
    parse_gm_certificate_pem, X500Attribute, X500AttributeType,
};
use libsmx::sm2::{generate_keypair, DEFAULT_ID, ID_KP_SERVER_AUTH};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::fs;
use std::path::Path;
use x509_cert::der::pem::LineEnding;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::EncodePublicKey;
use x509_cert::time::{Time, Validity};

/// 构建 CA 主体名称
fn build_ca_subject() -> Name {
    build_x500_name(&[
        X500Attribute::new(X500AttributeType::Country, "CN"),
        X500Attribute::new(X500AttributeType::State, "Beijing"),
        X500Attribute::new(X500AttributeType::Locality, "HaiDian"),
        X500Attribute::new(X500AttributeType::Organization, "GMCert.org"),
        X500Attribute::new(X500AttributeType::CommonName, "GMCert GM Root CA - 01"),
    ])
}

/// 构建终端实体主体名称（包含更多属性）
fn build_ee_subject(common_name: &str) -> Name {
    build_x500_name(&[
        X500Attribute::new(X500AttributeType::Country, "CN"),
        X500Attribute::new(X500AttributeType::State, "Beijing"),
        X500Attribute::new(X500AttributeType::Locality, "Beijing"),
        X500Attribute::new(X500AttributeType::Organization, "Ume"),
        X500Attribute::new(X500AttributeType::OrganizationalUnit, "IT"),
        X500Attribute::new(X500AttributeType::CommonName, common_name),
        X500Attribute::new(X500AttributeType::EmailAddress, "admin@test4.com"),
    ])
}

/// 构建有效期（使用当前时间和 1 年有效期）
fn build_validity_current() -> Validity {
    use std::time::{Duration, SystemTime};
    let not_before = SystemTime::now();
    let not_after = not_before + Duration::from_secs(365 * 24 * 3600); // 1 年
    Validity::<x509_cert::certificate::Rfc5280>::new(
        Time::try_from(not_before).unwrap(),
        Time::try_from(not_after).unwrap(),
    )
}

/// 构建序列号（随机 8 字节）
fn build_serial_random<R: Rng>(rng: &mut R) -> SerialNumber {
    let mut bytes = [0u8; 8];
    rng.fill_bytes(&mut bytes);
    SerialNumber::from(u64::from_be_bytes(bytes))
}

fn main() {
    let output_dir = Path::new("data/www_test4_com");
    fs::create_dir_all(output_dir).expect("Failed to create output directory");

    // 从目录名提取 Common Name
    let dir_name = output_dir.file_name().unwrap().to_str().unwrap();
    let common_name = dir_name.replace("_", ".");

    println!("🔐 生成国密证书和密钥到 {:?}", output_dir);
    println!("📛 Common Name: {}", common_name);

    let mut rng = StdRng::seed_from_u64(123456);
    let validity = build_validity_current();

    // ==================== 生成 CA 证书 ====================
    println!("\n1️⃣  生成 CA 密钥对和证书...");
    let (ca_priv_key, _ca_pub_key) = generate_keypair(&mut rng);
    let ca_subject = build_ca_subject();
    let ca_serial = build_serial_random(&mut rng);

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
    )
    .expect("CA certificate generation failed");

    println!("   ✅ CA 证书生成成功");

    // ==================== 生成服务器证书 ====================
    println!("\n2️⃣  生成服务器密钥对和证书...");
    let (server_priv_key, server_pub_key) = generate_keypair(&mut rng);
    let server_subject = build_ee_subject(&common_name);
    let server_serial = build_serial_random(&mut rng);

    // 服务器证书扩展（标准 X.509v3 扩展）
    let mut server_extensions = Vec::new();
    // Basic Constraints: CA:FALSE (critical)
    server_extensions.push(create_basic_constraints_extension(false, None));
    // Key Usage: Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement
    server_extensions.push(create_key_usage_extension(key_usage_presets::both_basic()));
    // Extended Key Usage: Server Authentication
    server_extensions.push(create_extended_key_usage_extension(&[ID_KP_SERVER_AUTH]));
    // Subject Alternative Name: DNS Name
    let dns_name =
        x509_cert::der::asn1::Ia5String::try_from(common_name.clone()).expect("Invalid DNS name");
    server_extensions.push(create_subject_alternative_name_extension(&[
        GeneralName::DnsName(dns_name),
    ]));
    // Subject Key Identifier
    server_extensions.push(create_subject_key_identifier_extension(&server_pub_key));
    // Authority Key Identifier
    server_extensions.push(create_authority_key_identifier_extension(&ca_cert));

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
    )
    .expect("Server certificate issuance failed");

    println!("   ✅ 服务器证书生成成功");

    // ==================== 生成客户端证书 ====================
    println!("\n3️⃣  生成客户端密钥对和证书...");
    let (client_priv_key, client_pub_key) = generate_keypair(&mut rng);
    let client_subject = build_ee_subject("client@test4.com");
    let client_serial = build_serial_random(&mut rng);

    // 客户端证书扩展
    let mut client_extensions = Vec::new();
    client_extensions.push(create_basic_constraints_extension(false, None));
    client_extensions.push(create_key_usage_extension(key_usage_presets::both_basic()));

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
    )
    .expect("Client certificate issuance failed");

    println!("   ✅ 客户端证书生成成功");

    // ==================== 保存文件 ====================
    println!("\n4️⃣  保存证书和密钥到文件...");

    // 使用与目录名匹配的命名格式（www.test4.com_ca_cert.pem 等）
    let cert_name = &common_name;

    // CA 证书
    let ca_cert_pem = generate_gm_certificate_pem(&ca_cert).expect("CA cert PEM encoding failed");
    fs::write(
        output_dir.join(format!("{}_ca_cert.pem", cert_name)),
        &ca_cert_pem,
    )
    .expect("Failed to write CA cert");
    println!("   ✅ 保存 {}_ca_cert.pem", cert_name);

    // CA 私钥
    let ca_key_pem = ca_priv_key
        .to_pkcs8_pem()
        .expect("CA key PEM encoding failed");
    fs::write(
        output_dir.join(format!("{}_ca_key.pem", cert_name)),
        &ca_key_pem,
    )
    .expect("Failed to write CA key");
    println!("   ✅ 保存 {}_ca_key.pem", cert_name);

    // 服务器证书
    let server_cert_pem =
        generate_gm_certificate_pem(&server_cert).expect("Server cert PEM encoding failed");
    fs::write(
        output_dir.join(format!("{}_server_cert.pem", cert_name)),
        &server_cert_pem,
    )
    .expect("Failed to write server cert");
    println!("   ✅ 保存 {}_server_cert.pem", cert_name);

    // 服务器私钥
    let server_key_pem = server_priv_key
        .to_pkcs8_pem()
        .expect("Server key PEM encoding failed");
    fs::write(
        output_dir.join(format!("{}_server_key.pem", cert_name)),
        &server_key_pem,
    )
    .expect("Failed to write server key");
    println!("   ✅ 保存 {}_server_key.pem", cert_name);

    // 服务器公钥
    let server_pub_pem = server_pub_key.to_public_key_pem(LineEnding::LF).unwrap();
    fs::write(
        output_dir.join(format!("{}_server_pub.pem", cert_name)),
        &server_pub_pem,
    )
    .expect("Failed to write server pub");
    println!("   ✅ 保存 {}_server_pub.pem", cert_name);

    // 客户端证书
    let client_cert_pem =
        generate_gm_certificate_pem(&client_cert).expect("Client cert PEM encoding failed");
    fs::write(
        output_dir.join(format!("{}_client_cert.pem", cert_name)),
        &client_cert_pem,
    )
    .expect("Failed to write client cert");
    println!("   ✅ 保存 {}_client_cert.pem", cert_name);

    // 客户端私钥
    let client_key_pem = client_priv_key
        .to_pkcs8_pem()
        .expect("Client key PEM encoding failed");
    fs::write(
        output_dir.join(format!("{}_client_key.pem", cert_name)),
        &client_key_pem,
    )
    .expect("Failed to write client key");
    println!("   ✅ 保存 {}_client_key.pem", cert_name);
    println!("   ✅ 保存 client_key.pem");

    // ==================== 验证证书链 ====================
    println!("\n5️⃣  验证证书链...");

    // 验证 CA 证书
    assert_eq!(ca_cert.issuer, ca_cert.subject, "CA 证书应该是自签名的");
    println!("   ✅ CA 证书是自签名的");

    // 验证服务器证书的签发者
    assert_eq!(
        server_cert.issuer, ca_cert.subject,
        "服务器证书的签发者应该是 CA"
    );
    println!("   ✅ 服务器证书由 CA 签发");

    // 验证客户端证书的签发者
    assert_eq!(
        client_cert.issuer, ca_cert.subject,
        "客户端证书的签发者应该是 CA"
    );
    println!("   ✅ 客户端证书由 CA 签发");

    // 验证服务器证书签名
    assert!(
        server_cert
            .verify_signature_with_ca(&ca_cert, DEFAULT_ID)
            .is_ok(),
        "服务器证书签名验证应该通过"
    );
    println!("   ✅ 服务器证书签名验证通过");

    // 验证客户端证书签名
    assert!(
        client_cert
            .verify_signature_with_ca(&ca_cert, DEFAULT_ID)
            .is_ok(),
        "客户端证书签名验证应该通过"
    );
    println!("   ✅ 客户端证书签名验证通过");

    // ==================== 验证 PEM 编解码 ====================
    println!("\n6️⃣  验证 PEM 编解码...");

    let parsed_ca_cert =
        parse_gm_certificate_pem(&ca_cert_pem.as_bytes()).expect("Failed to parse CA cert PEM");
    assert_eq!(ca_cert.serial_number, parsed_ca_cert.serial_number);
    println!("   ✅ CA 证书 PEM 编解码验证通过");

    let parsed_server_cert =
        parse_gm_certificate_pem(&server_cert_pem.as_bytes()).expect("Failed to parse server cert PEM");
    assert_eq!(server_cert.serial_number, parsed_server_cert.serial_number);
    println!("   ✅ 服务器证书 PEM 编解码验证通过");

    let parsed_client_cert =
        parse_gm_certificate_pem(&client_cert_pem.as_bytes()).expect("Failed to parse client cert PEM");
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
