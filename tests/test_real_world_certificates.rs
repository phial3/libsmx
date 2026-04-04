#![cfg(all(feature = "alloc", feature = "std"))]

//! 使用 data 目录中的真实证书和密钥进行证书和 CMS 测试
//! 
//! 测试说明：
//! - 对每套证书进行完整的加载、签名、验证测试
//! - 如果证书不是 SM2 曲线，测试会失败并标记错误
//! - 测试会继续进行，不会因为单个证书失败而中断
//! - 后续会提供更多证书文件进行测试

use libsmx::sm2::cert::GmCertificate;
use libsmx::sm2::cms;
use libsmx::sm2::PrivateKey;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::fs;

// ====================================================================================
// 证书测试套件
// ====================================================================================

/// 从 PEM 数据中提取第一个证书
/// 处理证书链文件（包含多个证书的情况）
fn extract_first_cert_from_pem(pem_data: &[u8]) -> Result<GmCertificate, String> {
    let pem_str = String::from_utf8_lossy(pem_data);
    
    // 查找第一个证书块
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";
    
    let begin_pos = pem_str.find(begin_marker)
        .ok_or("未找到证书开始标记")?;
    let end_pos = pem_str[begin_pos..].find(end_marker)
        .ok_or("未找到证书结束标记")? + begin_pos + end_marker.len();
    
    let cert_pem = pem_str[begin_pos..end_pos].as_bytes().to_vec();
    GmCertificate::from_pem(&cert_pem)
        .map_err(|e| format!("解析证书失败：{}", e))
}

/// 测试单个证书文件的完整功能
/// 
/// 参数：
/// - name: 证书名称（用于输出）
/// - cert_path: 证书文件路径
/// - key_path: 私钥文件路径
/// - key_format: 私钥格式 ("pkcs8" 或 "sec1")
/// 
/// 返回：测试是否通过
fn test_certificate(
    name: &str,
    cert_path: &str,
    key_path: &str,
    key_format: &str,
) -> bool {
    println!("\n{}", "=".repeat(70));
    println!("测试证书：{}", name);
    println!("证书路径：{}", cert_path);
    println!("私钥路径：{}", key_path);
    println!("私钥格式：{}", key_format);
    println!("{}", "=".repeat(70));

    // 1. 加载证书和私钥
    println!("\n[1/4] 加载证书和私钥...");
    let cert_pem = match fs::read(cert_path) {
        Ok(data) => data,
        Err(e) => {
            println!("❌ 读取证书失败：{}", e);
            return false;
        }
    };
    let key_pem = match fs::read(key_path) {
        Ok(data) => data,
        Err(e) => {
            println!("❌ 读取私钥失败：{}", e);
            return false;
        }
    };

    // 处理证书链文件（提取第一个证书）
    let cert = match extract_first_cert_from_pem(&cert_pem) {
        Ok(cert) => {
            println!("✅ 证书加载成功（从 PEM 文件中提取第一个证书）");
            cert
        }
        Err(e) => {
            println!("❌ {}", e);
            return false;
        }
    };

    let priv_key = if key_format == "pkcs8" {
        match PrivateKey::from_pkcs8_pem(&key_pem) {
            Ok(key) => key,
            Err(e) => {
                println!("❌ 解析私钥失败（PKCS#8 格式）: {}", e);
                return false;
            }
        }
    } else {
        match PrivateKey::from_sec1_pem(&key_pem) {
            Ok(key) => key,
            Err(e) => {
                println!("❌ 解析私钥失败（SEC1 格式）: {}", e);
                return false;
            }
        }
    };

    println!("   版本：{}", cert.version);
    println!("   序列号：{:02x?}", &cert.serial_number[..8.min(cert.serial_number.len())]);
    println!("   颁发者：{:02x?}", &cert.issuer[..16.min(cert.issuer.len())]);
    println!("   主体：{:02x?}", &cert.subject[..16.min(cert.subject.len())]);
    println!("   公钥信息长度：{} 字节", cert.subject_public_key_info.len());

    // 2. 验证证书和私钥匹配
    println!("\n[2/4] 验证证书和私钥匹配...");
    let cert_pub_key = match cert.extract_sm2_public_key() {
        Ok(key) => {
            println!("✅ 提取 SM2 公钥成功");
            key
        }
        Err(e) => {
            println!("\n❌ 提取 SM2 公钥失败：{}", e);
            println!("   错误类型：{:?}", e);
            println!("\n   诊断信息:");
            println!("   - 公钥数据长度：{} 字节", cert.subject_public_key_info.len());
            println!("   - 公钥数据：{:02x?}", &cert.subject_public_key_info[..32.min(cert.subject_public_key_info.len())]);
            println!("\n   可能原因:");
            println!("   - 证书使用的是非 SM2 曲线（如 P-256、secp256k1 等）");
            println!("   - 证书的 subjectPublicKeyInfo 中使用的 OID 不是 SM2 OID");
            println!("\n   调试命令:");
            println!("   openssl x509 -in {} -text -noout", cert_path);
            println!("   查看 'ASN1 OID' 字段，应该是 'SM2' 而不是其他值");
            println!("\n⚠️  证书 {} 测试失败 - 非 SM2 曲线", name);
            return false;
        }
    };

    let priv_pub_key = priv_key.public_key();
    if cert_pub_key == priv_pub_key {
        println!("✅ 证书和私钥匹配");
    } else {
        println!("\n❌ 证书和私钥不匹配");
        println!("   证书公钥：{:02x?}", &cert_pub_key[..16.min(cert_pub_key.len())]);
        println!("   私钥公钥：{:02x?}", &priv_pub_key[..16.min(priv_pub_key.len())]);
        println!("\n⚠️  证书 {} 测试失败 - 证书和私钥不匹配", name);
        return false;
    }

    // 3. 创建和验证 CMS 签名
    println!("\n[3/4] 创建和验证 CMS 电子签名...");
    let test_data = format!("Test data from {}", name).into_bytes();
    let id = b"1234567812345678";
    let mut rng = StdRng::seed_from_u64(123456);

    println!("创建 CMS 电子签名...");
    let signature = match cms::create_digital_signature(
        &test_data,
        &priv_key,
        &cert,
        id,
        &mut rng,
        false,
    ) {
        Ok(sig) => {
            println!("✅ 签名创建成功，长度：{} 字节", sig.len());
            sig
        }
        Err(e) => {
            println!("❌ CMS 签名创建失败：{}", e);
            println!("\n⚠️  证书 {} 测试失败 - 签名创建失败", name);
            return false;
        }
    };

    println!("验证 CMS 电子签名...");
    match cms::verify_digital_signature(&signature, id) {
        Ok(result) => {
            if result.is_valid {
                println!("✅ 签名验证成功");
                println!("   签名者数量：{}", result.signer_count);
                println!("   恢复内容：{}", String::from_utf8_lossy(&result.content));
                
                if result.content != test_data.as_slice() {
                    println!("\n❌ 恢复的内容不匹配");
                    println!("   原始内容：{:?}", String::from_utf8_lossy(&test_data));
                    println!("   恢复内容：{:?}", String::from_utf8_lossy(&result.content));
                    println!("\n⚠️  证书 {} 测试失败 - 签名验证通过但内容不匹配", name);
                    return false;
                }
            } else {
                println!("\n❌ 签名验证失败 - 签名无效");
                println!("   签名者数量：{}", result.signer_count);
                println!("   恢复内容：{:?}", String::from_utf8_lossy(&result.content));
                println!("\n   可能原因:");
                println!("   - 证书曲线与签名算法不匹配");
                println!("   - 签名验证过程中曲线参数不匹配");
                println!("\n⚠️  证书 {} 测试失败 - 签名验证失败", name);
                return false;
            }
        }
        Err(e) => {
            println!("\n❌ CMS 签名验证出错：{}", e);
            println!("   错误类型：{:?}", e);
            println!("\n   诊断信息:");
            println!("   - 签名长度：{} 字节", signature.len());
            println!("   - 证书公钥信息长度：{} 字节", cert.subject_public_key_info.len());
            println!("\n   可能原因:");
            println!("   - 证书使用的是非 SM2 曲线（如 P-256）");
            println!("   - 签名算法与证书曲线不匹配");
            println!("\n   调试命令:");
            println!("   openssl cms -in <signature_file> -inform DER -print_certs -text");
            println!("\n⚠️  证书 {} 测试失败 - CMS 签名验证失败", name);
            return false;
        }
    }

    // 4. 篡改检测测试
    println!("\n[4/4] 测试篡改检测...");
    let mut tampered_signature = signature.clone();
    
    // 尝试篡改内容
    if let Some(pos) = tampered_signature.windows(test_data.len())
        .position(|w| w == test_data.as_slice())
    {
        tampered_signature[pos] ^= 0xFF;
        println!("已篡改签名内容");
    }

    match cms::verify_digital_signature(&tampered_signature, id) {
        Ok(result) => {
            if !result.is_valid {
                println!("✅ 篡改检测成功 - 签名被识别为无效");
            } else {
                println!("\n❌ 篡改检测失败 - 篡改后的签名仍然有效！");
                println!("⚠️  证书 {} 测试失败 - 安全漏洞", name);
                return false;
            }
        }
        Err(_) => {
            println!("✅ 篡改检测成功 - 解析失败");
        }
    }

    println!("\n✅ 证书 {} 所有测试通过", name);
    true
}

// ====================================================================================
// 测试入口
// ====================================================================================

#[test]
fn test_all_certificates() {
    println!("\n{}", "#".repeat(70));
    println!("# 国密证书和 CMS 功能测试");
    println!("# 测试说明：对所有提供的证书进行完整的功能测试");
    println!("# 证书来源：data 目录中的三组证书");
    println!("# 注意：测试会继续进行，不会因为单个证书失败而中断");
    println!("{}", "#".repeat(70));

    let mut results = Vec::new();

    // 测试证书套件 1: www.test1.com（PKCS#8 私钥，SM2 曲线）
    let result1 = test_certificate(
        "www.test1.com",
        "data/www_test1_com/www.test1.com_cert.pem",
        "data/www_test1_com/www.test1.com_key.pem",
        "pkcs8",
    );
    results.push(("www.test1.com", result1));

    // 测试证书套件 2: www.test2.com（SEC1 私钥，P-256 曲线 - 预期失败）
    let result2 = test_certificate(
        "www.test2.com",
        "data/www_test2_com/www.test2.com_cert.pem",
        "data/www_test2_com/www.test2.com_key.pem",
        "sec1",
    );
    results.push(("www.test2.com", result2));

    // 测试证书套件 3: www.test3.com（SEC1 私钥，SM2 曲线，证书链文件）
    let result3 = test_certificate(
        "www.test3.com",
        "data/www_test3_com/www.test3.com_cert.pem",
        "data/www_test3_com/www.test3.com_key.pem",
        "sec1",
    );
    results.push(("www.test3.com", result3));

    // 打印测试总结
    println!("\n{}", "#".repeat(70));
    println!("# 测试总结");
    println!("{}", "#".repeat(70));
    
    let mut passed = 0;
    let mut failed = 0;
    
    for (name, result) in &results {
        if *result {
            println!("✅ {} - 通过", name);
            passed += 1;
        } else {
            println!("❌ {} - 失败", name);
            failed += 1;
        }
    }
    
    println!("\n总计：{} 通过，{} 失败", passed, failed);
    println!("{}", "#".repeat(70));
    
    // 如果有失败的测试，panic 以便在 CI 中标记失败
    if failed > 0 {
        panic!("{} 个证书测试失败", failed);
    }
}
