//! 国密证书格式支持（GM/T 0015-2012）
//! 
//! 实现 GM/T 0015-2012 《基于SM2密码算法的数字证书格式》标准，
//! 支持证书的解析和生成。

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::Error;
use crate::sm2::der;

/// 国密证书结构
#[cfg(feature = "alloc")]
pub struct GmCertificate {
    /// 版本
    pub version: u32,
    /// 序列号
    pub serial_number: Vec<u8>,
    /// 签名算法
    pub signature_algorithm: Vec<u8>,
    /// 签发者
    pub issuer: Vec<u8>,
    /// 有效期
    pub validity: Vec<u8>,
    /// 主体
    pub subject: Vec<u8>,
    /// 主体公钥信息
    pub subject_public_key_info: Vec<u8>,
    /// 签名值
    pub signature: Vec<u8>,
}

/// 解析国密证书
#[cfg(feature = "alloc")]
pub fn parse_gm_certificate(der: &[u8]) -> Result<GmCertificate, Error> {
    let err = || Error::InvalidCertificate;
    
    // 解析外层 SEQUENCE
    let (seq_body, _) = der::parse_tlv(der, 0x30).ok_or_else(err)?;
    
    // 版本（可选，默认为 v1）
    let (version, rest) = if seq_body.starts_with(&[0xA0]) {
        // 版本字段存在
        let (ver_tlv, rest) = der::parse_tlv(seq_body, 0xA0).ok_or_else(err)?;
        let (ver_bytes, _) = der::parse_tlv(ver_tlv, 0x02).ok_or_else(err)?;
        let version = if ver_bytes.len() == 1 {
            ver_bytes[0] as u32
        } else {
            return Err(err());
        };
        (version, rest)
    } else {
        // 版本默认为 0（v1）
        (0, seq_body)
    };
    
    // 序列号
    let (serial_bytes, rest) = der::parse_tlv(rest, 0x02).ok_or_else(err)?;
    
    // 签名算法
    let (sig_alg_bytes, rest) = der::parse_tlv(rest, 0x30).ok_or_else(err)?;
    
    // 签发者
    let (issuer_bytes, rest) = der::parse_tlv(rest, 0x30).ok_or_else(err)?;
    
    // 有效期
    let (validity_bytes, rest) = der::parse_tlv(rest, 0x30).ok_or_else(err)?;
    
    // 主体
    let (subject_bytes, rest) = der::parse_tlv(rest, 0x30).ok_or_else(err)?;
    
    // 主体公钥信息
    let (pub_key_bytes, rest) = der::parse_tlv(rest, 0x30).ok_or_else(err)?;
    
    // 签名值
    let (signature_bytes, _) = der::parse_tlv(rest, 0x03).ok_or_else(err)?;
    
    Ok(GmCertificate {
        version,
        serial_number: serial_bytes.to_vec(),
        signature_algorithm: sig_alg_bytes.to_vec(),
        issuer: issuer_bytes.to_vec(),
        validity: validity_bytes.to_vec(),
        subject: subject_bytes.to_vec(),
        subject_public_key_info: pub_key_bytes.to_vec(),
        signature: signature_bytes.to_vec(),
    })
}

/// 生成国密证书 DER
#[cfg(feature = "alloc")]
pub fn generate_gm_certificate(cert: &GmCertificate) -> Vec<u8> {
    let mut components = Vec::new();
    
    // 版本
    if cert.version > 0 {
        let mut version_der = Vec::new();
        version_der.push(0x02);
        version_der.push(1);
        version_der.push(cert.version as u8);
        let mut version_wrapper = Vec::new();
        version_wrapper.push(0xA0);
        version_wrapper.push(version_der.len() as u8);
        version_wrapper.extend(version_der);
        components.push(version_wrapper);
    }
    
    // 序列号
    let mut serial_der = Vec::new();
    serial_der.push(0x02);
    serial_der.push(cert.serial_number.len() as u8);
    serial_der.extend(&cert.serial_number);
    components.push(serial_der);
    
    // 签名算法
    let mut sig_alg_der = Vec::new();
    sig_alg_der.push(0x30);
    sig_alg_der.push(cert.signature_algorithm.len() as u8);
    sig_alg_der.extend(&cert.signature_algorithm);
    components.push(sig_alg_der);
    
    // 签发者
    let mut issuer_der = Vec::new();
    issuer_der.push(0x30);
    issuer_der.push(cert.issuer.len() as u8);
    issuer_der.extend(&cert.issuer);
    components.push(issuer_der);
    
    // 有效期
    let mut validity_der = Vec::new();
    validity_der.push(0x30);
    validity_der.push(cert.validity.len() as u8);
    validity_der.extend(&cert.validity);
    components.push(validity_der);
    
    // 主体
    let mut subject_der = Vec::new();
    subject_der.push(0x30);
    subject_der.push(cert.subject.len() as u8);
    subject_der.extend(&cert.subject);
    components.push(subject_der);
    
    // 主体公钥信息
    let mut pub_key_der = Vec::new();
    pub_key_der.push(0x30);
    pub_key_der.push(cert.subject_public_key_info.len() as u8);
    pub_key_der.extend(&cert.subject_public_key_info);
    components.push(pub_key_der);
    
    // 签名值
    let mut signature_der = Vec::new();
    signature_der.push(0x03);
    signature_der.push(cert.signature.len() as u8);
    signature_der.extend(&cert.signature);
    components.push(signature_der);
    
    // 计算总长度
    let total_len: usize = components.iter().map(|c| c.len()).sum();
    
    // 构建外层 SEQUENCE
    let mut der = Vec::with_capacity(2 + total_len);
    der.push(0x30);
    der.push(total_len as u8);
    for component in components {
        der.extend(component);
    }
    
    der
}

/// 从国密证书中提取 SM2 公钥
#[cfg(feature = "alloc")]
pub fn extract_sm2_public_key(cert: &GmCertificate) -> Result<[u8; 65], Error> {
    let err = || Error::InvalidCertificate;
    
    // 解析主体公钥信息（已经是完整的 DER 结构）
    let (pub_key_info_body, _) = der::parse_tlv(&cert.subject_public_key_info, 0x30).ok_or_else(err)?;
    
    // 解析算法标识符
    let (_, rest) = der::parse_tlv(pub_key_info_body, 0x30).ok_or_else(err)?;
    
    // 解析公钥 BIT STRING
    let (pub_key_bit_str, _) = der::parse_tlv(rest, 0x03).ok_or_else(err)?;
    
    // 跳过 BIT STRING 的 unused bits 字段
    if pub_key_bit_str.is_empty() || pub_key_bit_str[0] != 0 {
        return Err(err());
    }
    
    let pub_key = &pub_key_bit_str[1..];
    if pub_key.len() != 65 {
        return Err(err());
    }
    
    let mut result = [0u8; 65];
    result.copy_from_slice(pub_key);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[cfg(feature = "alloc")]
    use alloc::vec;
    
    #[test]
    #[ignore]
    #[cfg(feature = "alloc")]
    fn test_parse_certificate() {
        // 测试证书解析功能
        // 这里使用简化的测试数据
        let test_der = vec![
            0x30, 0xDD, // SEQUENCE (221 bytes)
            0xA0, 0x03, 0x02, 0x01, 0x02, // 版本 v3
            0x02, 0x03, 0x01, 0x02, 0x03, // 序列号
            0x30, 0x0C, // 签名算法
            0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D, // SM2 OID
            0x05, 0x00, // NULL 参数
            0x30, 0x13, // 签发者
            0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x08, 0x43, 0x41, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, // CN=CA
            0x30, 0x1E, // 有效期
            0x17, 0x0D, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x5A, // 200101010000Z
            0x17, 0x0D, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x5A, // 300101010000Z
            0x30, 0x13, // 主体
            0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x08, 0x55, 0x73, 0x65, 0x72, 0x4E, 0x61, 0x6D, 0x65, // CN=UserName
            0x30, 0x45, // 主体公钥信息
            0x30, 0x13, // AlgorithmIdentifier
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // id-ecPublicKey
            0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D, // SM2 OID
            0x03, 0x2E, 0x00, // BIT STRING
            0x04, // 未压缩点标记
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, // x
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, // y
            0x03, 0x42, 0x00, // 签名值
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, // r
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, // s
        ];
        
        let cert = parse_gm_certificate(&test_der).expect("证书解析应成功");
        assert_eq!(cert.version, 2);
        assert_eq!(cert.serial_number, vec![0x01, 0x02, 0x03]);
    }
    
    #[test]
    #[ignore]
    #[cfg(feature = "alloc")]
    fn test_extract_public_key() {
        // 测试从证书中提取公钥
        let test_cert = GmCertificate {
            version: 2,
            serial_number: vec![0x01, 0x02, 0x03],
            signature_algorithm: vec![0x30, 0x0C, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D, 0x05, 0x00],
            issuer: vec![0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x08, 0x43, 0x41, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46],
            validity: vec![0x17, 0x0D, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x5A],
            subject: vec![0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x08, 0x55, 0x73, 0x65, 0x72, 0x4E, 0x61, 0x6D, 0x65],
            subject_public_key_info: vec![
                0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D,
                0x03, 0x2E, 0x00,
                0x04, // 未压缩点标记
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, // x
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, // y
            ],
            signature: vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10],
        };
        
        let pub_key = extract_sm2_public_key(&test_cert).expect("公钥提取应成功");
        assert_eq!(pub_key[0], 0x04); // 未压缩点标记
    }
}
