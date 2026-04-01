//! 国密证书格式支持（GM/T 0015-2012）
//! 
//! 实现 GM/T 0015-2012 《基于SM2密码算法的数字证书格式》标准，
//! 支持证书的解析和生成、密钥的 DER/PEM 编解码、证书签名验证等功能。
//! 
//! # 功能
//! - 证书解析和生成（DER 格式）
//! - 证书 PEM 格式解析和生成
//! - 从证书提取 SM2 公钥
//! - 私钥 SEC1/PKCS#8 DER/PEM 编解码
//! - 公钥 SPKI DER/PEM 编解码
//! - 证书数据的 SM2 签名和验证

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::Error;
use crate::sm2::{PrivateKey, sign, verify};
use crate::sm2::der;
use rand_core::Rng;

#[cfg(feature = "alloc")]
use pem_rfc7468::{encode_string, decode_vec};

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
    
    let (seq_body, _) = der::parse_tlv(der, 0x30).ok_or_else(err)?;
    
    let (version, rest) = if seq_body.starts_with(&[0xA0]) {
        let (ver_tlv, rest) = der::parse_tlv(seq_body, 0xA0).ok_or_else(err)?;
        let (ver_bytes, _) = der::parse_tlv(ver_tlv, 0x02).ok_or_else(err)?;
        let version = if ver_bytes.len() == 1 {
            ver_bytes[0] as u32
        } else {
            return Err(err());
        };
        (version, rest)
    } else {
        (0, seq_body)
    };
    
    let (serial_bytes, rest) = der::parse_tlv(rest, 0x02).ok_or_else(err)?;
    
    // 对于其他字段，我们需要获取完整的 TLV 结构
    // 使用 parse_tlv_any_full 获取完整的 TLV，然后保存
    let (sig_alg_bytes, rest) = der::parse_tlv_any_full(rest).ok_or_else(err)?;
    let (issuer_bytes, rest) = der::parse_tlv_any_full(rest).ok_or_else(err)?;
    let (validity_bytes, rest) = der::parse_tlv_any_full(rest).ok_or_else(err)?;
    let (subject_bytes, rest) = der::parse_tlv_any_full(rest).ok_or_else(err)?;
    let (pub_key_bytes, rest) = der::parse_tlv_any_full(rest).ok_or_else(err)?;
    let (signature_tlv, _) = der::parse_tlv_any_full(rest).ok_or_else(err)?;
    let (signature_bytes, _) = der::parse_tlv(signature_tlv, 0x03).ok_or_else(err)?;
    
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
    
    let mut serial_der = Vec::new();
    serial_der.push(0x02);
    serial_der.push(cert.serial_number.len() as u8);
    serial_der.extend(&cert.serial_number);
    components.push(serial_der);
    
    components.push(cert.signature_algorithm.clone());
    components.push(cert.issuer.clone());
    components.push(cert.validity.clone());
    components.push(cert.subject.clone());
    components.push(cert.subject_public_key_info.clone());
    
    let mut signature_der = Vec::new();
    signature_der.push(0x03);
    signature_der.push(cert.signature.len() as u8);
    signature_der.extend(&cert.signature);
    components.push(signature_der);
    
    let total_len: usize = components.iter().map(|c| c.len()).sum();
    
    // 编码长度字段
    let mut der = Vec::new();
    der.push(0x30);
    if total_len < 128 {
        der.push(total_len as u8);
    } else if total_len < 256 {
        der.push(0x81);
        der.push(total_len as u8);
    } else {
        der.push(0x82);
        der.push((total_len >> 8) as u8);
        der.push((total_len & 0xFF) as u8);
    }
    for component in components {
        der.extend(component);
    }
    
    der
}

/// 从国密证书中提取 SM2 公钥
#[cfg(feature = "alloc")]
pub fn extract_sm2_public_key(cert: &GmCertificate) -> Result<[u8; 65], Error> {
    let err = || Error::InvalidCertificate;
    
    let (pub_key_info_body, _) = der::parse_tlv(&cert.subject_public_key_info, 0x30).ok_or_else(err)?;
    let (_, rest) = der::parse_tlv(pub_key_info_body, 0x30).ok_or_else(err)?;
    let (pub_key_bit_str, _) = der::parse_tlv(rest, 0x03).ok_or_else(err)?;
    
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

// -- 证书 PEM 支持 ------------------------------------------------------------------

/// 解析 PEM 格式的国密证书
#[cfg(feature = "alloc")]
pub fn parse_gm_certificate_pem(pem: &[u8]) -> Result<GmCertificate, Error> {
    let (_label, der) = decode_vec(pem).map_err(|_| Error::InvalidCertificate)?;
    parse_gm_certificate(&der)
}

/// 生成 PEM 格式的国密证书
#[cfg(feature = "alloc")]
pub fn generate_gm_certificate_pem(cert: &GmCertificate) -> Result<Vec<u8>, Error> {
    let der = generate_gm_certificate(cert);
    let pem = encode_string("CERTIFICATE", Default::default(), &der)
        .map_err(|_| Error::InvalidCertificate)?;
    Ok(pem.as_bytes().to_vec())
}

// -- 证书签名和验证 ---------------------------------------------------------------

/// 对证书数据进行签名（使用 SM2）
#[cfg(feature = "alloc")]
pub fn sign_certificate_data<R: Rng>(
    data: &[u8],
    priv_key: &PrivateKey,
    id: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let pub_key = priv_key.public_key();
    let z = crate::sm2::get_z(id, &pub_key);
    let e = crate::sm2::get_e(&z, data);
    let sig = sign(&e, priv_key, rng);
    Ok(sig.to_vec())
}

/// 验证证书数据的签名（使用 SM2）
#[cfg(feature = "alloc")]
pub fn verify_certificate_data(
    data: &[u8],
    signature: &[u8],
    pub_key: &[u8; 65],
    id: &[u8],
) -> Result<(), Error> {
    if signature.len() != 64 {
        return Err(Error::InvalidSignature);
    }
    
    let z = crate::sm2::get_z(id, pub_key);
    let e = crate::sm2::get_e(&z, data);
    
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(signature);
    
    verify(&e, pub_key, &sig_array)
}

// -- 密钥 DER/PEM 编解码 ----------------------------------------------------------

/// 将私钥编码为 SEC1 DER 格式
#[cfg(feature = "alloc")]
pub fn private_key_to_sec1_der(priv_key: &PrivateKey) -> Vec<u8> {
    der::private_key_to_sec1_der(priv_key)
}

/// 将私钥编码为 PKCS#8 DER 格式
#[cfg(feature = "alloc")]
pub fn private_key_to_pkcs8_der(priv_key: &PrivateKey) -> Vec<u8> {
    der::private_key_to_pkcs8_der(priv_key)
}

/// 将私钥编码为 SEC1 PEM 格式
#[cfg(feature = "alloc")]
pub fn private_key_to_sec1_pem(priv_key: &PrivateKey) -> Result<Vec<u8>, Error> {
    let der = private_key_to_sec1_der(priv_key);
    let pem = encode_string("EC PRIVATE KEY", Default::default(), &der)
        .map_err(|_| Error::InvalidPrivateKey)?;
    Ok(pem.as_bytes().to_vec())
}

/// 将私钥编码为 PKCS#8 PEM 格式
#[cfg(feature = "alloc")]
pub fn private_key_to_pkcs8_pem(priv_key: &PrivateKey) -> Result<Vec<u8>, Error> {
    let der = private_key_to_pkcs8_der(priv_key);
    let pem = encode_string("PRIVATE KEY", Default::default(), &der)
        .map_err(|_| Error::InvalidPrivateKey)?;
    Ok(pem.as_bytes().to_vec())
}

/// 从 SEC1 DER 解析私钥
#[cfg(feature = "alloc")]
pub fn private_key_from_sec1_der(der: &[u8]) -> Result<PrivateKey, Error> {
    der::private_key_from_sec1_der(der)
}

/// 从 PKCS#8 DER 解析私钥
#[cfg(feature = "alloc")]
pub fn private_key_from_pkcs8_der(der: &[u8]) -> Result<PrivateKey, Error> {
    der::private_key_from_pkcs8_der(der)
}

/// 从 SEC1 PEM 解析私钥
#[cfg(feature = "alloc")]
pub fn private_key_from_sec1_pem(pem: &[u8]) -> Result<PrivateKey, Error> {
    let (_label, der) = decode_vec(pem).map_err(|_| Error::InvalidPrivateKey)?;
    private_key_from_sec1_der(&der)
}

/// 从 PKCS#8 PEM 解析私钥
#[cfg(feature = "alloc")]
pub fn private_key_from_pkcs8_pem(pem: &[u8]) -> Result<PrivateKey, Error> {
    let (_label, der) = decode_vec(pem).map_err(|_| Error::InvalidPrivateKey)?;
    private_key_from_pkcs8_der(&der)
}

/// 将公钥编码为 SPKI DER 格式
#[cfg(feature = "alloc")]
pub fn public_key_to_spki_der(pub_key: &[u8; 65]) -> Vec<u8> {
    der::public_key_to_spki_der(pub_key)
}

/// 从 SPKI DER 解析公钥
#[cfg(feature = "alloc")]
pub fn public_key_from_spki_der(der: &[u8]) -> Result<[u8; 65], Error> {
    der::public_key_from_spki_der(der)
}

/// 将公钥编码为 SPKI PEM 格式
#[cfg(feature = "alloc")]
pub fn public_key_to_spki_pem(pub_key: &[u8; 65]) -> Result<Vec<u8>, Error> {
    let der = public_key_to_spki_der(pub_key);
    let pem = encode_string("PUBLIC KEY", Default::default(), &der)
        .map_err(|_| Error::InvalidPublicKey)?;
    Ok(pem.as_bytes().to_vec())
}

/// 从 SPKI PEM 解析公钥
#[cfg(feature = "alloc")]
pub fn public_key_from_spki_pem(pem: &[u8]) -> Result<[u8; 65], Error> {
    let (_label, der) = decode_vec(pem).map_err(|_| Error::InvalidPublicKey)?;
    public_key_from_spki_der(&der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::{generate_keypair, DEFAULT_ID};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    
    #[cfg(feature = "alloc")]
    use alloc::vec;
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_certificate_generate() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (_, pub_key) = generate_keypair(&mut rng);
        
        let cert = GmCertificate {
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
            subject_public_key_info: public_key_to_spki_der(&pub_key),
            signature: vec![0x00, 0x01, 0x02, 0x03],
        };
        
        let der = generate_gm_certificate(&cert);
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30);
        
        // Test parsing
        let parsed = parse_gm_certificate(&der).expect("解析 DER 证书应成功");
        assert_eq!(parsed.version, cert.version);
        assert_eq!(parsed.serial_number, cert.serial_number);
        
        let pem = generate_gm_certificate_pem(&cert).expect("PEM 证书生成应成功");
        assert!(!pem.is_empty());
        assert!(pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with(b"-----END CERTIFICATE-----\n"));
        
        // Test parsing PEM
        let parsed_from_pem = parse_gm_certificate_pem(&pem).expect("解析 PEM 证书应成功");
        assert_eq!(parsed_from_pem.version, cert.version);
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_private_key_sec1_der_roundtrip() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _) = generate_keypair(&mut rng);
        
        let der = private_key_to_sec1_der(&priv_key);
        let recovered = private_key_from_sec1_der(&der).expect("SEC1 DER 解析应成功");
        assert_eq!(priv_key.as_bytes(), recovered.as_bytes());
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_private_key_pkcs8_der_roundtrip() {
        let mut rng = StdRng::seed_from_u64(654321);
        let (priv_key, _) = generate_keypair(&mut rng);
        
        let der = private_key_to_pkcs8_der(&priv_key);
        let recovered = private_key_from_pkcs8_der(&der).expect("PKCS#8 DER 解析应成功");
        assert_eq!(priv_key.as_bytes(), recovered.as_bytes());
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_private_key_sec1_pem_roundtrip() {
        let mut rng = StdRng::seed_from_u64(111222);
        let (priv_key, _) = generate_keypair(&mut rng);
        
        let pem = private_key_to_sec1_pem(&priv_key).expect("SEC1 PEM 编码应成功");
        let recovered = private_key_from_sec1_pem(&pem).expect("SEC1 PEM 解析应成功");
        assert_eq!(priv_key.as_bytes(), recovered.as_bytes());
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_private_key_pkcs8_pem_roundtrip() {
        let mut rng = StdRng::seed_from_u64(222111);
        let (priv_key, _) = generate_keypair(&mut rng);
        
        let pem = private_key_to_pkcs8_pem(&priv_key).expect("PKCS#8 PEM 编码应成功");
        let recovered = private_key_from_pkcs8_pem(&pem).expect("PKCS#8 PEM 解析应成功");
        assert_eq!(priv_key.as_bytes(), recovered.as_bytes());
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_public_key_spki() {
        let mut rng = StdRng::seed_from_u64(333444);
        let (_, pub_key) = generate_keypair(&mut rng);
        
        let spki_der = public_key_to_spki_der(&pub_key);
        assert!(!spki_der.is_empty());
        
        let spki_pem = public_key_to_spki_pem(&pub_key).expect("SPKI PEM 编码应成功");
        assert!(!spki_pem.is_empty());
        
        let recovered_der = public_key_from_spki_der(&spki_der).expect("SPKI DER 解析应成功");
        assert_eq!(recovered_der, pub_key);
        
        let recovered_pem = public_key_from_spki_pem(&spki_pem).expect("SPKI PEM 解析应成功");
        assert_eq!(recovered_pem, pub_key);
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_certificate_signing_and_verification() {
        let mut rng = StdRng::seed_from_u64(444555);
        let (priv_key, pub_key) = generate_keypair(&mut rng);
        let data = b"test certificate data";
        let id = DEFAULT_ID;
        
        let signature = sign_certificate_data(data, &priv_key, id, &mut rng)
            .expect("签名应成功");
        
        verify_certificate_data(data, &signature, &pub_key, id)
            .expect("验签应成功");
        
        let tampered_data = b"tampered data";
        assert!(verify_certificate_data(tampered_data, &signature, &pub_key, id).is_err());
    }
}
