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
//! - X.509 标准证书支持（使用 x509-cert）

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::Error;
use crate::sm2::{PrivateKey, sign, verify};
use crate::sm2::der;
use rand_core::Rng;

#[cfg(feature = "alloc")]
use pem_rfc7468::{encode_string, decode_vec};

// x509-cert 相关导入
#[cfg(feature = "alloc")]
use x509_cert::Certificate;
#[cfg(feature = "alloc")]
use x509_cert::der::Decode;
#[cfg(feature = "alloc")]
use x509_cert::spki::ObjectIdentifier;

/// SM2 签名算法 OID (1.2.156.10197.1.501)
#[cfg(feature = "alloc")]
pub const SM2_SIG_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.1.501");

/// SM2 椭圆曲线公钥算法 OID (1.2.156.10197.1.301)
#[cfg(feature = "alloc")]
pub const SM2_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.1.301");

/// EC 公钥算法 OID (1.2.840.10045.2.1)
#[cfg(feature = "alloc")]
pub const EC_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// 国密证书结构
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
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

#[cfg(feature = "alloc")]
impl GmCertificate {
    /// 从 DER 格式解析证书
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        parse_gm_certificate(der)
    }

    /// 将证书编码为 DER 格式
    pub fn to_der(&self) -> Vec<u8> {
        generate_gm_certificate(self)
    }

    /// 从 PEM 格式解析证书
    pub fn from_pem(pem: &[u8]) -> Result<Self, Error> {
        parse_gm_certificate_pem(pem)
    }

    /// 将证书编码为 PEM 格式
    pub fn to_pem(&self) -> Result<Vec<u8>, Error> {
        generate_gm_certificate_pem(self)
    }

    /// 提取 SM2 公钥
    pub fn extract_sm2_public_key(&self) -> Result<[u8; 65], Error> {
        extract_sm2_public_key(self)
    }

    /// 验证证书有效期
    pub fn verify_validity(&self, current_time: &[u8]) -> Result<(), Error> {
        verify_certificate_validity(self, current_time)
    }

    /// 验证自签名证书
    pub fn verify_self_signed(&self, id: &[u8]) -> Result<(), Error> {
        verify_self_signed_cert(self, id)
    }
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
        let version_der = vec![0x02, 0x01, cert.version as u8];
        let mut version_wrapper = Vec::with_capacity(2 + version_der.len());
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

// -- X.509 证书支持（使用 x509-cert crate）--------------------------------------

/// 使用 x509-cert 解析 X.509 证书
#[cfg(feature = "alloc")]
pub fn parse_x509_certificate(der: &[u8]) -> Result<Certificate, Error> {
    Certificate::from_der(der).map_err(|_| Error::InvalidCertificate)
}

/// 检查证书是否使用 SM2 算法
/// 
/// 注意：此函数需要访问证书的签名算法 OID
#[cfg(feature = "alloc")]
pub fn is_sm2_certificate(cert: &Certificate) -> bool {
    // 通过证书的 DER 编码检查 OID
    // SM2 签名算法 OID: 1.2.156.10197.1.501
    // 对应的 DER 编码包含特定字节序列
    if let Ok(der) = x509_cert::der::Encode::to_der(cert) {
        // 检查是否包含 SM2 OID 的特征字节
        // OID 1.2.156.10197.1.501 的 DER 编码: 06 08 2A 81 1C CF 55 01 83 75
        der.windows(10).any(|window| {
            window == [0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75]
        })
    } else {
        false
    }
}

/// 证书有效期结构
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct ValidityPeriod {
    /// 生效时间 (UTCTime/GeneralizedTime 格式 YYMMDDHHMMSSZ)
    pub not_before: Vec<u8>,
    /// 过期时间 (UTCTime/GeneralizedTime 格式 YYMMDDHHMMSSZ)
    pub not_after: Vec<u8>,
}

/// 从证书有效期字段解析时间
/// 
/// 支持 UTCTime (2字节年份) 和 GeneralizedTime (4字节年份) 格式
#[cfg(feature = "alloc")]
pub fn parse_validity(validity_der: &[u8]) -> Result<ValidityPeriod, Error> {
    let err = || Error::InvalidCertificate;
    
    // 解析外层 SEQUENCE
    let (seq_body, _) = der::parse_tlv(validity_der, 0x30).ok_or_else(err)?;
    
    let mut rest = seq_body;
    
    // 解析 notBefore
    let (tag, _) = rest.split_first().ok_or_else(err)?;
    let (not_before, remaining) = if *tag == 0x17 {
        // UTCTime
        der::parse_tlv(rest, 0x17).ok_or_else(err)?
    } else if *tag == 0x18 {
        // GeneralizedTime
        der::parse_tlv(rest, 0x18).ok_or_else(err)?
    } else {
        return Err(err());
    };
    rest = remaining;
    
    // 解析 notAfter
    let (tag, _) = rest.split_first().ok_or_else(err)?;
    let (not_after, _) = if *tag == 0x17 {
        // UTCTime
        der::parse_tlv(rest, 0x17).ok_or_else(err)?
    } else if *tag == 0x18 {
        // GeneralizedTime
        der::parse_tlv(rest, 0x18).ok_or_else(err)?
    } else {
        return Err(err());
    };
    
    Ok(ValidityPeriod {
        not_before: not_before.to_vec(),
        not_after: not_after.to_vec(),
    })
}

/// 验证证书有效期
/// 
/// 检查当前时间是否在证书的有效期内
/// 注意：此函数需要外部提供当前时间（以 UTCTime 格式）
#[cfg(feature = "alloc")]
pub fn verify_certificate_validity(
    cert: &GmCertificate,
    current_time: &[u8], // YYMMDDHHMMSSZ 格式
) -> Result<(), Error> {
    let validity = parse_validity(&cert.validity)?;
    
    // 比较时间（字典序比较，因为都是 ASCII 格式）
    if current_time < validity.not_before.as_slice() {
        return Err(Error::InvalidCertificate); // 证书尚未生效
    }
    if current_time > validity.not_after.as_slice() {
        return Err(Error::InvalidCertificate); // 证书已过期
    }
    
    Ok(())
}

/// 生成有效期 DER 编码
/// 
/// 使用 UTCTime 格式 (tag 0x17)
#[cfg(feature = "alloc")]
pub fn generate_validity(not_before: &[u8], not_after: &[u8]) -> Vec<u8> {
    let mut validity = Vec::new();
    
    // notBefore UTCTime
    validity.push(0x17);
    validity.push(not_before.len() as u8);
    validity.extend_from_slice(not_before);
    
    // notAfter UTCTime
    validity.push(0x17);
    validity.push(not_after.len() as u8);
    validity.extend_from_slice(not_after);
    
    // 包装成 SEQUENCE
    let mut seq = Vec::new();
    seq.push(0x30);
    seq.push(validity.len() as u8);
    seq.extend(validity);
    
    seq
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
    let pem = encode_string(pem_labels::CERTIFICATE, Default::default(), &der)
        .map_err(|_| Error::InvalidCertificate)?;
    Ok(pem.as_bytes().to_vec())
}

/// 解析 PEM 格式的 X.509 证书
#[cfg(feature = "alloc")]
pub fn parse_x509_certificate_pem(pem: &[u8]) -> Result<Certificate, Error> {
    let (_label, der) = decode_vec(pem).map_err(|_| Error::InvalidCertificate)?;
    parse_x509_certificate(&der)
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

/// PEM 标签常量
#[cfg(feature = "alloc")]
mod pem_labels {
    pub const EC_PRIVATE_KEY: &str = "EC PRIVATE KEY";
    pub const PRIVATE_KEY: &str = "PRIVATE KEY";
    pub const PUBLIC_KEY: &str = "PUBLIC KEY";
    pub const CERTIFICATE: &str = "CERTIFICATE";
}

/// 将私钥编码为 SEC1 PEM 格式
#[cfg(feature = "alloc")]
pub fn private_key_to_sec1_pem(priv_key: &PrivateKey) -> Result<Vec<u8>, Error> {
    let der = der::private_key_to_sec1_der(priv_key);
    let pem = encode_string(pem_labels::EC_PRIVATE_KEY, Default::default(), &der)
        .map_err(|_| Error::InvalidPrivateKey)?;
    Ok(pem.as_bytes().to_vec())
}

/// 将私钥编码为 PKCS#8 PEM 格式
#[cfg(feature = "alloc")]
pub fn private_key_to_pkcs8_pem(priv_key: &PrivateKey) -> Result<Vec<u8>, Error> {
    let der = der::private_key_to_pkcs8_der(priv_key);
    let pem = encode_string(pem_labels::PRIVATE_KEY, Default::default(), &der)
        .map_err(|_| Error::InvalidPrivateKey)?;
    Ok(pem.as_bytes().to_vec())
}

/// 从 SEC1 PEM 解析私钥
#[cfg(feature = "alloc")]
pub fn private_key_from_sec1_pem(pem: &[u8]) -> Result<PrivateKey, Error> {
    let (_label, der) = decode_vec(pem).map_err(|_| Error::InvalidPrivateKey)?;
    der::private_key_from_sec1_der(&der)
}

/// 从 PKCS#8 PEM 解析私钥
#[cfg(feature = "alloc")]
pub fn private_key_from_pkcs8_pem(pem: &[u8]) -> Result<PrivateKey, Error> {
    let (_label, der) = decode_vec(pem).map_err(|_| Error::InvalidPrivateKey)?;
    der::private_key_from_pkcs8_der(&der)
}

/// 将公钥编码为 SPKI PEM 格式
#[cfg(feature = "alloc")]
pub fn public_key_to_spki_pem(pub_key: &[u8; 65]) -> Result<Vec<u8>, Error> {
    let der = der::public_key_to_spki_der(pub_key);
    let pem = encode_string(pem_labels::PUBLIC_KEY, Default::default(), &der)
        .map_err(|_| Error::InvalidPublicKey)?;
    Ok(pem.as_bytes().to_vec())
}

/// 从 SPKI PEM 解析公钥
#[cfg(feature = "alloc")]
pub fn public_key_from_spki_pem(pem: &[u8]) -> Result<[u8; 65], Error> {
    let (_label, der) = decode_vec(pem).map_err(|_| Error::InvalidPublicKey)?;
    der::public_key_from_spki_der(&der)
}

/// 将公钥转换为压缩格式 (33字节)
/// 
/// 压缩格式: 02||x (y为偶数) 或 03||x (y为奇数)
#[cfg(feature = "alloc")]
pub fn public_key_to_compressed(pub_key: &[u8; 65]) -> Result<[u8; 33], Error> {
    if pub_key[0] != 0x04 {
        return Err(Error::InvalidPublicKey);
    }
    
    let x = &pub_key[1..33];
    let y = &pub_key[33..65];
    
    // 根据 y 的最低位选择前缀
    let prefix = if y[31] & 1 == 0 { 0x02 } else { 0x03 };
    
    let mut compressed = [0u8; 33];
    compressed[0] = prefix;
    compressed[1..].copy_from_slice(x);
    
    Ok(compressed)
}

/// 从压缩格式还原公钥 (需要计算 y)
/// 
/// 使用椭圆曲线点解压缩算法：
/// 1. 从压缩格式提取 x 坐标和前缀
/// 2. 计算 α = x³ + ax + b (mod p)
/// 3. 计算 y = √α (mod p) 使用 Tonelli-Shanks 算法
/// 4. 根据前缀选择正确的 y 值（02=偶数，03=奇数）
#[cfg(feature = "alloc")]
pub fn public_key_from_compressed(compressed: &[u8; 33]) -> Result<[u8; 65], Error> {
    use crate::sm2::field::{fp_from_bytes, fp_to_bytes, fp_sqrt, fp_mul, fp_add, fp_square, CURVE_A, CURVE_B};
    
    // 验证前缀
    let prefix = compressed[0];
    if prefix != 0x02 && prefix != 0x03 {
        return Err(Error::InvalidPublicKey);
    }
    
    // 提取 x 坐标
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&compressed[1..33]);
    let x = fp_from_bytes(&x_bytes);
    
    // 计算 α = x³ + ax + b (mod p)
    let x2 = fp_square(&x);
    let x3 = fp_mul(&x2, &x);
    let ax = fp_mul(&CURVE_A, &x);
    let alpha = fp_add(&fp_add(&x3, &ax), &CURVE_B);
    
    // 计算 y = √α (mod p)
    let y = fp_sqrt(&alpha).ok_or(Error::InvalidPublicKey)?;
    let y_bytes = fp_to_bytes(&y);
    
    // 根据前缀选择正确的 y 值
    // 前缀 02 表示 y 为偶数，03 表示 y 为奇数
    let y_is_odd = y_bytes[31] & 1 == 1;
    let prefix_wants_odd = prefix == 0x03;
    
    let final_y_bytes = if y_is_odd != prefix_wants_odd {
        // 需要取 -y (mod p)
        use crate::sm2::field::fp_neg;
        let neg_y = fp_neg(&y);
        fp_to_bytes(&neg_y)
    } else {
        y_bytes
    };
    
    // 构造完整公钥
    let mut pub_key = [0u8; 65];
    pub_key[0] = 0x04; // 未压缩格式前缀
    pub_key[1..33].copy_from_slice(&x_bytes);
    pub_key[33..65].copy_from_slice(&final_y_bytes);
    
    Ok(pub_key)
}

/// 计算公钥指纹 (SM3)
#[cfg(feature = "alloc")]
pub fn public_key_fingerprint(pub_key: &[u8; 65]) -> [u8; 32] {
    use crate::sm3::Sm3Hasher;
    
    let mut hasher = Sm3Hasher::new();
    hasher.update(pub_key);
    hasher.finalize()
}

// -- 自签名证书生成 -------------------------------------------------------------

/// 生成自签名证书
/// 
/// 自签名证书中 issuer 和 subject 相同，使用自己的私钥签名
/// 
/// # 参数
/// - `priv_key`: 私钥（用于签名）
/// - `subject`: 主体名称 DER 编码
/// - `validity`: 有效期 DER 编码
/// - `serial_number`: 序列号
/// - `id`: SM2 签名 ID
/// - `rng`: 随机数生成器
/// 
/// # 返回
/// 生成的自签名证书
#[cfg(feature = "alloc")]
pub fn generate_self_signed_cert<R: Rng>(
    priv_key: &PrivateKey,
    subject: &[u8],
    validity: &[u8],
    serial_number: &[u8],
    id: &[u8],
    rng: &mut R,
) -> Result<GmCertificate, Error> {
    let pub_key = priv_key.public_key();
    let spki = der::public_key_to_spki_der(&pub_key);
    
    // SM2 签名算法标识符
    let sig_alg: Vec<u8> = alloc::vec![
        0x30, 0x0A, // SEQUENCE
        0x06, 0x08, // OID
        0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75, // 1.2.156.10197.1.501
    ];
    
    // 构建 TBSCertificate (待签名部分)
    let mut tbs = Vec::with_capacity(128);

    // version [0] INTEGER 2
    tbs.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);

    // serialNumber INTEGER
    tbs.push(0x02);
    tbs.push(serial_number.len() as u8);
    tbs.extend_from_slice(serial_number);
    
    // signature AlgorithmIdentifier
    tbs.extend_from_slice(&sig_alg);
    
    // issuer Name (自签名，issuer = subject)
    tbs.extend_from_slice(subject);
    
    // validity Validity
    tbs.extend_from_slice(validity);
    
    // subject Name
    tbs.extend_from_slice(subject);
    
    // subjectPublicKeyInfo
    tbs.extend_from_slice(&spki);
    
    // 对 TBSCertificate 签名
    let signature = sign_certificate_data(&tbs, priv_key, id, rng)?;
    
    Ok(GmCertificate {
        version: 2,
        serial_number: serial_number.to_vec(),
        signature_algorithm: sig_alg,
        issuer: subject.to_vec(),
        validity: validity.to_vec(),
        subject: subject.to_vec(),
        subject_public_key_info: spki,
        signature: signature.to_vec(),
    })
}

/// 验证自签名证书
/// 
/// 验证证书的签名是否由证书中的公钥验证通过
#[cfg(feature = "alloc")]
pub fn verify_self_signed_cert(cert: &GmCertificate, id: &[u8]) -> Result<(), Error> {
    // 提取公钥
    let pub_key = extract_sm2_public_key(cert)?;
    
    // 重建 TBSCertificate
    let mut tbs = Vec::with_capacity(256);

    // version [0] INTEGER 2
    tbs.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);

    // serialNumber
    tbs.push(0x02);
    tbs.push(cert.serial_number.len() as u8);
    tbs.extend_from_slice(&cert.serial_number);
    
    // signature
    tbs.extend_from_slice(&cert.signature_algorithm);
    
    // issuer
    tbs.extend_from_slice(&cert.issuer);
    
    // validity
    tbs.extend_from_slice(&cert.validity);
    
    // subject
    tbs.extend_from_slice(&cert.subject);
    
    // subjectPublicKeyInfo
    tbs.extend_from_slice(&cert.subject_public_key_info);
    
    // 验证签名
    verify_certificate_data(&tbs, &cert.signature, &pub_key, id)
}

// -- 测试 -----------------------------------------------------------------------

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
            subject_public_key_info: der::public_key_to_spki_der(&pub_key),
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
        
        let der = der::private_key_to_sec1_der(&priv_key);
        let recovered = der::private_key_from_sec1_der(&der).expect("SEC1 解析应成功");
        
        assert_eq!(priv_key.as_bytes(), recovered.as_bytes());
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_private_key_pkcs8_der_roundtrip() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _) = generate_keypair(&mut rng);
        
        let der = der::private_key_to_pkcs8_der(&priv_key);
        let recovered = der::private_key_from_pkcs8_der(&der).expect("PKCS#8 解析应成功");
        
        assert_eq!(priv_key.as_bytes(), recovered.as_bytes());
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_public_key_spki_der_roundtrip() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (_, pub_key) = generate_keypair(&mut rng);
        
        let der = der::public_key_to_spki_der(&pub_key);
        let recovered = der::public_key_from_spki_der(&der).expect("SPKI 解析应成功");
        
        assert_eq!(pub_key, recovered);
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_certificate_sign_verify() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, pub_key) = generate_keypair(&mut rng);
        
        let test_data = b"Test data for signing";
        let id = DEFAULT_ID;
        
        let signature = sign_certificate_data(test_data, &priv_key, id, &mut rng)
            .expect("签名应成功");
        
        verify_certificate_data(test_data, &signature, &pub_key, id)
            .expect("验证应成功");
        
        // 篡改数据应验证失败
        let tampered_data = b"Tampered data";
        assert!(verify_certificate_data(tampered_data, &signature, &pub_key, id).is_err());
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_public_key_compression() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (_, pub_key) = generate_keypair(&mut rng);
        
        // 测试压缩
        let compressed = public_key_to_compressed(&pub_key).expect("压缩应成功");
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
        
        // 验证压缩格式包含原始 x 坐标
        assert_eq!(&compressed[1..], &pub_key[1..33]);
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_public_key_fingerprint() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (_, pub_key) = generate_keypair(&mut rng);
        
        let fingerprint = public_key_fingerprint(&pub_key);
        assert_eq!(fingerprint.len(), 32); // SM3 输出 32 字节
        
        // 相同公钥应该产生相同指纹
        let fingerprint2 = public_key_fingerprint(&pub_key);
        assert_eq!(fingerprint, fingerprint2);
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_sm2_algorithm_identifiers() {
        // 验证 SM2 OID 常量已正确定义
        // OID 1.2.156.10197.1.501 (SM2 签名)
        assert_eq!(SM2_SIG_OID.as_bytes(), &[0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75]);
        // OID 1.2.156.10197.1.301 (SM2 椭圆曲线)
        assert_eq!(SM2_PUBKEY_OID.as_bytes(), &[0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D]);
        // OID 1.2.840.10045.2.1 (EC 公钥)
        assert_eq!(EC_PUBKEY_OID.as_bytes(), &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);
    }
    
    // -- 公钥解压缩测试 --------------------------------------------------------
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_public_key_decompression() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (_, pub_key) = generate_keypair(&mut rng);
        
        // 压缩公钥
        let compressed = public_key_to_compressed(&pub_key).expect("压缩应成功");
        
        // 解压缩公钥
        let decompressed = public_key_from_compressed(&compressed).expect("解压缩应成功");
        
        // 验证解压缩后的公钥与原始公钥相同
        assert_eq!(decompressed, pub_key);
        
        // 验证前缀正确性
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_public_key_decompression_invalid_prefix() {
        // 测试无效前缀
        let mut invalid_compressed = [0u8; 33];
        invalid_compressed[0] = 0x04; // 无效前缀
        
        assert!(public_key_from_compressed(&invalid_compressed).is_err());
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_public_key_compression_decompression_roundtrip() {
        let mut rng = StdRng::seed_from_u64(789012);
        
        // 测试多个密钥对
        for _i in 0..10 {
            let (_, pub_key) = generate_keypair(&mut rng);
            let compressed = public_key_to_compressed(&pub_key).expect("压缩应成功");
            let decompressed = public_key_from_compressed(&compressed).expect("解压缩应成功");
            assert_eq!(decompressed, pub_key);
        }
    }
    
    // -- 证书有效期测试 --------------------------------------------------------
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_validity_parsing() {
        // 构建有效期 DER
        let not_before = b"250101000000Z";
        let not_after = b"300101000000Z";
        let validity_der = generate_validity(not_before, not_after);
        
        // 解析有效期
        let validity = parse_validity(&validity_der).expect("解析有效期应成功");
        
        assert_eq!(validity.not_before, not_before.to_vec());
        assert_eq!(validity.not_after, not_after.to_vec());
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_certificate_validity_verification() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (_, pub_key) = generate_keypair(&mut rng);
        
        let validity = generate_validity(b"200101000000Z", b"300101000000Z");
        
        let cert = GmCertificate {
            version: 2,
            serial_number: vec![0x01],
            signature_algorithm: vec![0x30, 0x0A, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75],
            issuer: vec![0x31, 0x00],
            validity,
            subject: vec![0x31, 0x00],
            subject_public_key_info: der::public_key_to_spki_der(&pub_key),
            signature: vec![0x00; 64],
        };
        
        // 测试有效期内的时间
        assert!(verify_certificate_validity(&cert, b"250101000000Z").is_ok());
        
        // 测试过期时间
        assert!(verify_certificate_validity(&cert, b"400101000000Z").is_err());
        
        // 测试尚未生效时间
        assert!(verify_certificate_validity(&cert, b"100101000000Z").is_err());
    }

    // -- 自签名证书测试 --------------------------------------------------------
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_self_signed_cert_generation() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _) = generate_keypair(&mut rng);
        
        let subject = vec![
            0x31, 0x11,
            0x30, 0x0F,
            0x06, 0x03, 0x55, 0x04, 0x03,
            0x13, 0x08, b'S', b'e', b'l', b'f', b'S', b'i', b'g', b'n',
        ];
        let validity = generate_validity(b"250101000000Z", b"300101000000Z");
        let serial = vec![0x01, 0x02, 0x03, 0x04];
        
        let cert = generate_self_signed_cert(
            &priv_key,
            &subject,
            &validity,
            &serial,
            DEFAULT_ID,
            &mut rng,
        ).expect("自签名证书生成应成功");
        
        // 验证 issuer 和 subject 相同
        assert_eq!(cert.issuer, cert.subject);
        assert_eq!(cert.issuer, subject);
        assert_eq!(cert.serial_number, serial);
        assert_eq!(cert.version, 2);
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_self_signed_cert_verification() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _) = generate_keypair(&mut rng);
        
        let subject = vec![0x31, 0x00];
        let validity = generate_validity(b"250101000000Z", b"300101000000Z");
        let serial = vec![0x01];
        
        let cert = generate_self_signed_cert(
            &priv_key,
            &subject,
            &validity,
            &serial,
            DEFAULT_ID,
            &mut rng,
        ).expect("自签名证书生成应成功");
        
        // 验证自签名
        verify_self_signed_cert(&cert, DEFAULT_ID).expect("自签名验证应成功");
    }
    
    #[test]
    #[cfg(feature = "alloc")]
    fn test_self_signed_cert_tampered_signature_fails() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _) = generate_keypair(&mut rng);
        
        let subject = vec![0x31, 0x00];
        let validity = generate_validity(b"250101000000Z", b"300101000000Z");
        let serial = vec![0x01];
        
        let mut cert = generate_self_signed_cert(
            &priv_key,
            &subject,
            &validity,
            &serial,
            DEFAULT_ID,
            &mut rng,
        ).expect("自签名证书生成应成功");
        
        // 篡改签名
        if !cert.signature.is_empty() {
            cert.signature[0] ^= 0xFF;
        }
        
        // 验证应失败
        assert!(verify_self_signed_cert(&cert, DEFAULT_ID).is_err());
    }
}
