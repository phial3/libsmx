//! 国密证书格式支持（GM/T 0015-2012）
//!
//! 实现 GM/T 0015-2012 《基于SM2密码算法的数字证书格式》标准，
//! 支持证书的解析和生成、密钥的 DER/PEM 编解码、证书签名验证等功能。
//!
//! ## 主要功能
//!
//! - **证书操作**: 解析和生成符合 GM/T 0015-2012 标准的国密证书
//! - **密钥编解码**: 支持 SEC1、PKCS#8、SPKI 格式的 DER/PEM 编解码
//! - **证书验证**: 验证证书有效期、验证自签名证书
//! - **公钥压缩**: 支持公钥压缩格式（33字节）与完整格式（65字节）互转
//! - **电子签章**: 实现 PKCS#7/CMS SignedData 格式的电子签章（GM/T 0031-2014）
//! - **X.509 支持**: 集成 x509-cert crate 提供标准 X.509 证书解析
//!
//! ## 证书结构
//!
//! ```text
//! Certificate ::= SEQUENCE {
//!     tbsCertificate       TBSCertificate,
//!     signatureAlgorithm   AlgorithmIdentifier,
//!     signatureValue       BIT STRING
//! }
//!
//! TBSCertificate ::= SEQUENCE {
//!     version         [0]  Version DEFAULT v1,
//!     serialNumber         CertificateSerialNumber,
//!     signature            AlgorithmIdentifier,
//!     issuer               Name,
//!     validity             Validity,
//!     subject              Name,
//!     subjectPublicKeyInfo SubjectPublicKeyInfo,
//!     ...
//! }
//! ```

#![cfg(feature = "alloc")]
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::sm2::der;
use crate::sm2::{sign, verify, PrivateKey};
use rand_core::Rng;

use pem_rfc7468::{decode_vec, encode_string};

// x509-cert 相关导入
use x509_cert::der::Decode;
use x509_cert::spki::ObjectIdentifier;
use x509_cert::time::{Time, Validity};
use x509_cert::Certificate;

// chrono 时间库导入（用于标准时间处理）
#[cfg(feature = "std")]
use chrono::{Datelike, NaiveDate, NaiveDateTime, TimeZone, Utc};

// ====================================================================================
// 常量定义
// ====================================================================================

/// SM2 签名算法 OID (1.2.156.10197.1.501)
///
/// 用于标识 SM2 签名算法，在证书和签名结构中使用
pub const SM2_SIG_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.1.501");

/// SM2 椭圆曲线公钥算法 OID (1.2.156.10197.1.301)
///
/// 用于标识 SM2 椭圆曲线公钥算法
pub const SM2_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.1.301");

/// EC 公钥算法 OID (1.2.840.10045.2.1)
///
/// 通用椭圆曲线公钥算法 OID，与 SM2 算法 OID 配合使用
pub const EC_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

// ====================================================================================
// 数据结构
// ====================================================================================

/// 国密证书结构（GM/T 0015-2012）
///
/// 表示符合 GM/T 0015-2012 标准的 SM2 数字证书。
/// 证书包含主体公钥和签发者对该公钥的签名。
///
/// ## 字段说明
///
/// - `version`: 证书版本号，0=v1, 1=v2, 2=v3
/// - `serial_number`: 证书序列号，由签发者分配的唯一标识
/// - `signature_algorithm`: 签名算法标识符（DER 编码）
/// - `issuer`: 签发者名称（DER 编码的 X.500 Name）
/// - `validity`: 有效期（DER 编码的 SEQUENCE）
/// - `subject`: 主体名称（DER 编码的 X.500 Name）
/// - `subject_public_key_info`: 主体公钥信息（DER 编码的 SubjectPublicKeyInfo）
/// - `signature`: 签名值（原始字节）
#[derive(Debug, Clone)]
pub struct GmCertificate {
    /// 版本 (0=v1, 1=v2, 2=v3)
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

impl GmCertificate {
    /// 从 DER 格式解析证书
    ///
    /// 解析符合 GM/T 0015-2012 标准的 DER 编码证书。
    ///
    /// # 参数
    /// - `der`: DER 编码的证书数据
    ///
    /// # 返回
    /// - `Ok(GmCertificate)`: 解析成功的证书结构
    /// - `Err(Error::InvalidCertificate)`: 解析失败
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use libsmx::sm2::cert::GmCertificate;
    ///
    /// // 从 DER 编码解析证书
    /// let der_bytes: Vec<u8> = vec![/* DER encoded certificate */];
    /// let cert = GmCertificate::from_der(&der_bytes).expect("Valid certificate");
    /// ```
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        parse_gm_certificate(der)
    }

    /// 将证书编码为 DER 格式
    ///
    /// 将证书结构编码为符合 GM/T 0015-2012 标准的 DER 格式。
    ///
    /// # 返回
    /// DER 编码的证书字节数组
    pub fn to_der(&self) -> Vec<u8> {
        generate_gm_certificate(self)
    }

    /// 从 PEM 格式解析证书
    ///
    /// 解析 PEM 编码的证书（Base64 编码的 DER 数据，带 BEGIN/END 标记）。
    ///
    /// # 参数
    /// - `pem`: PEM 编码的证书数据
    ///
    /// # 返回
    /// - `Ok(GmCertificate)`: 解析成功的证书结构
    /// - `Err(Error::InvalidCertificate)`: 解析失败
    pub fn from_pem(pem: &[u8]) -> Result<Self, Error> {
        parse_gm_certificate_pem(pem)
    }

    /// 将证书编码为 PEM 格式
    ///
    /// 将证书编码为 PEM 格式（带 CERTIFICATE 标签的 Base64 编码）。
    ///
    /// # 返回
    /// - `Ok(Vec<u8>)`: PEM 编码的证书数据
    /// - `Err(Error::InvalidCertificate)`: 编码失败
    pub fn to_pem(&self) -> Result<Vec<u8>, Error> {
        generate_gm_certificate_pem(self)
    }

    /// 提取 SM2 公钥（65字节未压缩格式）
    ///
    /// 从证书的 subjectPublicKeyInfo 字段提取 65 字节未压缩公钥。
    /// 公钥格式：0x04 || x(32字节) || y(32字节)
    ///
    /// # 返回
    /// - `Ok([u8; 65])`: 65 字节未压缩公钥
    /// - `Err(Error::InvalidCertificate)`: 提取失败（格式错误或不是 SM2 公钥）
    pub fn extract_sm2_public_key(&self) -> Result<[u8; 65], Error> {
        extract_sm2_public_key(self)
    }

    /// 验证证书有效期
    ///
    /// 检查当前时间是否在证书的有效期内。
    ///
    /// # 参数
    /// - `current_timestamp`: 当前时间的 Unix 时间戳（秒）
    ///
    /// # 返回
    /// - `Ok(())`: 证书在有效期内
    /// - `Err(Error::InvalidCertificate)`: 证书尚未生效或已过期
    pub fn verify_validity(&self, current_timestamp: u64) -> Result<(), Error> {
        verify_certificate_validity(self, current_timestamp)
    }

    /// 验证证书有效期（使用 SystemTime）
    ///
    /// 检查当前时间是否在证书的有效期内。
    /// 接受标准库 `SystemTime` 类型，更易于使用。
    ///
    /// # 参数
    /// - `now`: 当前时间（SystemTime）
    ///
    /// # 返回
    /// - `Ok(())`: 证书在有效期内
    /// - `Err(Error::InvalidCertificate)`: 证书尚未生效或已过期
    #[cfg(feature = "std")]
    pub fn verify_validity_system_time(&self, now: std::time::SystemTime) -> Result<(), Error> {
        verify_certificate_validity_system_time(self, now)
    }

    /// 验证自签名证书
    ///
    /// 验证自签名证书的签名是否有效。
    /// 使用证书中的公钥验证证书的签名。
    ///
    /// # 参数
    /// - `id`: SM2 签名 ID（通常为 "1234567812345678"）
    ///
    /// # 返回
    /// - `Ok(())`: 签名验证通过
    /// - `Err(Error::InvalidSignature)`: 签名验证失败
    pub fn verify_self_signed(&self, id: &[u8]) -> Result<(), Error> {
        verify_self_signed_cert(self, id)
    }
}

// ====================================================================================
// 证书解析和生成
// ====================================================================================

/// 解析国密证书 DER 编码
///
/// 解析 GM/T 0015-2012 格式的国密证书，提取各个字段。
///
/// ## 解析流程
///
/// 1. 解析外层 SEQUENCE（整个证书）
/// 2. 解析版本号（可选，上下文标签 [0]）
/// 3. 解析序列号（INTEGER）
/// 4. 解析签名算法（AlgorithmIdentifier）
/// 5. 解析签发者（Name）
/// 6. 解析有效期（Validity SEQUENCE）
/// 7. 解析主体（Name）
/// 8. 解析主体公钥信息（SubjectPublicKeyInfo）
/// 9. 解析签名值（BIT STRING）
///
/// # 参数
/// - `der`: DER 编码的证书数据
///
/// # 返回
/// - `Ok(GmCertificate)`: 解析成功的证书结构
/// - `Err(Error::InvalidCertificate)`: 解析失败（格式错误）
///
/// # 注意
///
/// 此函数执行基本的 DER 解析，不验证签名的有效性。
/// 如需验证签名，请使用 `verify_self_signed_cert` 或 `verify_certificate_data`。
pub fn parse_gm_certificate(der: &[u8]) -> Result<GmCertificate, Error> {
    let err = || Error::InvalidCertificate;

    // 解析外层 SEQUENCE
    let (seq_body, _) = der::parse_tlv(der, 0x30).ok_or_else(err)?;

    // 解析版本（可选，上下文标签 [0]）
    let (version, rest) = if seq_body.starts_with(&[0xA0]) {
        let (ver_tlv, rest) = der::parse_tlv(seq_body, 0xA0).ok_or_else(err)?;
        let (ver_bytes, _) = der::parse_tlv(ver_tlv, 0x02).ok_or_else(err)?;
        let ver = ver_bytes.first().copied().unwrap_or(0) as u32;
        (ver, rest)
    } else {
        (0, seq_body)
    };

    // 解析序列号
    let (serial, rest) = der::parse_tlv(rest, 0x02).ok_or_else(err)?;

    // 解析签名算法
    let (sig_alg, rest) = der::parse_tlv_any_full(rest).ok_or_else(err)?;

    // 解析签发者
    let (issuer, rest) = der::parse_tlv_any_full(rest).ok_or_else(err)?;

    // 解析有效期（存储完整 TLV）
    let (validity_tlv, rest) = der::parse_tlv_any_full(rest).ok_or_else(err)?;
    if validity_tlv.is_empty() || validity_tlv[0] != 0x30 {
        return Err(err());
    }
    let validity = validity_tlv;

    // 解析主体
    let (subject, rest) = der::parse_tlv_any_full(rest).ok_or_else(err)?;

    // 解析主体公钥信息
    let (spki, rest) = der::parse_tlv_any_full(rest).ok_or_else(err)?;

    // 解析签名值（BIT STRING）
    let signature = if rest.len() > 3 && rest[0] == 0x03 {
        let (sig_bit_str, _) = der::parse_tlv(rest, 0x03).ok_or_else(err)?;
        if sig_bit_str.is_empty() || sig_bit_str[0] != 0 {
            return Err(err());
        }
        sig_bit_str[1..].to_vec()
    } else {
        rest.to_vec()
    };

    Ok(GmCertificate {
        version,
        serial_number: serial.to_vec(),
        signature_algorithm: sig_alg.to_vec(),
        issuer: issuer.to_vec(),
        validity: validity.to_vec(),
        subject: subject.to_vec(),
        subject_public_key_info: spki.to_vec(),
        signature,
    })
}

/// 生成国密证书 DER 编码
///
/// 将 GmCertificate 结构编码为符合 GM/T 0015-2012 标准的 DER 格式字节数组。
///
/// ## 编码流程
///
/// 1. 编码版本号（v3 及以上显式编码）
/// 2. 编码序列号（INTEGER）
/// 3. 编码签名算法（直接使用已有 DER）
/// 4. 编码签发者（直接使用已有 DER）
/// 5. 编码有效期（直接使用已有 DER）
/// 6. 编码主体（直接使用已有 DER）
/// 7. 编码主体公钥信息（直接使用已有 DER）
/// 8. 编码签名值（BIT STRING）
/// 9. 包装为外层 SEQUENCE
///
/// # 参数
/// - `cert`: 证书结构
///
/// # 返回
/// DER 编码的证书字节数组
///
/// # 注意
///
/// 此函数仅执行 DER 编码，不生成签名。
/// 签名值必须预先计算并存储在 `cert.signature` 中。
pub fn generate_gm_certificate(cert: &GmCertificate) -> Vec<u8> {
    let mut components = Vec::with_capacity(256);

    // 版本（v3 及以上需要显式编码）
    if cert.version > 0 {
        let version_der = vec![0x02, 0x01, cert.version as u8];
        let mut version_wrapper = Vec::with_capacity(2 + version_der.len());
        version_wrapper.push(0xA0);
        version_wrapper.push(version_der.len() as u8);
        version_wrapper.extend(version_der);
        components.push(version_wrapper);
    }

    // 序列号
    let mut serial_der = Vec::with_capacity(2 + cert.serial_number.len());
    serial_der.push(0x02);
    serial_der.push(cert.serial_number.len() as u8);
    serial_der.extend_from_slice(&cert.serial_number);
    components.push(serial_der);

    // 签名算法、签发者、有效期、主体、公钥信息直接使用已有 DER（已经是完整 TLV）
    components.push(cert.signature_algorithm.clone());
    components.push(cert.issuer.clone());
    components.push(cert.validity.clone());
    components.push(cert.subject.clone());
    components.push(cert.subject_public_key_info.clone());

    // 签名值（BIT STRING 编码）
    let mut sig_bit_str = Vec::with_capacity(3 + cert.signature.len());
    sig_bit_str.push(0x03);
    sig_bit_str.push((cert.signature.len() + 1) as u8);
    sig_bit_str.push(0x00); // unused bits
    sig_bit_str.extend_from_slice(&cert.signature);
    components.push(sig_bit_str);

    // 计算总长度并构建外层 SEQUENCE
    let total_len: usize = components.iter().map(|c| c.len()).sum();
    let mut der = Vec::with_capacity(2 + total_len);
    der.push(0x30);

    // 编码长度字段（支持短形式和长形式）
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
///
/// 从证书的 subjectPublicKeyInfo 字段提取 65 字节未压缩公钥。
///
/// ## 公钥格式
///
/// - 输入（SubjectPublicKeyInfo）: SEQUENCE { algorithm, subjectPublicKey BIT STRING }
/// - 输出: 0x04 || x(32字节) || y(32字节)
///
/// ## 验证
///
/// - 验证 algorithm 包含 SM2 OID (1.2.156.10197.1.301)
/// - 验证 BIT STRING 包含 65 字节未压缩公钥
///
/// # 参数
/// - `cert`: 国密证书
///
/// # 返回
/// - `Ok([u8; 65])`: 65 字节未压缩公钥
/// - `Err(Error::InvalidCertificate)`: 提取失败（格式错误或不是 SM2 公钥）
pub fn extract_sm2_public_key(cert: &GmCertificate) -> Result<[u8; 65], Error> {
    let err = || Error::InvalidCertificate;
    let spki = &cert.subject_public_key_info;

    // 解析 SubjectPublicKeyInfo SEQUENCE
    let (seq_body, _) = der::parse_tlv(spki, 0x30).ok_or_else(err)?;

    // 解析 AlgorithmIdentifier SEQUENCE
    let (alg_id, rest) = der::parse_tlv(seq_body, 0x30).ok_or_else(err)?;

    // 按照 RFC 5480 严格解析 AlgorithmIdentifier
    // AlgorithmIdentifier ::= SEQUENCE {
    //     algorithm  OBJECT IDENTIFIER,
    //     parameters ANY DEFINED BY algorithm OPTIONAL
    // }
    //
    // 对于 SM2，格式为:
    // SEQUENCE {
    //     OID 1.2.840.10045.2.1 (id-ecPublicKey)
    //     OID 1.2.156.10197.1.301 (SM2)
    // }

    // 解析第一个 OID (id-ecPublicKey = 1.2.840.10045.2.1)
    let (first_oid, params) = der::parse_tlv(alg_id, 0x06).ok_or_else(err)?;
    const EC_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    if first_oid != EC_OID {
        return Err(err());
    }

    // 解析第二个 OID (SM2 = 1.2.156.10197.1.301)
    let (second_oid, _) = der::parse_tlv(params, 0x06).ok_or_else(err)?;
    const SM2_OID: &[u8] = &[0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D];
    if second_oid != SM2_OID {
        return Err(err());
    }

    // 解析公钥 BIT STRING
    let (pub_key_bit_str, _) = der::parse_tlv(rest, 0x03).ok_or_else(err)?;
    if pub_key_bit_str.len() < 66 || pub_key_bit_str[0] != 0 {
        return Err(err());
    }

    // 提取公钥字节（跳过 unused bits 字节）
    let pub_key_bytes = &pub_key_bit_str[1..];
    if pub_key_bytes.len() != 65 || pub_key_bytes[0] != 0x04 {
        return Err(err());
    }

    let mut pub_key = [0u8; 65];
    pub_key.copy_from_slice(pub_key_bytes);
    Ok(pub_key)
}

// ====================================================================================
// X.509 证书支持
// ====================================================================================

/// 使用 x509-cert 解析 X.509 证书
///
/// 使用 x509-cert crate 解析标准 X.509 证书。
///
/// # 参数
/// - `der`: DER 编码的 X.509 证书
///
/// # 返回
/// - `Ok(Certificate)`: 解析成功的 x509-cert 证书结构
/// - `Err(Error::InvalidCertificate)`: 解析失败
///
/// # 注意
///
/// 此函数返回的是 x509-cert crate 的 Certificate 类型，
/// 与 `GmCertificate` 不同。如需国密证书操作，请使用 `parse_gm_certificate`。
pub fn parse_x509_certificate(der: &[u8]) -> Result<Certificate, Error> {
    Certificate::from_der(der).map_err(|_| Error::InvalidCertificate)
}

// ====================================================================================
// 时间处理
// ====================================================================================

/// 从证书有效期字段解析时间
///
/// 解析证书有效期 DER 编码，提取生效时间和过期时间。
/// 支持 UTCTime（2字节年份）和 GeneralizedTime（4字节年份）格式。
///
/// ## 有效期格式
///
/// ```text
/// Validity ::= SEQUENCE {
///     notBefore    Time,
///     notAfter     Time
/// }
///
/// Time ::= CHOICE {
///     utcTime        UTCTime,
///     generalTime    GeneralizedTime
/// }
/// ```
///
/// # 参数
/// - `validity_der`: 有效期 DER 编码数据
///
/// # 返回
/// - `Ok(Validity)`: 解析成功的有效期结构
/// - `Err(Error::InvalidCertificate)`: 解析失败（格式错误）
fn parse_validity(validity_der: &[u8]) -> Result<Validity, Error> {
    Validity::from_der(validity_der).map_err(|_| Error::InvalidCertificate)
}

/// 验证证书有效期
///
/// 检查当前时间（Unix 时间戳，秒）是否在证书的有效期内。
///
/// ## 验证逻辑
///
/// 1. 解析证书有效期字段
/// 2. 将 notBefore 和 notAfter 转换为 Unix 时间戳
/// 3. 检查 current_timestamp 是否在 [notBefore, notAfter] 范围内
///
/// # 参数
/// - `cert`: 国密证书
/// - `current_timestamp`: 当前时间的 Unix 时间戳（秒）
///
/// # 返回
/// - `Ok(())`: 证书在有效期内
/// - `Err(Error::InvalidCertificate)`: 证书尚未生效或已过期
///
/// # 示例
///
/// ```ignore
/// use libsmx::sm2::cert::{GmCertificate, verify_certificate_validity};
///
/// // 验证证书是否在有效期内
/// let cert: GmCertificate = /* 加载证书 */;
/// let current_time = 1735689600u64; // 2025-01-01 00:00:00 UTC
/// verify_certificate_validity(&cert, current_time).expect("Certificate valid");
/// ```
pub fn verify_certificate_validity(
    cert: &GmCertificate,
    current_timestamp: u64,
) -> Result<(), Error> {
    let validity = parse_validity(&cert.validity)?;

    let not_before = validity.not_before.to_unix_duration().as_secs();
    let not_after = validity.not_after.to_unix_duration().as_secs();

    if current_timestamp < not_before {
        return Err(Error::InvalidCertificate);
    }
    if current_timestamp > not_after {
        return Err(Error::InvalidCertificate);
    }

    Ok(())
}

/// 验证证书有效期（使用 SystemTime）
///
/// 检查证书是否在有效期内。接受标准库 `SystemTime` 类型，
/// 更易于使用。
///
/// ## 验证流程
///
/// 1. 解析证书有效期字段
/// 2. 将 notBefore 和 notAfter 转换为 SystemTime
/// 3. 检查当前时间是否在有效期内
///
/// # 参数
/// - `cert`: 国密证书
/// - `now`: 当前时间（SystemTime）
///
/// # 返回
/// - `Ok(())`: 证书在有效期内
/// - `Err(Error::InvalidCertificate)`: 证书尚未生效或已过期
///
/// # 示例
///
/// ```ignore
/// use libsmx::sm2::cert::{GmCertificate, verify_certificate_validity_system_time};
/// use std::time::SystemTime;
///
/// // 验证证书是否在有效期内
/// let cert: GmCertificate = /* 加载证书 */;
/// let now = SystemTime::now();
/// verify_certificate_validity_system_time(&cert, now).expect("Certificate valid");
/// ```
#[cfg(feature = "std")]
pub fn verify_certificate_validity_system_time(
    cert: &GmCertificate,
    now: std::time::SystemTime,
) -> Result<(), Error> {
    let current_timestamp = now
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidCertificate)?
        .as_secs();
    verify_certificate_validity(cert, current_timestamp)
}

/// 验证证书有效期（使用日期字符串）
///
/// 检查证书是否在有效期内。接受 "YYYY-MM-DD" 格式的日期字符串，
/// 便于人类直接使用。
///
/// ## 支持的日期格式
///
/// - `YYYY-MM-DD`：如 "2025-01-01"
/// - `YYYY-MM-DD HH:MM:SS`：如 "2025-01-01 12:30:00"
///
/// 时间默认为 UTC 00:00:00。
///
/// ## 验证流程
///
/// 1. 解析日期字符串为 Unix 时间戳
/// 2. 调用 `verify_certificate_validity` 进行验证
///
/// # 参数
/// - `cert`: 国密证书
/// - `date_str`: 日期字符串（格式：YYYY-MM-DD 或 YYYY-MM-DD HH:MM:SS）
///
/// # 返回
/// - `Ok(())`: 证书在有效期内
/// - `Err(Error::InvalidCertificate)`: 证书尚未生效或已过期，或日期格式错误
///
/// # 示例
///
/// ```ignore
/// use libsmx::sm2::cert::{GmCertificate, verify_certificate_validity_str};
///
/// // 验证证书是否在有效期内
/// let cert: GmCertificate = /* 加载证书 */;
/// verify_certificate_validity_str(&cert, "2025-01-01").expect("Certificate valid");
///
/// // 使用具体时间
/// verify_certificate_validity_str(&cert, "2025-01-01 12:30:00").expect("Certificate valid");
/// ```
#[cfg(feature = "std")]
pub fn verify_certificate_validity_str(cert: &GmCertificate, date_str: &str) -> Result<(), Error> {
    let timestamp = parse_date_str_to_timestamp(date_str)?;
    verify_certificate_validity(cert, timestamp)
}

/// 将日期字符串解析为 Unix 时间戳
///
/// 支持格式：
/// - `YYYY-MM-DD`（默认为 00:00:00）
/// - `YYYY-MM-DD HH:MM:SS`
///
/// # 参数
/// - `date_str`: 日期字符串
///
/// # 返回
/// - `Ok(u64)`: Unix 时间戳（秒）
/// - `Err(Error::InvalidCertificate)`: 解析失败
#[cfg(feature = "std")]
fn parse_date_str_to_timestamp(date_str: &str) -> Result<u64, Error> {
    // 使用 chrono 解析日期字符串
    // 支持格式：YYYY-MM-DD 或 YYYY-MM-DD HH:MM:SS
    let datetime = if date_str.contains(' ') {
        // 包含时间部分
        NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S")
            .map_err(|_| Error::InvalidCertificate)?
    } else {
        // 只有日期部分，使用默认时间 00:00:00
        let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
            .map_err(|_| Error::InvalidCertificate)?;
        date.and_hms_opt(0, 0, 0).ok_or(Error::InvalidCertificate)?
    };

    // 转换为 UTC DateTime 并获取 Unix 时间戳
    let utc_datetime = Utc.from_utc_datetime(&datetime);
    Ok(utc_datetime.timestamp() as u64)
}

/// 生成有效期 DER 编码（UTCTime 格式）
///
/// 生成符合 X.509 标准的有效期 DER 编码。
///
/// ## 输出格式
///
/// ```text
/// SEQUENCE {
///     UTCTime notBefore,
///     UTCTime notAfter
/// }
/// ```
///
/// # 参数
/// - `not_before`: 生效时间（UTCTime 格式，如 b"250101000000Z"）
/// - `not_after`: 过期时间（UTCTime 格式，如 b"300101000000Z"）
///
/// # 返回
/// 有效期 DER 编码字节数组
///
/// # 示例
///
/// ```
/// use libsmx::sm2::cert::generate_validity;
///
/// let validity = generate_validity(b"250101000000Z", b"300101000000Z");
/// ```
pub fn generate_validity(not_before: &[u8], not_after: &[u8]) -> Vec<u8> {
    let mut validity = Vec::with_capacity(32);

    // notBefore
    validity.push(0x17);
    validity.push(not_before.len() as u8);
    validity.extend_from_slice(not_before);

    // notAfter
    validity.push(0x17);
    validity.push(not_after.len() as u8);
    validity.extend_from_slice(not_after);

    // 包装为 SEQUENCE
    let mut seq = Vec::with_capacity(2 + validity.len());
    seq.push(0x30);
    seq.push(validity.len() as u8);
    seq.extend(validity);

    seq
}

/// 从日期字符串生成有效期 DER 编码
///
/// 使用人类可读的日期字符串生成有效期 DER 编码。
/// 支持 "YYYY-MM-DD" 和 "YYYY-MM-DD HH:MM:SS" 格式。
///
/// ## 日期格式
///
/// - `YYYY-MM-DD`：如 "2025-01-01"（默认为 00:00:00）
/// - `YYYY-MM-DD HH:MM:SS`：如 "2025-01-01 12:30:00"
///
/// 年份范围：1950-2049 使用 UTCTime，其他使用 GeneralizedTime
///
/// # 参数
/// - `not_before`: 生效时间日期字符串
/// - `not_after`: 过期时间日期字符串
///
/// # 返回
/// - `Ok(Vec<u8>)`: 有效期 DER 编码字节数组
/// - `Err(Error::InvalidCertificate)`: 日期格式错误
///
/// # 示例
///
/// ```ignore
/// use libsmx::sm2::cert::generate_validity_from_str;
///
/// let validity = generate_validity_from_str("2025-01-01", "2030-01-01")
///     .expect("Valid date strings");
///
/// // 使用具体时间
/// let validity = generate_validity_from_str("2025-01-01 12:30:00", "2030-01-01 12:30:00")
///     .expect("Valid date strings");
/// ```
#[cfg(feature = "std")]
pub fn generate_validity_from_str(not_before: &str, not_after: &str) -> Result<Vec<u8>, Error> {
    let not_before_bytes = date_str_to_utc_bytes(not_before)?;
    let not_after_bytes = date_str_to_utc_bytes(not_after)?;
    Ok(generate_validity(&not_before_bytes, &not_after_bytes))
}

/// 将日期字符串转换为 UTCTime 字节数组
///
/// 支持格式：
/// - `YYYY-MM-DD` -> YYMMDDHHMMSSZ
/// - `YYYY-MM-DD HH:MM:SS` -> YYMMDDHHMMSSZ
///
/// 年份范围：1950-2049（符合 RFC 5280 UTCTime 要求）
#[cfg(feature = "std")]
fn date_str_to_utc_bytes(date_str: &str) -> Result<Vec<u8>, Error> {
    // 使用 chrono 解析日期字符串
    let datetime = if date_str.contains(' ') {
        NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S")
            .map_err(|_| Error::InvalidCertificate)?
    } else {
        let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
            .map_err(|_| Error::InvalidCertificate)?;
        date.and_hms_opt(0, 0, 0).ok_or(Error::InvalidCertificate)?
    };

    // 验证年份范围（RFC 5280：UTCTime 年份范围为 1950-2049）
    let year = datetime.year();
    if !(1950..=2049).contains(&year) {
        return Err(Error::InvalidCertificate);
    }

    use alloc::string::ToString;
    // 使用 chrono 格式化为 YYMMDDHHMMSSZ
    let utc_str = datetime.format("%y%m%d%H%M%SZ").to_string();

    Ok(utc_str.into_bytes())
}

/// 从 x509_cert::time::Time 生成有效期 DER 编码
///
/// 使用 x509-cert 提供的 Time 类型生成有效期 DER 编码。
/// 支持 UtcTime 和 GeneralTime 两种格式。
///
/// # 参数
/// - `not_before`: 生效时间（x509_cert::time::Time）
/// - `not_after`: 过期时间（x509_cert::time::Time）
///
/// # 返回
/// 有效期 DER 编码字节数组
///
/// # 示例
///
/// ```ignore
/// use libsmx::sm2::cert::generate_validity_from_times;
/// use x509_cert::time::Time;
///
/// let not_before = Time::try_from(std::time::SystemTime::now()).unwrap();
/// let not_after = Time::try_from(
///     std::time::SystemTime::now() + std::time::Duration::from_secs(365 * 24 * 3600)
/// ).unwrap();
/// let validity = generate_validity_from_times(not_before, not_after);
/// ```
pub fn generate_validity_from_times(not_before: Time, not_after: Time) -> Vec<u8> {
    // 将 Time 转换为字节数组（Time 的 DER 编码）
    let mut validity = Vec::with_capacity(64);

    // notBefore - Time 编码为 UTCTime 或 GeneralizedTime
    let time_str = alloc::string::ToString::to_string(&not_before);
    let time_bytes = time_str.as_bytes();
    match not_before {
        Time::UtcTime(_) => {
            validity.push(0x17); // UTCTime tag
            validity.push(time_bytes.len() as u8);
            validity.extend_from_slice(time_bytes);
        }
        Time::GeneralTime(_) => {
            validity.push(0x18); // GeneralizedTime tag
            validity.push(time_bytes.len() as u8);
            validity.extend_from_slice(time_bytes);
        }
    }

    // notAfter
    let time_str = alloc::string::ToString::to_string(&not_after);
    let time_bytes = time_str.as_bytes();
    match not_after {
        Time::UtcTime(_) => {
            validity.push(0x17); // UTCTime tag
            validity.push(time_bytes.len() as u8);
            validity.extend_from_slice(time_bytes);
        }
        Time::GeneralTime(_) => {
            validity.push(0x18); // GeneralizedTime tag
            validity.push(time_bytes.len() as u8);
            validity.extend_from_slice(time_bytes);
        }
    }

    // 包装为 SEQUENCE
    let mut seq = Vec::with_capacity(4 + validity.len());
    seq.push(0x30);
    seq.push(validity.len() as u8);
    seq.extend(validity);

    seq
}

// ====================================================================================
// PEM 支持
// ====================================================================================

/// 解析 PEM 格式的国密证书
///
/// 解析 PEM 编码的国密证书，提取 DER 数据后解析为 GmCertificate。
///
/// ## PEM 格式
///
/// ```text
/// -----BEGIN CERTIFICATE-----
/// Base64编码的DER数据
/// -----END CERTIFICATE-----
/// ```
///
/// # 参数
/// - `pem`: PEM 编码的证书数据
///
/// # 返回
/// - `Ok(GmCertificate)`: 解析成功的证书结构
/// - `Err(Error::InvalidCertificate)`: 解析失败
pub fn parse_gm_certificate_pem(pem: &[u8]) -> Result<GmCertificate, Error> {
    let (_label, der) = decode_vec(pem).map_err(|_| Error::InvalidCertificate)?;
    parse_gm_certificate(&der)
}

/// 生成 PEM 格式的国密证书
///
/// 将 GmCertificate 编码为 PEM 格式。
///
/// # 参数
/// - `cert`: 国密证书
///
/// # 返回
/// - `Ok(Vec<u8>)`: PEM 编码的证书数据
/// - `Err(Error::InvalidCertificate)`: 编码失败
pub fn generate_gm_certificate_pem(cert: &GmCertificate) -> Result<Vec<u8>, Error> {
    let der = generate_gm_certificate(cert);
    let pem = encode_string("CERTIFICATE", Default::default(), &der)
        .map_err(|_| Error::InvalidCertificate)?;
    Ok(pem.as_bytes().to_vec())
}

/// 解析 PEM 格式的 X.509 证书
///
/// 解析 PEM 编码的 X.509 证书，使用 x509-cert crate 解析。
///
/// # 参数
/// - `pem`: PEM 编码的证书数据
///
/// # 返回
/// - `Ok(Certificate)`: 解析成功的 x509-cert 证书结构
/// - `Err(Error::InvalidCertificate)`: 解析失败
pub fn parse_x509_certificate_pem(pem: &[u8]) -> Result<Certificate, Error> {
    let (_label, der) = decode_vec(pem).map_err(|_| Error::InvalidCertificate)?;
    parse_x509_certificate(&der)
}

// ====================================================================================
// 证书签名和验证
// ====================================================================================

/// 对证书数据进行签名（使用 SM2）
///
/// 使用 SM2 算法对证书 TBS（To-Be-Signed）数据进行签名。
///
/// ## 签名流程
///
/// 1. 计算 Z 值（SM2 签名预处理）
/// 2. 计算 E 值（H(Z || M)）
/// 3. 使用 SM2 私钥签名
///
/// # 参数
/// - `data`: 待签名的证书数据（TBS 证书）
/// - `priv_key`: SM2 私钥
/// - `id`: SM2 签名 ID（通常为 "1234567812345678"）
/// - `rng`: 随机数生成器
///
/// # 返回
/// - `Ok(Vec<u8>)`: 64 字节签名值（r || s）
/// - `Err(Error)`: 签名失败
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
///
/// 使用 SM2 算法验证证书 TBS 数据的签名。
///
/// ## 验证流程
///
/// 1. 计算 Z 值（SM2 签名预处理）
/// 2. 计算 E 值（H(Z || M)）
/// 3. 使用 SM2 公钥验证签名
///
/// # 参数
/// - `data`: 证书数据（TBS 证书）
/// - `signature`: 签名值（64字节 r || s）
/// - `pub_key`: SM2 公钥（65字节未压缩格式）
/// - `id`: SM2 签名 ID（通常为 "1234567812345678"）
///
/// # 返回
/// - `Ok(())`: 签名验证通过
/// - `Err(Error::InvalidSignature)`: 签名验证失败
pub fn verify_certificate_data(
    data: &[u8],
    signature: &[u8],
    pub_key: &[u8; 65],
    id: &[u8],
) -> Result<(), Error> {
    let z = crate::sm2::get_z(id, pub_key);
    let e = crate::sm2::get_e(&z, data);

    let sig_array: [u8; 64] = signature.try_into().map_err(|_| Error::InvalidSignature)?;

    verify(&e, pub_key, &sig_array)
}

// ====================================================================================
// 密钥 PEM 编解码
// ====================================================================================

/// 将私钥编码为 SEC1 PEM 格式
///
/// 将 SM2 私钥编码为 SEC1（RFC 5915）格式的 PEM。
///
/// ## SEC1 格式
/// 将公钥编码为 SPKI PEM 格式
///
/// 将 SM2 公钥编码为 SPKI（SubjectPublicKeyInfo）格式的 PEM。
///
/// ## SPKI 格式
///
/// ```text
/// -----BEGIN PUBLIC KEY-----
/// Base64编码的DER数据
/// -----END PUBLIC KEY-----
/// ```
///
/// # 参数
/// - `pub_key`: 65 字节未压缩公钥
///
/// # 返回
/// - `Ok(Vec<u8>)`: PEM 编码的公钥
/// - `Err(Error::InvalidCertificate)`: 编码失败
pub fn public_key_to_spki_pem(pub_key: &[u8; 65]) -> Result<Vec<u8>, Error> {
    let der = der::public_key_to_spki_der(pub_key);
    let pem = encode_string("PUBLIC KEY", Default::default(), &der)
        .map_err(|_| Error::InvalidCertificate)?;
    Ok(pem.as_bytes().to_vec())
}

/// 从 SPKI PEM 解析公钥
///
/// 从 SPKI 格式的 PEM 解析 SM2 公钥。
///
/// # 参数
/// - `pem`: SPKI PEM 编码的公钥数据
///
/// # 返回
/// - `Ok([u8; 65])`: 65 字节未压缩公钥
/// - `Err(Error::InvalidCertificate)`: 解析失败
pub fn public_key_from_spki_pem(pem: &[u8]) -> Result<[u8; 65], Error> {
    let (_label, der) = decode_vec(pem).map_err(|_| Error::InvalidCertificate)?;
    der::public_key_from_spki_der(&der)
}

// ====================================================================================
// 公钥压缩/解压
// ====================================================================================

/// 将公钥转换为压缩格式 (33字节)
///
/// 将 65 字节未压缩公钥压缩为 33 字节格式。
///
/// ## 压缩格式
///
/// - **02 || x**: y 坐标为偶数
/// - **03 || x**: y 坐标为奇数
///
/// ## 压缩原理
///
/// 椭圆曲线方程 y² = x³ + ax + b，给定 x 可以计算出 y²，
/// 然后根据 y 的奇偶性选择正确的 y 值。
///
/// # 参数
/// - `pub_key`: 65 字节未压缩公钥 (0x04 || x || y)
///
/// # 返回
/// - `Ok([u8; 33])`: 33 字节压缩公钥
/// - `Err(Error::InvalidPublicKey)`: 输入格式错误
pub fn public_key_to_compressed(pub_key: &[u8; 65]) -> Result<[u8; 33], Error> {
    if pub_key[0] != 0x04 {
        return Err(Error::InvalidPublicKey);
    }

    let x = &pub_key[1..33];
    let y = &pub_key[33..65];

    // 根据 y 的奇偶性选择前缀
    let y_is_odd = y[31] & 1;
    let prefix = if y_is_odd != 0 { 0x03 } else { 0x02 };

    let mut compressed = [0u8; 33];
    compressed[0] = prefix;
    compressed[1..33].copy_from_slice(x);

    Ok(compressed)
}

/// 将压缩公钥解压为完整格式 (65字节)
///
/// 使用椭圆曲线点解压缩算法将 33 字节压缩公钥解压为 65 字节完整格式。
///
/// ## 解压算法
///
/// 1. 从压缩格式提取 x 坐标和前缀（02 或 03）
/// 2. 计算 α = x³ + ax + b (mod p)
/// 3. 计算 y = √α (mod p) 使用 Tonelli-Shanks 算法
/// 4. 根据前缀选择正确的 y 值（02=偶数，03=奇数）
///
/// ## 参数
/// - `compressed`: 33 字节压缩公钥
///
/// ## 返回
/// - `Ok([u8; 65])`: 65 字节未压缩公钥 (0x04 || x || y)
/// - `Err(Error::InvalidPublicKey)`: 解压失败（无效格式或坐标）
///
/// ## 注意
///
/// 需要启用 `alloc` feature 以使用有限域运算。
pub fn public_key_from_compressed(compressed: &[u8; 33]) -> Result<[u8; 65], Error> {
    use crate::sm2::field::{fp_from_bytes, fp_sqrt, fp_to_bytes};

    let prefix = compressed[0];
    if prefix != 0x02 && prefix != 0x03 {
        return Err(Error::InvalidPublicKey);
    }

    // 提取 x 坐标
    let x_bytes: [u8; 32] = compressed[1..33].try_into().unwrap();
    let x = fp_from_bytes(&x_bytes);

    // 计算 y² = x³ + ax + b
    let a = crate::sm2::field::CURVE_A;
    let b = crate::sm2::field::CURVE_B;

    let x3 = crate::sm2::field::fp_mul(&x, &crate::sm2::field::fp_mul(&x, &x));
    let ax = crate::sm2::field::fp_mul(&a, &x);
    let x3_plus_ax = crate::sm2::field::fp_add(&x3, &ax);
    let y2 = crate::sm2::field::fp_add(&x3_plus_ax, &b);

    // 计算 y = √y²
    let y = fp_sqrt(&y2).ok_or(Error::InvalidPublicKey)?;

    // 根据前缀选择正确的 y 值
    let y_is_odd = fp_to_bytes(&y)[31] & 1;
    let y_expected_odd = prefix == 0x03;

    let final_y = if (y_is_odd != 0) != y_expected_odd {
        crate::sm2::field::fp_neg(&y)
    } else {
        y
    };

    let y_bytes = fp_to_bytes(&final_y);

    // 构建未压缩公钥
    let mut pub_key = [0u8; 65];
    pub_key[0] = 0x04;
    pub_key[1..33].copy_from_slice(&x_bytes);
    pub_key[33..65].copy_from_slice(&y_bytes);

    Ok(pub_key)
}

/// 计算公钥指纹 (SM3)
///
/// 对公钥进行 SM3 哈希，生成 32 字节指纹。
///
/// ## 用途
///
/// 公钥指纹可用于：
/// - 快速比较公钥
/// - 证书标识
/// - 密钥管理
///
/// # 参数
/// - `pub_key`: 65 字节未压缩公钥
///
/// # 返回
/// 32 字节 SM3 哈希值
pub fn public_key_fingerprint(pub_key: &[u8; 65]) -> [u8; 32] {
    use crate::sm3::Sm3Hasher;

    let mut hasher = Sm3Hasher::new();
    hasher.update(pub_key);
    hasher.finalize()
}

// ====================================================================================
// 自签名证书
// ====================================================================================

/// 生成自签名证书
///
/// 生成自签名证书，其中 issuer 和 subject 相同，使用自己的私钥签名。
///
/// ## 自签名证书用途
///
/// - 根 CA 证书
/// - 测试证书
/// - 单一信任域内的证书
///
/// ## 证书结构
///
/// ```text
/// TBSCertificate:
///     version: v3 (2)
///     serialNumber: 指定序列号
///     signature: SM2 签名算法
///     issuer: 主体名称
///     validity: 指定有效期
///     subject: 主体名称（与 issuer 相同）
///     subjectPublicKeyInfo: 公钥信息
/// ```
///
/// # 参数
/// - `priv_key`: 私钥（用于签名和提取公钥）
/// - `subject`: 主体名称 DER 编码
/// - `validity`: 有效期 DER 编码
/// - `serial_number`: 证书序列号
/// - `id`: SM2 签名 ID（通常为 "1234567812345678"）
/// - `rng`: 随机数生成器
///
/// # 返回
/// - `Ok(GmCertificate)`: 生成的自签名证书
/// - `Err(Error)`: 生成失败
///
/// # 示例
///
/// ```
/// use libsmx::sm2::{generate_keypair, cert};
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
///
/// let mut rng = StdRng::seed_from_u64(123456);
/// let (priv_key, _) = generate_keypair(&mut rng);
///
/// let subject = vec![0x31, 0x00]; // 简单的 X.500 Name
/// let validity = cert::generate_validity(b"250101000000Z", b"300101000000Z");
/// let serial = vec![0x01];
///
/// let cert = cert::generate_self_signed_cert(
///     &priv_key,
///     &subject,
///     &validity,
///     &serial,
///     b"1234567812345678",
///     &mut rng,
/// ).expect("Failed to generate certificate");
/// ```
pub fn generate_self_signed_cert<R: Rng>(
    priv_key: &PrivateKey,
    subject: &[u8],
    validity: &[u8],
    serial_number: &[u8],
    id: &[u8],
    rng: &mut R,
) -> Result<GmCertificate, Error> {
    // 获取公钥
    let pub_key = priv_key.public_key();

    // 构建 SubjectPublicKeyInfo
    let spki = der::public_key_to_spki_der(&pub_key);

    // 构建 TBS 证书内容
    let mut tbs = Vec::with_capacity(256);

    // 版本 (v3)
    tbs.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);

    // 序列号
    tbs.push(0x02);
    tbs.push(serial_number.len() as u8);
    tbs.extend_from_slice(serial_number);

    // 签名算法 (SM2)
    let sig_alg = vec![
        0x30, 0x0A, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75,
    ];
    tbs.extend(&sig_alg);

    // 签发者 = 主体
    tbs.extend_from_slice(subject);

    // 有效期
    tbs.extend_from_slice(validity);

    // 主体
    tbs.extend_from_slice(subject);

    // 公钥信息
    tbs.extend(&spki);

    // 包装为 SEQUENCE
    let tbs_cert = wrap_sequence(tbs);

    // 签名
    let signature = sign_certificate_data(&tbs_cert, priv_key, id, rng)?;

    Ok(GmCertificate {
        version: 2,
        serial_number: serial_number.to_vec(),
        signature_algorithm: sig_alg,
        issuer: subject.to_vec(),
        validity: validity.to_vec(),
        subject: subject.to_vec(),
        subject_public_key_info: spki,
        signature,
    })
}

/// 验证自签名证书
///
/// 验证自签名证书的签名是否有效。
/// 使用证书中的公钥验证证书的签名。
///
/// ## 验证流程
///
/// 1. 从证书中提取 SM2 公钥
/// 2. 重建 TBS（To-Be-Signed）证书数据
/// 3. 使用公钥验证签名
///
/// # 参数
/// - `cert`: 自签名证书
/// - `id`: SM2 签名 ID（通常为 "1234567812345678"）
///
/// # 返回
/// - `Ok(())`: 签名验证通过
/// - `Err(Error::InvalidSignature)`: 签名验证失败
///
/// # 注意
///
/// 此函数仅验证签名的有效性，不验证证书有效期或其他属性。
pub fn verify_self_signed_cert(cert: &GmCertificate, id: &[u8]) -> Result<(), Error> {
    // 提取公钥
    let pub_key = extract_sm2_public_key(cert)?;

    // 重建 TBS 证书
    let mut tbs = Vec::with_capacity(256);

    // 版本
    let version_der = vec![0x02, 0x01, cert.version as u8];
    let mut version_wrapper = Vec::with_capacity(2 + version_der.len());
    version_wrapper.push(0xA0);
    version_wrapper.push(version_der.len() as u8);
    version_wrapper.extend(version_der);
    tbs.push(version_wrapper);

    // 序列号
    let mut serial_der = Vec::with_capacity(2 + cert.serial_number.len());
    serial_der.push(0x02);
    serial_der.push(cert.serial_number.len() as u8);
    serial_der.extend_from_slice(&cert.serial_number);
    tbs.push(serial_der);

    // 其他字段
    tbs.push(cert.signature_algorithm.clone());
    tbs.push(cert.issuer.clone());
    tbs.push(cert.validity.clone());
    tbs.push(cert.subject.clone());
    tbs.push(cert.subject_public_key_info.clone());

    // 包装为 SEQUENCE
    let tbs_cert = wrap_sequence_vec(tbs);

    // 验证签名
    verify_certificate_data(&tbs_cert, &cert.signature, &pub_key, id)
}

/// 将数据包装为 SEQUENCE（单个 Vec）
///
/// 将单个字节数组包装为 ASN.1 SEQUENCE 结构。
///
/// # 参数
/// - `content`: 要包装的内容
///
/// # 返回
/// SEQUENCE 编码的字节数组
fn wrap_sequence(content: Vec<u8>) -> Vec<u8> {
    let mut result = Vec::with_capacity(2 + content.len());
    result.push(0x30);

    let len = content.len();
    if len < 128 {
        result.push(len as u8);
    } else if len < 256 {
        result.push(0x81);
        result.push(len as u8);
    } else {
        result.push(0x82);
        result.push((len >> 8) as u8);
        result.push((len & 0xFF) as u8);
    }

    result.extend(content);
    result
}

/// 将多个 Vec 包装为 SEQUENCE
///
/// 将多个字节数组连接并包装为 ASN.1 SEQUENCE 结构。
///
/// # 参数
/// - `components`: 要连接的多个字节数组
///
/// # 返回
/// SEQUENCE 编码的字节数组
fn wrap_sequence_vec(components: Vec<Vec<u8>>) -> Vec<u8> {
    let total_len: usize = components.iter().map(|c| c.len()).sum();
    let mut result = Vec::with_capacity(2 + total_len);
    result.push(0x30);

    if total_len < 128 {
        result.push(total_len as u8);
    } else if total_len < 256 {
        result.push(0x81);
        result.push(total_len as u8);
    } else {
        result.push(0x82);
        result.push((total_len >> 8) as u8);
        result.push((total_len & 0xFF) as u8);
    }

    for component in components {
        result.extend(component);
    }

    result
}

// ====================================================================================
// 测试
// ====================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::generate_keypair;
    use crate::sm2::DEFAULT_ID;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // -- 证书测试 ------------------------------------------------------------

    #[test]
    fn test_certificate_generate() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _pub_key) = generate_keypair(&mut rng);

        let subject = vec![0x31, 0x00];
        let validity = generate_validity(b"250101000000Z", b"300101000000Z");
        let serial = vec![0x01];

        let cert = generate_self_signed_cert(
            &priv_key, &subject, &validity, &serial, DEFAULT_ID, &mut rng,
        )
        .expect("Certificate generation should succeed");

        assert_eq!(cert.issuer, cert.subject);
        assert_eq!(cert.issuer, subject);
        assert_eq!(cert.serial_number, serial);
        assert_eq!(cert.version, 2);
    }

    #[test]
    fn test_certificate_validity_verification() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (_priv_key, pub_key) = generate_keypair(&mut rng);

        let subject = vec![0x31, 0x00];
        let validity = generate_validity(b"250101000000Z", b"300101000000Z");
        let serial = vec![0x01];

        let cert = GmCertificate {
            version: 2,
            serial_number: serial,
            signature_algorithm: vec![
                0x30, 0x0A, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75,
            ],
            issuer: vec![0x31, 0x00],
            validity,
            subject,
            subject_public_key_info: der::public_key_to_spki_der(&pub_key),
            signature: vec![0x00; 64],
        };

        // 2025-01-01 00:00:00 UTC
        assert!(verify_certificate_validity(&cert, 1735689600).is_ok());
        // 2040-01-01 00:00:00 UTC (过期)
        assert!(verify_certificate_validity(&cert, 2208988800).is_err());
        // 2010-01-01 00:00:00 UTC (未生效)
        assert!(verify_certificate_validity(&cert, 1262304000).is_err());
    }

    #[test]
    fn test_self_signed_cert_verification() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _) = generate_keypair(&mut rng);

        let subject = vec![0x31, 0x00];
        let validity = generate_validity(b"250101000000Z", b"300101000000Z");
        let serial = vec![0x01];

        let cert = generate_self_signed_cert(
            &priv_key, &subject, &validity, &serial, DEFAULT_ID, &mut rng,
        )
        .expect("Certificate generation should succeed");

        verify_self_signed_cert(&cert, DEFAULT_ID)
            .expect("Self-signed verification should succeed");
    }

    // -- 密钥编解码测试 ------------------------------------------------------

    #[test]
    fn test_private_key_sec1_der_roundtrip() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _) = generate_keypair(&mut rng);

        let der = priv_key.to_sec1_der();
        let recovered = PrivateKey::from_sec1_der(&der).expect("Parse should succeed");

        assert_eq!(priv_key.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn test_private_key_pkcs8_der_roundtrip() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _) = generate_keypair(&mut rng);

        let der = priv_key.to_pkcs8_der();
        let recovered = PrivateKey::from_pkcs8_der(&der).expect("Parse should succeed");

        assert_eq!(priv_key.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn test_public_key_spki_der_roundtrip() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (_, pub_key) = generate_keypair(&mut rng);

        let der = der::public_key_to_spki_der(&pub_key);
        let recovered = der::public_key_from_spki_der(&der).expect("Parse should succeed");

        assert_eq!(pub_key, recovered);
    }

    // -- 公钥压缩测试 --------------------------------------------------------

    #[test]
    fn test_public_key_compression() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (_, pub_key) = generate_keypair(&mut rng);

        let compressed = public_key_to_compressed(&pub_key).expect("Compression should succeed");
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    }

    #[test]
    fn test_public_key_decompression() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (_, pub_key) = generate_keypair(&mut rng);

        let compressed = public_key_to_compressed(&pub_key).expect("Compression should succeed");
        let decompressed =
            public_key_from_compressed(&compressed).expect("Decompression should succeed");

        assert_eq!(pub_key, decompressed);
    }

    #[test]
    fn test_public_key_compression_decompression_roundtrip() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (_, pub_key) = generate_keypair(&mut rng);

        let compressed = public_key_to_compressed(&pub_key).expect("Compression should succeed");
        let decompressed =
            public_key_from_compressed(&compressed).expect("Decompression should succeed");

        assert_eq!(pub_key, decompressed);
    }

    // -- 公钥 PEM 编解码测试 -------------------------------------------------

    #[test]
    fn test_public_key_spki_pem_roundtrip() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (_, pub_key) = generate_keypair(&mut rng);

        // 编码为 PEM
        let pem = public_key_to_spki_pem(&pub_key).expect("PEM encoding should succeed");
        assert!(pem.starts_with(b"-----BEGIN PUBLIC KEY-----"));
        assert!(pem.ends_with(b"-----END PUBLIC KEY-----\n"));

        // 从 PEM 解析
        let recovered = public_key_from_spki_pem(&pem).expect("PEM parsing should succeed");
        assert_eq!(pub_key, recovered);
    }

    // -- 公钥指纹测试 --------------------------------------------------------

    #[test]
    fn test_public_key_fingerprint() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (_, pub_key) = generate_keypair(&mut rng);

        let fingerprint = public_key_fingerprint(&pub_key);
        assert_eq!(fingerprint.len(), 32); // SM3 输出为 32 字节

        // 相同公钥应该产生相同指纹
        let fingerprint2 = public_key_fingerprint(&pub_key);
        assert_eq!(fingerprint, fingerprint2);

        // 不同公钥应该产生不同指纹（概率极高）
        let (_, pub_key2) = generate_keypair(&mut rng);
        let fingerprint3 = public_key_fingerprint(&pub_key2);
        assert_ne!(fingerprint, fingerprint3);
    }

    // -- 证书 PEM 编解码测试 -------------------------------------------------

    #[test]
    fn test_certificate_pem_roundtrip() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _pub_key) = generate_keypair(&mut rng);

        let subject = vec![0x31, 0x00];
        let validity = generate_validity(b"250101000000Z", b"300101000000Z");
        let serial = vec![0x01];

        let cert = generate_self_signed_cert(
            &priv_key, &subject, &validity, &serial, DEFAULT_ID, &mut rng,
        )
        .expect("Certificate generation should succeed");

        // 编码为 PEM
        let pem = generate_gm_certificate_pem(&cert).expect("PEM encoding should succeed");
        assert!(pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with(b"-----END CERTIFICATE-----\n"));

        // 从 PEM 解析
        let recovered = parse_gm_certificate_pem(&pem).expect("PEM parsing should succeed");
        assert_eq!(cert.version, recovered.version);
        assert_eq!(cert.serial_number, recovered.serial_number);
        assert_eq!(cert.issuer, recovered.issuer);
        assert_eq!(cert.subject, recovered.subject);
    }
}
