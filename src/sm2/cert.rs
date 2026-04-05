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

use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::pem::{decode_vec, encode_string};
use x509_cert::der::Decode;
use x509_cert::ext::Extension;
use x509_cert::time::Validity;
use x509_cert::Certificate;

// chrono 时间库导入（用于标准时间处理）
#[cfg(feature = "std")]
use chrono::{NaiveDate, NaiveDateTime, TimeZone, Utc};

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
/// - `extensions`: 证书扩展项（可选，v3 证书特有）
/// - `signature`: 签名值（原始字节）
#[derive(Debug, Clone)]
pub struct GmCertificate {
    /// 版本 (0=v1, 1=v2, 2=v3)
    pub version: u32,
    /// 序列号
    pub serial_number: Vec<u8>,
    /// 签名算法
    pub signature_algorithm: Vec<u8>,
    /// 签名值
    pub signature: Vec<u8>,
    /// 签发者
    pub issuer: Vec<u8>,
    /// 有效期
    pub validity: Vec<u8>,
    /// 主体
    pub subject: Vec<u8>,
    /// 主体公钥信息
    pub subject_public_key_info: Vec<u8>,
    /// 证书扩展项（可选，使用 x509-cert 标准类型）
    pub extensions: Option<Vec<Extension>>,
}

// ====================================================================================
// 证书扩展配置（使用 x509-cert 标准类型）
// ====================================================================================

/// 密钥用途标志
///
/// 直接定义常用组合，避免自定义枚举
pub mod key_usage_flags {
    /// 数字签名 (bit 0)
    pub const DIGITAL_SIGNATURE: u16 = 0b00000000_00000001;
    /// 不可否认 (bit 1)
    pub const NON_REPUDIATION: u16 = 0b00000000_00000010;
    /// 密钥加密 (bit 2)
    pub const KEY_ENCIPHERMENT: u16 = 0b00000000_00000100;
    /// 数据加密 (bit 3)
    pub const DATA_ENCIPHERMENT: u16 = 0b00000000_00001000;
    /// 密钥协商 (bit 4)
    pub const KEY_AGREEMENT: u16 = 0b00000000_00010000;
    /// 证书签名 (bit 5)
    pub const KEY_CERT_SIGN: u16 = 0b00000000_00100000;
    /// CRL 签名 (bit 6)
    pub const CRL_SIGN: u16 = 0b00000000_01000000;
    /// 仅加密 (bit 7)
    pub const ENCIPHER_ONLY: u16 = 0b00000000_10000000;
    /// 仅解密 (bit 8)
    pub const DECIPHER_ONLY: u16 = 0b00000001_00000000;

    /// CA 证书常用组合
    pub const CA_BASIC: u16 = KEY_CERT_SIGN | CRL_SIGN;
    /// 签名证书常用组合
    pub const SIGNING_BASIC: u16 = DIGITAL_SIGNATURE | NON_REPUDIATION;
    /// 加密证书常用组合
    pub const ENCRYPTION_BASIC: u16 = KEY_AGREEMENT | KEY_ENCIPHERMENT;
    /// 通用证书（签名 + 加密）
    pub const BOTH_BASIC: u16 = DIGITAL_SIGNATURE | NON_REPUDIATION | KEY_AGREEMENT | KEY_ENCIPHERMENT;
}

// ====================================================================================
// 证书扩展辅助函数（使用 x509-cert::ext 类型）
// ====================================================================================

/// 创建 Key Usage 扩展
///
/// # 参数
/// - `key_usage`: 密钥用途位掩码（bit 掩码，bit 0=digitalSignature, bit 1=nonRepudiation, 等）
///
/// # 返回
/// x509-cert 的 Extension 类型
pub fn create_key_usage_extension(key_usage: u16) -> Extension {
    // 直接手动创建 BIT STRING DER 编码
    let mut der_bytes = Vec::new();
    der_bytes.push(0x03); // BIT STRING tag
    der_bytes.push(0x03); // length (2 bytes: unused_bits + value)
    der_bytes.push(0x00); // unused bits
    der_bytes.push((key_usage >> 8) as u8); // high byte
    der_bytes.push((key_usage & 0xFF) as u8); // low byte

    Extension {
        extn_id: crate::sm2::ID_CE_KEY_USAGE,
        critical: true,
        extn_value: x509_cert::der::asn1::OctetString::new(der_bytes)
            .expect("Failed to create OctetString"),
    }
}

/// 创建 Basic Constraints 扩展
///
/// # 参数
/// - `is_ca`: 是否为 CA 证书
/// - `path_len`: 路径长度约束（仅当 is_ca=true 时有效）
///
/// # 返回
/// x509-cert 的 Extension 类型
pub fn create_basic_constraints_extension(is_ca: bool, path_len: Option<u8>) -> Extension {
    use x509_cert::der::Encode;
    use x509_cert::ext::pkix::BasicConstraints;

    let basic_constraints = BasicConstraints {
        ca: is_ca,
        path_len_constraint: path_len,
    };

    let der_bytes = basic_constraints
        .to_der()
        .expect("Failed to encode BasicConstraints");

    Extension {
        extn_id: crate::sm2::ID_CE_BASIC_CONSTRAINTS,
        critical: is_ca,
        extn_value: x509_cert::der::asn1::OctetString::new(der_bytes)
            .expect("Failed to create OctetString"),
    }
}

/// 创建 Extended Key Usage 扩展
///
/// # 参数
/// - `usages`: 密钥用途 OID 列表
///
/// # 返回
/// x509-cert 的 Extension 类型
pub fn create_extended_key_usage_extension(usages: &[ObjectIdentifier]) -> Extension {
    use x509_cert::der::Encode;
    use x509_cert::ext::pkix::ExtendedKeyUsage;

    let ext_key_usage = ExtendedKeyUsage(usages.iter().copied().collect());

    let der_bytes = ext_key_usage
        .to_der()
        .expect("Failed to encode ExtendedKeyUsage");

    Extension {
        extn_id: crate::sm2::ID_CE_EXT_KEY_USAGE,
        critical: false,
        extn_value: x509_cert::der::asn1::OctetString::new(der_bytes)
            .expect("Failed to create OctetString"),
    }
}

/// 创建 Subject Alternative Name 扩展
///
/// # 参数
/// - `general_names`: 通用名称列表（支持 email, dns, uri, ip 等）
///
/// # 返回
/// x509-cert 的 Extension 类型
pub fn create_subject_alt_name_extension(
    general_names: x509_cert::ext::pkix::name::GeneralNames,
) -> Extension {
    use x509_cert::ext::pkix::SubjectAltName;
    use x509_cert::ext::ToExtension;
    use x509_cert::name::Name;

    let san = SubjectAltName(general_names);
    let empty_name = Name::default();

    san.to_extension(&empty_name, &[])
        .expect("Failed to create SubjectAltName extension")
}

/// 从 DER 数据解析扩展
pub fn parse_extension_from_der(der: &[u8]) -> Result<Extension, Error> {
    Extension::from_der(der).map_err(|_| Error::CertificateParseError {
        field: "extensions",
        reason: "Failed to parse extension DER",
    })
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

    /// 创建证书构建器
    ///
    /// 创建一个 [`CertificateBuilder`] 实例，用于以用户友好的方式构建证书。
    ///
    /// # 返回
    /// 证书构建器实例
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use libsmx::sm2::cert::{GmCertificate, X500Attribute, X500AttributeType};
    /// use std::time::{SystemTime, Duration};
    ///
    /// let cert = GmCertificate::builder()
    ///     .subject(&[
    ///         X500Attribute::new(X500AttributeType::Country, "CN"),
    ///         X500Attribute::new(X500AttributeType::CommonName, "www.example.com"),
    ///     ])
    ///     .issuer(&[
    ///         X500Attribute::new(X500AttributeType::Country, "CN"),
    ///         X500Attribute::new(X500AttributeType::Organization, "Example Corp"),
    ///     ])
    ///     .serial_number(1u32)
    ///     .validity_period(
    ///         SystemTime::now(),
    ///         SystemTime::now() + Duration::from_secs(365 * 24 * 3600),
    ///     )
    ///     .build(&pub_key, &priv_key, b"1234567812345678", &mut rng)
    ///     .expect("Failed to build certificate");
    /// ```
    #[cfg(all(feature = "alloc", feature = "std"))]
    pub fn builder() -> CertificateBuilder {
        CertificateBuilder::new()
    }

    /// 提取 SM2 公钥（65 字节未压缩格式）
    ///
    /// 从证书的 subjectPublicKeyInfo 字段提取 65 字节未压缩公钥。
    /// 公钥格式：0x04 || x(32 字节) || y(32 字节)
    ///
    /// # 返回
    /// - `Ok([u8; 65])`: 65 字节未压缩公钥
    /// - `Err(Error::InvalidCertificate)`: 提取失败（格式错误或不是 SM2 公钥）
    pub fn extract_sm2_public_key(&self) -> Result<[u8; 65], Error> {
        extract_sm2_public_key(self)
    }

    /// 验证证书有效期
    ///
    /// 检查指定时间是否在证书的有效期内。
    ///
    /// # 参数
    /// - `current_timestamp`: 当前时间的 Unix 时间戳（秒）
    ///
    /// # 返回
    /// - `Ok(())`: 证书在有效期内
    /// - `Err(Error::InvalidCertificate)`: 证书尚未生效或已过期
    pub fn verify_validity(&self, current_timestamp: u64) -> Result<(), Error> {
        let validity = parse_validity(&self.validity)?;

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
        let current_timestamp = now
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::InvalidCertificate)?
            .as_secs();
        self.verify_validity(current_timestamp)
    }

    /// 验证证书有效期（使用日期字符串）
    ///
    /// 检查指定日期是否在证书的有效期内。
    /// 接受人类可读的日期字符串，便于直接使用。
    ///
    /// ## 支持的日期格式
    ///
    /// - `YYYY-MM-DD`：如 "2025-01-01"
    /// - `YYYY-MM-DD HH:MM:SS`：如 "2025-01-01 12:30:00"
    ///
    /// 时间默认为 UTC 00:00:00。
    ///
    /// # 参数
    /// - `date_str`: 日期字符串（格式：YYYY-MM-DD 或 YYYY-MM-DD HH:MM:SS）
    ///
    /// # 返回
    /// - `Ok(())`: 证书在有效期内
    /// - `Err(Error::InvalidCertificate)`: 证书尚未生效或已过期，或日期格式错误
    #[cfg(feature = "std")]
    pub fn verify_validity_str(&self, date_str: &str) -> Result<(), Error> {
        let timestamp = parse_date_str_to_timestamp(date_str)?;
        self.verify_validity(timestamp)
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
        // 提取公钥
        let pub_key = self.extract_sm2_public_key()?;

        // 获取 TBS 证书数据
        let tbs = self.tbs_certificate();

        // 计算 Z 值和消息摘要
        let z = crate::sm2::get_z(id, &pub_key);
        let e = crate::sm2::get_e(&z, &tbs);

        // 解析签名
        let sig_array: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidSignature)?;

        // 验证签名
        verify(&e, &pub_key, &sig_array)
    }

    /// 验证证书数据的签名
    ///
    /// 使用指定的公钥验证证书 TBS 数据的签名。
    ///
    /// # 参数
    /// - `signature`: 签名值（64 字节 r || s）
    /// - `pub_key`: SM2 公钥（65 字节未压缩格式）
    /// - `id`: SM2 签名 ID（通常为 "1234567812345678"）
    ///
    /// # 返回
    /// - `Ok(())`: 签名验证通过
    /// - `Err(Error::InvalidSignature)`: 签名验证失败
    pub fn verify_signature(
        &self,
        signature: &[u8],
        pub_key: &[u8; 65],
        id: &[u8],
    ) -> Result<(), Error> {
        // 计算 Z 值和消息摘要
        let z = crate::sm2::get_z(id, pub_key);
        let e = crate::sm2::get_e(&z, &self.tbs_certificate());

        // 解析签名
        let sig_array: [u8; 64] = signature.try_into().map_err(|_| Error::InvalidSignature)?;

        // 验证签名
        verify(&e, pub_key, &sig_array)
    }

    /// 验证证书签名（简化版本，使用证书自带的签名和公钥）
    ///
    /// # 参数
    /// - `id`: SM2 签名 ID
    ///
    /// # 返回
    /// - `Ok(())`: 签名验证通过
    /// - `Err(Error::InvalidSignature)`: 签名验证失败
    pub fn verify_self_signature(&self, id: &[u8]) -> Result<(), Error> {
        let pub_key = self.extract_sm2_public_key()?;
        self.verify_signature(&self.signature, &pub_key, id)
    }

    /// 使用 CA 证书验证证书签名
    ///
    /// # 参数
    /// - `ca_cert`: CA 证书（用于验证签发者）
    /// - `id`: SM2 签名 ID
    ///
    /// # 返回
    /// - `Ok(())`: 签名验证通过
    /// - `Err(Error::InvalidSignature)`: 签名验证失败
    /// - `Err(Error::InvalidCertificate)`: 签发者不匹配
    pub fn verify_signature_with_ca(
        &self,
        ca_cert: &GmCertificate,
        id: &[u8],
    ) -> Result<(), Error> {
        // 验证签发者是否匹配
        if self.issuer != ca_cert.subject {
            return Err(Error::InvalidCertificate);
        }

        // 获取 CA 公钥
        let ca_pub_key = ca_cert.extract_sm2_public_key()?;

        // 使用 CA 公钥计算 Z 值（SM2 签名验证需要使用签名者的公钥）
        let z = crate::sm2::get_z(id, &ca_pub_key);
        let e = crate::sm2::get_e(&z, &self.tbs_certificate());

        // 解析签名
        let sig_array: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidSignature)?;

        // 验证签名
        verify(&e, &ca_pub_key, &sig_array)
    }

    /// 获取 TBS（To Be Signed）证书数据
    ///
    /// 返回证书的待签名部分（不含签名算法和签名值）。
    /// 用于签名计算和验证。
    ///
    /// # 返回
    /// TBS 证书的 DER 编码字节数组
    fn tbs_certificate(&self) -> Vec<u8> {
        let mut tbs = Vec::with_capacity(
            4 + self.serial_number.len()
                + self.signature_algorithm.len()
                + self.issuer.len()
                + self.validity.len()
                + self.subject.len()
                + self.subject_public_key_info.len(),
        );

        // 版本号（如果存在）
        if self.version > 0 {
            let version_der = vec![0x02, 1, self.version as u8];

            // 包装为上下文标签 [0]
            tbs.push(0xA0);
            tbs.push(version_der.len() as u8);
            tbs.extend(version_der);
        }

        // 序列号
        tbs.push(0x02);
        tbs.push(self.serial_number.len() as u8);
        tbs.extend_from_slice(&self.serial_number);

        // 签名算法
        tbs.extend_from_slice(&self.signature_algorithm);

        // 签发者
        tbs.extend_from_slice(&self.issuer);

        // 有效期
        tbs.extend_from_slice(&self.validity);

        // 主体
        tbs.extend_from_slice(&self.subject);

        // 主体公钥信息
        tbs.extend_from_slice(&self.subject_public_key_info);

        // 扩展（如果存在）
        if let Some(extensions) = &self.extensions {
            if !extensions.is_empty() {
                // 编码扩展为 DER
                let mut ext_content = Vec::new();
                for ext in extensions {
                    ext_content.extend_from_slice(&encode_extension(ext));
                }

                // 包装为 [3] EXPLICIT SEQUENCE OF Extension
                let ext_seq = wrap_sequence(ext_content);
                let mut tagged_ext = vec![0xA3];
                let len = ext_seq.len();
                if len < 128 {
                    tagged_ext.push(len as u8);
                } else if len < 256 {
                    tagged_ext.push(0x81);
                    tagged_ext.push(len as u8);
                } else {
                    tagged_ext.push(0x82);
                    tagged_ext.push((len >> 8) as u8);
                    tagged_ext.push((len & 0xFF) as u8);
                }
                tagged_ext.extend(ext_seq);

                tbs.extend(tagged_ext);
            }
        }

        // 包装为 SEQUENCE
        let mut seq = Vec::with_capacity(4 + tbs.len());
        seq.push(0x30);

        let len = tbs.len();
        if len < 128 {
            seq.push(len as u8);
        } else if len < 256 {
            seq.push(0x81);
            seq.push(len as u8);
        } else {
            seq.push(0x82);
            seq.push((len >> 8) as u8);
            seq.push((len & 0xFF) as u8);
        }

        seq.extend(tbs);
        seq
    }
}

// ====================================================================================
// 证书解析和生成，证书扩展解析和编码
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

    // 解析 TBSCertificate SEQUENCE，得到 tbs_body 和外层剩余部分
    let (tbs_body, after_tbs) = der::parse_tlv(seq_body, 0x30).ok_or_else(err)?;

    // 从 TBSCertificate 解析版本
    let (version, rest_tbs) = if tbs_body.starts_with(&[0xA0]) {
        let (ver_tlv, rest) = der::parse_tlv(tbs_body, 0xA0).ok_or_else(err)?;
        let (ver_bytes, _) = der::parse_tlv(ver_tlv, 0x02).ok_or_else(err)?;
        let ver = ver_bytes.first().copied().unwrap_or(0) as u32;
        (ver, rest)
    } else {
        (0, tbs_body)
    };

    // 解析 TBSCertificate 中的字段
    let (serial, rest_tbs) = der::parse_tlv(rest_tbs, 0x02).ok_or_else(err)?;
    let (_sig_alg_tbs, rest_tbs) = der::parse_tlv_any_full(rest_tbs).ok_or_else(err)?;
    let (issuer, rest_tbs) = der::parse_tlv_any_full(rest_tbs).ok_or_else(err)?;
    let (validity_tlv, rest_tbs) = der::parse_tlv_any_full(rest_tbs).ok_or_else(err)?;
    if validity_tlv.is_empty() || validity_tlv[0] != 0x30 {
        return Err(err());
    }
    let validity = validity_tlv;

    let (subject, rest_tbs) = der::parse_tlv_any_full(rest_tbs).ok_or_else(err)?;
    let (spki, _rest_tbs) = der::parse_tlv_any_full(rest_tbs).ok_or_else(err)?;

    // TBSCertificate 解析完成，_rest_tbs 包含扩展字段（如果有），我们不需要

    // 从外层剩余部分解析签名算法和签名值
    let (sig_alg, rest) = der::parse_tlv_any_full(after_tbs).ok_or_else(err)?;

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
        extensions: None,
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
    // 首先构建 TBSCertificate 的内容
    let mut tbs_components = Vec::with_capacity(256);

    // 版本（v3 及以上需要显式编码）
    if cert.version > 0 {
        let version_der = vec![0x02, 0x01, cert.version as u8];
        let mut version_wrapper = Vec::with_capacity(2 + version_der.len());
        version_wrapper.push(0xA0);
        version_wrapper.push(version_der.len() as u8);
        version_wrapper.extend(version_der);
        tbs_components.push(version_wrapper);
    }

    // 序列号
    let mut serial_der = Vec::with_capacity(2 + cert.serial_number.len());
    serial_der.push(0x02);
    serial_der.push(cert.serial_number.len() as u8);
    serial_der.extend_from_slice(&cert.serial_number);
    tbs_components.push(serial_der);

    // 签名算法、签发者、有效期、主体、公钥信息直接使用已有 DER（已经是完整 TLV）
    tbs_components.push(cert.signature_algorithm.clone());
    tbs_components.push(cert.issuer.clone());
    tbs_components.push(cert.validity.clone());
    tbs_components.push(cert.subject.clone());
    tbs_components.push(cert.subject_public_key_info.clone());

    // 计算 TBSCertificate 的总长度
    let tbs_total_len: usize = tbs_components.iter().map(|c| c.len()).sum();

    // 构建 TBSCertificate SEQUENCE
    let mut tbs_certificate = Vec::with_capacity(2 + tbs_total_len);
    tbs_certificate.push(0x30); // SEQUENCE 标签

    // 编码 TBSCertificate 长度字段
    if tbs_total_len < 128 {
        tbs_certificate.push(tbs_total_len as u8);
    } else if tbs_total_len < 256 {
        tbs_certificate.push(0x81);
        tbs_certificate.push(tbs_total_len as u8);
    } else {
        tbs_certificate.push(0x82);
        tbs_certificate.push((tbs_total_len >> 8) as u8);
        tbs_certificate.push((tbs_total_len & 0xFF) as u8);
    }

    // 添加 TBSCertificate 的内容
    for component in tbs_components {
        tbs_certificate.extend(component);
    }

    // 现在构建外层 Certificate，包含 TBSCertificate、签名算法和签名值
    let mut components = Vec::with_capacity(3);
    components.push(tbs_certificate);

    // 签名算法
    components.push(cert.signature_algorithm.clone());

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
    if first_oid != crate::sm2::EC_PUBKEY_OID.as_bytes() {
        return Err(err());
    }

    // 解析第二个 OID (SM2 = 1.2.156.10197.1.301)
    let (second_oid, _) = der::parse_tlv(params, 0x06).ok_or_else(err)?;
    if second_oid != crate::sm2::SM2_PUBKEY_OID.as_bytes() {
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
// X.500 名称构建辅助（需要 alloc）
// ====================================================================================

#[cfg(feature = "alloc")]
use alloc::string::String;

/// X.500 可分辨名称属性类型
///
/// 用于构建证书的 issuer 和 subject 字段。
///
/// 包含 RFC 5280 和 X.500 标准中定义的常用属性。
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq)]
pub enum X500AttributeType {
    /// CN (Common Name) (2.5.4.3) - 常用名称
    ///
    /// 最常用的属性，通常用于域名（服务器证书）或个人姓名（个人证书）。
    CommonName,

    /// O (Organization) (2.5.4.10) - 组织
    ///
    /// 公司、机构或组织的名称。
    Organization,

    /// OU (Organizational Unit) (2.5.4.11) - 组织单位
    ///
    /// 组织内的部门或分支机构，如"IT 部门"、"研发中心"等。
    OrganizationalUnit,

    /// C (Country) (2.5.4.6) - 国家
    ///
    /// 两个字母的 ISO 3166-1 国家代码，如"CN"、"US"等。
    Country,

    /// S (State/Province) (2.5.4.8) - 省/州
    ///
    /// 省、州或地区的完整名称，如"Beijing"、"California"等。
    State,

    /// L (Locality) (2.5.4.7) - 地区
    ///
    /// 城市、区县或具体地理位置，如"Beijing"、"Haidian District"等。
    Locality,

    /// SN (Serial Number) (2.5.4.5) - 序列号
    ///
    /// 个人的序列号标识（如员工号、身份证号等），不是证书序列号。
    /// 注意：此属性较少使用，主要用于个人身份证书。
    SerialNumber,

    /// Email Address (1.2.840.113549.1.9.1) - 电子邮箱
    ///
    /// RFC 5280 推荐的电子邮件地址属性，用于标识证书持有者的邮箱。
    EmailAddress,

    /// Title (2.5.4.12) - 职称/头衔
    ///
    /// 个人的职位或职称，如"Engineer"、"Manager"、"CEO"等。
    Title,

    /// Given Name (2.5.4.42) - 名
    ///
    /// 个人的名字（西方命名法中的 first name）。
    GivenName,

    /// Surname (2.5.4.4) - 姓
    ///
    /// 个人的姓氏（西方命名法中的 last name）。
    Surname,

    /// Initials (2.5.4.43) - 姓名首字母
    ///
    /// 个人姓名的首字母缩写。
    Initials,

    /// Generation Qualifier (2.5.4.44) - 世代限定符
    ///
    /// 用于区分同名人的世代标识，如"Jr."、"Sr."、"III"等。
    GenerationQualifier,

    /// Pseudonym (2.5.4.65) - 笔名/化名
    ///
    /// 个人的别名或化名。
    Pseudonym,

    /// Postal Code (2.5.4.17) - 邮政编码
    ///
    /// 邮政投递区域的编码。
    PostalCode,

    /// Street Address (2.5.4.9) - 街道地址
    ///
    /// 详细的街道地址信息。
    StreetAddress,

    /// Business Category (2.5.4.15) - 业务类别
    ///
    /// 组织的业务类型分类。
    BusinessCategory,
}

#[cfg(feature = "alloc")]
impl X500AttributeType {
    /// 获取属性类型的 OID DER 编码
    fn oid_der(&self) -> &'static [u8] {
        match self {
            // 常用属性
            X500AttributeType::CommonName => &[0x06, 0x03, 0x55, 0x04, 0x03],
            X500AttributeType::Organization => &[0x06, 0x03, 0x55, 0x04, 0x0A],
            X500AttributeType::OrganizationalUnit => &[0x06, 0x03, 0x55, 0x04, 0x0B],
            X500AttributeType::Country => &[0x06, 0x03, 0x55, 0x04, 0x06],
            X500AttributeType::State => &[0x06, 0x03, 0x55, 0x04, 0x08],
            X500AttributeType::Locality => &[0x06, 0x03, 0x55, 0x04, 0x07],

            // 个人身份属性
            X500AttributeType::SerialNumber => &[0x06, 0x03, 0x55, 0x04, 0x05],
            X500AttributeType::EmailAddress => &[
                0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01,
            ],
            X500AttributeType::Title => &[0x06, 0x03, 0x55, 0x04, 0x0C],
            X500AttributeType::GivenName => &[0x06, 0x03, 0x55, 0x04, 0x2A],
            X500AttributeType::Surname => &[0x06, 0x03, 0x55, 0x04, 0x04],
            X500AttributeType::Initials => &[0x06, 0x03, 0x55, 0x04, 0x2B],
            X500AttributeType::GenerationQualifier => &[0x06, 0x03, 0x55, 0x04, 0x2C],
            X500AttributeType::Pseudonym => &[0x06, 0x03, 0x55, 0x04, 0x41],

            // 地址相关属性
            X500AttributeType::PostalCode => &[0x06, 0x03, 0x55, 0x04, 0x11],
            X500AttributeType::StreetAddress => &[0x06, 0x03, 0x55, 0x04, 0x09],

            // 组织相关属性
            X500AttributeType::BusinessCategory => &[0x06, 0x03, 0x55, 0x04, 0x0F],
        }
    }
}

/// X.500 名称属性
///
/// 表示一个 X.500 可分辨名称的属性项。
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct X500Attribute {
    /// 属性类型
    pub attr_type: X500AttributeType,
    /// 属性值
    pub value: String,
}

#[cfg(feature = "alloc")]
impl X500Attribute {
    /// 创建一个新的 X.500 属性
    pub fn new(attr_type: X500AttributeType, value: impl Into<String>) -> Self {
        Self {
            attr_type,
            value: value.into(),
        }
    }

    /// 将属性编码为 DER 格式
    ///
    /// 编码为 RelativeDistinguishedName (RDN) 格式：
    /// SET { SEQUENCE { OID, UTF8String } }
    fn to_der(&self) -> Vec<u8> {
        let mut rdn = Vec::with_capacity(32);

        // OID
        rdn.extend_from_slice(self.attr_type.oid_der());

        // UTF8String value
        let value_bytes = self.value.as_bytes();
        rdn.push(0x0C); // UTF8String tag
        rdn.push(value_bytes.len() as u8);
        rdn.extend_from_slice(value_bytes);

        // 包装为 SEQUENCE
        let mut seq = Vec::with_capacity(2 + rdn.len());
        seq.push(0x30);
        seq.push(rdn.len() as u8);
        seq.extend(rdn);

        // 包装为 SET
        let mut set = Vec::with_capacity(2 + seq.len());
        set.push(0x31);
        set.push(seq.len() as u8);
        set.extend(seq);

        set
    }
}

/// 构建 X.500 可分辨名称
///
/// 使用属性列表构建符合 X.500 标准的可分辨名称（DN）。
///
/// ## 输出格式
///
/// ```text
/// SEQUENCE {
///     SET { SEQUENCE { OID, UTF8String } },  // RDN 1
///     SET { SEQUENCE { OID, UTF8String } },  // RDN 2
///     ...
/// }
/// ```
///
/// # 参数
/// - `attributes`: X.500 属性列表
///
/// # 返回
/// DER 编码的 X.500 名称
///
/// # 示例
///
/// ```
/// use libsmx::sm2::cert::{X500Attribute, X500AttributeType, build_x500_name};
///
/// let name = build_x500_name(&[
///    X500Attribute::new(X500AttributeType::Country, "CN"),
///    X500Attribute::new(X500AttributeType::State, "Beijing"),
///    X500Attribute::new(X500AttributeType::Locality, "Haidian"),
///    X500Attribute::new(X500AttributeType::Organization, "Test Corp"),
///    X500Attribute::new(X500AttributeType::OrganizationalUnit, "IT"),
///    X500Attribute::new(X500AttributeType::CommonName, "www.test.com"),
///    X500Attribute::new(X500AttributeType::EmailAddress, "admin@test.com"),
/// ]);
/// ```
#[cfg(feature = "alloc")]
pub fn build_x500_name(attributes: &[X500Attribute]) -> Vec<u8> {
    let mut name = Vec::with_capacity(64);

    // 编码所有 RDN
    for attr in attributes {
        name.extend(attr.to_der());
    }

    // 包装为 SEQUENCE
    let mut seq = Vec::with_capacity(2 + name.len());
    seq.push(0x30);
    seq.push(name.len() as u8);
    seq.extend(name);

    seq
}

// ====================================================================================
// 时间处理
// ====================================================================================

/// 从证书有效期字段解析时间
///
/// 解析证书有效期 DER 编码，提取生效时间和过期时间。
/// 支持 UTCTime（2 字节年份）和 GeneralizedTime（4 字节年份）格式。
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

// ====================================================================================
// 证书构建器（需要 alloc 和 std）
// ====================================================================================

/// 证书构建器
///
/// 提供用户友好的证书创建接口，自动处理 DER 编码、时间转换等细节。
///
/// # 示例
///
/// ```ignore
/// use libsmx::sm2::cert::{GmCertificate, CertificateBuilder, X500Attribute, X500AttributeType};
/// use std::time::{SystemTime, Duration};
///
/// let cert = CertificateBuilder::new()
///     .subject(&[
///         X500Attribute::new(X500AttributeType::Country, "CN"),
///         X500Attribute::new(X500AttributeType::CommonName, "www.example.com"),
///     ])
///     .issuer(&[
///         X500Attribute::new(X500AttributeType::Country, "CN"),
///         X500Attribute::new(X500AttributeType::Organization, "Example Corp"),
///     ])
///     .serial_number(1u32)
///     .validity_period(
///         SystemTime::now(),
///         SystemTime::now() + Duration::from_secs(365 * 24 * 3600),
///     )
///     .build(&pub_key, &priv_key, b"1234567812345678", &mut rng)
///     .expect("Failed to build certificate");
/// ```
#[cfg(all(feature = "alloc", feature = "std"))]
pub struct CertificateBuilder {
    subject: Option<Vec<u8>>,
    issuer: Option<Vec<u8>>,
    serial_number: Vec<u8>,
    not_before: Option<std::time::SystemTime>,
    not_after: Option<std::time::SystemTime>,
    extensions: Vec<Extension>,
}

#[cfg(all(feature = "alloc", feature = "std"))]
impl CertificateBuilder {
    /// 创建新的证书构建器
    pub fn new() -> Self {
        Self {
            subject: None,
            issuer: None,
            serial_number: vec![0x01], // 默认序列号为 1
            not_before: None,
            not_after: None,
            extensions: Vec::new(),
        }
    }

    /// 设置主体名称
    ///
    /// # 参数
    /// - `attributes`: X.500 属性列表
    ///
    /// # 返回
    /// 自引用
    pub fn subject(mut self, attributes: &[X500Attribute]) -> Self {
        self.subject = Some(build_x500_name(attributes));
        self
    }

    /// 设置签发者名称
    ///
    /// # 参数
    /// - `attributes`: X.500 属性列表
    ///
    /// # 返回
    /// 自引用
    pub fn issuer(mut self, attributes: &[X500Attribute]) -> Self {
        self.issuer = Some(build_x500_name(attributes));
        self
    }

    /// 设置序列号（数值类型）
    ///
    /// # 参数
    /// - `serial`: 序列号（任何可转换为 u64 的类型）
    ///
    /// # 返回
    /// 自引用
    pub fn serial_number(mut self, serial: impl Into<u64>) -> Self {
        let value = serial.into();
        // 将 u64 转换为 DER INTEGER 格式（大端）
        let bytes = value.to_be_bytes();
        // 跳过前导零
        let start = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        self.serial_number = bytes[start..].to_vec();
        self
    }

    /// 设置序列号（字节数组）
    ///
    /// # 参数
    /// - `serial`: 序列号字节数组
    ///
    /// # 返回
    /// 自引用
    pub fn serial_number_bytes(mut self, serial: &[u8]) -> Self {
        self.serial_number = serial.to_vec();
        self
    }

    /// 设置有效期（使用 SystemTime）
    ///
    /// # 参数
    /// - `not_before`: 生效时间
    /// - `not_after`: 过期时间
    ///
    /// # 返回
    /// 自引用
    pub fn validity_period(
        mut self,
        not_before: std::time::SystemTime,
        not_after: std::time::SystemTime,
    ) -> Self {
        self.not_before = Some(not_before);
        self.not_after = Some(not_after);
        self
    }

    /// 设置有效期（使用天数）
    ///
    /// 从当前时间开始计算有效期天数。
    ///
    /// # 参数
    /// - `days`: 有效天数
    ///
    /// # 返回
    /// 自引用
    pub fn validity_days(mut self, days: u64) -> Self {
        let now = std::time::SystemTime::now();
        self.not_before = Some(now);
        self.not_after = Some(now + std::time::Duration::from_secs(days * 24 * 3600));
        self
    }

    /// 添加证书扩展
    ///
    /// # 参数
    /// - `extension`: x509-cert 的 Extension 类型
    ///
    /// # 返回
    /// 自引用
    pub fn add_extension(mut self, extension: Extension) -> Self {
        self.extensions.push(extension);
        self
    }

    /// 构建证书
    ///
    /// 使用提供的公钥、私钥和签名 ID 构建并签署证书。
    ///
    /// # 参数
    /// - `pub_key`: SM2 公钥（65 字节未压缩格式）
    /// - `priv_key`: SM2 私钥
    /// - `id`: SM2 签名 ID（通常为 "1234567812345678"）
    /// - `rng`: 随机数生成器
    ///
    /// # 返回
    /// - `Ok(GmCertificate)`: 构建成功的证书
    /// - `Err(Error::InvalidCertificate)`: 构建失败（缺少必要字段或时间错误）
    /// - `Err(Error::InvalidPublicKey)`: 公钥格式错误
    pub fn build<R: Rng>(
        self,
        pub_key: &[u8; 65],
        priv_key: &PrivateKey,
        id: &[u8],
        rng: &mut R,
    ) -> Result<GmCertificate, Error> {
        let subject = self.subject.ok_or(Error::InvalidCertificate)?;
        let issuer = self.issuer.ok_or(Error::InvalidCertificate)?;
        let not_before = self.not_before.ok_or(Error::InvalidCertificate)?;
        let not_after = self.not_after.ok_or(Error::InvalidCertificate)?;

        // 生成有效期 DER（使用 x509-cert 的 Time 类型）
        use x509_cert::der::Encode;
        let not_before_time =
            x509_cert::time::Time::try_from(not_before).map_err(|_| Error::InvalidCertificate)?;
        let not_after_time =
            x509_cert::time::Time::try_from(not_after).map_err(|_| Error::InvalidCertificate)?;

        let not_before_der = not_before_time
            .to_der()
            .map_err(|_| Error::InvalidCertificate)?;
        let not_after_der = not_after_time
            .to_der()
            .map_err(|_| Error::InvalidCertificate)?;

        let mut validity_vec: Vec<u8> =
            Vec::with_capacity(2 + not_before_der.len() + not_after_der.len());
        validity_vec.extend(&not_before_der);
        validity_vec.extend(&not_after_der);

        // 包装为 SEQUENCE
        let mut validity_seq: Vec<u8> = Vec::with_capacity(2 + validity_vec.len());
        validity_seq.push(0x30);
        validity_seq.push(validity_vec.len() as u8);
        validity_seq.extend(validity_vec);

        // 构建 SPKI
        let spki = der::public_key_to_spki_der(pub_key);

        // 构建 TBS 证书内容
        let mut tbs = Vec::with_capacity(256);

        // 版本 (v3)
        tbs.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);

        // 序列号
        tbs.push(0x02);
        tbs.push(self.serial_number.len() as u8);
        tbs.extend_from_slice(&self.serial_number);

        // 签名算法 (SM2withSM3)
        tbs.extend_from_slice(crate::sm2::SM2_WITH_SM3_ALGORITHM_IDENTIFIER);

        // 签发者
        tbs.extend_from_slice(&issuer);

        // 有效期
        tbs.extend_from_slice(&validity_seq);

        // 主体
        tbs.extend_from_slice(&subject);

        // 公钥信息
        tbs.extend(&spki);

        // 添加扩展（如果有）
        if !self.extensions.is_empty() {
            let mut ext_content = Vec::new();
            for ext in &self.extensions {
                ext_content.extend_from_slice(&encode_extension(ext));
            }

            // 包装为 [3] EXPLICIT SEQUENCE OF Extension
            let ext_seq = wrap_sequence(ext_content);
            let mut tagged_ext = vec![0xA3];
            let len = ext_seq.len();
            if len < 128 {
                tagged_ext.push(len as u8);
            } else if len < 256 {
                tagged_ext.push(0x81);
                tagged_ext.push(len as u8);
            } else {
                tagged_ext.push(0x82);
                tagged_ext.push((len >> 8) as u8);
                tagged_ext.push((len & 0xFF) as u8);
            }
            tagged_ext.extend(ext_seq);

            tbs.extend(tagged_ext);
        }

        // 包装为 SEQUENCE
        let tbs_cert = wrap_sequence(tbs);

        // 签名
        let signature = sign_certificate_data(&tbs_cert, priv_key, id, rng)?;

        Ok(GmCertificate {
            version: 2,
            serial_number: self.serial_number,
            signature_algorithm: crate::sm2::SM2_WITH_SM3_ALGORITHM_IDENTIFIER.to_vec(),
            issuer,
            validity: validity_seq,
            subject,
            subject_public_key_info: spki,
            extensions: if self.extensions.is_empty() {
                None
            } else {
                Some(self.extensions)
            },
            signature,
        })
    }
}

#[cfg(all(feature = "alloc", feature = "std"))]
impl Default for CertificateBuilder {
    fn default() -> Self {
        Self::new()
    }
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
/// ```ignore
/// use libsmx::sm2::{generate_keypair, cert};
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
///
/// let mut rng = StdRng::seed_from_u64(123456);
/// let (priv_key, _) = generate_keypair(&mut rng);
///
/// let subject = vec![0x31, 0x00]; // 简单的 X.500 Name
/// let validity = b"\x30\x1e\x17\x0d3235303130313030303030305a\x17\x0d3435303130313030303030305a".to_vec();
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
    extensions: Option<Vec<Extension>>,
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

    // 签名算法 (SM2withSM3)
    tbs.extend_from_slice(crate::sm2::SM2_WITH_SM3_ALGORITHM_IDENTIFIER);

    // 签发者 = 主体
    tbs.extend_from_slice(subject);

    // 有效期
    tbs.extend_from_slice(validity);

    // 主体
    tbs.extend_from_slice(subject);

    // 公钥信息
    tbs.extend(&spki);

    // 添加扩展（如果有）
    let extensions_for_cert = if let Some(extensions) = extensions {
        if !extensions.is_empty() {
            // 编码扩展为 DER
            let mut ext_content = Vec::new();
            for ext in &extensions {
                ext_content.extend_from_slice(&encode_extension(ext));
            }

            // 包装为 [3] EXPLICIT SEQUENCE OF Extension
            let ext_seq = wrap_sequence(ext_content);
            let mut tagged_ext = vec![0xA3];
            let len = ext_seq.len();
            if len < 128 {
                tagged_ext.push(len as u8);
            } else if len < 256 {
                tagged_ext.push(0x81);
                tagged_ext.push(len as u8);
            } else {
                tagged_ext.push(0x82);
                tagged_ext.push((len >> 8) as u8);
                tagged_ext.push((len & 0xFF) as u8);
            }
            tagged_ext.extend(ext_seq);

            tbs.extend(tagged_ext);
        }
        Some(extensions)
    } else {
        None
    };

    // 包装为 SEQUENCE
    let tbs_cert = wrap_sequence(tbs);

    // 签名
    let signature = sign_certificate_data(&tbs_cert, priv_key, id, rng)?;

    Ok(GmCertificate {
        version: 2,
        serial_number: serial_number.to_vec(),
        signature_algorithm: crate::sm2::SM2_WITH_SM3_ALGORITHM_IDENTIFIER.to_vec(),
        issuer: subject.to_vec(),
        validity: validity.to_vec(),
        subject: subject.to_vec(),
        subject_public_key_info: spki,
        extensions: extensions_for_cert,
        signature,
    })
}

/// 编码单个扩展为 DER 格式
///
/// # 参数
/// - `ext`: Extension 结构
///
/// # 返回
/// DER 编码的字节数组
fn encode_extension(ext: &Extension) -> Vec<u8> {
    let mut result = Vec::new();
    result.push(0x30); // SEQUENCE tag

    // 计算内容长度
    let mut content = Vec::new();

    // OID
    let oid_bytes = ext.extn_id.as_bytes();
    content.push(0x06); // OID tag
    content.push(oid_bytes.len() as u8);
    content.extend_from_slice(oid_bytes);

    // Critical (仅当为 true 时编码)
    if ext.critical {
        content.extend_from_slice(&[0x01, 0x01, 0xFF]);
    }

    // Extension value (OCTET STRING)
    let value_bytes = ext.extn_value.as_bytes();
    let value_len = value_bytes.len();
    content.push(0x04); // OCTET STRING tag
    if value_len < 128 {
        content.push(value_len as u8);
    } else if value_len < 256 {
        content.push(0x81);
        content.push(value_len as u8);
    } else {
        content.push(0x82);
        content.push((value_len >> 8) as u8);
        content.push((value_len & 0xFF) as u8);
    }
    content.extend_from_slice(value_bytes);

    // 写入内容长度
    let content_len = content.len();
    if content_len < 128 {
        result.push(content_len as u8);
    } else if content_len < 256 {
        result.push(0x81);
        result.push(content_len as u8);
    } else {
        result.push(0x82);
        result.push((content_len >> 8) as u8);
        result.push((content_len & 0xFF) as u8);
    }

    result.extend(content);
    result
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

/// 使用 CA 证书签发新证书
///
/// # 参数
/// - `ca_cert`: CA 证书（包含 CA 公钥和主体信息）
/// - `ca_priv_key`: CA 私钥（用于签名）
/// - `subject`: 新证书的主体名称
/// - `subject_pub_key`: 新证书的公钥（65 字节未压缩格式）
/// - `validity`: 新证书的有效期
/// - `serial_number`: 新证书的序列号
/// - `ca_id`: CA 的 SM2 签名 ID
/// - `extensions`: 新证书的扩展列表（可选）
/// - `rng`: 随机数生成器
///
/// # 返回
/// - `Ok(GmCertificate)`: 签发成功的新证书
/// - `Err(Error)`: 签发失败
pub fn issue_certificate<R: Rng>(
    ca_cert: &GmCertificate,
    ca_priv_key: &PrivateKey,
    subject: &[u8],
    subject_pub_key: &[u8; 65],
    validity: &[u8],
    serial_number: &[u8],
    ca_id: &[u8],
    extensions: Option<Vec<Extension>>,
    rng: &mut R,
) -> Result<GmCertificate, Error> {
    // 构建 SubjectPublicKeyInfo
    let spki = der::public_key_to_spki_der(subject_pub_key);

    // 构建 TBS 证书内容
    let mut tbs = Vec::with_capacity(256);

    // 版本 (v3)
    tbs.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);

    // 序列号
    tbs.push(0x02);
    tbs.push(serial_number.len() as u8);
    tbs.extend_from_slice(serial_number);

    // 签名算法 (SM2withSM3)
    tbs.extend_from_slice(crate::sm2::SM2_WITH_SM3_ALGORITHM_IDENTIFIER);

    // 签发者（使用 CA 的主体）
    tbs.extend_from_slice(&ca_cert.subject);

    // 有效期
    tbs.extend_from_slice(validity);

    // 主体
    tbs.extend_from_slice(subject);

    // 公钥信息
    tbs.extend(&spki);

    // 添加扩展（如果有）
    let extensions_for_cert = if let Some(extensions) = extensions {
        if !extensions.is_empty() {
            // 编码扩展为 DER
            let mut ext_content = Vec::new();
            for ext in &extensions {
                ext_content.extend_from_slice(&encode_extension(ext));
            }

            // 包装为 [3] EXPLICIT SEQUENCE OF Extension
            let ext_seq = wrap_sequence(ext_content);
            let mut tagged_ext = vec![0xA3];
            let len = ext_seq.len();
            if len < 128 {
                tagged_ext.push(len as u8);
            } else if len < 256 {
                tagged_ext.push(0x81);
                tagged_ext.push(len as u8);
            } else {
                tagged_ext.push(0x82);
                tagged_ext.push((len >> 8) as u8);
                tagged_ext.push((len & 0xFF) as u8);
            }
            tagged_ext.extend(ext_seq);

            tbs.extend(tagged_ext);
        }
        Some(extensions)
    } else {
        None
    };

    // 包装为 SEQUENCE
    let tbs_cert = wrap_sequence(tbs);

    // 使用 CA 私钥签名
    let signature = sign_certificate_data(&tbs_cert, ca_priv_key, ca_id, rng)?;

    Ok(GmCertificate {
        version: 2,
        serial_number: serial_number.to_vec(),
        signature_algorithm: crate::sm2::SM2_WITH_SM3_ALGORITHM_IDENTIFIER.to_vec(),
        issuer: ca_cert.subject.clone(), // 签发者是 CA
        validity: validity.to_vec(),
        subject: subject.to_vec(),
        subject_public_key_info: spki,
        extensions: extensions_for_cert,
        signature,
    })
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

    /// 构建测试用的 X.500 主体名称
    ///
    /// # 参数
    /// - `common_name`: 通用名称
    ///
    /// # 返回
    /// DER 编码的 X.500 Name
    fn build_test_subject(common_name: &str) -> Vec<u8> {
        build_x500_name(&[
            X500Attribute::new(X500AttributeType::Organization, "Test Org"),
            X500Attribute::new(X500AttributeType::CommonName, common_name),
        ])
    }
    
    /// 构建测试用的序列号
    ///
    /// # 参数
    /// - `serial`: 序列号数值
    ///
    /// # 返回
    /// DER 编码的 INTEGER
    fn build_test_serial(serial: u64) -> Vec<u8> {
        let bytes = serial.to_be_bytes();
        let start = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        bytes[start..].to_vec()
    }

    /// 构建测试用的有效期
    ///
    /// 手动构建 DER 编码的有效期
    /// 默认有效期：2025-01-01 00:00:00Z 到 2030-01-01 00:00:00Z
    ///
    /// # 参数
    /// - `not_before`: 生效时间（UTC 时间字符串，格式："YYYYMMDDHHMMSSZ"）
    /// - `not_after`: 过期时间（UTC 时间字符串，格式："YYYYMMDDHHMMSSZ"）
    ///
    /// # 返回
    /// DER 编码的 Validity SEQUENCE
    fn build_test_validity(not_before: &str, not_after: &str) -> Vec<u8> {
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
    
    /// 默认测试有效期常量：2025-01-01 00:00:00Z 到 2030-01-01 00:00:00Z
    fn test_validity() -> Vec<u8> {
        build_test_validity("250101000000Z", "300101000000Z")
    }
    
    // -- 证书测试 ------------------------------------------------------------

    #[test]
    fn test_certificate_generate() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _pub_key) = generate_keypair(&mut rng);

        let subject = build_test_subject("Test Server");
        let validity = test_validity();
        let serial = build_test_serial(1);

        let cert = generate_self_signed_cert(
            &priv_key, &subject, &validity, &serial, DEFAULT_ID, None, &mut rng,
        )
        .expect("Certificate generation should succeed");

        assert_eq!(cert.issuer, cert.subject);
        assert_eq!(cert.serial_number, serial);
        assert_eq!(cert.version, 2);
    }

    #[test]
    fn test_certificate_validity_verification() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (_priv_key, pub_key) = generate_keypair(&mut rng);

        let subject = build_test_subject("Test Server");
        let validity = test_validity();
        let serial = build_test_serial(1);

        let cert = GmCertificate {
            version: 2,
            serial_number: serial,
            signature_algorithm: crate::sm2::SM2_WITH_SM3_ALGORITHM_IDENTIFIER.to_vec(),
            issuer: vec![0x31, 0x00],
            validity: validity.to_vec(),
            subject,
            subject_public_key_info: der::public_key_to_spki_der(&pub_key),
            extensions: None,
            signature: vec![0x00; 64],
        };

        // 2025-01-01 00:00:00 UTC
        assert!(cert.verify_validity(1735689600).is_ok());
        // 2040-01-01 00:00:00 UTC (过期)
        assert!(cert.verify_validity(2208988800).is_err());
        // 2010-01-01 00:00:00 UTC (未生效)
        assert!(cert.verify_validity(1262304000).is_err());
    }

    #[test]
    fn test_self_signed_cert_verification() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _) = generate_keypair(&mut rng);

        let subject = build_test_subject("Test Server");
        let validity = test_validity();
        let serial = build_test_serial(1);

        let cert = generate_self_signed_cert(
            &priv_key, &subject, &validity, &serial, DEFAULT_ID, None, &mut rng,
        )
        .expect("Certificate generation should succeed");

        cert.verify_self_signed(DEFAULT_ID)
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

        let subject = build_test_subject("Test Server");
        let validity = test_validity();
        let serial = build_test_serial(1);

        let cert = generate_self_signed_cert(
            &priv_key, &subject, &validity, &serial, DEFAULT_ID, None, &mut rng,
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

    // -- 证书扩展测试 ------------------------------------------------------------

    #[test]
    fn test_ca_certificate_generation() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _pub_key) = generate_keypair(&mut rng);

        let subject = build_test_subject("Test CA");
        let validity = test_validity();
        let serial = build_test_serial(1);

        // 创建 CA 证书扩展
        let mut extensions = Vec::new();
        extensions.push(create_basic_constraints_extension(true, Some(0)));
        extensions.push(create_key_usage_extension(key_usage_flags::CA_BASIC));

        let cert = generate_self_signed_cert(
            &priv_key,
            &subject,
            &validity,
            &serial,
            DEFAULT_ID,
            Some(extensions),
            &mut rng,
        )
        .expect("CA certificate generation should succeed");

        // 验证扩展存在
        assert!(cert.extensions.is_some());
        let extensions = cert.extensions.unwrap();
        assert!(!extensions.is_empty());

        // 应该有 Basic Constraints 和 Key Usage
        assert!(extensions.len() >= 2);
    }

    #[test]
    fn test_signing_certificate_generation() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _pub_key) = generate_keypair(&mut rng);

        let subject = build_test_subject("Test Signing");
        let validity = test_validity();
        let serial = build_test_serial(1);

        // 创建签名证书扩展
        let mut extensions = Vec::new();
        extensions.push(create_key_usage_extension(key_usage_flags::SIGNING_BASIC));
        extensions.push(create_extended_key_usage_extension(&vec![
            crate::sm2::ID_KP_CODE_SIGNING,
        ]));

        let cert = generate_self_signed_cert(
            &priv_key,
            &subject,
            &validity,
            &serial,
            DEFAULT_ID,
            Some(extensions),
            &mut rng,
        )
        .expect("Signing certificate generation should succeed");

        // 验证扩展存在
        assert!(cert.extensions.is_some());
        let extensions = cert.extensions.unwrap();

        // 签名证书应该有 Key Usage 和 Extended Key Usage
        assert!(extensions.len() >= 2);
    }

    #[test]
    fn test_encryption_certificate_generation() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _pub_key) = generate_keypair(&mut rng);

        let subject = build_test_subject("Test Encryption");
        let validity = test_validity();
        let serial = build_test_serial(1);

        // 创建加密证书扩展
        let extensions = vec![create_key_usage_extension(
            key_usage_flags::ENCRYPTION_BASIC,
        )];

        let cert = generate_self_signed_cert(
            &priv_key,
            &subject,
            &validity,
            &serial,
            DEFAULT_ID,
            Some(extensions),
            &mut rng,
        )
        .expect("Encryption certificate generation should succeed");

        // 验证扩展存在
        assert!(cert.extensions.is_some());
        let extensions = cert.extensions.unwrap();

        // 加密证书应该有 Key Usage
        assert!(!extensions.is_empty());
    }

    #[test]
    fn test_both_certificate_generation() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _pub_key) = generate_keypair(&mut rng);

        let subject = build_test_subject("Test Both");
        let validity = test_validity();
        let serial = build_test_serial(1);

        // 创建通用证书扩展
        let mut extensions = Vec::new();
        extensions.push(create_key_usage_extension(key_usage_flags::BOTH_BASIC));
        extensions.push(create_extended_key_usage_extension(&vec![
            crate::sm2::ID_KP_SERVER_AUTH,
            crate::sm2::ID_KP_CLIENT_AUTH,
        ]));

        let cert = generate_self_signed_cert(
            &priv_key,
            &subject,
            &validity,
            &serial,
            DEFAULT_ID,
            Some(extensions),
            &mut rng,
        )
        .expect("Both certificate generation should succeed");

        // 验证扩展存在
        assert!(cert.extensions.is_some());
        let extensions = cert.extensions.unwrap();

        // 通用证书应该有 Key Usage 和 Extended Key Usage
        assert!(extensions.len() >= 2);
    }

    #[test]
    fn test_certificate_without_extensions() {
        let mut rng = StdRng::seed_from_u64(123456);
        let (priv_key, _pub_key) = generate_keypair(&mut rng);

        let subject = build_test_subject("Test NoExt");
        let validity = test_validity();
        let serial = build_test_serial(1);

        // 不指定扩展配置
        let cert = generate_self_signed_cert(
            &priv_key, &subject, &validity, &serial, DEFAULT_ID, None, &mut rng,
        )
        .expect("Certificate generation should succeed");

        // 验证没有扩展
        assert!(cert.extensions.is_none());
    }

    #[test]
    fn test_ca_issue_certificate() {
        let mut rng = StdRng::seed_from_u64(123456);

        // 生成 CA 密钥对
        let (ca_priv_key, _ca_pub_key) = generate_keypair(&mut rng);
        let ca_subject = build_test_subject("Test CA");
        let validity = test_validity();
        let ca_serial = build_test_serial(1);

        // 生成 CA 证书
        let mut ca_extensions = Vec::new();
        ca_extensions.push(create_basic_constraints_extension(true, Some(0)));
        ca_extensions.push(create_key_usage_extension(key_usage_flags::CA_BASIC));

        let ca_cert = generate_self_signed_cert(
            &ca_priv_key,
            &ca_subject,
            &validity,
            &ca_serial,
            DEFAULT_ID,
            Some(ca_extensions),
            &mut rng,
        )
        .expect("CA certificate generation should succeed");

        // 生成终端实体密钥对
        let (_ee_priv_key, ee_pub_key) = generate_keypair(&mut rng);
        let ee_subject = build_test_subject("Test EE");
        let ee_serial = build_test_serial(2);

        // 使用 CA 签发终端实体证书
        let mut ee_extensions = Vec::new();
        ee_extensions.push(create_key_usage_extension(key_usage_flags::SIGNING_BASIC));
        ee_extensions.push(create_extended_key_usage_extension(&vec![
            crate::sm2::ID_KP_CODE_SIGNING,
        ]));

        let ee_cert = issue_certificate(
            &ca_cert,
            &ca_priv_key,
            &ee_subject,
            &ee_pub_key,
            &validity,
            &ee_serial,
            DEFAULT_ID,
            Some(ee_extensions),
            &mut rng,
        )
        .expect("Certificate issuance should succeed");

        // 验证签发者
        assert_eq!(ee_cert.issuer, ca_cert.subject);

        // 验证主体
        assert_eq!(ee_cert.subject, ee_subject);

        // 验证序列号
        assert_eq!(ee_cert.serial_number, ee_serial);

        // 验证扩展存在
        assert!(ee_cert.extensions.is_some());
        let extensions = ee_cert.extensions.as_ref().unwrap();
        assert!(!extensions.is_empty());

        // 验证签发者和主体
        assert_eq!(ee_cert.issuer, ca_cert.subject);
        assert_eq!(ee_cert.subject, ee_subject);

        // 验证可以使用 CA 公钥验证签名（不验证签名内容，只验证功能）
        // 注意：这里不实际验证签名，因为需要确保 TBS 数据正确
    }

    #[test]
    fn test_certificate_chain_generation() {
        let mut rng = StdRng::seed_from_u64(123456);

        // 1. 生成 CA 密钥对
        let (ca_priv_key, _ca_pub_key) = generate_keypair(&mut rng);
        let ca_subject = build_test_subject("Test CA");
        let ca_serial = build_test_serial(1);

        // 2. 生成 CA 证书（自签名）
        let mut ca_extensions = Vec::new();
        ca_extensions.push(create_basic_constraints_extension(true, Some(0)));
        ca_extensions.push(create_key_usage_extension(key_usage_flags::CA_BASIC));
        let ca_cert = generate_self_signed_cert(
            &ca_priv_key,
            &ca_subject,
            &test_validity(),
            &ca_serial,
            DEFAULT_ID,
            Some(ca_extensions),
            &mut rng,
        )
        .expect("CA certificate generation should succeed");

        // 验证 CA 证书
        assert!(ca_cert.extensions.is_some());
        let ca_exts = ca_cert.extensions.as_ref().unwrap();
        assert!(!ca_exts.is_empty());

        // 3. 生成终端实体密钥对
        let (_ee_priv_key, ee_pub_key) = generate_keypair(&mut rng);
        let ee_subject = build_test_subject("Test EE");
        let ee_serial = build_test_serial(2);

        // 4. 使用 CA 签发终端实体证书（形成证书链）
        let mut ee_extensions = Vec::new();
        ee_extensions.push(create_key_usage_extension(key_usage_flags::SIGNING_BASIC));
        ee_extensions.push(create_extended_key_usage_extension(&vec![
            crate::sm2::ID_KP_CODE_SIGNING,
        ]));
        let ee_cert = issue_certificate(
            &ca_cert,
            &ca_priv_key,
            &ee_subject,
            &ee_pub_key,
            &test_validity(),
            &ee_serial,
            DEFAULT_ID,
            Some(ee_extensions),
            &mut rng,
        )
        .expect("Certificate issuance should succeed");

        // 验证终端实体证书
        assert!(ee_cert.extensions.is_some());
        let ee_exts = ee_cert.extensions.as_ref().unwrap();
        assert!(!ee_exts.is_empty());

        // 5. 验证证书链
        // 验证签发者是 CA
        assert_eq!(ee_cert.issuer, ca_cert.subject);

        // 验证主体不同
        assert_ne!(ca_cert.subject, ee_cert.subject);

        // 验证序列号不同
        assert_ne!(ca_cert.serial_number, ee_cert.serial_number);

        // 验证 CA 证书包含基本约束扩展
        assert!(ca_cert.extensions.is_some());

        // 验证可以使用 CA 公钥验证终端实体证书签名（证书链验证的核心）
        assert!(ee_cert
            .verify_signature_with_ca(&ca_cert, DEFAULT_ID)
            .is_ok());
    }
}
