//! 证书撤销列表（CRL）支持（RFC 5280）
//!
//! 实现 X.509 证书撤销列表的解析、验证和管理功能。
//!
//! ## 主要功能
//!
//! - **CRL 解析**: 解析 DER/PEM 编码的 CRL
//! - **CRL 验证**: 验证 CRL 签名和有效期
//! - **证书状态检查**: 检查证书是否被撤销
//! - **CRL 生成**: 生成符合 RFC 5280 标准的 CRL
//!
//! ## 数据结构
//!
//! ```text
//! CertificateList ::= SEQUENCE {
//!     tbsCertList          TBSCertList,
//!     signatureAlgorithm   AlgorithmIdentifier,
//!     signatureValue       BIT STRING
//! }
//!
//! TBSCertList ::= SEQUENCE {
//!     version                 Version OPTIONAL,
//!     signature               AlgorithmIdentifier,
//!     issuer                  Name,
//!     thisUpdate              Time,
//!     nextUpdate              Time OPTIONAL,
//!     revokedCertificates     SEQUENCE OF SEQUENCE {
//!          userCertificate         CertificateSerialNumber,
//!          revocationDate          Time,
//!          crlEntryExtensions      Extensions OPTIONAL
//!     } OPTIONAL,
//!     crlExtensions           [0] EXPLICIT Extensions OPTIONAL
//! }
//! ```

#![cfg(feature = "alloc")]

use alloc::vec::Vec;

use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::der::{Decode, Encode};
use x509_cert::der::pem::{decode_vec, encode_string};
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifier;
use x509_cert::time::Time;

use crate::error::Error;
use crate::sm2::{sign, verify, PrivateKey, PublicKey};

/// 被撤销的证书条目
///
/// 包含被撤销证书的序列号、撤销时间和撤销原因。
#[derive(Debug, Clone)]
pub struct RevokedCertificate {
    /// 被撤销证书的序列号
    pub serial_number: SerialNumber,
    /// 撤销时间
    pub revocation_date: Time,
    /// 撤销原因代码（可选）
    /// 根据 RFC 5280 §5.3.1 CRLReason 扩展：
    ///   - 0: unspecified (未指定)
    ///   - 1: keyCompromise (密钥泄露)
    ///   - 2: cACompromise (CA 密钥泄露)
    ///   - 3: affiliationChanged (隶属关系变更)
    ///   - 4: superseded (证书被替代)
    ///   - 5: cessationOfOperation (停止运营)
    ///   - 6: certificateHold (证书挂起)
    ///   - 7: (未使用)
    ///   - 8: removeFromCRL (从 CRL 中移除)
    ///   - 9: privilegeWithdrawn (权限撤销)
    ///   - 10: aACompromise (属性机构泄露)
    pub reason_code: Option<u8>,
    /// 无效日期（可选，RFC 5280 §5.3.2）
    /// 表示证书实际变为无效的时间，可能早于撤销时间
    pub invalidity_date: Option<Time>,
    /// CRL 条目扩展（RFC 5280 §5.3）
    /// 包含 CRLReason、Invalidity Date、Certificate Issuer 等扩展
    pub crl_entry_extensions: Option<Extensions>,
}

/// 证书撤销列表（CRL）
///
/// 提供对 RFC 5280 标准 CRL 的高级封装，
/// 支持解析、验证和证书状态检查。
#[derive(Debug, Clone)]
pub struct Crl {
    /// 原始 CertificateList 结构
    pub certificate_list: CertificateList,
}

impl Crl {
    /// 从 DER 编码解析 CRL
    ///
    /// # 参数
    /// - `der`: DER 编码的 CRL 数据
    ///
    /// # 返回
    /// - `Ok(Crl)`: 解析成功的 CRL
    /// - `Err(Error::InvalidCrl)`: 解析失败
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use libsmx::sm2::crl::Crl;
    ///
    /// let der_bytes: Vec<u8> = vec![/* DER encoded CRL */];
    /// let crl = Crl::from_der(&der_bytes).expect("Valid CRL");
    /// ```
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let certificate_list = CertificateList::from_der(der)
            .map_err(|_| Error::InvalidCrl)?;
        Ok(Crl { certificate_list })
    }

    /// 从 PEM 编码解析 CRL
    ///
    /// # 参数
    /// - `pem`: PEM 编码的 CRL 数据
    ///
    /// # 返回
    /// - `Ok(Crl)`: 解析成功的 CRL
    /// - `Err(Error::InvalidCrl)`: 解析失败
    pub fn from_pem(pem: &[u8]) -> Result<Self, Error> {
        let (_label, der) = decode_vec(pem)
            .map_err(|_| Error::InvalidCrl)?;
        Self::from_der(&der)
    }

    /// 将 CRL 编码为 DER 格式
    ///
    /// # 返回
    /// DER 编码的 CRL 字节数组
    pub fn to_der(&self) -> Vec<u8> {
        self.certificate_list.to_der()
            .expect("CRL encoding should not fail")
    }

    /// 将 CRL 编码为 PEM 格式
    ///
    /// # 返回
    /// - `Ok(Vec<u8>)`: PEM 编码的 CRL 数据
    /// - `Err(Error::InvalidCrl)`: 编码失败
    pub fn to_pem(&self) -> Result<Vec<u8>, Error> {
        let der = self.to_der();
        encode_string("X509 CRL", Default::default(), &der)
            .map(|s| s.into_bytes())
            .map_err(|_| Error::InvalidCrl)
    }

    /// 获取签发者名称
    pub fn issuer(&self) -> &Name {
        &self.certificate_list.tbs_cert_list.issuer
    }

    /// 获取本次更新时间
    pub fn this_update(&self) -> &Time {
        &self.certificate_list.tbs_cert_list.this_update
    }

    /// 获取下次更新时间（可选）
    pub fn next_update(&self) -> Option<&Time> {
        self.certificate_list.tbs_cert_list.next_update.as_ref()
    }

    /// 获取被撤销的证书列表
    pub fn revoked_certificates(&self) -> Option<&[RevokedCert]> {
        self.certificate_list.tbs_cert_list.revoked_certificates.as_deref()
    }

    /// 获取 CRL 扩展
    pub fn extensions(&self) -> Option<&Extensions> {
        self.certificate_list.tbs_cert_list.crl_extensions.as_ref()
    }

    /// 检查指定序列号的证书是否被撤销
    ///
    /// # 参数
    /// - `serial`: 证书序列号
    ///
    /// # 返回
    /// - `true`: 证书已被撤销
    /// - `false`: 证书未被撤销
    pub fn is_revoked(&self, serial: &SerialNumber) -> bool {
        if let Some(revoked) = self.revoked_certificates() {
            revoked.iter().any(|cert| cert.serial_number == *serial)
        } else {
            false
        }
    }

    /// 验证 CRL 签名
    ///
    /// 使用签发者的公钥验证 CRL 的签名是否有效。
    ///
    /// # 参数
    /// - `issuer_pub_key`: 签发者的公钥
    /// - `id`: SM2 签名 ID（通常为 "1234567812345678"）
    ///
    /// # 返回
    /// - `Ok(())`: 签名验证通过
    /// - `Err(Error::InvalidSignature)`: 签名验证失败
    pub fn verify_signature(
        &self,
        issuer_pub_key: &PublicKey,
        id: &[u8],
    ) -> Result<(), Error> {
        // 获取签名算法 OID
        let sig_alg_oid = self.certificate_list.tbs_cert_list.signature.oid;
        
        // 确保是 SM2 签名算法
        if sig_alg_oid != crate::sm2::SM2_SIGNATURE_OID {
            return Err(Error::UnsupportedAlgorithm);
        }

        // 获取 TBSCertList 的 DER 编码
        let tbs_der = self.certificate_list.tbs_cert_list.to_der()
            .map_err(|_| Error::InvalidCrl)?;

        // 计算消息摘要（SM3）
        let z = crate::sm2::get_z(id, issuer_pub_key.as_bytes());
        let e = crate::sm2::get_e(&z, &tbs_der);

        // 获取签名值
        let sig_bytes = self.certificate_list.signature.raw_bytes();
        if sig_bytes.len() != 64 {
            return Err(Error::InvalidSignature);
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(sig_bytes);

        // 验证签名
        verify(&e, issuer_pub_key.as_bytes(), &sig)
    }

    /// 检查 CRL 是否在有效期内
    ///
    /// # 参数
    /// - `now`: 当前时间
    ///
    /// # 返回
    /// - `Ok(())`: CRL 有效
    /// - `Err(Error::ExpiredCrl)`: CRL 已过期
    #[cfg(feature = "std")]
    pub fn verify_validity(&self, now: std::time::SystemTime) -> Result<(), Error> {
        let this_update = self.this_update();
        if now < (*this_update).try_into().map_err(|_| Error::InvalidCrl)? {
            return Err(Error::InvalidCrl);
        }

        if let Some(next_update) = self.next_update() {
            if now > (*next_update).try_into().map_err(|_| Error::InvalidCrl)? {
                return Err(Error::ExpiredCrl);
            }
        }

        Ok(())
    }

    /// 完整的 CRL 验证（签名 + 有效期）
    ///
    /// # 参数
    /// - `issuer_pub_key`: CRL 签发者的公钥
    /// - `id`: SM2 签名 ID
    /// - `now`: 当前时间
    ///
    /// # 返回
    /// - `Ok(())`: CRL 验证通过
    /// - `Err(Error)`: 验证失败
    #[cfg(feature = "std")]
    pub fn verify_complete(
        &self,
        issuer_pub_key: &PublicKey,
        id: &[u8],
        now: std::time::SystemTime,
    ) -> Result<(), Error> {
        // 验证签名
        self.verify_signature(issuer_pub_key, id)?;
        
        // 验证有效期
        self.verify_validity(now)?;
        
        Ok(())
    }

    /// 获取被撤销证书的详细信息
    ///
    /// # 参数
    /// - `serial`: 证书序列号
    ///
    /// # 返回
    /// - `Some(RevokedCert)`: 撤销信息
    /// - `None`: 证书未被撤销
    pub fn get_revocation_info(&self, serial: &SerialNumber) -> Option<&RevokedCert> {
        self.revoked_certificates().and_then(|revoked| {
            revoked.iter().find(|r| r.serial_number == *serial)
        })
    }
}

/// CRL 构建器
///
/// 用于创建和签发新的证书撤销列表。
///
/// # 示例
///
/// ```ignore
/// use libsmx::sm2::crl::CrlBuilder;
/// use libsmx::sm2::cert::build_x500_name;
/// use libsmx::sm2::X500AttributeType;
/// use std::time::SystemTime;
///
/// let issuer = build_x500_name(&[
///     (X500AttributeType::Organization, "Test CA"),
/// ]);
///
/// let crl = CrlBuilder::new()
///     .issuer(&issuer)
///     .this_update(SystemTime::now())
///     .next_update(SystemTime::now() + std::time::Duration::from_secs(86400))
///     .add_revoked(serial_number, revocation_time, Some(1)) // 1 = keyCompromise
///     .sign(&ca_priv_key, b"1234567812345678", &mut rng)
///     .expect("Failed to sign CRL");
/// ```
#[cfg(feature = "std")]
pub struct CrlBuilder {
    issuer: Option<Name>,
    this_update: Option<std::time::SystemTime>,
    next_update: Option<std::time::SystemTime>,
    revoked_certs: Vec<RevokedCertificate>,
    extensions: Option<Extensions>,
}

#[cfg(feature = "std")]
impl CrlBuilder {
    /// 创建新的 CRL 构建器
    pub fn new() -> Self {
        Self {
            issuer: None,
            this_update: None,
            next_update: None,
            revoked_certs: Vec::new(),
            extensions: None,
        }
    }

    /// 设置签发者名称
    pub fn issuer(mut self, issuer: &Name) -> Self {
        self.issuer = Some(issuer.clone());
        self
    }

    /// 设置本次更新时间
    pub fn this_update(mut self, time: std::time::SystemTime) -> Self {
        self.this_update = Some(time);
        self
    }

    /// 设置下次更新时间
    pub fn next_update(mut self, time: std::time::SystemTime) -> Self {
        self.next_update = Some(time);
        self
    }

    /// 添加被撤销的证书（含完整扩展支持）
    ///
    /// # 参数
    /// - `serial`: 被撤销证书的序列号
    /// - `revocation_time`: 撤销时间
    /// - `reason_code`: 撤销原因代码（可选）
    ///   根据 RFC 5280 §5.3.1 CRLReason 扩展：
    ///   - 0: unspecified (未指定)
    ///   - 1: keyCompromise (密钥泄露)
    ///   - 2: cACompromise (CA 密钥泄露)
    ///   - 3: affiliationChanged (隶属关系变更)
    ///   - 4: superseded (证书被替代)
    ///   - 5: cessationOfOperation (停止运营)
    ///   - 6: certificateHold (证书挂起)
    ///   - 8: removeFromCRL (从 CRL 中移除)
    ///   - 9: privilegeWithdrawn (权限撤销)
    ///   - 10: aACompromise (属性机构泄露)
    /// - `invalidity_date`: 无效日期（可选，仅用于 certificateHold 状态）
    ///   表示证书实际变为无效的时间，可能早于撤销时间
    ///
    /// # 标准参考
    /// - RFC 5280 §5.3 CRL Entry Extensions
    /// - RFC 5280 §5.3.1 CRLReason
    /// - RFC 5280 §5.3.2 Invalidity Date
    pub fn add_revoked(
        mut self,
        serial: SerialNumber,
        revocation_time: std::time::SystemTime,
        reason_code: Option<u8>,
        invalidity_date: Option<std::time::SystemTime>,
    ) -> Self {
        let revocation_date = Time::try_from(revocation_time)
            .expect("Valid system time");
        
        // 根据 RFC 5280 §5.3 构建 CRL 条目扩展
        let crl_entry_extensions = if reason_code.is_some() || invalidity_date.is_some() {
            // 扩展将通过 sign 方法构建
            // 这里仅标记需要扩展
            Some(Extensions::default())
        } else {
            None
        };
        
        self.revoked_certs.push(RevokedCertificate {
            serial_number: serial,
            revocation_date,
            reason_code,
            invalidity_date: invalidity_date.map(|t| Time::try_from(t).expect("Valid system time")),
            crl_entry_extensions,
        });
        self
    }

    /// 设置 CRL 扩展
    pub fn extensions(mut self, extensions: Extensions) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// 签发 CRL
    ///
    /// # 参数
    /// - `ca_priv_key`: CA 私钥
    /// - `id`: SM2 签名 ID
    /// - `rng`: 随机数生成器
    ///
    /// # 返回
    /// - `Ok(Crl)`: 签发成功的 CRL
    /// - `Err(Error)`: 签发失败
    ///
    /// # 标准参考
    /// - RFC 5280 §5.1.2.2 Signature Algorithm
    /// - RFC 5280 §5.1.2.3 TBSCertList
    /// - RFC 5280 §5.3 CRL Entry Extensions
    pub fn sign<R: rand_core::Rng>(
        self,
        ca_priv_key: &PrivateKey,
        id: &[u8],
        rng: &mut R,
    ) -> Result<Crl, Error> {
        let issuer = self.issuer.ok_or(Error::InvalidCrl)?;
        let this_update = self.this_update.ok_or(Error::InvalidCrl)?;
        let this_update_time = Time::try_from(this_update)
            .map_err(|_| Error::InvalidCrl)?;
        let next_update_time = self.next_update
            .map(|t| Time::try_from(t).map_err(|_| Error::InvalidCrl))
            .transpose()?;

        // 构建被撤销证书列表（包含完整的 CRL 条目扩展）
        let revoked_certs = if self.revoked_certs.is_empty() {
            None
        } else {
            let revoked: Vec<RevokedCert> = self.revoked_certs
                .iter()
                .map(|rc| {
                    // 根据 RFC 5280 §5.3 构建 CRL 条目扩展
                    let entry_extensions = build_crl_entry_extensions(
                        rc.reason_code,
                        rc.invalidity_date.as_ref(),
                    );
                    
                    RevokedCert {
                        serial_number: rc.serial_number.clone(),
                        revocation_date: rc.revocation_date.clone(),
                        crl_entry_extensions: entry_extensions,
                    }
                })
                .collect();
            Some(revoked)
        };

        // 构建 TBSCertList
        let tbs_cert_list = TbsCertList {
            version: x509_cert::certificate::Version::V2,
            signature: AlgorithmIdentifier {
                oid: crate::sm2::SM2_SIGNATURE_OID,
                parameters: None,
            },
            issuer,
            this_update: this_update_time,
            next_update: next_update_time,
            revoked_certificates: revoked_certs,
            crl_extensions: self.extensions,
        };

        // 计算 TBSCertList 的 DER 编码
        let tbs_der = tbs_cert_list.to_der()
            .map_err(|_| Error::InvalidCrl)?;

        // 计算消息摘要
        let pub_key = ca_priv_key.public_key();
        let z = crate::sm2::get_z(id, pub_key.as_bytes());
        let e = crate::sm2::get_e(&z, &tbs_der);

        // 签名
        let sig = sign(&e, ca_priv_key, rng);

        // 构建完整的 CertificateList
        let certificate_list = CertificateList {
            tbs_cert_list,
            signature_algorithm: AlgorithmIdentifier {
                oid: crate::sm2::SM2_SIGNATURE_OID,
                parameters: None,
            },
            signature: x509_cert::der::asn1::BitString::new(0, &sig)
                .map_err(|_| Error::InvalidCrl)?,
        };

        Ok(Crl { certificate_list })
    }
}

/// 构建 CRL 条目扩展（RFC 5280 §5.3）
///
/// 根据 RFC 5280 标准构建被撤销证书条目的扩展，包括：
/// - CRLReason (§5.3.1): 撤销原因
/// - Invalidity Date (§5.3.2): 证书实际失效日期
/// - Certificate Issuer (§5.3.3): 证书签发者（仅用于间接 CRL）
///
/// # 参数
/// - `reason_code`: 撤销原因代码
/// - `invalidity_date`: 无效日期（可选）
///
/// # 返回
/// - `Some(Extensions)`: 构建的扩展列表
/// - `None`: 无扩展
fn build_crl_entry_extensions(
    reason_code: Option<u8>,
    invalidity_date: Option<&Time>,
) -> Option<Extensions> {
    if reason_code.is_none() && invalidity_date.is_none() {
        return None;
    }

    // 注意：x509_cert 库的 Extensions 类型是 Vec<Extension>
    // 我们需要手动构建扩展条目
    let mut extensions = alloc::vec::Vec::new();

    // CRLReason 扩展 (OID: 2.5.29.21)
    if let Some(reason) = reason_code {
        // CRLReason 是 ENUMERATED 类型
        // DER 编码: 0x0A (ENUMERATED) + 长度 + 值
        let reason_der = match reason {
            0..=10 => {
                // 单字节枚举值
                let mut buf = alloc::vec![0x0A, 0x01, reason];
                // 包装为 OCTET STRING (扩展值必须是 OCTET STRING)
                let mut octet = alloc::vec![0x04, buf.len() as u8];
                octet.append(&mut buf);
                octet
            }
            _ => {
                // 无效的 reason_code，跳过
                alloc::vec![]
            }
        };

        if !reason_der.is_empty() {
            extensions.push(x509_cert::ext::Extension {
                extn_id: crate::sm2::ID_CE_CRL_REASONS,
                critical: false, // CRLReason 不是关键扩展
                extn_value: x509_cert::der::asn1::OctetString::new(reason_der.as_slice())
                    .expect("Valid OCTET STRING"),
            });
        }
    }

    // Invalidity Date 扩展 (OID: 2.5.29.24)
    if let Some(inv_date) = invalidity_date {
        // Invalidity Date 是 GeneralizedTime 类型
        let inv_date_der = inv_date.to_der()
            .expect("Valid Time encoding");
        
        extensions.push(x509_cert::ext::Extension {
            extn_id: crate::sm2::ID_CE_INVALIDITY_DATE,
            critical: false, // Invalidity Date 不是关键扩展
            extn_value: x509_cert::der::asn1::OctetString::new(inv_date_der.as_slice())
                .expect("Valid OCTET STRING"),
        });
    }

    if extensions.is_empty() {
        None
    } else {
        Some(extensions)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::sm2::cert::{build_x500_name, X500Attribute, X500AttributeType};
    use crate::sm2::generate_keypair;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_crl_builder_and_verify() {
        let mut rng = StdRng::seed_from_u64(12345);
        let (ca_priv_key, ca_pub_key) = generate_keypair(&mut rng);

        let issuer = build_x500_name(&[
            X500Attribute::new(X500AttributeType::Organization, "Test CA"),
            X500Attribute::new(X500AttributeType::CommonName, "Test CA Root"),
        ]);

        let revoked_serial = SerialNumber::from(100u32);
        let revocation_time = SystemTime::now() - Duration::from_secs(3600);

        let crl = CrlBuilder::new()
            .issuer(&issuer)
            .this_update(SystemTime::now() - Duration::from_secs(60))
            .next_update(SystemTime::now() + Duration::from_secs(86400))
            .add_revoked(revoked_serial.clone(), revocation_time, Some(1), None)
            .sign(&ca_priv_key, b"1234567812345678", &mut rng)
            .expect("CRL signing should succeed");

        // 验证 CRL 签名
        crl.verify_signature(&ca_pub_key, b"1234567812345678")
            .expect("CRL signature should be valid");

        // 验证 CRL 有效期
        crl.verify_validity(SystemTime::now())
            .expect("CRL should be valid");

        // 检查被撤销的证书
        assert!(crl.is_revoked(&revoked_serial));

        // 检查未被撤销的证书
        let other_serial = SerialNumber::from(200u32);
        assert!(!crl.is_revoked(&other_serial));
    }

    #[test]
    fn test_crl_der_roundtrip() {
        let mut rng = StdRng::seed_from_u64(12345);
        let (ca_priv_key, _) = generate_keypair(&mut rng);

        let issuer = build_x500_name(&[
            X500Attribute::new(X500AttributeType::Organization, "Test CA"),
        ]);

        let crl = CrlBuilder::new()
            .issuer(&issuer)
            .this_update(SystemTime::now())
            .next_update(SystemTime::now() + Duration::from_secs(86400))
            .sign(&ca_priv_key, b"1234567812345678", &mut rng)
            .expect("CRL signing should succeed");

        // DER 编码/解码往返
        let der = crl.to_der();
        let parsed = Crl::from_der(&der)
            .expect("CRL parsing should succeed");

        assert_eq!(parsed.issuer(), crl.issuer());
        assert_eq!(parsed.this_update(), crl.this_update());
    }

    #[test]
    fn test_crl_expired() {
        let mut rng = StdRng::seed_from_u64(12345);
        let (ca_priv_key, _) = generate_keypair(&mut rng);

        let issuer = build_x500_name(&[
            X500Attribute::new(X500AttributeType::Organization, "Test CA"),
        ]);

        let crl = CrlBuilder::new()
            .issuer(&issuer)
            .this_update(SystemTime::now() - Duration::from_secs(172800)) // 2 天前
            .next_update(SystemTime::now() - Duration::from_secs(86400)) // 1 天前过期
            .sign(&ca_priv_key, b"1234567812345678", &mut rng)
            .expect("CRL signing should succeed");

        // 验证应该失败（已过期）
        let result = crl.verify_validity(SystemTime::now());
        assert!(result.is_err());
    }
}
