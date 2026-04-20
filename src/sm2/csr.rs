//! CSR (PKCS#10) 证书签名请求和证书链验证
//!
//! 实现 RFC 2986 定义的 PKCS#10 证书签名请求（CSR）功能，
//! 以及 RFC 5280 定义的证书链验证功能。

#![cfg(feature = "alloc")]

use crate::error::Error;
use crate::sm2::cert::GmCertificate;
use crate::sm2::{get_e, get_z, sign, verify, PrivateKey, PublicKey, DEFAULT_ID};

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use x509_cert::der::asn1::{Any, BitString};
use x509_cert::der::pem::LineEnding;
use x509_cert::der::{Decode, Encode};
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo, Version};
use x509_cert::spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};

// ====================================================================================
// CSR (PKCS#10) 证书签名请求
// ====================================================================================

/// 证书签名请求（PKCS#10 / RFC 2986）
///
/// 用于向 CA 申请证书，包含申请者的公钥和身份信息，
/// 并由申请者的私钥签名以证明对该公钥的所有权。
#[derive(Debug, Clone)]
pub struct CertificateSigningRequest {
    /// CSR 信息（主体、公钥、属性）
    pub info: CertReqInfo,
    /// 签名算法标识
    pub algorithm: AlgorithmIdentifier<ObjectIdentifier>,
    /// 签名值
    pub signature: BitString,
}

impl CertificateSigningRequest {
    /// 创建证书签名请求（CSR）
    pub fn create<R: rand_core::Rng>(
        priv_key: &PrivateKey,
        subject: &Name,
        id: &[u8],
        rng: &mut R,
    ) -> Result<Self, Error> {
        let pub_key = priv_key.public_key();
        let public_key = SubjectPublicKeyInfo::from_der(&pub_key.to_spki().to_der().unwrap())
            .map_err(|_| Error::InvalidPublicKey)?;

        let info = CertReqInfo {
            version: Version::V1,
            subject: subject.clone(),
            public_key,
            attributes: Default::default(),
        };

        let info_der = info.to_der().map_err(|_| Error::InvalidSignature)?;

        let z = get_z(id, pub_key.as_bytes());
        let e = get_e(&z, &info_der);
        let signature_bytes = sign(&e, priv_key, rng);

        let signature = BitString::new(0, signature_bytes).map_err(|_| Error::InvalidSignature)?;

        Ok(Self {
            info,
            algorithm: crate::sm2::oids::SM2_SIGNATURE_ALGORITHM,
            signature,
        })
    }

    /// 验证 CSR 签名
    pub fn verify(&self) -> Result<(), Error> {
        let pub_key_bytes: [u8; 65] = self
            .info
            .public_key
            .subject_public_key
            .raw_bytes()
            .try_into()
            .map_err(|_| Error::InvalidPublicKey)?;
        let pub_key = PublicKey::from_bytes(&pub_key_bytes).map_err(|_| Error::InvalidPublicKey)?;

        let info_der = self.info.to_der().map_err(|_| Error::InvalidSignature)?;

        let sig_bytes = self.signature.raw_bytes();
        if sig_bytes.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(sig_bytes);

        let z = get_z(DEFAULT_ID, pub_key.as_bytes());
        let e = get_e(&z, &info_der);

        verify(&e, pub_key.as_bytes(), &sig_array)
    }

    /// 将 CSR 编码为 DER 格式
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let algorithm_der = self
            .algorithm
            .to_der()
            .map_err(|_| Error::InvalidSignature)?;
        let algorithm_any = Any::from_der(&algorithm_der).map_err(|_| Error::InvalidSignature)?;

        let cert_req = CertReq {
            info: self.info.clone(),
            algorithm: AlgorithmIdentifier {
                oid: self.algorithm.oid,
                parameters: Some(algorithm_any),
            },
            signature: self.signature.clone(),
        };

        cert_req.to_der().map_err(|_| Error::InvalidSignature)
    }

    /// 从 DER 编码解码 CSR
    pub fn from_der(data: &[u8]) -> Result<Self, Error> {
        let cert_req = CertReq::from_der(data).map_err(|_| Error::InvalidSignature)?;

        let algorithm = AlgorithmIdentifier {
            oid: cert_req.algorithm.oid,
            parameters: None,
        };

        Ok(Self {
            info: cert_req.info,
            algorithm,
            signature: cert_req.signature,
        })
    }

    /// 将 CSR 编码为 PEM 格式
    pub fn to_pem(&self) -> Result<String, Error> {
        let der = self.to_der()?;
        x509_cert::der::pem::encode_string("CERTIFICATE REQUEST", LineEnding::LF, &der)
            .map_err(|_| Error::InvalidSignature)
    }

    /// 从 PEM 编码解码 CSR
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let (label, der) =
            x509_cert::der::pem::decode_vec(pem.as_bytes()).map_err(|_| Error::InvalidSignature)?;

        if label != "CERTIFICATE REQUEST" {
            return Err(Error::InvalidSignature);
        }

        Self::from_der(&der)
    }

    /// 获取主体名称
    pub fn subject(&self) -> &Name {
        &self.info.subject
    }

    /// 获取公钥
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        let pub_key_bytes: [u8; 65] = self
            .info
            .public_key
            .subject_public_key
            .raw_bytes()
            .try_into()
            .map_err(|_| Error::InvalidPublicKey)?;
        PublicKey::from_bytes(&pub_key_bytes).map_err(|_| Error::InvalidPublicKey)
    }
}

// ====================================================================================
// 证书链验证
// ====================================================================================

/// 证书链验证结果
#[derive(Debug, Clone)]
pub struct ChainValidationResult {
    /// 验证是否通过
    pub is_valid: bool,
    /// 证书链（从终端证书到根证书）
    pub chain: Vec<GmCertificate>,
    /// 验证过程中的错误信息
    pub errors: Vec<String>,
}

/// 证书链验证器
#[derive(Debug, Clone, Default)]
pub struct CertificateChain {
    /// 证书列表
    pub certificates: Vec<GmCertificate>,
}

impl CertificateChain {
    /// 创建新的证书链
    pub fn new() -> Self {
        Self {
            certificates: Vec::new(),
        }
    }

    /// 添加证书到链中
    pub fn add_certificate(&mut self, cert: GmCertificate) {
        self.certificates.push(cert);
    }

    /// 添加多个证书到链中
    pub fn add_certificates(&mut self, certs: &[GmCertificate]) {
        self.certificates.extend(certs.iter().cloned());
    }

    /// 验证证书链（std 版本，支持时间验证）
    #[cfg(feature = "std")]
    pub fn verify(&self, trust_anchors: &[GmCertificate]) -> ChainValidationResult {
        let mut errors = Vec::new();

        if self.certificates.is_empty() {
            errors.push("证书链为空".into());
            return ChainValidationResult {
                is_valid: false,
                chain: self.certificates.clone(),
                errors,
            };
        }

        let chain = match self.build_chain(trust_anchors) {
            Ok(c) => c,
            Err(e) => {
                errors.push(e);
                return ChainValidationResult {
                    is_valid: false,
                    chain: self.certificates.clone(),
                    errors,
                };
            }
        };

        let now = std::time::SystemTime::now();

        for i in 0..chain.len() {
            let cert = &chain[i];

            // 验证有效期
            if let Err(e) = cert.verify_validity_system_time(now) {
                errors.push(format!("证书 {:?} 有效期验证失败: {:?}", cert.subject, e));
            }

            // 最后一个证书是信任锚，不需要验证签名
            if i == chain.len() - 1 {
                continue;
            }

            // 验证证书签名
            let issuer_cert = &chain[i + 1];
            if let Err(e) = cert.verify_signature_with_ca(issuer_cert, DEFAULT_ID) {
                errors.push(format!("证书 {:?} 签名验证失败: {:?}", cert.subject, e));
            }
        }

        ChainValidationResult {
            is_valid: errors.is_empty(),
            chain,
            errors,
        }
    }

    /// 构建证书链路径
    fn build_chain(&self, trust_anchors: &[GmCertificate]) -> Result<Vec<GmCertificate>, String> {
        if self.certificates.is_empty() {
            return Err("No certificates in chain".into());
        }

        let mut chain = Vec::new();
        let mut current = &self.certificates[0];
        chain.push(current.clone());

        let max_iterations = self.certificates.len() + trust_anchors.len();
        let mut iterations = 0;

        loop {
            if iterations >= max_iterations {
                return Err("Certificate chain too long or contains cycles".into());
            }
            iterations += 1;

            // 检查当前证书的签发者是否是信任锚
            if let Some(anchor) = trust_anchors.iter().find(|a| a.subject == current.issuer) {
                chain.push(anchor.clone());
                break;
            }

            // 检查当前证书的签发者是否在证书链中
            if let Some(issuer) = self
                .certificates
                .iter()
                .find(|c| c.subject == current.issuer)
            {
                if chain
                    .iter()
                    .any(|c| c.subject == issuer.subject && c.serial_number == issuer.serial_number)
                {
                    return Err("Certificate chain contains cycles".into());
                }
                chain.push(issuer.clone());
                current = issuer;
            } else {
                // 自签名证书（根证书）
                if current.issuer == current.subject {
                    chain.push(current.clone());
                    break;
                }
                return Err(format!(
                    "Cannot find issuer for certificate: {:?}",
                    current.subject
                ));
            }
        }

        Ok(chain)
    }

    /// 获取链中的证书数量
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// 检查链是否为空
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::sm2::cert::{
        build_x500_name, generate_self_signed_cert, issue_certificate, X500Attribute,
        X500AttributeType,
    };
    use crate::sm2::generate_keypair;
    use core::str::FromStr;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};

    fn build_test_validity() -> Validity {
        let not_before = Time::from_str("2024-01-01T00:00:00Z").unwrap();
        let not_after = Time::from_str("2030-01-01T00:00:00Z").unwrap();
        Validity::new(not_before, not_after)
    }

    #[test]
    fn test_csr_create_and_verify() {
        let mut rng = StdRng::seed_from_u64(12345);
        let (priv_key, _) = generate_keypair(&mut rng);
        let subject = build_x500_name(&[X500Attribute::new(
            X500AttributeType::CommonName,
            "test.example.com",
        )]);

        let csr = CertificateSigningRequest::create(&priv_key, &subject, DEFAULT_ID, &mut rng)
            .expect("Failed to create CSR");

        csr.verify().expect("CSR signature verification failed");
    }

    #[test]
    fn test_csr_der_roundtrip() {
        let mut rng = StdRng::seed_from_u64(12345);
        let (priv_key, _) = generate_keypair(&mut rng);
        let subject = build_x500_name(&[X500Attribute::new(
            X500AttributeType::CommonName,
            "test.example.com",
        )]);

        let csr = CertificateSigningRequest::create(&priv_key, &subject, DEFAULT_ID, &mut rng)
            .expect("Failed to create CSR");

        let der = csr.to_der().expect("Failed to encode CSR");
        let csr_decoded = CertificateSigningRequest::from_der(&der).expect("Failed to decode CSR");

        assert_eq!(csr.subject(), csr_decoded.subject());
    }

    #[test]
    fn test_csr_pem_roundtrip() {
        let mut rng = StdRng::seed_from_u64(12345);
        let (priv_key, _) = generate_keypair(&mut rng);
        let subject = build_x500_name(&[X500Attribute::new(
            X500AttributeType::CommonName,
            "test.example.com",
        )]);

        let csr = CertificateSigningRequest::create(&priv_key, &subject, DEFAULT_ID, &mut rng)
            .expect("Failed to create CSR");

        let pem = csr.to_pem().expect("Failed to encode CSR to PEM");
        let csr_decoded =
            CertificateSigningRequest::from_pem(&pem).expect("Failed to decode CSR from PEM");

        assert_eq!(csr.subject(), csr_decoded.subject());
    }

    #[test]
    fn test_certificate_chain_verification() {
        let mut rng = StdRng::seed_from_u64(12345);

        // 创建根 CA
        let (ca_priv_key, _) = generate_keypair(&mut rng);
        let ca_subject = build_x500_name(&[
            X500Attribute::new(X500AttributeType::Organization, "Test CA"),
            X500Attribute::new(X500AttributeType::CommonName, "Root CA"),
        ]);
        let ca_serial = SerialNumber::from(1u64);
        let ca_validity = build_test_validity();
        let ca_cert = generate_self_signed_cert(
            &ca_priv_key,
            &ca_subject,
            &ca_validity,
            &ca_serial,
            DEFAULT_ID,
            None,
            &mut rng,
        )
        .expect("Failed to generate CA certificate");

        // 创建终端证书
        let (end_priv_key, _) = generate_keypair(&mut rng);
        let end_subject = build_x500_name(&[X500Attribute::new(
            X500AttributeType::CommonName,
            "test.example.com",
        )]);
        let end_serial = SerialNumber::from(100u64);
        let end_validity = build_test_validity();
        let end_cert = issue_certificate(
            &ca_cert,
            &ca_priv_key,
            &end_subject,
            &end_priv_key.public_key(),
            &end_validity,
            &end_serial,
            DEFAULT_ID,
            None,
            &mut rng,
        )
        .expect("Failed to generate end certificate");

        // 验证证书链
        let mut chain = CertificateChain::new();
        chain.add_certificate(end_cert);

        let mut trust_anchors = Vec::new();
        trust_anchors.push(ca_cert);

        let result = chain.verify(&trust_anchors);
        assert!(
            result.is_valid,
            "Certificate chain verification should succeed: {:?}",
            result.errors
        );
    }
}
