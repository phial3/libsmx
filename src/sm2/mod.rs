//! SM2 椭圆曲线公钥密码算法（GB/T 32918.1-5-2016）
//!
//! 实现内容：
//! - 密钥生成（§6.1）
//! - Z 值与消息摘要计算（§5.5）
//! - 数字签名与验签（§6.2, §6.3）
//! - 公钥加密与解密（§7.1, §7.2）
//!
//! # 合规说明
//! 签名必须使用 `SM3(Z||M)` 作为消息摘要，而非直接 `SM3(M)`。
//! 所有公开签名接口均要求调用方提供用户 ID（或已计算好的 Z 值）。

pub mod der;
pub mod ec;
pub mod field;
pub mod key_exchange;

#[cfg(feature = "alloc")]
pub mod cert;

#[cfg(feature = "alloc")]
pub mod cms;

#[cfg(feature = "alloc")]
pub mod crl;

#[cfg(feature = "alloc")]
pub mod csr;

#[cfg(feature = "alloc")]
pub use der::{
    private_key_from_pkcs8_der, private_key_from_sec1_der, private_key_to_pkcs8_der,
    private_key_to_sec1_der,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use alloc::string::String;

#[cfg(feature = "alloc")]
use x509_cert::{
    der::{pem, Decode, Encode},
    spki::{ObjectIdentifier, SubjectPublicKeyInfo},
};

use crypto_bigint::U256;
use rand_core::Rng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;
use crate::sm2::ec::{multi_scalar_mul, AffinePoint, JacobianPoint};
use crate::sm2::field::{
    fn_add, fn_inv, fn_mul, fn_sub, fp_to_bytes, Fn, CURVE_A, CURVE_B, GROUP_ORDER,
    GROUP_ORDER_MINUS_1, GX, GY,
};
use crate::sm3::Sm3Hasher;

/// SM2 默认用户可辨别标识（GB/T 32918.2-2016 §A.2 示例值）
///
/// 当调用方无自定义 ID 时，应使用此常量作为 `sign_message` / `verify_message` 的 `id` 参数。
pub const DEFAULT_ID: &[u8] = b"1234567812345678";

// ====================================================================================
// OID 常量定义（使用 ObjectIdentifier 类型）
// ====================================================================================

/// OID 常量模块（需要 alloc feature）
///
/// 包含 SM2/SM3、PKCS#7/CMS、X.509 证书扩展等相关 OID 常量。
#[cfg(feature = "alloc")]
pub mod oids {
    use x509_cert::spki::{AlgorithmIdentifier, ObjectIdentifier};

    /// SM2 椭圆曲线参数 OID (1.2.156.10197.1.301)
    ///
    /// 国密 SM2 椭圆曲线公钥算法参数标识符（sm2p256v1）
    pub const SM2_CURVE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.1.301");

    /// SM2 签名算法 OID (1.2.156.10197.1.501)
    ///
    /// SM2withSM3 签名算法标识符，用于 X.509 证书签名算法
    pub const SM2_SIGNATURE_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.156.10197.1.501");

    /// SM3 哈希算法 OID (1.2.156.10197.1.401)
    pub const SM3_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.1.401");

    /// EC 公钥算法 OID (1.2.840.10045.2.1)
    ///
    /// 通用椭圆曲线公钥算法 OID（id-ecPublicKey），与 SM2 算法 OID 配合使用
    pub const EC_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

    /// PKCS#7/CMS SignedData OID (1.2.840.113549.1.7.2)
    ///
    /// 用于 PKCS#7/CMS 签名数据内容类型
    pub const PKCS7_SIGNED_DATA_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

    /// PKCS#7/CMS Data OID (1.2.840.113549.1.7.1)
    ///
    /// 用于 PKCS#7/CMS 数据内容类型
    pub const PKCS7_DATA_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

    /// content-type 属性 OID (1.2.840.113549.1.9.3)
    ///
    /// 用于 CMS 签名属性 content-type
    pub const CONTENT_TYPE_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

    /// message-digest 属性 OID (1.2.840.113549.1.9.4)
    ///
    /// 用于 CMS 签名属性 message-digest
    pub const MESSAGE_DIGEST_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

    /// signing-time 属性 OID (1.2.840.113549.1.9.5)
    ///
    /// 用于 CMS 签名属性 signing-time
    pub const SIGNING_TIME_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

    // 证书扩展 OID (X.509 v3 Extensions)

    /// id-ce-basicConstraints OID (2.5.29.19)
    ///
    /// 基本约束扩展，用于标识 CA 证书和路径长度约束
    pub const ID_CE_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

    /// id-ce-keyUsage OID (2.5.29.15)
    ///
    /// 密钥用途扩展，标识证书公钥的用途
    pub const ID_CE_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

    /// id-ce-extKeyUsage OID (2.5.29.37)
    ///
    /// 扩展密钥用途扩展，指示证书的一个或多个用途
    pub const ID_CE_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

    /// id-ce-subjectAltName OID (2.5.29.17)
    ///
    /// 主体备用名称扩展
    pub const ID_CE_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

    /// id-ce-issuerAltName OID (2.5.29.18)
    ///
    /// 签发者备用名称扩展
    pub const ID_CE_ISSUER_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.18");

    /// id-ce-certificatePolicies OID (2.5.29.32)
    ///
    /// 证书策略扩展
    pub const ID_CE_CERTIFICATE_POLICIES: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.5.29.32");

    /// id-ce-cRLDistributionPoints OID (2.5.29.31)
    ///
    /// CRL 分发点扩展
    pub const ID_CE_CRL_DISTRIBUTION_POINTS: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.5.29.31");

    /// id-ce-authorityKeyIdentifier OID (2.5.29.35)
    ///
    /// 机构密钥标识符扩展
    pub const ID_CE_AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.5.29.35");

    /// id-ce-subjectKeyIdentifier OID (2.5.29.14)
    ///
    /// 主体密钥标识符扩展
    pub const ID_CE_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.5.29.14");

    /// id-ce-cRLReasons OID (2.5.29.21)
    ///
    /// CRL 撤销原因扩展
    pub const ID_CE_CRL_REASONS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.21");

    /// id-ce-invalidityDate OID (2.5.29.24)
    ///
    /// CRL 无效日期扩展
    pub const ID_CE_INVALIDITY_DATE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.24");

    /// anyExtendedKeyUsage OID (2.5.29.37.0)
    ///
    /// 任何扩展密钥用途
    pub const ANY_EXTENDED_KEY_USAGE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.5.29.37.0");

    /// id-kp-serverAuth OID (1.3.6.1.5.5.7.3.1)
    ///
    /// 服务器认证密钥用途
    pub const ID_KP_SERVER_AUTH: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

    /// id-kp-clientAuth OID (1.3.6.1.5.5.7.3.2)
    ///
    /// 客户端认证密钥用途
    pub const ID_KP_CLIENT_AUTH: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

    /// id-kp-codeSigning OID (1.3.6.1.5.5.7.3.3)
    ///
    /// 代码签名密钥用途
    pub const ID_KP_CODE_SIGNING: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

    /// id-kp-emailProtection OID (1.3.6.1.5.5.7.3.4)
    ///
    /// 电子邮件保护密钥用途
    pub const ID_KP_EMAIL_PROTECTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");

    /// SM2 公钥算法标识符（用于 SubjectPublicKeyInfo）
    ///
    /// 完整的 AlgorithmIdentifier，包含 id-ecPublicKey 和 SM2 曲线参数
    pub const SM2_SPKI_ALGORITHM: AlgorithmIdentifier<ObjectIdentifier> = AlgorithmIdentifier {
        oid: EC_PUBKEY_OID,
        parameters: Some(SM2_CURVE_OID),
    };

    /// SM2 签名算法标识符（用于 X.509 证书签名算法和 CMS 签名）
    ///
    /// 完整的 AlgorithmIdentifier for SM2withSM3
    /// 注意：国密标准中 SM2withSM3 算法标识符不包含 parameters
    pub const SM2_SIGNATURE_ALGORITHM: AlgorithmIdentifier<ObjectIdentifier> =
        AlgorithmIdentifier {
            oid: SM2_SIGNATURE_OID,
            parameters: None,
        };

    /// SM3 摘要算法标识符（用于 CMS digestAlgorithms）
    ///
    /// 符合 RFC 5652 标准的 AlgorithmIdentifier
    pub const SM3_DIGEST_ALGORITHM: AlgorithmIdentifier<ObjectIdentifier> = AlgorithmIdentifier {
        oid: SM3_OID,
        parameters: None,
    };
}

// 重新导出 OID 常量以保持向后兼容
#[cfg(feature = "alloc")]
pub use oids::*;

// ── 私钥类型 ──────────────────────────────────────────────────────────────────

/// SM2 私钥（32 字节，离开作用域自动清零）
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    bytes: [u8; 32],
}

impl PrivateKey {
    /// 从字节构造私钥（验证 d ∈ [1, n-2]）
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let d = U256::from_be_slice(bytes);
        if bool::from(d.is_zero()) || d >= GROUP_ORDER_MINUS_1 {
            return Err(Error::InvalidPrivateKey);
        }
        Ok(PrivateKey { bytes: *bytes })
    }

    /// 以字节引用访问私钥（不泄露值所有权）
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// 计算对应公钥（返回 PublicKey 类型）
    pub fn public_key(&self) -> PublicKey {
        let d = U256::from_be_slice(&self.bytes);
        let pub_jac = JacobianPoint::scalar_mul_g(&d);
        // Reason: 私钥合法性已在构造时验证，scalar_mul_g 结果不会是无穷远点
        let pub_aff = pub_jac
            .to_affine()
            .expect("valid private key produces valid public key");
        PublicKey::from_bytes(&pub_aff.to_bytes())
            .expect("valid affine point produces valid public key")
    }
}

// 证书相关方法（需要 alloc feature）
#[cfg(feature = "alloc")]
impl PrivateKey {
    /// 将私钥编码为 SEC1 DER 格式
    pub fn to_sec1_der(&self) -> Vec<u8> {
        private_key_to_sec1_der(self)
    }

    /// 将私钥编码为 PKCS#8 DER 格式
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        private_key_to_pkcs8_der(self)
    }

    /// 将私钥编码为 SEC1 PEM 格式
    ///
    /// 将 SM2 私钥编码为 SEC1（RFC 5915）格式的 PEM。
    #[cfg(feature = "alloc")]
    pub fn to_sec1_pem(&self) -> Result<String, Error> {
        let der = private_key_to_sec1_der(self);
        pem::encode_string("EC PRIVATE KEY", Default::default(), &der)
            .map_err(|_| Error::InvalidPrivateKey)
    }

    /// 将私钥编码为 PKCS#8 PEM 格式
    ///
    /// 将 SM2 私钥编码为 PKCS#8（RFC 5958）格式的 PEM。
    #[cfg(feature = "alloc")]
    pub fn to_pkcs8_pem(&self) -> Result<String, Error> {
        let der = private_key_to_pkcs8_der(self);
        pem::encode_string("PRIVATE KEY", Default::default(), &der)
            .map_err(|_| Error::InvalidPrivateKey)
    }

    /// 从 SEC1 DER 解析私钥
    pub fn from_sec1_der(der: &[u8]) -> Result<Self, Error> {
        private_key_from_sec1_der(der)
    }

    /// 从 PKCS#8 DER 解析私钥
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        private_key_from_pkcs8_der(der)
    }

    /// 从 SEC1 PEM 解析私钥
    ///
    /// 从 SEC1 格式的 PEM 解析 SM2 私钥。
    #[cfg(feature = "alloc")]
    pub fn from_sec1_pem(pem: &[u8]) -> Result<Self, Error> {
        let (_label, der) = pem::decode_vec(pem).map_err(|_| Error::InvalidCertificate)?;
        private_key_from_sec1_der(&der)
    }

    /// 从 PKCS#8 PEM 解析私钥
    ///
    /// 从 PKCS#8 格式的 PEM 解析 SM2 私钥。
    #[cfg(feature = "alloc")]
    pub fn from_pkcs8_pem(pem: &[u8]) -> Result<Self, Error> {
        let (_label, der) = pem::decode_vec(pem).map_err(|_| Error::InvalidCertificate)?;
        private_key_from_pkcs8_der(&der)
    }
}

// ── 公钥类型 ──────────────────────────────────────────────────────────────────

/// SM2 公钥（65 字节未压缩格式：0x04 || X(32B) || Y(32B)）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; 65],
}

impl PublicKey {
    /// 从字节构造公钥（支持压缩格式和未压缩格式）
    ///
    /// 支持两种格式：
    /// - **未压缩格式 (65字节)**: `0x04 || X(32B) || Y(32B)`
    /// - **压缩格式 (33字节)**: `0x02/0x03 || X(32B)`（自动解压）
    ///
    /// # 参数
    /// - `bytes`: 公钥字节（65字节未压缩或33字节压缩格式）
    ///
    /// # 返回
    /// - `Ok(PublicKey)`: 解压后的65字节未压缩格式公钥
    /// - `Err(Error::InvalidPublicKey)`: 格式错误或坐标无效
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match bytes.len() {
            65 if bytes[0] == 0x04 => {
                let mut pubkey = [0u8; 65];
                pubkey.copy_from_slice(bytes);
                Ok(PublicKey { bytes: pubkey })
            }
            33 if bytes[0] == 0x02 || bytes[0] == 0x03 => {
                let mut compressed = [0u8; 33];
                compressed.copy_from_slice(bytes);
                Self::from_compressed(&compressed)
            }
            _ => Err(Error::InvalidPublicKey),
        }
    }

    /// 以字节引用访问公钥
    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.bytes
    }

    /// 将公钥转换为字节数组（不泄露值所有权）
    pub fn to_bytes(&self) -> [u8; 65] {
        self.bytes
    }

    /// 获取 X 坐标（32 字节）
    pub fn x(&self) -> [u8; 32] {
        let mut x = [0u8; 32];
        x.copy_from_slice(&self.bytes[1..33]);
        x
    }

    /// 获取 Y 坐标（32 字节）
    pub fn y(&self) -> [u8; 32] {
        let mut y = [0u8; 32];
        y.copy_from_slice(&self.bytes[33..65]);
        y
    }

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
    pub fn to_compressed(&self) -> Result<[u8; 33], Error> {
        let x = &self.x();
        let y = &self.y();

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
    pub fn from_compressed(compressed: &[u8; 33]) -> Result<Self, Error> {
        use crate::sm2::field::{fp_from_bytes, fp_sqrt, fp_to_bytes};

        let prefix = compressed[0];
        if prefix != 0x02 && prefix != 0x03 {
            return Err(Error::InvalidPublicKey);
        }

        // 提取 x 坐标
        let x_bytes: [u8; 32] = compressed[1..33].try_into().unwrap();
        let x = fp_from_bytes(&x_bytes);

        // 计算 y² = x³ + ax + b
        let a = CURVE_A;
        let b = CURVE_B;

        let x3 = field::fp_mul(&x, &field::fp_mul(&x, &x));
        let ax = field::fp_mul(&a, &x);
        let x3_plus_ax = field::fp_add(&x3, &ax);
        let y2 = field::fp_add(&x3_plus_ax, &b);

        // 计算 y = √y²
        let y = fp_sqrt(&y2).ok_or(Error::InvalidPublicKey)?;

        // 根据前缀选择正确的 y 值
        let y_is_odd = fp_to_bytes(&y)[31] & 1;
        let y_expected_odd = prefix == 0x03;

        let final_y = if (y_is_odd != 0) != y_expected_odd {
            field::fp_neg(&y)
        } else {
            y
        };

        let y_bytes = fp_to_bytes(&final_y);

        // 构建未压缩公钥
        let mut pub_key = [0u8; 65];
        pub_key[0] = 0x04;
        pub_key[1..33].copy_from_slice(&x_bytes);
        pub_key[33..65].copy_from_slice(&y_bytes);

        Ok(Self { bytes: pub_key })
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
    pub fn fingerprint(&self) -> [u8; 32] {
        use crate::sm3::Sm3Hasher;
        let mut hasher = Sm3Hasher::new();
        hasher.update(self.as_bytes());
        hasher.finalize()
    }

    /// 将公钥转换为 SPKI 格式
    #[cfg(feature = "alloc")]
    pub fn to_spki(
        &self,
    ) -> SubjectPublicKeyInfo<ObjectIdentifier, x509_cert::der::asn1::BitString> {
        use x509_cert::spki::EncodePublicKey;
        let document = &self.to_public_key_der().unwrap();
        let der_bytes = document.to_der().unwrap();
        SubjectPublicKeyInfo::<ObjectIdentifier, x509_cert::der::asn1::BitString>::from_der(
            &der_bytes,
        )
        .unwrap()
    }

    /// 将 SPKI 格式的公钥转换为 SM2 公钥
    #[cfg(feature = "alloc")]
    pub fn from_spki(
        spki: &SubjectPublicKeyInfo<ObjectIdentifier, x509_cert::der::asn1::BitString>,
    ) -> Self {
        use x509_cert::spki::DecodePublicKey;
        Self::from_public_key_der(&spki.to_der().unwrap()).unwrap()
    }
}

#[cfg(feature = "alloc")]
impl x509_cert::spki::EncodePublicKey for PublicKey {
    fn to_public_key_der(&self) -> x509_cert::spki::Result<x509_cert::der::Document> {
        use x509_cert::der::asn1::BitString;
        // 创建 BIT STRING（公钥数据）
        let subject_public_key =
            BitString::new(0, self.as_bytes()).map_err(|_| x509_cert::spki::Error::KeyMalformed)?;

        let spki = SubjectPublicKeyInfo {
            algorithm: SM2_SPKI_ALGORITHM,
            subject_public_key,
        };

        // 编码为 DER
        x509_cert::der::Document::encode_msg(&spki)
            .map_err(|_| x509_cert::spki::Error::KeyMalformed)
    }
}

#[cfg(feature = "alloc")]
impl x509_cert::spki::DecodePublicKey for PublicKey {
    fn from_public_key_der(bytes: &[u8]) -> x509_cert::spki::Result<Self> {
        use x509_cert::der::asn1::BitString;
        // 解析 SPKI
        let spki: SubjectPublicKeyInfo<ObjectIdentifier, BitString> =
            SubjectPublicKeyInfo::from_der(bytes)
                .map_err(|_| Error::InvalidPublicKey)
                .unwrap();

        // 验证算法 OID（id-ecPublicKey）
        if spki.algorithm.oid != EC_PUBKEY_OID {
            return Err(x509_cert::spki::Error::OidUnknown {
                oid: spki.algorithm.oid,
            });
        }

        // 验证参数 OID（SM2 曲线）
        match spki.algorithm.parameters {
            Some(oid) if oid == SM2_CURVE_OID => {}
            _ => return Err(x509_cert::spki::Error::KeyMalformed),
        }

        // 提取公钥数据
        let pub_key_bytes: &[u8] = spki.subject_public_key.raw_bytes();
        // 验证公钥长度（应为 65 字节：0x04 || X(32B) || Y(32B)）
        if pub_key_bytes.len() != 65 {
            return Err(x509_cert::spki::Error::KeyMalformed);
        }

        let mut bytes = [0u8; 65];
        bytes.copy_from_slice(pub_key_bytes);
        Ok(Self::from_bytes(&bytes).unwrap())
    }
}

// ── 密钥生成 ──────────────────────────────────────────────────────────────────

/// 生成 SM2 密钥对（私钥 + 公钥）
///
/// 符合 GB/T 32918.1-2016 §6.1
/// 需要提供 `rand_core::Rng` 实现（如 `rand::rngs::StdRng`）。
pub fn generate_keypair<R: Rng>(rng: &mut R) -> (PrivateKey, PublicKey) {
    loop {
        let mut d_bytes = [0u8; 32];
        rng.fill_bytes(&mut d_bytes);
        let d = U256::from_be_slice(&d_bytes);
        // 私钥 d ∈ [1, n-2]
        if bool::from(d.is_zero()) || d >= GROUP_ORDER_MINUS_1 {
            d_bytes.zeroize();
            continue;
        }
        // Reason: 私钥满足范围约束，PrivateKey::from_bytes 不会失败
        let priv_key = PrivateKey { bytes: d_bytes };
        let pub_key = priv_key.public_key();
        return (priv_key, pub_key);
    }
}

// ── Z 值计算（GB/T 32918.2-2016 §5.5）────────────────────────────────────────

/// 计算用户标识的 Z 值
///
/// Z = SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)
///
/// # 参数
/// - `id`: 用户可辨别标识（通常使用 `b"1234567812345678"` 作为���认值）
/// - `pub_key`: 用户公钥（65 字节，04||x||y）
pub fn get_z(id: &[u8], pub_key: &[u8; 65]) -> [u8; 32] {
    // ENTL：ID 长度（比特数），2 字节大端
    let entl = (id.len() * 8) as u16;
    let mut h = Sm3Hasher::new();
    h.update(&entl.to_be_bytes());
    h.update(id);
    h.update(&fp_to_bytes(&CURVE_A));
    h.update(&fp_to_bytes(&CURVE_B));
    h.update(&fp_to_bytes(&GX));
    h.update(&fp_to_bytes(&GY));
    h.update(&pub_key[1..33]); // Px
    h.update(&pub_key[33..65]); // Py
    h.finalize()
}

/// 计算消息摘要 e = SM3(Z || M)
///
/// 符合 GB/T 32918.2-2016 §5.5
pub fn get_e(z: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut h = Sm3Hasher::new();
    h.update(z);
    h.update(msg);
    h.finalize()
}

// ── 数字签名（GB/T 32918.2-2016 §6.2）───────────────────────────────────────

/// SM2 签名（使用指定随机数 k，用于确定性测试和标准向量验证）
///
/// # 参数
/// - `e`: 消息摘要 e = SM3(Z||M)（32 字节）
/// - `pri_key`: 私钥
/// - `k`: 随机数 k ∈ [1, n-1]
///
/// # 返回
/// 64 字节签名 r||s，或错误码
pub fn sign_with_k(e: &[u8; 32], pri_key: &PrivateKey, k: &U256) -> Result<[u8; 64], Error> {
    let d = U256::from_be_slice(pri_key.as_bytes());

    // 步骤 2：计算 (x1, y1) = k·G
    let kg_aff = JacobianPoint::scalar_mul_g(k)
        .to_affine()
        .map_err(|_| Error::InvalidSignature)?;
    let x1 = fp_to_bytes(&kg_aff.x);

    // 步骤 3：r = (e + x1) mod n
    let e_val = U256::from_be_slice(e);
    let x1_val = U256::from_be_slice(&x1);
    let r_fn = fn_add(&Fn::new(&e_val), &Fn::new(&x1_val));
    let r = r_fn.retrieve();

    // r == 0 或 r+k == n 时无效（此随机数不可用）
    if bool::from(r.is_zero()) {
        return Err(Error::InvalidSignature);
    }
    if fn_add(&r_fn, &Fn::new(k)).retrieve().is_zero().into() {
        return Err(Error::InvalidSignature);
    }

    // 步骤 4：s = (1+d)^-1 · (k - r·d) mod n
    let d_fn = Fn::new(&d);
    let one_plus_d = fn_add(&Fn::ONE, &d_fn);
    let inv = fn_inv(&one_plus_d).ok_or(Error::InvalidPrivateKey)?;
    let rd = fn_mul(&r_fn, &d_fn);
    let s_fn = fn_mul(&inv, &fn_sub(&Fn::new(k), &rd));
    let s = s_fn.retrieve();

    if bool::from(s.is_zero()) {
        return Err(Error::InvalidSignature);
    }

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r.to_be_bytes());
    sig[32..].copy_from_slice(&s.to_be_bytes());
    Ok(sig)
}

/// SM2 签名（标准接口，随机 k）
///
/// # 合规说明
/// 此函数接受预计算好的消息摘要 `e = SM3(Z||M)`。
/// 调用方应先用 `get_z` + `get_e` 计算 e，确保满足 GB/T 32918.2-2016 §5.5。
/// SM2 签名（便捷接口，自动计算 Z 值与消息摘要）
///
/// 等同于 `get_z` + `get_e` + `sign` 的组合，适合不需要手动管理摘要的场景。
///
/// # 参数
/// - `msg`: 原始消息
/// - `id`: 用户可辨别标识（通常使用 `b"1234567812345678"`）
/// - `pri_key`: 私钥
/// - `rng`: 随机数生成器
///
/// # 合规说明
/// 内部自动计算 `Z = SM3(ENTL||ID||a||b||Gx||Gy||Px||Py)` 和 `e = SM3(Z||M)`，
/// 符合 GB/T 32918.2-2016 §5.5。
pub fn sign_message<R: Rng>(msg: &[u8], id: &[u8], pri_key: &PrivateKey, rng: &mut R) -> [u8; 64] {
    let pub_key = pri_key.public_key();
    let z = get_z(id, pub_key.as_bytes());
    let e = get_e(&z, msg);
    sign(&e, pri_key, rng)
}

/// SM2 验签（便捷接口，自动计算 Z 值与消息摘要）
///
/// 等同于 `get_z` + `get_e` + `verify` 的组合。
///
/// # 参数
/// - `msg`: 原始消息
/// - `id`: 用户可辨别标识
/// - `pub_key`: 公钥
/// - `sig`: 签名（64 字节，r||s）
pub fn verify_message(
    msg: &[u8],
    id: &[u8],
    pub_key: &[u8; 65],
    sig: &[u8; 64],
) -> Result<(), Error> {
    let z = get_z(id, pub_key);
    let e = get_e(&z, msg);
    verify(&e, pub_key, sig)
}

/// SM2 签名（标准接口，随机 k）
///
/// # 合规说明
/// 此函数接受预计算好的消息摘要 `e = SM3(Z||M)`。
/// 调用方应先用 `get_z` + `get_e` 计算 e，确保满足 GB/T 32918.2-2016 §5.5。
pub fn sign<R: Rng>(e: &[u8; 32], pri_key: &PrivateKey, rng: &mut R) -> [u8; 64] {
    loop {
        let mut k_bytes = [0u8; 32];
        rng.fill_bytes(&mut k_bytes);
        let k = U256::from_be_slice(&k_bytes);
        k_bytes.zeroize();
        if bool::from(k.is_zero()) || k >= GROUP_ORDER {
            continue;
        }
        if let Ok(sig) = sign_with_k(e, pri_key, &k) {
            return sig;
        }
    }
}

// ── 签名验证（GB/T 32918.2-2016 §6.3）───────────────────────────────────────

/// SM2 验签
///
/// # 参数
/// - `e`: 消息摘要 e = SM3(Z||M)（32 字节）
/// - `pub_key`: 公钥
/// - `sig`: 签名（64 字节，r||s）
///
/// # 返回
/// 验证通过返回 `Ok(())`，否则返回错误码
pub fn verify(e: &[u8; 32], pub_key: &[u8; 65], sig: &[u8; 64]) -> Result<(), Error> {
    let r = U256::from_be_slice(&sig[..32]);
    let s = U256::from_be_slice(&sig[32..]);
    let n = GROUP_ORDER;

    // 步骤 1：r, s ∈ [1, n-1]
    if bool::from(r.is_zero()) || r >= n || bool::from(s.is_zero()) || s >= n {
        return Err(Error::InvalidSignature);
    }

    // 步骤 2：t = (r + s) mod n，t ≠ 0
    let t_fn = fn_add(&Fn::new(&r), &Fn::new(&s));
    let t = t_fn.retrieve();
    if bool::from(t.is_zero()) {
        return Err(Error::VerifyFailed);
    }

    // 步骤 3：P = s·G + t·PA
    let pa = AffinePoint::from_bytes(pub_key)?;
    let point = multi_scalar_mul(&s, &t, &pa)?;

    // 步骤 4：R = (e + P.x) mod n，验证 R == r
    let e_val = U256::from_be_slice(e);
    let px_val = U256::from_be_slice(&fp_to_bytes(&point.x));
    let r_check = fn_add(&Fn::new(&e_val), &Fn::new(&px_val)).retrieve();

    // 常量时间比较防时序侧信道
    // Reason: r 和 r_check 都是 U256（32 字节），ct_eq 是字节级常量时间操作
    if r.to_be_bytes().ct_eq(&r_check.to_be_bytes()).unwrap_u8() != 1 {
        return Err(Error::VerifyFailed);
    }
    Ok(())
}

// ── 公钥加密（GB/T 32918.4-2016 §7.1）──────────────────────────────────────

/// SM2 公钥加密
///
/// 输出格式：C1||C3||C2（新格式，GB/T 32918.4-2016 §6.1）
/// - C1：65 字节，04||x||y（随机点 k·G）
/// - C3：32 字节，SM3(x2||M||y2)
/// - C2：len(M) 字节，M ⊕ KDF(x2||y2, len(M))
///
/// 需要 `alloc` feature。
#[cfg(feature = "alloc")]
pub fn encrypt<R: Rng>(pub_key: &PublicKey, message: &[u8], rng: &mut R) -> Result<Vec<u8>, Error> {
    let pa = AffinePoint::from_bytes(pub_key.as_bytes())?;

    loop {
        // A1：生成随机 k ∈ [1, n-1]
        let mut k_bytes = [0u8; 32];
        rng.fill_bytes(&mut k_bytes);
        let k = U256::from_be_slice(&k_bytes);
        k_bytes.zeroize();
        if bool::from(k.is_zero()) || k >= GROUP_ORDER {
            continue;
        }

        // A2：C1 = k·G
        let c1_aff = match JacobianPoint::scalar_mul_g(&k).to_affine() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let c1 = c1_aff.to_bytes();

        // A3：计算 k·PA
        let pa_jac = JacobianPoint::from_affine(&pa);
        let kpa_aff = match JacobianPoint::scalar_mul(&k, &pa_jac).to_affine() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let x2 = fp_to_bytes(&kpa_aff.x);
        let y2 = fp_to_bytes(&kpa_aff.y);

        // A4：t = KDF(x2||y2, klen)
        let mut z_input = [0u8; 64];
        z_input[..32].copy_from_slice(&x2);
        z_input[32..].copy_from_slice(&y2);
        let t = crate::kdf::kdf(&z_input, message.len());

        // t 全零时重新选 k（空消息时跳过此检查）
        // Reason: 使用常量时间全零检查，防止时序侧信道泄露 t 的内容
        if !t.is_empty() {
            let mut all_zero = 0u8;
            for &b in &t {
                all_zero |= b;
            }
            if all_zero == 0 {
                continue;
            }
        }

        // A5：C2 = M ⊕ t
        let c2: Vec<u8> = message.iter().zip(t.iter()).map(|(&m, &k)| m ^ k).collect();

        // A6：C3 = SM3(x2||M||y2)
        let mut h = Sm3Hasher::new();
        h.update(&x2);
        h.update(message);
        h.update(&y2);
        let c3 = h.finalize();

        // 输出 C1||C3||C2
        let mut output = Vec::with_capacity(65 + 32 + message.len());
        output.extend_from_slice(&c1);
        output.extend_from_slice(&c3);
        output.extend_from_slice(&c2);
        return Ok(output);
    }
}

// ── 公钥解密（GB/T 32918.4-2016 §7.2）──────────────────────────────────────

/// SM2 公钥解密（新格式 C1||C3||C2）
///
/// 解密后对 C3 进行常量时间验证，防止 padding oracle 攻击。
/// 需要 `alloc` feature。
#[cfg(feature = "alloc")]
pub fn decrypt(pri_key: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    // 最短：C1(65) + C3(32) + C2(0+) = 97
    if ciphertext.len() < 97 {
        return Err(Error::InvalidInputLength);
    }

    let d = U256::from_be_slice(pri_key.as_bytes());

    // 解析 C1（65 字节）
    let c1_bytes: [u8; 65] = ciphertext[0..65].try_into().unwrap();
    let c1 = AffinePoint::from_bytes(&c1_bytes)?;

    // 解析 C3（32 字节）和 C2
    let c3_expected: [u8; 32] = ciphertext[65..97].try_into().unwrap();
    let c2 = &ciphertext[97..];

    // 计算 d·C1
    let c1_jac = JacobianPoint::from_affine(&c1);
    let dc1_aff = JacobianPoint::scalar_mul(&d, &c1_jac).to_affine()?;
    let x2 = fp_to_bytes(&dc1_aff.x);
    let y2 = fp_to_bytes(&dc1_aff.y);

    // t = KDF(x2||y2, klen)
    let mut z_input = [0u8; 64];
    z_input[..32].copy_from_slice(&x2);
    z_input[32..].copy_from_slice(&y2);
    let t = crate::kdf::kdf(&z_input, c2.len());

    // t 全零时解密失败（空消息时跳过此检查）
    // Reason: 使用常量时间全零检查，防止时序侧信道泄露 t 的内容
    if !t.is_empty() {
        let mut all_zero = 0u8;
        for &b in &t {
            all_zero |= b;
        }
        if all_zero == 0 {
            return Err(Error::DecryptFailed);
        }
    }

    // 恢复候选明文 M' = C2 ⊕ t
    let m: Vec<u8> = c2.iter().zip(t.iter()).map(|(&c, &k)| c ^ k).collect();

    // 验证 C3 = SM3(x2||M'||y2)（常量时间比较）
    let mut h = Sm3Hasher::new();
    h.update(&x2);
    h.update(&m);
    h.update(&y2);
    let c3_computed = h.finalize();

    // Reason: 先验证 C3 再返回明文，防止 chosen-ciphertext 攻击
    if c3_expected.ct_eq(&c3_computed).unwrap_u8() != 1 {
        return Err(Error::DecryptFailed);
    }
    Ok(m)
}

// ── 密钥封装机制 KEM（GB/T 32918.4-2016 §8）──────────────────────────────────

/// SM2 密钥封装（KEM 封装）
///
/// 根据 GB/T 32918.4-2016 §8.1 实现密钥封装机制。
/// 封装一个随机密钥，返回（密文，共享密钥）对。
///
/// # 参数
/// - `pub_key`: 接收方的公钥
/// - `key_len`: 期望的共享密钥长度（字节）
/// - `rng`: 随机数生成器
///
/// # 返回
/// - `(密文, 共享密钥)`: 密文为 C1||C2 格式，共享密钥为派生的密钥材料
///
/// # 标准
/// - GB/T 32918.4-2016 §8.1（KEM 封装）
#[cfg(feature = "alloc")]
pub fn kem_encrypt<R: Rng>(
    pub_key: &PublicKey,
    key_len: usize,
    rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if key_len == 0 {
        return Err(Error::InvalidInputLength);
    }

    let pa = AffinePoint::from_bytes(pub_key.as_bytes())?;

    loop {
        // A1：生成随机 k ∈ [1, n-1]
        let mut k_bytes = [0u8; 32];
        rng.fill_bytes(&mut k_bytes);
        let k = U256::from_be_slice(&k_bytes);
        k_bytes.zeroize();
        if bool::from(k.is_zero()) || k >= GROUP_ORDER {
            continue;
        }

        // A2：C1 = k·G
        let c1_aff = match JacobianPoint::scalar_mul_g(&k).to_affine() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let c1 = c1_aff.to_bytes();

        // A3：计算 k·PA
        let pa_jac = JacobianPoint::from_affine(&pa);
        let kpa_aff = match JacobianPoint::scalar_mul(&k, &pa_jac).to_affine() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let x2 = fp_to_bytes(&kpa_aff.x);
        let y2 = fp_to_bytes(&kpa_aff.y);

        // A4：K = KDF(x2||y2, klen)
        let mut z_input = [0u8; 64];
        z_input[..32].copy_from_slice(&x2);
        z_input[32..].copy_from_slice(&y2);
        let k_key = crate::kdf::kdf(&z_input, key_len);

        // K 全零时重新选 k
        // Reason: 使用常量时间全零检查，防止时序侧信道泄露 K 的内容
        {
            let mut all_zero = 0u8;
            for &b in &k_key {
                all_zero |= b;
            }
            if all_zero == 0 {
                continue;
            }
        }

        // 输出 C1（65 字节）作为封装密文
        let ciphertext = c1.to_vec();

        return Ok((ciphertext, k_key));
    }
}

/// SM2 密钥解封（KEM 解封）
///
/// 根据 GB/T 32918.4-2016 §8.2 实现密钥解封机制。
/// 从密文中解封出共享密钥。
///
/// # 参数
/// - `pri_key`: 接收方的私钥
/// - `ciphertext`: 封装密文（C1 格式，65 字节）
/// - `key_len`: 期望的共享密钥长度（字节）
///
/// # 返回
/// - `共享密钥`: 派生的密钥材料
///
/// # 标准
/// - GB/T 32918.4-2016 §8.2（KEM 解封）
#[cfg(feature = "alloc")]
pub fn kem_decrypt(
    pri_key: &PrivateKey,
    ciphertext: &[u8],
    key_len: usize,
) -> Result<Vec<u8>, Error> {
    if key_len == 0 {
        return Err(Error::InvalidInputLength);
    }

    // 密文应为 C1（65 字节）
    if ciphertext.len() != 65 {
        return Err(Error::InvalidInputLength);
    }

    let d = U256::from_be_slice(pri_key.as_bytes());

    // 解析 C1
    let c1_bytes: [u8; 65] = ciphertext[0..65].try_into().unwrap();
    let c1 = AffinePoint::from_bytes(&c1_bytes)?;

    // 计算 d·C1
    let c1_jac = JacobianPoint::from_affine(&c1);
    let dc1_aff = JacobianPoint::scalar_mul(&d, &c1_jac).to_affine()?;
    let x2 = fp_to_bytes(&dc1_aff.x);
    let y2 = fp_to_bytes(&dc1_aff.y);

    // K = KDF(x2||y2, klen)
    let mut z_input = [0u8; 64];
    z_input[..32].copy_from_slice(&x2);
    z_input[32..].copy_from_slice(&y2);
    let k_key = crate::kdf::kdf(&z_input, key_len);

    // K 全零时解封失败
    // Reason: 使用常量时间全零检查，防止时序侧信道泄露 K 的内容
    {
        let mut all_zero = 0u8;
        for &b in &k_key {
            all_zero |= b;
        }
        if all_zero == 0 {
            return Err(Error::DecryptFailed);
        }
    }

    Ok(k_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    struct FakeRng([u8; 32]);
    impl rand_core::TryRng for FakeRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            for (i, b) in dest.iter_mut().enumerate() {
                *b = self.0[i % 32];
            }
            Ok(())
        }
    }

    #[test]
    fn test_sign_with_k_basic() {
        // 测试 sign_with_k 基本功能
        let d_bytes: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
            0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
            0x4d, 0xf7, 0xc5, 0xb8,
        ];
        let pri_key = PrivateKey::from_bytes(&d_bytes).expect("私钥有效");
        let pub_key = pri_key.public_key();

        let msg = b"hello sm2";
        let z = get_z(DEFAULT_ID, &pub_key.as_bytes());
        let e = get_e(&z, msg);

        // 使用固定 k（仅测试用）—— k 必须 ∈ [1, n-1]
        let k_bytes: [u8; 32] = [
            0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a, 0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0,
            0x2d, 0xcc, 0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce, 0x6d, 0x54, 0xb8, 0x0d,
            0xea, 0xc1, 0xbc, 0x21,
        ];
        let k = U256::from_be_slice(&k_bytes);
        let sig = sign_with_k(&e, &pri_key, &k).expect("签名应成功");

        verify(&e, &pub_key.as_bytes(), &sig).expect("验签应通过");
    }

    #[test]
    fn test_get_z_basic() {
        // 测试 Z 值计算基本功能
        let pub_key = PublicKey::from_bytes(&[0x04u8; 65]).expect("公钥应有效");
        let z1 = get_z(DEFAULT_ID, &pub_key.as_bytes());
        let z2 = get_z(DEFAULT_ID, &pub_key.as_bytes());
        assert_eq!(z1, z2);
    }
}
