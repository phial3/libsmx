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

// 重新导出 der 模块的密钥编解码函数
#[cfg(feature = "alloc")]
pub use der::{
    private_key_from_pkcs8_der, private_key_from_sec1_der, private_key_to_pkcs8_der,
    private_key_to_sec1_der, public_key_from_spki_der, public_key_to_spki_der,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use x509_cert::der::pem::{decode_vec, encode_string};

use crypto_bigint::U256;
use rand_core::Rng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use x509_cert::der::asn1::ObjectIdentifier;

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

/// SM2 椭圆曲线公钥算法 sm2p256v1 OID (1.2.156.10197.1.301)
pub const SM2_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.1.301");

/// SM2withSM3 签名算法 OID (1.2.156.10197.1.501)
/// 与 SM2_SIGN_OID 相同，用于 X.509 证书签名算法标识
pub const SM2_WITH_SM3_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.1.501");

/// SM3 哈希算法 OID (1.2.156.10197.1.401)
pub const SM3_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.1.401");

/// EC 公钥算法 OID (1.2.840.10045.2.1)
/// 通用椭圆曲线公钥算法 OID（id-ecPublicKey），与 SM2 算法 OID 配合使用
pub const EC_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// PKCS#7/CMS SignedData OID (1.2.840.113549.1.7.2)
/// 用于 PKCS#7/CMS 签名数据内容类型
pub const PKCS7_SIGNED_DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// id-data OID (1.2.840.113549.1.7.1)
/// 用于 PKCS#7/CMS 数据内容类型
pub const ID_DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// content-type 属性 OID (1.2.840.113549.1.9.3)
/// 用于 CMS 签名属性 content-type
pub const CONTENT_TYPE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// message-digest 属性 OID (1.2.840.113549.1.9.4)
/// 用于 CMS 签名属性 message-digest
pub const MESSAGE_DIGEST_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// signing-time 属性 OID (1.2.840.113549.1.9.5)
/// 用于 CMS 签名属性 signing-time
pub const SIGNING_TIME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

// ====================================================================================
// 证书扩展 OID (X.509 v3 Extensions)
// ====================================================================================

/// id-ce-basicConstraints OID (2.5.29.19)
/// 基本约束扩展，用于标识 CA 证书和路径长度约束
pub const ID_CE_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

/// id-ce-keyUsage OID (2.5.29.15)
/// 密钥用途扩展，标识证书公钥的用途
pub const ID_CE_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

/// id-ce-extKeyUsage OID (2.5.29.37)
/// 扩展密钥用途扩展，指示证书的一个或多个用途
pub const ID_CE_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// id-ce-subjectAltName OID (2.5.29.17)
/// 主体备用名称扩展
pub const ID_CE_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// id-ce-issuerAltName OID (2.5.29.18)
/// 签发者备用名称扩展
pub const ID_CE_ISSUER_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.18");

/// id-ce-certificatePolicies OID (2.5.29.32)
/// 证书策略扩展
pub const ID_CE_CERTIFICATE_POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");

/// id-ce-cRLDistributionPoints OID (2.5.29.31)
/// CRL 分发点扩展
pub const ID_CE_CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");

/// id-ce-authorityKeyIdentifier OID (2.5.29.35)
/// 机构密钥标识符扩展
pub const ID_CE_AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");

/// id-ce-subjectKeyIdentifier OID (2.5.29.14)
/// 主体密钥标识符扩展
pub const ID_CE_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

/// anyExtendedKeyUsage OID (2.5.29.37.0)
/// 任何扩展密钥用途
pub const ANY_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37.0");

/// 扩展密钥用途 OID 常量
///
/// id-kp-serverAuth OID (1.3.6.1.5.5.7.3.1)
/// 服务器认证密钥用途
pub const ID_KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

/// id-kp-clientAuth OID (1.3.6.1.5.5.7.3.2)
/// 客户端认证密钥用途
pub const ID_KP_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

/// id-kp-codeSigning OID (1.3.6.1.5.5.7.3.3)
/// 代码签名密钥用途
pub const ID_KP_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

/// id-kp-emailProtection OID (1.3.6.1.5.5.7.3.4)
/// 电子邮件保护密钥用途
pub const ID_KP_EMAIL_PROTECTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");

/// SM2 椭圆曲线算法标识符（用于 SubjectPublicKeyInfo）
///
/// 完整的 AlgorithmIdentifier DER 编码，包含 id-ecPublicKey 和 SM2 曲线参数：
/// SEQUENCE { OID id-ecPublicKey (1.2.840.10045.2.1), OID SM2 (1.2.156.10197.1.301) }
pub const SM2_EC_PUBKEY_PARAMETER: &[u8] = &[
    0x30, 0x13, // SEQUENCE, length = 19
    0x06, 0x07, // OID, length = 7
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // id-ecPublicKey (1.2.840.10045.2.1)
    0x06, 0x08, // OID, length = 8
    0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D, // SM2 (1.2.156.10197.1.301)
];

/// SM2withSM3 签名算法标识符（用于 X.509 证书签名算法）
///
/// 完整的 AlgorithmIdentifier for SM2withSM3 DER 编码：
/// SEQUENCE { OID SM2withSM3 (1.2.156.10197.1.501) }
/// 注意：国密标准中 SM2withSM3 算法标识符不包含 parameters
pub const SM2_WITH_SM3_ALGORITHM_IDENTIFIER: &[u8] = &[
    0x30, 0x0A, // SEQUENCE, length = 10
    0x06, 0x08, // OID, length = 8
    0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75, // SM2withSM3 (1.2.156.10197.1.501)
];

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

    /// 计算对应公钥（65 字节，04||x||y）
    pub fn public_key(&self) -> [u8; 65] {
        let d = U256::from_be_slice(&self.bytes);
        let pub_jac = JacobianPoint::scalar_mul_g(&d);
        // Reason: 私钥合法性已在构造时验证，scalar_mul_g 结果不会是无穷远点
        let pub_aff = pub_jac
            .to_affine()
            .expect("valid private key produces valid public key");
        pub_aff.to_bytes()
    }
}

// 证书相关方法（需要 alloc feature）
#[cfg(feature = "alloc")]
impl PrivateKey {
    /// 将私钥编码为 SEC1 DER 格式
    pub fn to_sec1_der(&self) -> Vec<u8> {
        der::private_key_to_sec1_der(self)
    }

    /// 将私钥编码为 PKCS#8 DER 格式
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        der::private_key_to_pkcs8_der(self)
    }

    /// 将私钥编码为 SEC1 PEM 格式
    ///
    /// 将 SM2 私钥编码为 SEC1（RFC 5915）格式的 PEM。
    pub fn to_sec1_pem(&self) -> Result<Vec<u8>, Error> {
        let der = der::private_key_to_sec1_der(self);
        let pem = encode_string("EC PRIVATE KEY", Default::default(), &der)
            .map_err(|_| Error::InvalidCertificate)?;
        Ok(pem.as_bytes().to_vec())
    }

    /// 将私钥编码为 PKCS#8 PEM 格式
    ///
    /// 将 SM2 私钥编码为 PKCS#8（RFC 5958）格式的 PEM。
    pub fn to_pkcs8_pem(&self) -> Result<Vec<u8>, Error> {
        let der = der::private_key_to_pkcs8_der(self);
        let pem = encode_string("PRIVATE KEY", Default::default(), &der)
            .map_err(|_| Error::InvalidCertificate)?;
        Ok(pem.as_bytes().to_vec())
    }

    /// 从 SEC1 DER 解析私钥
    pub fn from_sec1_der(der: &[u8]) -> Result<Self, Error> {
        der::private_key_from_sec1_der(der)
    }

    /// 从 PKCS#8 DER 解析私钥
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        der::private_key_from_pkcs8_der(der)
    }

    /// 从 SEC1 PEM 解析私钥
    ///
    /// 从 SEC1 格式的 PEM 解析 SM2 私钥。
    pub fn from_sec1_pem(pem: &[u8]) -> Result<Self, Error> {
        let (_label, der) = decode_vec(pem).map_err(|_| Error::InvalidCertificate)?;
        der::private_key_from_sec1_der(&der)
    }

    /// 从 PKCS#8 PEM 解析私钥
    ///
    /// 从 PKCS#8 格式的 PEM 解析 SM2 私钥。
    pub fn from_pkcs8_pem(pem: &[u8]) -> Result<Self, Error> {
        let (_label, der) = decode_vec(pem).map_err(|_| Error::InvalidCertificate)?;
        der::private_key_from_pkcs8_der(&der)
    }
}

// ── 密钥生成 ──────────────────────────────────────────────────────────────────

/// 生成 SM2 密钥对（私钥 + 公钥 65 字节）
///
/// 符合 GB/T 32918.1-2016 §6.1
/// 需要提供 `rand_core::RngCore` 实现（如 `rand::rngs::OsRng`）。
pub fn generate_keypair<R: Rng>(rng: &mut R) -> (PrivateKey, [u8; 65]) {
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
    let z = get_z(id, &pub_key);
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
/// - `pub_key`: 公钥（65 字节，04||x||y）
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
/// - `pub_key`: 公钥（65 字节，04||x||y）
/// - `sig`: 签名（64 字��，r||s）
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
pub fn encrypt<R: Rng>(pub_key: &[u8; 65], message: &[u8], rng: &mut R) -> Result<Vec<u8>, Error> {
    let pa = AffinePoint::from_bytes(pub_key)?;

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
        if !t.is_empty() && t.iter().all(|&b| b == 0) {
            continue;
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
    if !t.is_empty() && t.iter().all(|&b| b == 0) {
        return Err(Error::DecryptFailed);
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_get_z_deterministic() {
        let pub_key = [0x04u8; 65];
        let z1 = get_z(DEFAULT_ID, &pub_key);
        let z2 = get_z(DEFAULT_ID, &pub_key);
        assert_eq!(z1, z2);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        // 使用 GB/T 32918 附录 A 的私钥示例（私钥需在 [1, n-2]）
        let d_bytes: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
            0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
            0x4d, 0xf7, 0xc5, 0xb8,
        ];
        let pri_key = PrivateKey::from_bytes(&d_bytes).expect("私钥有效");
        let pub_key = pri_key.public_key();

        let msg = b"hello sm2";
        let z = get_z(DEFAULT_ID, &pub_key);
        let e = get_e(&z, msg);

        // 使用固定 k（仅测试用）—— k 必须 ∈ [1, n-1]
        let k_bytes: [u8; 32] = [
            0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a, 0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0,
            0x2d, 0xcc, 0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce, 0x6d, 0x54, 0xb8, 0x0d,
            0xea, 0xc1, 0xbc, 0x21,
        ];
        let k = U256::from_be_slice(&k_bytes);
        let sig = sign_with_k(&e, &pri_key, &k).expect("签名应成功");

        verify(&e, &pub_key, &sig).expect("验签应通过");
    }

    #[test]
    fn test_verify_rejects_tampered_sig() {
        let d_bytes: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
            0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
            0x4d, 0xf7, 0xc5, 0xb8,
        ];
        let pri_key = PrivateKey::from_bytes(&d_bytes).unwrap();
        let pub_key = pri_key.public_key();

        let msg = b"hello sm2";
        let z = get_z(DEFAULT_ID, &pub_key);
        let e = get_e(&z, msg);

        let k_bytes: [u8; 32] = [
            0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a, 0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0,
            0x2d, 0xcc, 0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce, 0x6d, 0x54, 0xb8, 0x0d,
            0xea, 0xc1, 0xbc, 0x21,
        ];
        let k = U256::from_be_slice(&k_bytes);
        let mut sig = sign_with_k(&e, &pri_key, &k).unwrap();

        // 篡改签名第一个字节
        sig[0] ^= 0x01;
        assert!(verify(&e, &pub_key, &sig).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let d_bytes: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
            0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
            0x4d, 0xf7, 0xc5, 0xb8,
        ];
        let pri_key = PrivateKey::from_bytes(&d_bytes).unwrap();
        let pub_key = pri_key.public_key();
        let msg = b"Hello, SM2 encryption!";

        // 使用固定随机数（测试专用）
        let mut rng = FakeRng([
            0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a, 0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0,
            0x2d, 0xcc, 0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce, 0x6d, 0x54, 0xb8, 0x0d,
            0xea, 0xc1, 0xbc, 0x21,
        ]);

        let ciphertext = encrypt(&pub_key, msg, &mut rng).expect("加密应成功");
        let plaintext = decrypt(&pri_key, &ciphertext).expect("解密应成功");
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_sign_message_verify_message_roundtrip() {
        let d_bytes: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
            0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
            0x4d, 0xf7, 0xc5, 0xb8,
        ];
        let pri_key = PrivateKey::from_bytes(&d_bytes).unwrap();
        let pub_key = pri_key.public_key();

        let mut rng = FakeRng([
            0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a, 0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0,
            0x2d, 0xcc, 0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce, 0x6d, 0x54, 0xb8, 0x0d,
            0xea, 0xc1, 0xbc, 0x21,
        ]);

        let msg = b"hello sign_message";
        let sig = sign_message(msg, DEFAULT_ID, &pri_key, &mut rng);
        verify_message(msg, DEFAULT_ID, &pub_key, &sig).expect("便捷验签应通过");
    }

    #[test]
    fn test_verify_message_rejects_wrong_id() {
        let d_bytes: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
            0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
            0x4d, 0xf7, 0xc5, 0xb8,
        ];
        let pri_key = PrivateKey::from_bytes(&d_bytes).unwrap();
        let pub_key = pri_key.public_key();

        let mut rng = FakeRng([
            0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a, 0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0,
            0x2d, 0xcc, 0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce, 0x6d, 0x54, 0xb8, 0x0d,
            0xea, 0xc1, 0xbc, 0x21,
        ]);

        let msg = b"hello sign_message";
        let sig = sign_message(msg, DEFAULT_ID, &pri_key, &mut rng);
        // 用错误 ID 验签应失败
        assert!(verify_message(msg, b"wrong-id", &pub_key, &sig).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_decrypt_rejects_tampered_ciphertext() {
        let d_bytes: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
            0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
            0x4d, 0xf7, 0xc5, 0xb8,
        ];
        let pri_key = PrivateKey::from_bytes(&d_bytes).unwrap();
        let pub_key = pri_key.public_key();
        let msg = b"test message";

        let mut rng = FakeRng([
            0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a, 0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0,
            0x2d, 0xcc, 0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce, 0x6d, 0x54, 0xb8, 0x0d,
            0xea, 0xc1, 0xbc, 0x21,
        ]);

        let mut ciphertext = encrypt(&pub_key, msg, &mut rng).unwrap();
        // 篡改 C3 部分（字节 65..97）
        ciphertext[70] ^= 0xFF;
        assert!(decrypt(&pri_key, &ciphertext).is_err());
    }
}
