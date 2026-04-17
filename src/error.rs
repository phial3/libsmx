//! 统一错误类型
//!
//! 所有 libsmx 操作均通过此模块中的 [`Error`] 类型报告错误，
//! 兼容 `no_std` 环境（不依赖 `std::error::Error` trait）。

#[cfg(feature = "alloc")]
use alloc::string::String;
use core::fmt;

/// libsmx 统一错误类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    // ── SM2 错误 ────────────────────────────────────────────────────────────
    /// 私钥不在合法范围 [1, n-2]
    InvalidPrivateKey,
    /// 公钥不在椭圆曲线上或格式错误
    InvalidPublicKey,
    /// 签名值 (r, s) 格式或范围不合法
    InvalidSignature,
    /// 签名验证失败（r_check ≠ r）
    VerifyFailed,
    /// 解密失败（MAC/C3 验证不通过或密文格式错误）
    DecryptFailed,
    /// 点在无穷远处（密钥交换中的退化情况）
    PointAtInfinity,
    /// 输入数据长度不合法
    InvalidInputLength,
    /// 密钥交换失败（共享点为无穷远或 KDF 输出全零）
    KeyExchangeFailed,

    // ── SM4 错误 ────────────────────────────────────────────────────────────
    /// AEAD 认证标签验证失败（GCM/CCM 解密时）
    AuthTagMismatch,
    /// 填充无效（PKCS#5/PKCS#7 解密时）
    InvalidPadding,
    /// GCM/CCM/OCB nonce 长度无效（推荐 12 字节）
    InvalidNonceLength,
    /// AEAD 认证标签无效（OCB/SIV/EAX/Key Wrap 解密时）
    InvalidTag,

    // ── SM9 错误 ────────────────────────────────────────────────────────────
    /// 输入点不在曲线上
    NotOnCurve,
    /// 标量或私钥为零
    ZeroScalar,
    /// 输入整数超出域范围
    IntegerOutOfRange,
    /// SM9 解密验证失败
    Sm9DecryptFailed,
    /// SM9 签名验证失败
    Sm9VerifyFailed,

    // ── 证书错误 ────────────────────────────────────────────────────────────
    /// 无效的证书（格式错误）
    InvalidCertificate,
    /// 证书解析错误
    CertificateParseError {
        /// 解析失败的字段
        field: &'static str,
        /// 错误原因
        reason: &'static str,
    },
    /// 证书验证错误
    #[cfg(feature = "alloc")]
    CertificateValidationError {
        /// 验证阶段
        stage: &'static str,
        /// 错误原因
        reason: String,
    },
    /// 证书已过期
    CertificateExpired,
    /// 证书尚未生效
    CertificateNotYetValid,
    /// 证书链验证失败
    #[cfg(feature = "alloc")]
    CertificateChainError {
        /// 失败的证书索引
        index: usize,
        /// 错误原因
        reason: String,
    },
    /// 证书吊销
    CertificateRevoked,

    // ── CRL 错误 ────────────────────────────────────────────────────────────
    /// 无效的 CRL（格式错误）
    InvalidCrl,
    /// CRL 已过期
    ExpiredCrl,
    /// 不支持的算法
    UnsupportedAlgorithm,

    // ── CMS/电子签章错误 ────────────────────────────────────────────────────
    /// CMS 解析错误
    CmsParseError {
        /// 解析失败的字段
        field: &'static str,
        /// 错误原因
        reason: &'static str,
    },
    /// CMS 验证错误
    #[cfg(feature = "alloc")]
    CmsValidationError {
        /// 验证阶段
        stage: &'static str,
        /// 错误原因
        reason: String,
    },
    /// 签名者未找到
    SignerNotFound,
    /// 签名属性错误
    SignedAttrsError {
        /// 属性类型
        attr_type: &'static str,
        /// 错误原因
        reason: &'static str,
    },

    // ── DER 编码错误 ────────────────────────────────────────────────────────
    /// DER 编码错误
    DerEncodeError {
        /// 编码失败的字段
        field: &'static str,
        /// 错误原因
        reason: &'static str,
    },
    /// DER 解码错误
    DerDecodeError {
        /// 解码失败的字段
        field: &'static str,
        /// 错误原因
        reason: &'static str,
    },
    /// DER 长度编码错误
    DerLengthError,

    // ── 通用错误 ────────────────────────────────────────────────────────────
    /// 输入数据格式无效
    InvalidInput,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidPrivateKey => write!(f, "invalid private key"),
            Error::InvalidPublicKey => write!(f, "invalid public key"),
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::VerifyFailed => write!(f, "signature verification failed"),
            Error::DecryptFailed => write!(f, "decryption failed"),
            Error::PointAtInfinity => write!(f, "point at infinity"),
            Error::InvalidInputLength => write!(f, "invalid input length"),
            Error::KeyExchangeFailed => write!(f, "key exchange failed"),
            Error::AuthTagMismatch => write!(f, "authentication tag mismatch"),
            Error::InvalidPadding => write!(f, "invalid padding"),
            Error::InvalidNonceLength => write!(f, "invalid nonce length"),
            Error::InvalidTag => write!(f, "invalid tag"),
            Error::NotOnCurve => write!(f, "point not on curve"),
            Error::ZeroScalar => write!(f, "zero scalar"),
            Error::IntegerOutOfRange => write!(f, "integer out of range"),
            Error::Sm9DecryptFailed => write!(f, "SM9 decryption failed"),
            Error::Sm9VerifyFailed => write!(f, "SM9 signature verification failed"),
            Error::InvalidInput => write!(f, "invalid input"),
            
            // 证书错误
            Error::InvalidCertificate => write!(f, "invalid certificate"),
            Error::CertificateParseError { field, reason } => {
                write!(f, "certificate parse error in {}: {}", field, reason)
            }
            #[cfg(feature = "alloc")]
            Error::CertificateValidationError { stage, reason } => {
                write!(f, "certificate validation error at {}: {}", stage, reason)
            }
            Error::CertificateExpired => write!(f, "certificate has expired"),
            Error::CertificateNotYetValid => write!(f, "certificate is not yet valid"),
            #[cfg(feature = "alloc")]
            Error::CertificateChainError { index, reason } => {
                write!(f, "certificate chain error at index {}: {}", index, reason)
            }
            Error::CertificateRevoked => write!(f, "certificate has been revoked"),
            
            // CRL 错误
            Error::InvalidCrl => write!(f, "invalid CRL"),
            Error::ExpiredCrl => write!(f, "CRL has expired"),
            Error::UnsupportedAlgorithm => write!(f, "unsupported algorithm"),
            
            // CMS 错误
            Error::CmsParseError { field, reason } => {
                write!(f, "CMS parse error in {}: {}", field, reason)
            }
            #[cfg(feature = "alloc")]
            Error::CmsValidationError { stage, reason } => {
                write!(f, "CMS validation error at {}: {}", stage, reason)
            }
            Error::SignerNotFound => write!(f, "signer not found"),
            Error::SignedAttrsError { attr_type, reason } => {
                write!(f, "signed attributes error for {}: {}", attr_type, reason)
            }
            
            // DER 错误
            Error::DerEncodeError { field, reason } => {
                write!(f, "DER encode error in {}: {}", field, reason)
            }
            Error::DerDecodeError { field, reason } => {
                write!(f, "DER decode error in {}: {}", field, reason)
            }
            Error::DerLengthError => write!(f, "DER length error"),
        }
    }
}

// Reason: std::error::Error 只在 std 环境可用；no_std 环境下仅提供 Display + Debug。
//   条件编译确保 alloc-only 场景不引入 std 依赖。
#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// libsmx 统一 Result 类型
pub type Result<T> = core::result::Result<T, Error>;
