//! rustls `CryptoProvider` 实现（RFC 8998 国密 TLS 套件）

extern crate alloc;

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::rustls_provider::sign::Sm2Sm3Algorithm;
use pki_types::PrivateKeyDer;
use rustls::crypto::{
    CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SignatureScheme, SigningKey,
    TicketProducer, TicketerFactory, WebPkiSupportedAlgorithms,
};
use rustls::error::Error;

pub mod hash;
pub mod hmac;
pub mod kx;
pub mod sign;
pub mod tls13;

/// rustls 支持的 SM2_SM3 签名验证算法集合
pub static SUPPORTED_SM2_ALGS: WebPkiSupportedAlgorithms = match WebPkiSupportedAlgorithms::new(
    &[&SM2_SM3_ALG],
    &[(SignatureScheme::SM2_SM3, &[&SM2_SM3_ALG])],
) {
    Ok(s) => s,
    Err(_) => panic!("SM2 algs consistency check failed"),
};

/// SM2-SM3 签名验证算法实例
///
/// 可直接用于 rustls 的签名验证配置。
static SM2_SM3_ALG: Sm2Sm3Algorithm = Sm2Sm3Algorithm;

/// 构造国密 `CryptoProvider`
pub fn provider() -> CryptoProvider {
    static TLS13_SUITES: &[&rustls::Tls13CipherSuite] =
        &[tls13::TLS13_SM4_GCM_SM3, tls13::TLS13_SM4_CCM_SM3];
    static KX_GROUPS: &[&dyn rustls::crypto::kx::SupportedKxGroup] = &[kx::CURVE_SM2];

    CryptoProvider {
        tls12_cipher_suites: Cow::Borrowed(&[]),
        tls13_cipher_suites: Cow::Borrowed(TLS13_SUITES),
        kx_groups: Cow::Borrowed(KX_GROUPS),
        signature_verification_algorithms: SUPPORTED_SM2_ALGS,
        secure_random: &Random,
        key_provider: &SmKeyProvider,
        ticketer_factory: &SmTicketerFactory,
    }
}

// ── SecureRandom ──────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Random;

impl SecureRandom for Random {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        getrandom::fill(buf).map_err(|_| GetRandomFailed)
    }
}

// ── KeyProvider ───────────────────────────────────────────────────────────────

#[derive(Debug)]
struct SmKeyProvider;

impl KeyProvider for SmKeyProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Box<dyn SigningKey>, Error> {
        sign::load_private_key(key_der)
    }
}

// ── TicketerFactory ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct SmTicketerFactory;

impl TicketerFactory for SmTicketerFactory {
    fn ticketer(&self) -> Result<Arc<dyn TicketProducer>, Error> {
        // Reason: TLS session ticket 加密暂不支持，返回错误；
        //   后续可用 SM4-GCM 实现 ticket 加密
        Err(Error::General(
            "SM ticket factory not yet implemented".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::SM2_SM3_ALG;
    use crate::sm2::{generate_keypair, sign_message, DEFAULT_ID};
    use alloc::vec::Vec;
    use pki_types::SignatureVerificationAlgorithm;

    fn sign_with_der(message: &[u8]) -> ([u8; 65], Vec<u8>) {
        let mut rng = crate::rustls_provider::kx::Sm2Rng;
        let (pri_key, pub_key) = generate_keypair(&mut rng);
        let sig_raw = sign_message(message, DEFAULT_ID, &pri_key, &mut rng);
        (pub_key.to_bytes(), sig_raw.to_vec())
    }

    #[test]
    fn test_verify_valid_signature() {
        let msg = b"test message";
        let (pub_key, sig) = sign_with_der(msg);
        SM2_SM3_ALG.verify_signature(&pub_key, msg, &sig).unwrap();
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let (pub_key, sig) = sign_with_der(b"original");
        let result = SM2_SM3_ALG.verify_signature(&pub_key, b"tampered", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_pubkey_fails() {
        let msg = b"hello";
        let (_, sig) = sign_with_der(msg);
        // 用另一个公钥验证
        let mut rng = crate::rustls_provider::kx::Sm2Rng;
        let (_, other_pub) = generate_keypair(&mut rng);
        let result = SM2_SM3_ALG.verify_signature(other_pub.as_bytes(), msg, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_invalid_pubkey_len_fails() {
        let (_, sig) = sign_with_der(b"msg");
        // 公钥长度不是 65 字节时应报错
        let result = SM2_SM3_ALG.verify_signature(&[0u8; 32], b"msg", &sig);
        assert!(result.is_err());
    }
}
