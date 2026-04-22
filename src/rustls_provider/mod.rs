//! rustls `CryptoProvider` 实现（RFC 8998 国密 TLS 套件）

extern crate alloc;

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

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
        Ok(Arc::new(SmTicketProducer::new()?))
    }
}

const TICKET_KEY_SIZE: usize = 16;
const TICKET_NONCE_SIZE: usize = 12;
const TICKET_TAG_SIZE: usize = 16;

#[derive(Debug)]
struct SmTicketProducer {
    key: [u8; TICKET_KEY_SIZE],
}

impl SmTicketProducer {
    fn new() -> Result<Self, Error> {
        let mut key = [0u8; TICKET_KEY_SIZE];
        Random
            .fill(&mut key)
            .map_err(|_| Error::General("rng failed".into()))?;
        Ok(SmTicketProducer { key })
    }

    fn gcm_encrypt(&self, nonce: &[u8; 12], plaintext: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let (ct, tag) = crate::sm4::sm4_encrypt_gcm(&self.key, nonce, &[], plaintext);
        (ct, tag)
    }

    fn gcm_decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8], tag: &[u8; 16]) -> Option<Vec<u8>> {
        crate::sm4::sm4_decrypt_gcm(&self.key, nonce, &[], ciphertext, tag).ok()
    }
}

impl TicketProducer for SmTicketProducer {
    fn encrypt(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = [0u8; TICKET_NONCE_SIZE];
        Random.fill(&mut nonce).ok()?;

        let (ciphertext, tag) = self.gcm_encrypt(&nonce, plaintext);

        let mut result = Vec::with_capacity(TICKET_NONCE_SIZE + ciphertext.len() + TICKET_TAG_SIZE);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&tag);

        Some(result)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let min_len = TICKET_NONCE_SIZE + TICKET_TAG_SIZE;
        if ciphertext.len() < min_len {
            return None;
        }

        let nonce: [u8; 12] = ciphertext[..12].try_into().ok()?;
        let tag_start = ciphertext.len() - TICKET_TAG_SIZE;
        let ciphertext_body = &ciphertext[TICKET_NONCE_SIZE..tag_start];
        let tag: [u8; 16] = ciphertext[tag_start..].try_into().ok()?;

        self.gcm_decrypt(&nonce, ciphertext_body, &tag)
    }

    fn lifetime(&self) -> Duration {
        Duration::from_secs(60 * 60 * 24)
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
