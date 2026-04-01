//! 国密密钥派生函数（GM/T 0005-2012 / GB/T 32918.4-2016）
//!
//! 本模块提供统一的 KDF 实现，作为 SM2、SM9 等上层协议的密钥派生基础。
//!
//! # 标准参考
//!
//! | 函数 | 标准 | 用途 |
//! |------|------|------|
//! | [`kdf`] | GB/T 32918.4 §5.4.3 | SM2/SM9 密钥派生 |
//! | [`kdf_with_info`] | GM/T 0005-2012 | 带共享信息的 KDF |
//! | [`pbkdf2`] | RFC 2898 | 基于密码的密钥派生 |
//!
//! # 设计说明
//!
//! SM2 标准中的 `KDF(Z, klen)` 和 SM9 标准中的 `KDF(Z, klen)` 算法完全相同：
//! `KDF(Z, klen) = SM3(Z‖CT_1) ‖ SM3(Z‖CT_2) ‖ ...`（CT_i 为 32-bit 大端计数器）。
//! GM/T 0005-2012 在此基础上增加了可选的 `shared_info` 字段。
//! 本模块将三者统一为一个实现，避免代码重复。

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::Error;
use crate::sm3::{hmac_sm3, Sm3Hasher};

/// SM3 单轮 KDF 输出长度（字节）
const KDF_BLOCK_LEN: usize = crate::sm3::DIGEST_LEN;

/// SM2/SM9 KDF 密钥派生函数（GB/T 32918.4 §5.4.3 / GB/T 38635.1 §5.4.3）
///
/// `KDF(Z, klen) = SM3(Z‖CT_1) ‖ SM3(Z‖CT_2) ‖ ...`
///
/// 其中 `CT_i` 为 32-bit 大端计数器，从 1 开始。
///
/// # 参数
/// - `z`: 输入密钥材料（共享点坐标等）
/// - `klen`: 期望输出字节数
///
/// # 错误
/// - `klen` 为 0 时返回空 `Vec`
///
/// # 标准
/// - GB/T 32918.4-2016 §5.4.3（SM2）
/// - GB/T 38635.1-2020 §5.4.3（SM9）
#[cfg(feature = "alloc")]
pub fn kdf(z: &[u8], klen: usize) -> Vec<u8> {
    kdf_with_info(z, klen, &[])
}

/// 带共享信息的 KDF 密钥派生函数（GM/T 0005-2012）
///
/// `KDF(Z, klen, shared_info) = SM3(Z‖CT_1‖shared_info) ‖ SM3(Z‖CT_2‖shared_info) ‖ ...`
///
/// 当 `shared_info` 为空时，退化为标准 SM2/SM9 KDF。
///
/// # 参数
/// - `z`: 输入密钥材料
/// - `klen`: 期望输出字节数
/// - `shared_info`: 可选的共享信息（可为空）
///
/// # 错误
/// - `klen` 为 0 时返回空 `Vec`
#[cfg(feature = "alloc")]
pub fn kdf_with_info(z: &[u8], klen: usize, shared_info: &[u8]) -> Vec<u8> {
    if klen == 0 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(klen + KDF_BLOCK_LEN);
    let mut counter: u32 = 1;

    while result.len() < klen {
        let mut h = Sm3Hasher::new();
        h.update(z);
        h.update(&counter.to_be_bytes());
        if !shared_info.is_empty() {
            h.update(shared_info);
        }
        result.extend_from_slice(&h.finalize());
        counter += 1;
    }

    result.truncate(klen);
    result
}

/// 基于密码的密钥派生函数 PBKDF2-HMAC-SM3（RFC 2898）
///
/// 使用 HMAC-SM3 作为伪随机函数（PRF），从密码派生密钥。
///
/// # 参数
/// - `password`: 密码
/// - `salt`: 盐值
/// - `iterations`: 迭代次数（必须 ≥ 1）
/// - `dklen`: 期望输出字节数（不得超过 `u32::MAX * 32`）
///
/// # 错误
/// - `iterations` 为 0 时返回 `Error::InvalidInput`
/// - `dklen` 超过 `u32::MAX * 32` 时返回 `Error::InvalidInputLength`
///
/// # 标准
/// - RFC 2898 §5.2（PBKDF2）
#[cfg(feature = "alloc")]
pub fn pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dklen: usize,
) -> Result<Vec<u8>, Error> {
    if iterations == 0 {
        return Err(Error::InvalidInput);
    }

    // RFC 2898 §5.2 限制：dklen ≤ (2^32 - 1) * hLen
    let max_dklen = (u32::MAX as usize) * KDF_BLOCK_LEN;
    if dklen > max_dklen {
        return Err(Error::InvalidInputLength);
    }

    if dklen == 0 {
        return Ok(Vec::new());
    }

    let mut result = Vec::with_capacity(dklen + KDF_BLOCK_LEN);
    let mut block_index: u32 = 1;

    while result.len() < dklen {
        // U_1 = HMAC(password, salt || INT(block_index))
        let mut salt_block = [0u8; 64 + 4];
        let salt_len = salt.len().min(64);
        salt_block[..salt_len].copy_from_slice(&salt[..salt_len]);
        salt_block[salt_len..salt_len + 4].copy_from_slice(&block_index.to_be_bytes());
        let mut u = hmac_sm3(password, &salt_block[..salt_len + 4]);

        // T = U_1
        let mut t = u;

        // U_2 .. U_c
        for _ in 1..iterations {
            u = hmac_sm3(password, &u);
            for i in 0..t.len() {
                t[i] ^= u[i];
            }
        }

        result.extend_from_slice(&t);
        block_index += 1;
    }

    result.truncate(dklen);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    #[test]
    fn test_kdf_length() {
        let z = b"test input";
        assert_eq!(kdf(z, 32).len(), 32);
        assert_eq!(kdf(z, 48).len(), 48);
        assert_eq!(kdf(z, 1).len(), 1);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_kdf_deterministic() {
        let z = b"shared secret";
        assert_eq!(kdf(z, 32), kdf(z, 32));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_kdf_prefix_consistency() {
        let z = b"input";
        let k32 = kdf(z, 32);
        let k64 = kdf(z, 64);
        assert_eq!(&k64[..32], &k32[..]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_kdf_with_info() {
        let z = b"key_material";
        let info = b"shared_info";

        let k_no_info = kdf(z, 32);
        let k_with_info = kdf_with_info(z, 32, info);

        assert_eq!(k_no_info.len(), 32);
        assert_eq!(k_with_info.len(), 32);
        assert_ne!(k_no_info, k_with_info, "带 shared_info 的 KDF 输出应不同");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_kdf_with_empty_info_equals_kdf() {
        let z = b"key_material";
        assert_eq!(kdf(z, 32), kdf_with_info(z, 32, &[]));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_kdf_zero_length() {
        let result = kdf(b"test", 0);
        assert!(result.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pbkdf2_basic() {
        let password = b"password";
        let salt = b"salt";
        let derived = pbkdf2(password, salt, 1, 32).unwrap();
        assert_eq!(derived.len(), 32);

        let derived2 = pbkdf2(password, salt, 1, 32).unwrap();
        assert_eq!(derived, derived2, "PBKDF2 应为确定性函数");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pbkdf2_iterations_affect_output() {
        let password = b"password";
        let salt = b"salt";
        let d1 = pbkdf2(password, salt, 1, 32).unwrap();
        let d2 = pbkdf2(password, salt, 2, 32).unwrap();
        assert_ne!(d1, d2, "不同迭代次数应产生不同输出");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pbkdf2_zero_iterations_rejected() {
        let result = pbkdf2(b"password", b"salt", 0, 32);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InvalidInput);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pbkdf2_zero_length() {
        let result = pbkdf2(b"password", b"salt", 1, 0).unwrap();
        assert!(result.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pbkdf2_long_output() {
        let derived = pbkdf2(b"password", b"salt", 1, 64).unwrap();
        assert_eq!(derived.len(), 64);

        let derived32 = pbkdf2(b"password", b"salt", 1, 32).unwrap();
        assert_eq!(&derived[..32], &derived32[..], "长输出前缀应与短输出一致");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pbkdf2_different_passwords() {
        let d1 = pbkdf2(b"pass1", b"salt", 1, 32).unwrap();
        let d2 = pbkdf2(b"pass2", b"salt", 1, 32).unwrap();
        assert_ne!(d1, d2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pbkdf2_different_salts() {
        let d1 = pbkdf2(b"password", b"salt1", 1, 32).unwrap();
        let d2 = pbkdf2(b"password", b"salt2", 1, 32).unwrap();
        assert_ne!(d1, d2);
    }
}
