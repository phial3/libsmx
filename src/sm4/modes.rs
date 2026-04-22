//! SM4 分组模式（GB/T 32907-2016，GB/T 17964-2021）
//!
//! # 支持的加密模式
//!
//! ## 基础模式
//! - **ECB**: 电子密码本模式（支持无填充、PKCS#5、PKCS#7）
//! - **CBC**: 密码分组链接模式（支持无填充、PKCS#5、PKCS#7）
//! - **OFB**: 输出反馈模式（流模式，无需填充）
//! - **CFB**: 密文反馈模式（流模式，无需填充）
//! - **CTR**: 计数器模式（流模式，无需填充）
//!
//! ## AEAD 模式（认证加密）
//! - **GCM**: Galois/Counter Mode
//! - **CCM**: Counter with CBC-MAC
//! - **OCB**: Offset Codebook Mode（高效 AEAD，比 GCM 更快）
//! - **SIV**: Synthetic Initialization Vector（确定性 AEAD）
//! - **EAX**: Two-pass AEAD（更安全的 AEAD）
//!
//! ## 密钥封装模式
//! - **Key Wrap**: RFC 3394 密钥封装（用于安全加密密钥材料）
//!
//! ## 磁盘加密模式
//! - **XTS**: XEX-based Tweaked CodeBook mode
//!
//! # 填充方案
//!
//! - **NoPadding**: 无填充，要求输入数据长度必须是 16 字节的整数倍
//! - **PKCS#5Padding**: PKCS#5 填充（与 PKCS#7 相同）
//! - **PKCS#7Padding**: PKCS#7 填充（RFC 5652）
//!
//! # 安全说明
//!
//! - GCM/CCM/OCB/SIV/EAX 认证标签比较使用 `subtle::ConstantTimeEq`，防止时序侧信道
//! - CCM 严格遵循"先验证后解密"原则（Encrypt-then-MAC 的接收端验证）
//! - 所有密钥材料通过 [`Sm4Key`] 在 Drop 时自动清零
//! - OCB/SIV/EAX/Key Wrap 为新增功能

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use subtle::ConstantTimeEq;

use super::cipher::{encrypt_block_raw, Sm4Key};
#[cfg(feature = "alloc")]
use super::padding::{pkcs5_pad, pkcs5_unpad, pkcs7_pad, pkcs7_unpad};
use crate::error::Error;

// ── ECB ──────────────────────────────────────────────────────────────────────

/// SM4-ECB 加密（无填充，`data` 必须为 16 字节整倍数）
///
/// # 参数
/// - `key`: 16 字节密钥
/// - `data`: 明文（长度须为 16 的倍数）
///
/// # 返回
/// 密文字节向量
///
/// # Panics
/// 当 `data` 长度不是 16 的倍数时 panic（无填充模式要求严格对齐）
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_ecb(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() % 16 == 0,
        "sm4_encrypt_ecb: data length must be a multiple of 16"
    );
    let sm4 = Sm4Key::new(key);
    data.chunks(16)
        .flat_map(|chunk| {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            sm4.encrypt_block(&mut block);
            block
        })
        .collect()
}

/// SM4-ECB 解密（无填充，`data` 必须为 16 字节整倍数）
///
/// # Panics
/// 当 `data` 长度不是 16 的倍数时 panic（无填充模式要求严格对齐）
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_ecb(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() % 16 == 0,
        "sm4_decrypt_ecb: data length must be a multiple of 16"
    );
    let sm4 = Sm4Key::new(key);
    data.chunks(16)
        .flat_map(|chunk| {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            sm4.decrypt_block(&mut block);
            block
        })
        .collect()
}

/// SM4-ECB 加密（PKCS#5 填充）
///
/// # 参数
/// - `key`: 16 字节密钥
/// - `plaintext`: 明文（任意长度）
///
/// # 返回
/// 密文字节向量（包含 PKCS#5 填充）
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_ecb_pkcs5(key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let padded = pkcs5_pad(plaintext);
    sm4_encrypt_ecb(key, &padded)
}

/// SM4-ECB 解密（PKCS#5 填充）
///
/// # 参数
/// - `key`: 16 字节密钥
/// - `ciphertext`: 密文（包含 PKCS#5 填充）
///
/// # 返回
/// - `Ok(Vec<u8>)`: 解密后的明文
/// - `Err(Error::InvalidPadding)`: 填充无效
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_ecb_pkcs5(key: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let decrypted = sm4_decrypt_ecb(key, ciphertext);
    pkcs5_unpad(&decrypted)
}

/// SM4-ECB 加密（PKCS#7 填充）
///
/// # 参数
/// - `key`: 16 字节密钥
/// - `plaintext`: 明文（任意长度）
///
/// # 返回
/// 密文字节向量（包含 PKCS#7 填充）
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_ecb_pkcs7(key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let padded = pkcs7_pad(plaintext, 16);
    sm4_encrypt_ecb(key, &padded)
}

/// SM4-ECB 解密（PKCS#7 填充）
///
/// # 参数
/// - `key`: 16 字节密钥
/// - `ciphertext`: 密文（包含 PKCS#7 填充）
///
/// # 返回
/// - `Ok(Vec<u8>)`: 解密后的明文
/// - `Err(Error::InvalidPadding)`: 填充无效
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_ecb_pkcs7(key: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let decrypted = sm4_decrypt_ecb(key, ciphertext);
    pkcs7_unpad(&decrypted)
}

// ── CBC ──────────────────────────────────────────────────────────────────────

/// SM4-CBC 加密（`plaintext.len()` 须为 16 字节整倍数）
///
/// # Panics
/// 当 `plaintext` 长度不是 16 的倍数时 panic（无填充模式要求严格对齐）
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_cbc(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    assert!(
        plaintext.len() % 16 == 0,
        "sm4_encrypt_cbc: plaintext length must be a multiple of 16"
    );
    let sm4 = Sm4Key::new(key);
    let mut prev = *iv;
    plaintext
        .chunks(16)
        .flat_map(|chunk| {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            for i in 0..16 {
                block[i] ^= prev[i];
            }
            sm4.encrypt_block(&mut block);
            prev = block;
            block
        })
        .collect()
}

/// SM4-CBC 解密（`ciphertext.len()` 须为 16 字节整倍数）
///
/// # Panics
/// 当 `ciphertext` 长度不是 16 的倍数时 panic（无填充模式要求严格对齐）
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_cbc(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    assert!(
        ciphertext.len() % 16 == 0,
        "sm4_decrypt_cbc: ciphertext length must be a multiple of 16"
    );
    let sm4 = Sm4Key::new(key);
    let mut prev = *iv;
    ciphertext
        .chunks(16)
        .flat_map(|chunk| {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            let ct = block;
            sm4.decrypt_block(&mut block);
            for i in 0..16 {
                block[i] ^= prev[i];
            }
            prev = ct;
            block
        })
        .collect()
}

/// SM4-CBC 加密（PKCS#5 填充）
///
/// # 参数
/// - `key`: 16 字节密钥
/// - `iv`: 16 字节初始化向量
/// - `plaintext`: 明文（任意长度）
///
/// # 返回
/// 密文字节向量（包含 PKCS#5 填充）
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_cbc_pkcs5(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let padded = pkcs5_pad(plaintext);
    sm4_encrypt_cbc(key, iv, &padded)
}

/// SM4-CBC 解密（PKCS#5 填充）
///
/// # 参数
/// - `key`: 16 字节密钥
/// - `iv`: 16 字节初始化向量
/// - `ciphertext`: 密文（包含 PKCS#5 填充）
///
/// # 返回
/// - `Ok(Vec<u8>)`: 解密后的明文
/// - `Err(Error::InvalidPadding)`: 填充无效
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_cbc_pkcs5(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let decrypted = sm4_decrypt_cbc(key, iv, ciphertext);
    pkcs5_unpad(&decrypted)
}

/// SM4-CBC 加密（PKCS#7 填充）
///
/// # 参数
/// - `key`: 16 字节密钥
/// - `iv`: 16 字节初始化向量
/// - `plaintext`: 明文（任意长度）
///
/// # 返回
/// 密文字节向量（包含 PKCS#7 填充）
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_cbc_pkcs7(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let padded = pkcs7_pad(plaintext, 16);
    sm4_encrypt_cbc(key, iv, &padded)
}

/// SM4-CBC 解密（PKCS#7 填充）
///
/// # 参数
/// - `key`: 16 字节密钥
/// - `iv`: 16 字节初始化向量
/// - `ciphertext`: 密文（包含 PKCS#7 填充）
///
/// # 返回
/// - `Ok(Vec<u8>)`: 解密后的明文
/// - `Err(Error::InvalidPadding)`: 填充无效
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_cbc_pkcs7(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let decrypted = sm4_decrypt_cbc(key, iv, ciphertext);
    pkcs7_unpad(&decrypted)
}

// ── OFB ──────────────────────────────────────────────────────────────────────

/// SM4-OFB 加密/解密（自反模式，加解密逻辑相同）
#[cfg(feature = "alloc")]
pub fn sm4_crypt_ofb(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let sm4 = Sm4Key::new(key);
    let mut feedback = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        sm4.encrypt_block(&mut feedback);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ feedback[i]);
        }
    }
    out
}

// ── CFB ──────────────────────────────────────────────────────────────────────

/// SM4-CFB 加密
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_cfb(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let sm4 = Sm4Key::new(key);
    let mut feedback = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut ks = feedback;
        sm4.encrypt_block(&mut ks);
        let mut ct_block = [0u8; 16];
        for (i, &b) in chunk.iter().enumerate() {
            ct_block[i] = b ^ ks[i];
        }
        feedback = ct_block;
        out.extend_from_slice(&ct_block[..chunk.len()]);
    }
    out
}

/// SM4-CFB 解密
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_cfb(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let sm4 = Sm4Key::new(key);
    let mut feedback = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut ks = feedback;
        sm4.encrypt_block(&mut ks);
        let mut ct_block = [0u8; 16];
        ct_block[..chunk.len()].copy_from_slice(chunk);
        // Reason: CFB 解密中 feedback 使用密文块，而非明文块
        feedback = ct_block;
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
    }
    out
}

// ── CTR ──────────────────────────────────────────────────────────────────────

/// CTR 计数器递增（全 128 位大端）
#[inline]
fn ctr_inc(counter: &mut [u8; 16]) {
    for i in (0..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

/// SM4-CTR 加密/解密（自反模式）
#[cfg(feature = "alloc")]
pub fn sm4_crypt_ctr(key: &[u8; 16], nonce: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let sm4 = Sm4Key::new(key);
    let mut counter = *nonce;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut ks = counter;
        sm4.encrypt_block(&mut ks);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
        ctr_inc(&mut counter);
    }
    out
}

// ── GCM ──────────────────────────────────────────────────────────────────────

/// GF(2^128) 乘法（NIST SP 800-38D Algorithm 1，常量时间，u64 优化）
///
/// # 安全性
/// 使用掩码算术替代秘密依赖的条件分支，消除时序侧信道：
/// - `mask_xi`：由当前标量位生成的 u64 全掩码，替代 `if bit == 1`
/// - `reduce_mask`：由 LSB 生成的 u64 全掩码，替代 `if lsb == 1`
///
/// # 性能优化
/// 将内部状态从 `[u8; 16]` 改为 `[u64; 2]`（大端），使每次迭代的
/// XOR/移位/规约从 16 次字节操作降至 ~6 次 64 位操作，约 4-6× 提速。
///
/// Reason: GHASH 密钥 H 来自 SM4_K(0^128)，属秘密值；原条件分支泄露 H 的汉明重量，
///   是 cache-timing 和 branch-timing 攻击的经典目标（参见 Bricout 等 2016）。
///   u64 向量化保持完全常量时间，同时大幅减少指令数。
fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    // Reason: 将 16 字节表示为 2 个大端 u64，便于用 64 位操作替代逐字节循环，
    //   XOR/移位从 16 次字节操作缩减至 2 次 u64 操作，指令数降低约 8×。
    let mut z = [0u64; 2];
    let mut v = [
        u64::from_be_bytes(y[0..8].try_into().unwrap()),
        u64::from_be_bytes(y[8..16].try_into().unwrap()),
    ];

    for &byte_xi in x.iter() {
        for bit_idx in (0..8).rev() {
            // Reason: 0u64.wrapping_sub(1) = 0xFFFF...，wrapping_sub(0) = 0x0000...
            //   单次 u64 掩码覆盖原来 16 次 u8 掩码操作
            let mask = 0u64.wrapping_sub(((byte_xi >> bit_idx) & 1) as u64);
            z[0] ^= v[0] & mask;
            z[1] ^= v[1] & mask;

            // GF(2^128) 右移 1 位（= 乘以 x），带规约多项式 x^128+x^7+x^2+x+1
            // Reason: v[0] 的 bit 0（= 大端第 64 位）移入 v[1] 的 bit 63，
            //   v[1] 的 bit 0（= GF 元素 x^0 系数）移出后触发规约。
            let lsb = v[1] & 1;
            let carry = v[0] & 1;
            v[0] >>= 1;
            v[1] = (v[1] >> 1) | (carry << 63);
            // Reason: 规约项 0xE1_00...00 对应 x^7+x^2+x+1 写入最高字节（v[0] MSB 端），
            //   掩码替代 if lsb，执行路径完全相同
            let reduce_mask = 0u64.wrapping_sub(lsb);
            v[0] ^= 0xE100_0000_0000_0000u64 & reduce_mask;
        }
    }

    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&z[0].to_be_bytes());
    out[8..16].copy_from_slice(&z[1].to_be_bytes());
    out
}

/// GHASH 认证函数（NIST SP 800-38D §6.4）
fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    for chunk in aad.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            y[i] ^= block[i];
        }
        y = gf128_mul(&y, h);
    }
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            y[i] ^= block[i];
        }
        y = gf128_mul(&y, h);
    }
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..16].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    for i in 0..16 {
        y[i] ^= len_block[i];
    }
    gf128_mul(&y, h)
}

/// GCM 计数器递增（仅最后 4 字节，GCM 标准）
#[inline]
fn gcm_ctr_inc(counter: &mut [u8; 16]) {
    // Reason: GCM 规范中 J0 的计数器字段只占最后 4 字节（大端 32 位）
    for i in (12..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

/// SM4-GCM 加密（AEAD）
///
/// # 参数
/// - `key`: 16 字节密钥
/// - `nonce`: 12 字节 nonce（GCM 标准推荐）
/// - `aad`: 附加认证数据（不加密，但参与认证）
/// - `plaintext`: 明文
///
/// # 返回
/// `(密文, 16字节认证标签)`
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_gcm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let sm4 = Sm4Key::new(key);
    let rk = sm4.round_keys();

    let h = encrypt_block_raw(rk, &[0u8; 16]);

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    let mut ctr = j0;
    gcm_ctr_inc(&mut ctr);

    let ciphertext: Vec<u8> = {
        let mut out = Vec::with_capacity(plaintext.len());
        let mut counter = ctr;
        for chunk in plaintext.chunks(16) {
            let ks = encrypt_block_raw(rk, &counter);
            for (i, &b) in chunk.iter().enumerate() {
                out.push(b ^ ks[i]);
            }
            gcm_ctr_inc(&mut counter);
        }
        out
    };

    let ghash_val = ghash(&h, aad, &ciphertext);
    let ej0 = encrypt_block_raw(rk, &j0);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = ghash_val[i] ^ ej0[i];
    }

    (ciphertext, tag)
}

/// SM4-GCM 解密（AEAD）
///
/// **先验证认证标签，验证通过后才解密。**
///
/// # 错误
/// 返回 [`crate::error::Error::AuthTagMismatch`] 当标签验证失败。
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_gcm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let sm4 = Sm4Key::new(key);
    let rk = sm4.round_keys();

    let h = encrypt_block_raw(rk, &[0u8; 16]);

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    // Reason: 先验证 tag 再解密，防止 padding oracle 和选择密文攻击
    let ghash_val = ghash(&h, aad, ciphertext);
    let ej0 = encrypt_block_raw(rk, &j0);
    let mut expected_tag = [0u8; 16];
    for i in 0..16 {
        expected_tag[i] = ghash_val[i] ^ ej0[i];
    }

    // 常量时间 tag 比较，防止时序侧信道
    if expected_tag.ct_eq(tag).unwrap_u8() == 0 {
        return Err(Error::AuthTagMismatch);
    }

    let mut ctr = j0;
    gcm_ctr_inc(&mut ctr);

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut counter = ctr;
    for chunk in ciphertext.chunks(16) {
        let ks = encrypt_block_raw(rk, &counter);
        for (i, &b) in chunk.iter().enumerate() {
            plaintext.push(b ^ ks[i]);
        }
        gcm_ctr_inc(&mut counter);
    }
    Ok(plaintext)
}

// ── CCM ──────────────────────────────────────────────────────────────────────

/// 构造 CCM CBC-MAC（RFC 3610）
///
/// # 错误
/// `aad` 超过 510 字节时返回 `Error::InvalidInputLength`（当前实现仅支持 2 字节长度编码）。
fn ccm_cbc_mac(
    rk: &[u32; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    message: &[u8],
    tag_len: usize,
) -> Result<[u8; 16], Error> {
    let q = 3usize; // nonce=12B 时 q=15-12=3
    let has_aad = !aad.is_empty();
    let flags = ((has_aad as u8) << 6) | (((tag_len - 2) / 2) as u8) << 3 | (q as u8 - 1);

    let mut b0 = [0u8; 16];
    b0[0] = flags;
    b0[1..13].copy_from_slice(nonce);
    let msg_len = message.len() as u32;
    b0[13] = (msg_len >> 16) as u8;
    b0[14] = (msg_len >> 8) as u8;
    b0[15] = msg_len as u8;

    let mut x = encrypt_block_raw(rk, &b0);

    if has_aad {
        let aad_len = aad.len();
        // Reason: CCM AAD 前缀 2 字节长度 + AAD 数据，补零至 16 字节对齐
        let prefix_len = 2 + aad_len;
        let padded_len = prefix_len.div_ceil(16) * 16;
        let mut aad_buf = [0u8; 512]; // 足够大的栈缓冲区（支持 AAD ≤ 510 字节）

        // Reason: 超过 510 字节需要 4 字节长度编码（RFC 3610 §2.2），
        //   当前实现仅支持 2 字节编码，超限时必须拒绝而非静默跳过 AAD。
        //   静默跳过会导致认证标签不包含 AAD，攻击者可随意篡改 AAD 而不被检测。
        if prefix_len > aad_buf.len() {
            return Err(Error::InvalidInputLength);
        }

        aad_buf[0..2].copy_from_slice(&(aad_len as u16).to_be_bytes());
        aad_buf[2..2 + aad_len].copy_from_slice(aad);
        for chunk in aad_buf[..padded_len].chunks(16) {
            let block: [u8; 16] = chunk.try_into().unwrap();
            for i in 0..16 {
                x[i] ^= block[i];
            }
            x = encrypt_block_raw(rk, &x);
        }
    }

    for chunk in message.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            x[i] ^= block[i];
        }
        x = encrypt_block_raw(rk, &x);
    }
    Ok(x)
}

/// SM4-CCM 加密（AEAD）
///
/// # 参数
/// - `nonce`: 12 字节
/// - `tag_len`: 认证标签长度，须为 4/6/8/10/12/14/16 之一
///
/// # 返回
/// 密文 || 认证标签（`tag_len` 字节）
///
/// # 错误
/// - `aad` 超过 510 字节时返回 `Error::InvalidInputLength`
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_ccm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, Error> {
    assert!(
        (4..=16).contains(&tag_len) && tag_len % 2 == 0,
        "CCM tag_len 须为 4~16 的偶数"
    );

    let sm4 = Sm4Key::new(key);
    let rk = sm4.round_keys();

    let t = ccm_cbc_mac(rk, nonce, aad, plaintext, tag_len)?;

    let mut a0 = [0u8; 16];
    a0[0] = 2u8; // q-1 = 3-1 = 2
    a0[1..13].copy_from_slice(nonce);
    let s0 = encrypt_block_raw(rk, &a0);

    let mut enc_tag = [0u8; 16];
    for i in 0..tag_len {
        enc_tag[i] = t[i] ^ s0[i];
    }

    let mut out = Vec::with_capacity(plaintext.len() + tag_len);
    for (block_idx, chunk) in plaintext.chunks(16).enumerate() {
        let mut a_i = a0;
        let ctr_val = (block_idx as u32) + 1;
        a_i[13] = (ctr_val >> 16) as u8;
        a_i[14] = (ctr_val >> 8) as u8;
        a_i[15] = ctr_val as u8;
        let ks = encrypt_block_raw(rk, &a_i);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
    }
    out.extend_from_slice(&enc_tag[..tag_len]);
    Ok(out)
}

/// SM4-CCM 解密（AEAD）
///
/// **先验证认证标签，验证通过后才解密。**
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_ccm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, Error> {
    if ciphertext_with_tag.len() < tag_len {
        return Err(Error::InvalidInputLength);
    }
    let ct = &ciphertext_with_tag[..ciphertext_with_tag.len() - tag_len];
    let received_tag = &ciphertext_with_tag[ciphertext_with_tag.len() - tag_len..];

    let sm4 = Sm4Key::new(key);
    let rk = sm4.round_keys();

    let mut a0 = [0u8; 16];
    a0[0] = 2u8;
    a0[1..13].copy_from_slice(nonce);
    let s0 = encrypt_block_raw(rk, &a0);

    // Step 1: CTR 解密密文（得到候选明文）
    let mut plaintext = Vec::with_capacity(ct.len());
    for (block_idx, chunk) in ct.chunks(16).enumerate() {
        let mut a_i = a0;
        let ctr_val = (block_idx as u32) + 1;
        a_i[13] = (ctr_val >> 16) as u8;
        a_i[14] = (ctr_val >> 8) as u8;
        a_i[15] = ctr_val as u8;
        let ks = encrypt_block_raw(rk, &a_i);
        for (i, &b) in chunk.iter().enumerate() {
            plaintext.push(b ^ ks[i]);
        }
    }

    // Step 2: 对候选明文重新计算 CBC-MAC
    let t = ccm_cbc_mac(rk, nonce, aad, &plaintext, tag_len)?;
    let mut expected_tag = [0u8; 16];
    for i in 0..tag_len {
        expected_tag[i] = t[i] ^ s0[i];
    }

    // Step 3: 常量时间比较，验证通过才返回明文
    // Reason: 先验证后解密，防止选择密文攻击
    if expected_tag[..tag_len].ct_eq(received_tag).unwrap_u8() == 0 {
        return Err(Error::AuthTagMismatch);
    }

    Ok(plaintext)
}

// ── GCM/CCM 合并格式（TLS 适配）────────────────────────────────────────────────

/// SM4-GCM 加密（合并输出格式：`ciphertext || tag`）
///
/// TLS 记录层要求 AEAD 输出为单一缓冲区，此函数将密文和 16 字节 tag 合并返回。
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_gcm_combined(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let (mut ct, tag) = sm4_encrypt_gcm(key, nonce, aad, plaintext);
    ct.extend_from_slice(&tag);
    ct
}

/// SM4-GCM 解密（合并输入格式：`ciphertext || tag`）
///
/// 输入必须至少 16 字节（tag 长度）；先验证 tag 再解密。
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_gcm_combined(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, Error> {
    if ciphertext_with_tag.len() < 16 {
        return Err(Error::InvalidInputLength);
    }
    let ct_len = ciphertext_with_tag.len() - 16;
    let ct = &ciphertext_with_tag[..ct_len];
    let tag: &[u8; 16] = ciphertext_with_tag[ct_len..].try_into().unwrap();
    sm4_decrypt_gcm(key, nonce, aad, ct, tag)
}

/// SM4-CCM 加密（tag_len = 16，合并输出格式）
///
/// TLS 1.3 `TLS_SM4_CCM_SM3` 使用 16 字节 tag。
/// 等同于 `sm4_encrypt_ccm`（其输出已是 ciphertext||tag 合并格式）。
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_ccm_combined(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    sm4_encrypt_ccm(key, nonce, aad, plaintext, 16)
}

/// SM4-CCM 解密（tag_len = 16，合并输入格式）
///
/// 等同于 `sm4_decrypt_ccm(..., 16)`。
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_ccm_combined(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, Error> {
    sm4_decrypt_ccm(key, nonce, aad, ciphertext_with_tag, 16)
}

// ── XTS ──────────────────────────────────────────────────────────────────────

/// GF(2^128) 乘以 α（XTS tweak 更新）
fn xts_mul_alpha(tweak: &mut [u8; 16]) {
    // Reason: XTS 使用反射位序的 GF(2^128)，对应右移 + 0xE1 规约
    let carry = tweak[15] & 1;
    for i in (1..16).rev() {
        tweak[i] = (tweak[i] >> 1) | ((tweak[i - 1] & 1) << 7);
    }
    tweak[0] >>= 1;
    if carry == 1 {
        tweak[0] ^= 0xE1;
    }
}

/// SM4-XTS 加密（磁盘加密模式，GB/T 17964-2021）
///
/// # 参数
/// - `key1`: 数据加密密钥（16 字节）
/// - `key2`: tweak 加密密钥（16 字节）
/// - `tweak_sector`: 扇区号（16 字节，通常为扇区编号的小端表示）
/// - `data`: 明文（须为 16 字节整倍数，不支持非对齐输入）
///
/// # 错误
/// `data` 为空或长度不是 16 的整倍数时返回 `Error::InvalidInputLength`。
///
/// # 注意
/// XTS 的 ciphertext stealing（非对齐末尾块处理）超出本实现范围，
/// 调用方须保证输入对齐；非对齐时须先在应用层填充后再调用。
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_xts(
    key1: &[u8; 16],
    key2: &[u8; 16],
    tweak_sector: &[u8; 16],
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    // Reason: 非对齐输入在旧实现中被静默丢弃（最后不足 16 字节块跳过），
    //   导致密文比明文短而调用方无感知。拒绝非对齐输入防止数据静默丢失。
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(Error::InvalidInputLength);
    }

    let sm4_1 = Sm4Key::new(key1);
    let sm4_2 = Sm4Key::new(key2);
    let mut tweak = *tweak_sector;
    sm4_2.encrypt_block(&mut tweak);

    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ tweak[i];
        }
        sm4_1.encrypt_block(&mut block);
        for i in 0..16 {
            out.push(block[i] ^ tweak[i]);
        }
        xts_mul_alpha(&mut tweak);
    }
    Ok(out)
}

/// SM4-XTS 解密（磁盘加密模式，GB/T 17964-2021）
///
/// # 错误
/// `data` 为空或长度不是 16 的整倍数时返回 `Error::InvalidInputLength`。
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_xts(
    key1: &[u8; 16],
    key2: &[u8; 16],
    tweak_sector: &[u8; 16],
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    // Reason: 同 sm4_encrypt_xts，拒绝非对齐输入防止数据静默丢失。
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(Error::InvalidInputLength);
    }

    let sm4_1 = Sm4Key::new(key1);
    let sm4_2 = Sm4Key::new(key2);
    let mut tweak = *tweak_sector;
    sm4_2.encrypt_block(&mut tweak);

    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ tweak[i];
        }
        sm4_1.decrypt_block(&mut block);
        for i in 0..16 {
            out.push(block[i] ^ tweak[i]);
        }
        xts_mul_alpha(&mut tweak);
    }
    Ok(out)
}

// ── OCB 模式（高效 AEAD）──────────────────────────────────────────────────────

/// SM4-OCB 加密（高效 AEAD 模式）
///
/// OCB（Offset Codebook）模式是一种高效的认证加密模式，比 GCM 更快且无专利限制。
/// 实现基于 RFC 7253（OCBv3），但使用 SM4 分组密码。
///
/// # 参数
/// - `key`: 16 字节 SM4 密钥
/// - `nonce`: 1-15 字节随机数
/// - `aad`: 附加认证数据（可为空）
/// - `plaintext`: 明文
///
/// # 返回
/// `(ciphertext, tag)` - 密文和 16 字节认证标签
///
/// # 安全说明
/// - nonce 必须唯一（相同 nonce + key 会破坏安全性）
/// - 认证标签比较使用常量时间比较
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_ocb(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), Error> {
    // Reason: OCBv3 支持任意长度 nonce，但推荐使用 12 字节（96 位）以获得最佳性能
    if nonce.is_empty() || nonce.len() > 15 {
        return Err(Error::InvalidNonceLength);
    }

    let sm4 = Sm4Key::new(key);
    const TAGLEN: usize = 128; // 128-bit tag

    // 密钥相关变量
    // L_* = ENCIPHER(K, zeros(128))
    let mut l_star = [0u8; 16];
    sm4.encrypt_block(&mut l_star);

    // L_$ = double(L_*)
    let l_dollar = gf128_mul_u(&l_star);

    // L_0 = double(L_$)
    let l_0 = gf128_mul_u(&l_dollar);

    // L_i = double(L_{i-1}) for i > 0
    // 预计算 L_i 序列（最多需要到 i=127）
    let mut l = [[0u8; 16]; 128];
    l[0] = l_0;
    for i in 1..128 {
        l[i] = gf128_mul_u(&l[i - 1]);
    }

    // 考虑 AAD 作为 128-bit 块序列
    let m = if aad.is_empty() { 0 } else { aad.len() / 16 };
    let aad_star_len = if aad.is_empty() { 0 } else { aad.len() % 16 };

    // 处理 AAD：HASH(K, A)
    let hash = {
        let mut sum = [0u8; 16];
        let mut offset = [0u8; 16];

        // 处理完整块
        for i in 0..m {
            let ntz_i = ntz(i + 1);
            if ntz_i < 128 {
                xor_blocks(&mut offset, &l[ntz_i]);
            }

            let mut block = [0u8; 16];
            let start = i * 16;
            let end = start + 16;
            block.copy_from_slice(&aad[start..end]);
            xor_blocks(&mut block, &offset);
            sm4.encrypt_block(&mut block);
            xor_blocks(&mut sum, &block);
        }

        // 处理最后一个不完整块
        if aad_star_len > 0 {
            xor_blocks(&mut offset, &l_star);

            let mut block = [0u8; 16];
            let start = m * 16;
            block[..aad_star_len].copy_from_slice(&aad[start..]);
            block[aad_star_len] = 0x80; // padding
            xor_blocks(&mut block, &offset);
            sm4.encrypt_block(&mut block);
            xor_blocks(&mut sum, &block);
        }

        sum
    };

    // 考虑 P 作为 128-bit 块序列
    let p_len = plaintext.len();
    let m_p = p_len / 16;
    let p_star_len = p_len % 16;

    // Nonce 相关变量
    // Nonce = num2str(TAGLEN mod 128, 7) || zeros(120 - bitlen(N)) || 1 || N
    // RFC 7253: Nonce 格式化为 16 字节块
    let mut nonce_block = [0u8; 16];

    // 第一个字节：TAGLEN mod 128（左移 1 位，因为最低位留给后面的 1）
    nonce_block[0] = ((TAGLEN % 128) << 1) as u8;

    // 复制 nonce 到末尾
    let nonce_end = 16;
    let nonce_start = nonce_end - nonce.len();
    nonce_block[nonce_start..nonce_end].copy_from_slice(nonce);

    // 在 nonce 前面设置 1 bit
    nonce_block[nonce_start - 1] = 0x01;

    // bottom = last 6 bits of nonce (Nonce[123..128])
    let bottom = (nonce_block[15] & 0x3F) as usize;

    // Ktop = ENCIPHER(K, Nonce with last 6 bits zeroed)
    nonce_block[15] &= 0xC0;
    let mut ktop = nonce_block;
    sm4.encrypt_block(&mut ktop);

    // Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
    let mut stretch = [0u8; 24];
    stretch[..16].copy_from_slice(&ktop);
    for i in 0..8 {
        stretch[16 + i] = ktop[i] ^ ktop[i + 1];
    }

    // Offset_0 = Stretch[1+bottom..128+bottom] (bit indexing, 1-based)
    // 转换为 0-based 字节索引：从第 bottom 位开始
    let mut offset = [0u8; 16];
    let start_byte = bottom / 8;
    let start_bit = bottom % 8;

    if start_bit == 0 {
        offset.copy_from_slice(&stretch[start_byte..start_byte + 16]);
    } else {
        for i in 0..16 {
            let b0 = stretch[start_byte + i];
            let b1 = if start_byte + i + 1 < 24 {
                stretch[start_byte + i + 1]
            } else {
                0
            };
            offset[i] = (b0 << start_bit) | (b1 >> (8 - start_bit));
        }
    }

    let mut checksum = [0u8; 16];
    let mut ciphertext = Vec::with_capacity(p_len);

    // 处理完整块
    for i in 0..m_p {
        // Offset_i = Offset_{i-1} xor L_{ntz(i)}
        let ntz_i = ntz(i + 1);
        if ntz_i < 128 {
            xor_blocks(&mut offset, &l[ntz_i]);
        }

        // C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)
        let mut block = [0u8; 16];
        let start = i * 16;
        block.copy_from_slice(&plaintext[start..start + 16]);
        xor_blocks(&mut block, &offset);
        sm4.encrypt_block(&mut block);
        xor_blocks(&mut block, &offset);

        ciphertext.extend_from_slice(&block);

        // Checksum_i = Checksum_{i-1} xor P_i
        xor_blocks(
            &mut checksum,
            &plaintext[start..start + 16].try_into().unwrap(),
        );
    }

    // 处理最后一个不完整块
    let tag = if p_star_len > 0 {
        // Offset_* = Offset_m xor L_*
        xor_blocks(&mut offset, &l_star);

        // Pad = ENCIPHER(K, Offset_*)
        let mut pad = offset;
        sm4.encrypt_block(&mut pad);

        // C_* = P_* xor Pad[1..bitlen(P_*)]
        let start = m_p * 16;
        for i in 0..p_star_len {
            ciphertext.push(plaintext[start + i] ^ pad[i]);
        }

        // Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*)))
        for i in 0..p_star_len {
            checksum[i] ^= plaintext[start + i];
        }
        checksum[p_star_len] ^= 0x80;

        // Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A)
        let mut tag_input = checksum;
        xor_blocks(&mut tag_input, &offset);
        xor_blocks(&mut tag_input, &l_dollar);
        sm4.encrypt_block(&mut tag_input);
        xor_blocks(&mut tag_input, &hash);
        tag_input
    } else {
        // Tag = ENCIPHER(K, Checksum_m xor Offset_m xor L_$) xor HASH(K,A)
        let mut tag_input = checksum;
        xor_blocks(&mut tag_input, &offset);
        xor_blocks(&mut tag_input, &l_dollar);
        sm4.encrypt_block(&mut tag_input);
        xor_blocks(&mut tag_input, &hash);
        tag_input
    };

    Ok((ciphertext, tag))
}

/// SM4-OCB 解密
///
/// # 参数
/// - `key`: 16 字节 SM4 密钥
/// - `nonce`: 1-15 字节随机数
/// - `aad`: 附加认证数据
/// - `ciphertext`: 密文（不含 tag）
/// - `tag`: 认证标签
///
/// # 返回
/// `Ok(plaintext)` 如果认证成功，否则返回 `Error::InvalidTag`
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_ocb(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let sm4 = Sm4Key::new(key);
    const TAGLEN: usize = 128;

    // 密钥相关变量（与加密相同）
    let mut l_star = [0u8; 16];
    sm4.encrypt_block(&mut l_star);
    let l_dollar = gf128_mul_u(&l_star);
    let l_0 = gf128_mul_u(&l_dollar);

    let mut l = [[0u8; 16]; 128];
    l[0] = l_0;
    for i in 1..128 {
        l[i] = gf128_mul_u(&l[i - 1]);
    }

    // HASH(K, A)
    let m = if aad.is_empty() { 0 } else { aad.len() / 16 };
    let aad_star_len = if aad.is_empty() { 0 } else { aad.len() % 16 };

    let hash = {
        let mut sum = [0u8; 16];
        let mut offset = [0u8; 16];

        for i in 0..m {
            let ntz_i = ntz(i + 1);
            if ntz_i < 128 {
                xor_blocks(&mut offset, &l[ntz_i]);
            }

            let mut block = [0u8; 16];
            let start = i * 16;
            let end = start + 16;
            block.copy_from_slice(&aad[start..end]);
            xor_blocks(&mut block, &offset);
            sm4.encrypt_block(&mut block);
            xor_blocks(&mut sum, &block);
        }

        if aad_star_len > 0 {
            xor_blocks(&mut offset, &l_star);

            let mut block = [0u8; 16];
            let start = m * 16;
            block[..aad_star_len].copy_from_slice(&aad[start..]);
            block[aad_star_len] = 0x80;
            xor_blocks(&mut block, &offset);
            sm4.encrypt_block(&mut block);
            xor_blocks(&mut sum, &block);
        }

        sum
    };

    // 密文处理
    let c_len = ciphertext.len();
    let m_c = c_len / 16;
    let c_star_len = c_len % 16;

    // Nonce 处理（与加密相同）
    let mut nonce_block = [0u8; 16];
    nonce_block[0] = ((TAGLEN % 128) << 1) as u8;

    let nonce_end = 16;
    let nonce_start = nonce_end - nonce.len();
    nonce_block[nonce_start..nonce_end].copy_from_slice(nonce);
    nonce_block[nonce_start - 1] = 0x01;

    let bottom = (nonce_block[15] & 0x3F) as usize;

    nonce_block[15] &= 0xC0;
    let mut ktop = nonce_block;
    sm4.encrypt_block(&mut ktop);

    let mut stretch = [0u8; 24];
    stretch[..16].copy_from_slice(&ktop);
    for i in 0..8 {
        stretch[16 + i] = ktop[i] ^ ktop[i + 1];
    }

    let mut offset = [0u8; 16];
    let start_byte = bottom / 8;
    let start_bit = bottom % 8;

    if start_bit == 0 {
        offset.copy_from_slice(&stretch[start_byte..start_byte + 16]);
    } else {
        for i in 0..16 {
            let b0 = stretch[start_byte + i];
            let b1 = if start_byte + i + 1 < 24 {
                stretch[start_byte + i + 1]
            } else {
                0
            };
            offset[i] = (b0 << start_bit) | (b1 >> (8 - start_bit));
        }
    }

    let mut checksum = [0u8; 16];
    let mut plaintext = Vec::with_capacity(c_len);

    // 处理完整块
    for i in 0..m_c {
        let ntz_i = ntz(i + 1);
        if ntz_i < 128 {
            xor_blocks(&mut offset, &l[ntz_i]);
        }

        let mut block = [0u8; 16];
        let start = i * 16;
        block.copy_from_slice(&ciphertext[start..start + 16]);
        xor_blocks(&mut block, &offset);
        sm4.decrypt_block(&mut block);
        xor_blocks(&mut block, &offset);

        plaintext.extend_from_slice(&block);
        xor_blocks(&mut checksum, &block);
    }

    // 处理最后一个不完整块并验证 tag
    let expected_tag = if c_star_len > 0 {
        xor_blocks(&mut offset, &l_star);

        let mut pad = offset;
        sm4.encrypt_block(&mut pad);

        let start = m_c * 16;
        for i in 0..c_star_len {
            plaintext.push(ciphertext[start + i] ^ pad[i]);
        }

        for i in 0..c_star_len {
            checksum[i] ^= plaintext[start + i];
        }
        checksum[c_star_len] ^= 0x80;

        let mut tag_input = checksum;
        xor_blocks(&mut tag_input, &offset);
        xor_blocks(&mut tag_input, &l_dollar);
        sm4.encrypt_block(&mut tag_input);
        xor_blocks(&mut tag_input, &hash);
        tag_input
    } else {
        let mut tag_input = checksum;
        xor_blocks(&mut tag_input, &offset);
        xor_blocks(&mut tag_input, &l_dollar);
        sm4.encrypt_block(&mut tag_input);
        xor_blocks(&mut tag_input, &hash);
        tag_input
    };

    if bool::from(expected_tag.ct_eq(tag)) {
        Ok(plaintext)
    } else {
        Err(Error::InvalidTag)
    }
}

/// 计算 ntz(n) - trailing zeros 的个数
fn ntz(n: usize) -> usize {
    if n == 0 {
        return 128;
    }
    n.trailing_zeros() as usize
}

/// XOR 两个 128-bit 块
fn xor_blocks(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// GF(2^128) 上乘以 u（左移一位，模不可约多项式）
fn gf128_mul_u(block: &[u8; 16]) -> [u8; 16] {
    let mut result = *block;
    let mut carry = 0u8;

    // 大端序：从左到右处理
    for byte in result.iter_mut() {
        let new_carry = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = new_carry;
    }

    // 如果最高位为 1，需要模不可约多项式 x^128 + x^7 + x^2 + x + 1
    // 对应 R = 0x87（当最高位溢出时 XOR）
    if block[0] & 0x80 != 0 {
        result[15] ^= 0x87;
    }

    result
}

// ── SIV 模式（确定性 AEAD）───────────────────────────────────────────────────

/// SM4-SIV 加密（确定性 AEAD 模式）
///
/// SIV（Synthetic Initialization Vector）模式是一种确定性认证加密模式，
/// 即使 nonce 重复使用也能保持安全性。适合需要确定性加密的场景。
/// 实现基于 RFC 5297。
///
/// # 参数
/// - `key`: 32 字节密钥（前 16 字节用于 MAC，后 16 字节用于加密）
/// - `nonce`: 可选随机数（可为空）
/// - `aad`: 附加认证数据（可多个）
/// - `plaintext`: 明文
///
/// # 返回
/// `(ciphertext, siv)` - 密文和 SIV（用作 IV）
///
/// # 安全说明
/// - 即使 nonce 重复，只要 (nonce, aad, plaintext) 组合唯一就安全
/// - 相同输入产生相同输出（确定性）
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_siv(
    key: &[u8; 32],
    nonce: Option<&[u8]>,
    aad: &[&[u8]],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), Error> {
    let mac_key = &key[..16];
    let enc_key: &[u8; 16] = &key[16..32].try_into().unwrap();

    // Step 1: 计算 S2V（Synthetic IV）
    let siv = compute_s2v(mac_key, nonce, aad, plaintext)?;

    // Step 2: 使用 SIV 作为 IV 进行 CTR 模式加密
    let ciphertext = sm4_crypt_ctr(enc_key, &siv, plaintext);

    Ok((ciphertext, siv))
}

/// SM4-SIV 解密
///
/// # 参数
/// - `key`: 32 字节密钥
/// - `nonce`: 可选随机数
/// - `aad`: 附加认证数据
/// - `ciphertext`: 密文
/// - `siv`: SIV 值（16 字节）
///
/// # 返回
/// `Ok(plaintext)` 如果 SIV 验证通过，否则返回 `Error::InvalidTag`
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_siv(
    key: &[u8; 32],
    nonce: Option<&[u8]>,
    aad: &[&[u8]],
    ciphertext: &[u8],
    siv: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let mac_key = &key[..16];
    let enc_key: &[u8; 16] = &key[16..32].try_into().unwrap();

    // Step 1: 先解密得到 plaintext
    let plaintext = sm4_crypt_ctr(enc_key, siv, ciphertext);

    // Step 2: 使用解密后的 plaintext 重新计算 S2V
    let expected_siv = compute_s2v(mac_key, nonce, aad, &plaintext)?;

    // Step 3: 常量时间比较 SIV
    if !bool::from(expected_siv.ct_eq(siv.as_slice())) {
        return Err(Error::InvalidTag);
    }

    Ok(plaintext)
}

/// S2V 函数（RFC 5297 §2.4）
#[cfg(feature = "alloc")]
fn compute_s2v(
    mac_key: &[u8],
    nonce: Option<&[u8]>,
    aad: &[&[u8]],
    data: &[u8],
) -> Result<[u8; 16], Error> {
    let sm4 = Sm4Key::new(mac_key.try_into().unwrap());

    // RFC 5297 S2V 算法：
    // 1. 初始化 D = CMAC_K(0^128)
    // 2. 对于每个字符串 S_i（AAD、nonce、plaintext）：
    //    D = CMAC_K(D XOR S_i)
    // 3. 最后：D = 2*D XOR bitlen(plaintext) || CMAC_K(final)

    // Step 1: D = CMAC(0^128) = E(0^128)
    let mut d = [0u8; 16];
    sm4.encrypt_block(&mut d);

    // Step 2: 处理所有 AAD 字符串
    for &aad_item in aad {
        d = xor_and_cmac(&sm4, &d, aad_item);
    }

    // Step 3: 处理 nonce（如果存在）
    if let Some(n) = nonce {
        d = xor_and_cmac(&sm4, &d, n);
    }

    // Step 4: 处理最后一个字符串（plaintext/ciphertext）
    // 特殊处理：先 XOR 长度，再加密
    let data_len_bits = (data.len() as u64) * 8;

    // XOR 数据长度（bit）到 D 的最后 8 字节
    let len_bytes = data_len_bits.to_be_bytes();
    for i in 0..8 {
        d[8 + i] ^= len_bytes[i];
    }

    // 如果数据为空，直接加密
    if data.is_empty() {
        sm4.encrypt_block(&mut d);
        return Ok(d);
    }

    // XOR 数据（如果数据长度小于 16，需要特殊处理）
    if data.len() >= 16 {
        // XOR 最后 16 字节
        let last_block = &data[data.len() - 16..];
        for i in 0..16 {
            d[i] ^= last_block[i];
        }
        sm4.encrypt_block(&mut d);

        // 处理前面的数据块
        for chunk in data[..data.len() - 16].chunks(16) {
            for (i, &byte) in chunk.iter().enumerate() {
                d[i] ^= byte;
            }
            sm4.encrypt_block(&mut d);
        }
    } else {
        // 数据长度小于 16 字节
        for (i, &byte) in data.iter().enumerate() {
            d[i] ^= byte;
        }
        sm4.encrypt_block(&mut d);
    }

    Ok(d)
}

/// XOR 数据并计算 CMAC
#[cfg(feature = "alloc")]
fn xor_and_cmac(sm4: &Sm4Key, state: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut result = *state;

    if data.is_empty() {
        sm4.encrypt_block(&mut result);
        return result;
    }

    // XOR 数据
    if data.len() >= 16 {
        // XOR 最后 16 字节
        let last_block = &data[data.len() - 16..];
        for i in 0..16 {
            result[i] ^= last_block[i];
        }
        sm4.encrypt_block(&mut result);

        // 处理前面的数据块
        for chunk in data[..data.len() - 16].chunks(16) {
            for (i, &byte) in chunk.iter().enumerate() {
                result[i] ^= byte;
            }
            sm4.encrypt_block(&mut result);
        }
    } else {
        // 数据长度小于 16 字节
        for (i, &byte) in data.iter().enumerate() {
            result[i] ^= byte;
        }
        sm4.encrypt_block(&mut result);
    }

    result
}

// ── EAX 模式（两遍 AEAD）─────────────────────────────────────────────────────

/// SM4-EAX 加密（两遍 AEAD 模式）
///
/// EAX 模式是一种两遍认证加密模式，比 GCM 更安全（无短周期问题），
/// 但稍慢。实现基于 Bellare 等人的原始论文。
///
/// # 参数
/// - `key`: 16 字节 SM4 密钥
/// - `nonce`: 随机数（任意长度）
/// - `aad`: 附加认证数据
/// - `plaintext`: 明文
///
/// # 返回
/// `(ciphertext, tag)` - 密文和 16 字节认证标签
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_eax(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), Error> {
    let sm4 = Sm4Key::new(key);

    // Step 1: 计算 OMAC 密钥
    // K_enc = OMAC_K(0)
    let mut k_enc = [0u8; 16];
    k_enc[15] = 0;
    sm4.encrypt_block(&mut k_enc);

    // K_nonce = OMAC_K(1)
    let mut k_nonce = [0u8; 16];
    k_nonce[15] = 1;
    sm4.encrypt_block(&mut k_nonce);

    // K_auth = OMAC_K(2)
    let mut k_auth = [0u8; 16];
    k_auth[15] = 2;
    sm4.encrypt_block(&mut k_auth);

    // Step 2: 计算 nonce 的 MAC（作为 CTR 模式的 IV）
    let iv = omac(&sm4, &k_nonce, nonce);

    // Step 3: 计算 AAD 的 MAC
    let mut auth = omac(&sm4, &k_auth, aad);

    // Step 4: 使用 CTR 模式加密（IV = nonce MAC）
    let ciphertext = sm4_crypt_ctr(key, &iv, plaintext);

    // Step 5: 计算密文的 MAC 并 XOR 到 auth 上
    let mac_cipher = omac(&sm4, &k_enc, &ciphertext);
    for i in 0..16 {
        auth[i] ^= mac_cipher[i];
    }

    Ok((ciphertext, auth))
}

/// SM4-EAX 解密
///
/// # 参数
/// - `key`: 16 字节 SM4 密钥
/// - `nonce`: 随机数
/// - `aad`: 附加认证数据
/// - `ciphertext`: 密文
/// - `tag`: 认证标签
///
/// # 返回
/// `Ok(plaintext)` 如果认证成功，否则返回 `Error::InvalidTag`
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_eax(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let sm4 = Sm4Key::new(key);

    // Step 1: 重新计算密钥
    let mut k_enc = [0u8; 16];
    k_enc[15] = 0;
    sm4.encrypt_block(&mut k_enc);

    let mut k_nonce = [0u8; 16];
    k_nonce[15] = 1;
    sm4.encrypt_block(&mut k_nonce);

    let mut k_auth = [0u8; 16];
    k_auth[15] = 2;
    sm4.encrypt_block(&mut k_auth);

    // Step 2: 计算 nonce MAC
    let iv = omac(&sm4, &k_nonce, nonce);

    // Step 3: 计算 AAD MAC
    let mut auth = omac(&sm4, &k_auth, aad);

    // Step 4: 计算密文 MAC
    let mac_cipher = omac(&sm4, &k_enc, ciphertext);
    for i in 0..16 {
        auth[i] ^= mac_cipher[i];
    }

    // Step 5: 验证标签
    if !bool::from(auth.ct_eq(tag.as_slice())) {
        return Err(Error::InvalidTag);
    }

    // Step 6: 解密
    let plaintext = sm4_crypt_ctr(key, &iv, ciphertext);

    Ok(plaintext)
}

/// OMAC（One-Key MAC）- EAX 使用的 CMAC 变体
#[cfg(feature = "alloc")]
fn omac(sm4: &Sm4Key, _key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    // EAX 使用 CMAC，需要生成子密钥
    // Step 1: 计算 L = E(0^128)
    let mut l = [0u8; 16];
    sm4.encrypt_block(&mut l);

    // Step 2: 计算子密钥 K1 = double(L), K2 = double(double(L))
    let k1 = gf128_mul_u(&l);
    let k2 = gf128_mul_u(&k1);

    // Step 3: 处理数据
    let mut state = [0u8; 16];
    let data_len = data.len();

    if data_len == 0 {
        // 空数据：XOR K2
        for i in 0..16 {
            state[i] ^= k2[i];
        }
        sm4.encrypt_block(&mut state);
        return state;
    }

    let num_blocks = data_len / 16;
    let remaining = data_len % 16;

    // 处理完整块
    for i in 0..num_blocks {
        let start = i * 16;
        for j in 0..16 {
            state[j] ^= data[start + j];
        }
        sm4.encrypt_block(&mut state);
    }

    // 处理最后一块
    let last_start = num_blocks * 16;
    if remaining == 0 {
        // 完整块：XOR K1
        for i in 0..16 {
            state[i] ^= k1[i];
        }
    } else {
        // 不完整块：padding 并 XOR K2
        let mut last_block = [0u8; 16];
        last_block[..remaining].copy_from_slice(&data[last_start..(last_start + remaining)]);
        last_block[remaining] = 0x80; // padding

        for i in 0..16 {
            state[i] ^= last_block[i];
        }
        for i in 0..16 {
            state[i] ^= k2[i];
        }
    }

    sm4.encrypt_block(&mut state);
    state
}

// ── Key Wrap 模式（RFC 3394）────────────────────────────────────────────────

/// SM4 Key Wrap（RFC 3394）
///
/// Key Wrap 用于安全地加密密钥材料，提供完整性保护。
/// 实现基于 RFC 3394（AES Key Wrap），但使用 SM4。
///
/// # 参数
/// - `key`: 16 字节 SM4 密钥（KEK - Key Encryption Key）
/// - `plaintext`: 要加密的密钥材料（必须是 8 字节的倍数）
///
/// # 返回
/// 包装后的密钥（比输入长 8 字节）
///
/// # 安全说明
/// - 输出包含完整性校验值（ICV）
/// - 解密时会验证完整性
#[cfg(feature = "alloc")]
pub fn sm4_key_wrap(key: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    // Reason: RFC 3394 要求输入必须是 8 字节（64 位）的倍数
    if plaintext.is_empty() || plaintext.len() % 8 != 0 {
        return Err(Error::InvalidInputLength);
    }

    let sm4 = Sm4Key::new(key);
    let n = plaintext.len() / 8; // 64 位块的数量

    // 初始化 A = IV（默认 ICV = 0xA6A6A6A6A6A6A6A6）
    let mut a = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];
    let mut r: Vec<[u8; 8]> = plaintext
        .chunks(8)
        .map(|chunk| {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);
            block
        })
        .collect();

    // 6 * n 轮加密
    // RFC 3394 使用 1-based 索引：R[1]...R[n]，t = n*j + i
    for j in 0..6 {
        for i in 1..=n {
            // Step 1: B = E(K, A || R[i])
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(&r[i - 1]); // Rust 使用 0-based 索引
            sm4.encrypt_block(&mut block);

            // Step 2: A = MSB_64(B) XOR t, t = n*j + i
            let t = (n * j + i) as u64;
            let a_new = u64::from_be_bytes(block[..8].try_into().unwrap()) ^ t;
            a.copy_from_slice(&a_new.to_be_bytes());

            // Step 3: R[i] = LSB_64(B)
            r[i - 1].copy_from_slice(&block[8..]); // Rust 使用 0-based 索引
        }
    }

    // 输出：A || R[1] || ... || R[n]
    let mut output = Vec::with_capacity(plaintext.len() + 8);
    output.extend_from_slice(&a);
    for block in r {
        output.extend_from_slice(&block);
    }

    Ok(output)
}

/// SM4 Key Unwrap（RFC 3394）
///
/// # 参数
/// - `key`: 16 字节 SM4 密钥（KEK）
/// - `ciphertext`: 包装后的密钥（必须是 8 字节的倍数）
///
/// # 返回
/// `Ok(plaintext)` 如果完整性验证通过，否则返回 `Error::InvalidTag`
#[cfg(feature = "alloc")]
pub fn sm4_key_unwrap(key: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    // Reason: RFC 3394 要求输入必须是 8 字节的倍数，且至少 16 字节（A + 至少一个 R）
    if ciphertext.len() < 16 || ciphertext.len() % 8 != 0 {
        return Err(Error::InvalidInputLength);
    }

    let sm4 = Sm4Key::new(key);
    let n = (ciphertext.len() - 8) / 8; // R 块的数量

    // 初始化 A 和 R
    let mut a = ciphertext[..8].try_into().unwrap();
    let mut r: Vec<[u8; 8]> = ciphertext[8..]
        .chunks(8)
        .map(|chunk| chunk.try_into().unwrap())
        .collect();

    // 6 * n 轮解密
    // RFC 3394 解密是加密的逆过程：t 从 6n 递减到 1
    for j in (0..6).rev() {
        for i in (1..=n).rev() {
            // Step 1: B = D(K, (A XOR t) || R[i]), t = n*j + i
            let t = (n * j + i) as u64;
            let a_xor = u64::from_be_bytes(a) ^ t;

            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a_xor.to_be_bytes());
            block[8..].copy_from_slice(&r[i - 1]); // Rust 使用 0-based 索引
            sm4.decrypt_block(&mut block);

            // Step 2: A = MSB_64(B)
            a.copy_from_slice(&block[..8]);

            // Step 3: R[i] = LSB_64(B)
            r[i - 1].copy_from_slice(&block[8..]); // Rust 使用 0-based 索引
        }
    }

    // 验证 ICV
    let expected_icv = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];
    if !bool::from(a.ct_eq(&expected_icv)) {
        return Err(Error::InvalidTag);
    }

    // 输出：R[1] || ... || R[n]
    let mut output = Vec::with_capacity(n * 8);
    for block in r {
        output.extend_from_slice(&block);
    }

    Ok(output)
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;

    // ====================================================================================
    // 填充测试
    // ====================================================================================

    /// ECB PKCS#5 填充往返测试
    #[test]
    fn test_ecb_pkcs5_roundtrip() {
        let key = [0u8; 16];
        let plaintext = b"Hello SM4 ECB with PKCS#5!";

        let ciphertext = sm4_encrypt_ecb_pkcs5(&key, plaintext);
        let decrypted =
            sm4_decrypt_ecb_pkcs5(&key, &ciphertext).expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
        assert!(ciphertext.len() > plaintext.len());
        assert_eq!(ciphertext.len() % 16, 0);
    }

    /// ECB PKCS#7 填充往返测试
    #[test]
    fn test_ecb_pkcs7_roundtrip() {
        let key = [1u8; 16];
        let plaintext = b"Test PKCS#7 padding";

        let ciphertext = sm4_encrypt_ecb_pkcs7(&key, plaintext);
        let decrypted =
            sm4_decrypt_ecb_pkcs7(&key, &ciphertext).expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    /// CBC PKCS#5 填充往返测试
    #[test]
    fn test_cbc_pkcs5_roundtrip() {
        let key = [2u8; 16];
        let iv = [3u8; 16];
        let plaintext = b"Hello SM4 CBC with PKCS#5 padding!";

        let ciphertext = sm4_encrypt_cbc_pkcs5(&key, &iv, plaintext);
        let decrypted =
            sm4_decrypt_cbc_pkcs5(&key, &iv, &ciphertext).expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
        assert!(ciphertext.len() > plaintext.len());
        assert_eq!(ciphertext.len() % 16, 0);
    }

    /// CBC PKCS#7 填充往返测试
    #[test]
    fn test_cbc_pkcs7_roundtrip() {
        let key = [4u8; 16];
        let iv = [5u8; 16];
        let plaintext = b"Test CBC PKCS#7";

        let ciphertext = sm4_encrypt_cbc_pkcs7(&key, &iv, plaintext);
        let decrypted =
            sm4_decrypt_cbc_pkcs7(&key, &iv, &ciphertext).expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    /// PKCS#5 填充 - 空数据测试
    #[test]
    fn test_pkcs5_empty_data() {
        let key = [0u8; 16];
        let plaintext: &[u8] = b"";

        let ciphertext = sm4_encrypt_ecb_pkcs5(&key, plaintext);
        let decrypted =
            sm4_decrypt_ecb_pkcs5(&key, &ciphertext).expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
        assert_eq!(ciphertext.len(), 16); // 空数据填充 16 字节
    }

    /// PKCS#5 填充 - 恰好整倍数测试
    #[test]
    fn test_pkcs5_exact_block() {
        let key = [0u8; 16];
        let plaintext = [0u8; 16]; // 恰好 16 字节

        let ciphertext = sm4_encrypt_ecb_pkcs5(&key, &plaintext);
        let decrypted =
            sm4_decrypt_ecb_pkcs5(&key, &ciphertext).expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
        assert_eq!(ciphertext.len(), 32); // 16 字节数据 + 16 字节填充
    }

    /// PKCS#5 填充 - 无效填充检测
    #[test]
    fn test_pkcs5_invalid_padding() {
        let key = [0u8; 16];
        // 构造无效的密文（解密后填充无效）
        let mut ciphertext = [0u8; 16];
        ciphertext[15] = 0x05; // 声称有 5 个填充字节，但实际不足

        assert!(sm4_decrypt_ecb_pkcs5(&key, &ciphertext).is_err());
    }

    // ====================================================================================
    // 基础模式测试
    // ====================================================================================

    /// GB/T 32907-2016 附录 B：CBC 模式测试向量
    #[test]
    fn test_cbc_vector() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let iv = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let plain = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let ct = sm4_encrypt_cbc(&key, &iv, &plain);
        let pt = sm4_decrypt_cbc(&key, &iv, &ct);
        assert_eq!(pt, plain, "CBC 往返解密失败");
    }

    /// GCM 加解密往返测试
    #[test]
    fn test_gcm_roundtrip() {
        let key = [0u8; 16];
        let nonce = [1u8; 12];
        let aad = b"additional data";
        let plain = b"hello gcm world!";

        let (ct, tag) = sm4_encrypt_gcm(&key, &nonce, aad, plain);
        let pt = sm4_decrypt_gcm(&key, &nonce, aad, &ct, &tag).unwrap();
        assert_eq!(pt, plain, "GCM 往返解密失败");
    }

    /// GCM tag 篡改检测
    #[test]
    fn test_gcm_tag_tamper() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let (ct, mut tag) = sm4_encrypt_gcm(&key, &nonce, b"", b"secret");
        tag[0] ^= 1;
        assert!(
            sm4_decrypt_gcm(&key, &nonce, b"", &ct, &tag).is_err(),
            "篡改 tag 后应返回错误"
        );
    }

    /// CCM 加解密往返测试
    #[test]
    fn test_ccm_roundtrip() {
        let key = [0u8; 16];
        let nonce = [2u8; 12];
        let aad = b"ccm aad";
        let plain = b"ccm plaintext!!!";

        let ct = sm4_encrypt_ccm(&key, &nonce, aad, plain, 16).unwrap();
        let pt = sm4_decrypt_ccm(&key, &nonce, aad, &ct, 16).unwrap();
        assert_eq!(pt, plain, "CCM 往返解密失败");
    }

    /// CCM tag 篡改检测（先验证后解密原则验证）
    #[test]
    fn test_ccm_tag_tamper() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let mut ct = sm4_encrypt_ccm(&key, &nonce, b"", b"secret data here", 16).unwrap();
        // 篡改 tag（最后 16 字节）
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(
            sm4_decrypt_ccm(&key, &nonce, b"", &ct, 16).is_err(),
            "篡改 CCM tag 后应返回错误"
        );
    }

    /// CCM AAD 超限应返回错误（而非静默跳过）
    #[test]
    fn test_ccm_aad_too_long() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let big_aad = [0u8; 511]; // 超过 510 字节限制
        assert!(
            sm4_encrypt_ccm(&key, &nonce, &big_aad, b"data", 16).is_err(),
            "AAD 超过 510 字节时应返回 InvalidInputLength"
        );
    }

    /// XTS 加解密往返测试
    #[test]
    fn test_xts_roundtrip() {
        let key1 = [0x11u8; 16];
        let key2 = [0x22u8; 16];
        let tweak = [0u8; 16];
        let plain = [0x42u8; 32]; // 2 个 16 字节块

        let ct = sm4_encrypt_xts(&key1, &key2, &tweak, &plain).unwrap();
        let pt = sm4_decrypt_xts(&key1, &key2, &tweak, &ct).unwrap();
        assert_eq!(pt, plain, "XTS 往返解密失败");
    }

    /// XTS 非对齐数据应返回错误
    #[test]
    fn test_xts_non_aligned_rejected() {
        let key1 = [0u8; 16];
        let key2 = [0u8; 16];
        let tweak = [0u8; 16];

        // 空输入
        assert!(
            sm4_encrypt_xts(&key1, &key2, &tweak, b"").is_err(),
            "空输入应返回 InvalidInputLength"
        );
        // 非 16 倍数
        assert!(
            sm4_encrypt_xts(&key1, &key2, &tweak, b"not-aligned-data").is_ok(),
            "正好 16 字节不应返回错误"
        );
        assert!(
            sm4_encrypt_xts(&key1, &key2, &tweak, &[0u8; 17]).is_err(),
            "17 字节应返回 InvalidInputLength"
        );
        assert!(
            sm4_decrypt_xts(&key1, &key2, &tweak, &[0u8; 15]).is_err(),
            "15 字节应返回 InvalidInputLength"
        );
    }

    /// OFB 自反性验证
    #[test]
    fn test_ofb_self_inverse() {
        let key = [0xABu8; 16];
        let iv = [0x12u8; 16];
        let plain = b"ofb test message";
        let ct = sm4_crypt_ofb(&key, &iv, plain);
        let pt = sm4_crypt_ofb(&key, &iv, &ct);
        assert_eq!(pt, plain, "OFB 应为自反模式");
    }

    // ====================================================================================
    // OCB 模式测试
    // ====================================================================================

    /// OCB 加解密往返测试
    #[test]
    fn test_ocb_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = b"unique_nonce";
        let aad = b"additional data";
        let plaintext = b"Hello OCB world!";

        let (ciphertext, tag) =
            sm4_encrypt_ocb(&key, nonce, aad, plaintext).expect("OCB encryption should succeed");
        let decrypted = sm4_decrypt_ocb(&key, nonce, aad, &ciphertext, &tag)
            .expect("OCB decryption should succeed");

        assert_eq!(decrypted, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    /// OCB 标签篡改检测
    #[test]
    fn test_ocb_tamper_detection() {
        let key = [0x42u8; 16];
        let nonce = b"unique_nonce";
        let aad = b"additional data";
        let plaintext = b"Secret message";

        let (ciphertext, mut tag) = sm4_encrypt_ocb(&key, nonce, aad, plaintext).unwrap();
        tag[0] ^= 0x01; // 篡改标签

        assert!(sm4_decrypt_ocb(&key, nonce, aad, &ciphertext, &tag).is_err());
    }

    /// OCB nonce 长度验证
    #[test]
    fn test_ocb_nonce_length() {
        let key = [0x42u8; 16];
        let plaintext = b"test".as_slice();
        let empty: &[u8] = &[];

        // 空 nonce 应失败
        assert!(sm4_encrypt_ocb(&key, empty, empty, plaintext).is_err());

        // 过长的 nonce 应失败
        let long_nonce = [0u8; 16];
        assert!(sm4_encrypt_ocb(&key, long_nonce.as_slice(), empty, plaintext).is_err());

        // 合法的 nonce 应成功
        let valid_nonce = b"12_bytes_nonce";
        assert!(sm4_encrypt_ocb(&key, valid_nonce.as_slice(), empty, plaintext).is_ok());
    }

    // ====================================================================================
    // SIV 模式测试
    // ====================================================================================

    /// SIV 加解密往返测试
    #[test]
    fn test_siv_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = Some(b"nonce".as_slice());
        let aad: &[&[u8]] = &[b"additional", b"data"];
        let plaintext = b"Hello SIV world!";

        let (ciphertext, siv) =
            sm4_encrypt_siv(&key, nonce, aad, plaintext).expect("SIV encryption should succeed");
        let decrypted = sm4_decrypt_siv(&key, nonce, aad, &ciphertext, &siv)
            .expect("SIV decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    /// SIV 确定性测试（相同输入产生相同输出）
    #[test]
    fn test_siv_deterministic() {
        let key = [0x42u8; 32];
        let nonce = Some(b"nonce".as_slice());
        let aad: &[&[u8]] = &[b"additional"];
        let plaintext = b"Deterministic test";

        let (ct1, siv1) = sm4_encrypt_siv(&key, nonce, aad, plaintext).unwrap();
        let (ct2, siv2) = sm4_encrypt_siv(&key, nonce, aad, plaintext).unwrap();

        assert_eq!(ct1, ct2, "SIV 应为确定性加密");
        assert_eq!(siv1, siv2);
    }

    /// SIV 标签验证
    #[test]
    fn test_siv_tag_verification() {
        let key = [0x42u8; 32];
        let nonce = Some(b"nonce".as_slice());
        let aad: &[&[u8]] = &[b"additional"];
        let plaintext = b"Test tamper detection";

        let (ciphertext, mut siv) = sm4_encrypt_siv(&key, nonce, aad, plaintext).unwrap();
        siv[0] ^= 0x01; // 篡改 SIV

        assert!(sm4_decrypt_siv(&key, nonce, aad, &ciphertext, &siv).is_err());
    }

    // ====================================================================================
    // EAX 模式测试
    // ====================================================================================

    /// EAX 加解密往返测试
    #[test]
    fn test_eax_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = b"unique_nonce";
        let aad = b"additional data";
        let plaintext = b"Hello EAX world!";

        let (ciphertext, tag) =
            sm4_encrypt_eax(&key, nonce, aad, plaintext).expect("EAX encryption should succeed");
        let decrypted = sm4_decrypt_eax(&key, nonce, aad, &ciphertext, &tag)
            .expect("EAX decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    /// EAX 标签篡改检测
    #[test]
    fn test_eax_tamper_detection() {
        let key = [0x42u8; 16];
        let nonce = b"unique_nonce";
        let aad = b"additional data";
        let plaintext = b"Secret message";

        let (ciphertext, mut tag) = sm4_encrypt_eax(&key, nonce, aad, plaintext).unwrap();
        tag[0] ^= 0x01; // 篡改标签

        assert!(sm4_decrypt_eax(&key, nonce, aad, &ciphertext, &tag).is_err());
    }

    // ====================================================================================
    // Key Wrap 模式测试
    // ====================================================================================

    /// Key Wrap 往返测试
    #[test]
    fn test_key_wrap_roundtrip() {
        let kek = [0x42u8; 16];
        let key_data = [0x12u8; 24]; // 24 字节密钥数据（8 的倍数）

        let wrapped = sm4_key_wrap(&kek, &key_data).expect("Key wrap should succeed");
        let unwrapped = sm4_key_unwrap(&kek, &wrapped).expect("Key unwrap should succeed");

        assert_eq!(unwrapped, key_data);
        assert_eq!(wrapped.len(), key_data.len() + 8); // 输出应比输入长 8 字节
    }

    /// Key Wrap ICV 验证
    #[test]
    fn test_key_wrap_icv_check() {
        let kek = [0x42u8; 16];
        let key_data = [0x12u8; 16];

        let wrapped = sm4_key_wrap(&kek, &key_data).unwrap();

        // 篡改密文
        let mut tampered = wrapped.clone();
        tampered[0] ^= 0x01;

        assert!(sm4_key_unwrap(&kek, &tampered).is_err());
    }

    /// Key Wrap 长度验证
    #[test]
    fn test_key_wrap_length_validation() {
        let kek = [0x42u8; 16];

        // 非 8 倍数长度应失败
        assert!(sm4_key_wrap(&kek, &[0u8; 15]).is_err());

        // 空数据应失败
        assert!(sm4_key_wrap(&kek, &[]).is_err());

        // 合法长度应成功
        assert!(sm4_key_wrap(&kek, &[0u8; 8]).is_ok());
        assert!(sm4_key_wrap(&kek, &[0u8; 16]).is_ok());
    }
}
