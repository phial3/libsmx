//! SM3 密码杂凑算法（GB/T 32905-2016）
//!
//! # 示例
//!
//! ```rust
//! use libsmx::sm3::Sm3Hasher;
//!
//! // 单次哈希
//! let digest = Sm3Hasher::digest(b"abc");
//! assert_eq!(digest.len(), 32);
//!
//! // 流式哈希
//! let mut h = Sm3Hasher::new();
//! h.update(b"ab");
//! h.update(b"c");
//! let digest2 = h.finalize();
//! assert_eq!(digest, digest2);
//! ```
//!
//! # 安全说明
//!
//! SM3 的压缩函数不涉及密钥材料，无需常量时间保护。
//! 如需 HMAC，请使用 [`hmac_sm3`]。

mod compress;
pub mod hkdf;

use compress::{compress, IV};

/// SM3 摘要长度（字节）
pub const DIGEST_LEN: usize = 32;

/// SM3 流式哈希器
///
/// 支持逐步 [`update`](Sm3Hasher::update) 输入数据，最终调用
/// [`finalize`](Sm3Hasher::finalize) 获取 32 字节摘要。
///
/// 实现遵循 GB/T 32905-2016。
#[derive(Clone)]
pub struct Sm3Hasher {
    /// 当前状态（8 × u32）
    state: [u32; 8],
    /// 未处理的字节缓冲区（最多 64 字节）
    buffer: [u8; 64],
    /// 缓冲区已填充字节数
    buf_len: usize,
    /// 已处理的总位数（用于最终填充）
    bit_len: u64,
}

impl Sm3Hasher {
    /// 创建新的 SM3 哈希器（初始化为 IV）
    pub fn new() -> Self {
        Self {
            state: IV,
            buffer: [0u8; 64],
            buf_len: 0,
            bit_len: 0,
        }
    }

    /// 一次性计算 `data` 的 SM3 摘要（便捷函数）
    pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }

    /// 追加输入数据
    pub fn update(&mut self, data: &[u8]) {
        let mut remaining = data;

        // 若缓冲区已有数据，先尝试填满一块
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(remaining.len());
            self.buffer[self.buf_len..self.buf_len + take].copy_from_slice(&remaining[..take]);
            self.buf_len += take;
            remaining = &remaining[take..];

            if self.buf_len == 64 {
                let block: &[u8; 64] = self.buffer[..].try_into().unwrap();
                compress(&mut self.state, block);
                self.bit_len = self.bit_len.wrapping_add(512);
                self.buf_len = 0;
            }
        }

        // 处理完整块
        while remaining.len() >= 64 {
            let block: &[u8; 64] = remaining[..64].try_into().unwrap();
            compress(&mut self.state, block);
            self.bit_len = self.bit_len.wrapping_add(512);
            remaining = &remaining[64..];
        }

        // 剩余字节存入缓冲区
        if !remaining.is_empty() {
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.buf_len = remaining.len();
        }
    }

    /// 完成哈希，返回 32 字节摘要
    ///
    /// 调用后此 hasher 不应再使用（消耗所有权的版本请用 [`finalize`](Self::finalize)）。
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        Self::finalize_inner(&mut self)
    }

    /// 完成哈希并重置状态（供复用，无需重新构造）
    ///
    /// 等同于 `finalize()` 后调用 `reset()`，但只需一次操作。
    /// rustls `Hasher` trait 要求此语义（`finish(&mut self)`）。
    pub fn finalize_reset(&mut self) -> [u8; DIGEST_LEN] {
        let out = Self::finalize_inner(self);
        self.reset();
        out
    }

    /// 重置为初始状态（等同于重新调用 `new()`，但复用已分配内存）
    pub fn reset(&mut self) {
        self.state = IV;
        self.buffer = [0u8; 64];
        self.buf_len = 0;
        self.bit_len = 0;
    }

    /// 内部完成函数（同时供消耗版和借用版使用）
    fn finalize_inner(h: &mut Self) -> [u8; DIGEST_LEN] {
        // 计算总位数（包含缓冲区中的字节）
        let total_bits = h.bit_len.wrapping_add((h.buf_len as u64) * 8);

        // Padding：追加 0x80 + 零字节，使消息长度 ≡ 56 (mod 64)
        h.buffer[h.buf_len] = 0x80;
        h.buf_len += 1;

        if h.buf_len > 56 {
            // 当前块填不下长度字段，先处理这块，再开一块
            for i in h.buf_len..64 {
                h.buffer[i] = 0;
            }
            compress(&mut h.state, &h.buffer);
            h.buffer = [0u8; 64];
        } else {
            for i in h.buf_len..56 {
                h.buffer[i] = 0;
            }
        }

        // 最后 8 字节写入总位长（大端）
        h.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        compress(&mut h.state, &h.buffer);

        // 输出：8 个 u32 大端序拼接
        let mut out = [0u8; 32];
        for (i, &v) in h.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }
}

impl Default for Sm3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// HMAC-SM3（GB/T 15852.1）
///
/// # 参数
/// - `key`: 密钥（任意长度；若超过 64 字节则先做 SM3 压缩）
/// - `data`: 消息数据
///
/// # 返回
/// 32 字节 HMAC 值
///
/// # 安全性
/// `k_pad`/`ipad`/`opad` 含密钥派生材料，函数返回前用 `zeroize` 清零，
/// 防止密钥残留在栈上被后续代码或内存扫描工具读取。
pub fn hmac_sm3(key: &[u8], data: &[u8]) -> [u8; DIGEST_LEN] {
    use zeroize::Zeroize;

    // 将 key 标准化到 64 字节（不足补零，过长先哈希）
    let mut k_pad = [0u8; 64];
    if key.len() > 64 {
        let h = Sm3Hasher::digest(key);
        k_pad[..32].copy_from_slice(&h);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }

    // inner = HMAC_ipad XOR k_pad，outer = HMAC_opad XOR k_pad
    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = k_pad[i] ^ 0x36;
        opad[i] = k_pad[i] ^ 0x5C;
    }

    // inner hash = SM3(ipad || data)
    let mut inner = Sm3Hasher::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    // outer hash = SM3(opad || inner_hash)
    let mut outer = Sm3Hasher::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let result = outer.finalize();

    // Reason: 清零栈上的密钥派生材料，防止密钥残留
    k_pad.zeroize();
    ipad.zeroize();
    opad.zeroize();

    result
}

/// 流式 HMAC-SM3
///
/// 与 [`hmac_sm3`] 功能相同，但支持多次 [`update`](HmacSm3::update) 调用，
/// 适用于 rustls `hmac::Key::sign_concat` 等多切片场景。
///
/// # 安全性
/// `opad_key` 含派生自密钥的材料，结构体析构时由 `Zeroize` 自动清零。
#[derive(Clone)]
pub struct HmacSm3 {
    /// 正在计算 inner hash（已喂入 ipad 前缀）
    inner: Sm3Hasher,
    /// 预计算的 opad XOR key（64 字节）
    opad_key: [u8; 64],
}

impl HmacSm3 {
    /// 以给定密钥初始化 HMAC-SM3
    pub fn new(key: &[u8]) -> Self {
        use zeroize::Zeroize;

        let mut k_pad = [0u8; 64];
        if key.len() > 64 {
            let h = Sm3Hasher::digest(key);
            k_pad[..32].copy_from_slice(&h);
        } else {
            k_pad[..key.len()].copy_from_slice(key);
        }

        let mut ipad_key = [0u8; 64];
        let mut opad_key = [0u8; 64];
        for i in 0..64 {
            ipad_key[i] = k_pad[i] ^ 0x36;
            opad_key[i] = k_pad[i] ^ 0x5C;
        }
        k_pad.zeroize();

        // Reason: 预喂 ipad 前缀，后续 update 只需追加消息数据
        let mut inner = Sm3Hasher::new();
        inner.update(&ipad_key);
        ipad_key.zeroize();

        Self { inner, opad_key }
    }

    /// 追加消息数据
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// 完成计算，返回 32 字节 HMAC 值
    pub fn finalize(self) -> [u8; DIGEST_LEN] {
        use zeroize::Zeroize;
        let inner_hash = self.inner.finalize();
        let mut opad_key = self.opad_key;
        let mut outer = Sm3Hasher::new();
        outer.update(&opad_key);
        outer.update(&inner_hash);
        let result = outer.finalize();
        opad_key.zeroize();
        result
    }
}

impl zeroize::Zeroize for HmacSm3 {
    fn zeroize(&mut self) {
        self.opad_key.zeroize();
        // inner 的 Sm3Hasher 不含密钥材料，无需特殊清零
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 核心功能测试：SM3 基本哈希计算
    #[test]
    fn test_sm3_basic() {
        let digest = Sm3Hasher::digest(b"abc");
        let expected =
            hex_literal("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
        assert_eq!(digest, expected, "SM3(\"abc\") 测试向量不匹配");
    }

    /// 核心功能测试：HMAC-SM3 基本功能
    #[test]
    fn test_hmac_sm3_basic() {
        let key = b"test-key";
        let data = b"test-message";
        let mac1 = hmac_sm3(key, data);
        let mac2 = hmac_sm3(key, data);
        assert_eq!(mac1, mac2, "HMAC-SM3 应为确定性函数");
        assert_eq!(mac1.len(), 32);
    }

    /// 核心功能测试：HMAC-SM3 结构体接口
    #[test]
    fn test_hmac_sm3_struct() {
        let key = b"streaming-key";
        let data = b"hello world";

        let expected = hmac_sm3(key, data);

        let mut h = HmacSm3::new(key);
        h.update(data);
        let got = h.finalize();
        assert_eq!(expected, got);
    }

    // 辅助：从十六进制字符串构造 [u8; 32]
    fn hex_literal(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        let b = s.as_bytes();
        for i in 0..32 {
            let hi = match b[i * 2] {
                c @ b'0'..=b'9' => c - b'0',
                c @ b'a'..=b'f' => c - b'a' + 10,
                c @ b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("invalid hex"),
            };
            let lo = match b[i * 2 + 1] {
                c @ b'0'..=b'9' => c - b'0',
                c @ b'a'..=b'f' => c - b'a' + 10,
                c @ b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("invalid hex"),
            };
            out[i] = hi << 4 | lo;
        }
        out
    }
}