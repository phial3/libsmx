//! SM4 填充方案实现
//!
//! 实现常见的分组密码填充方案，用于处理非 16 字节整数倍的数据。
//!
//! # 支持的填充方式
//!
//! - **NoPadding**: 无填充，要求输入数据长度必须是 16 字节的整数倍
//! - **PKCS#5Padding**: PKCS#5 填充（实际使用与 PKCS#7 相同的算法）
//! - **PKCS#7Padding**: PKCS#7 填充（RFC 5652）
//!
//! # PKCS#5/PKCS#7 填充说明
//!
//! PKCS#5 和 PKCS#7 填充算法相同，都是在数据的末尾填充 N 个字节，
//! 每个填充字节的值都是 N。其中 N 是需要填充的字节数（1-16）。
//!
//! 例如：
//! - 如果数据长度为 15 字节，需要填充 1 字节：`[0x01]`
//! - 如果数据长度为 14 字节，需要填充 2 字节：`[0x02, 0x02]`
//! - 如果数据长度已经是 16 的倍数，则填充 16 字节：`[0x10, 0x10, ..., 0x10]`
//!
//! # 示例
//!
//! ```
//! use libsmx::sm4::padding::{pkcs7_pad, pkcs7_unpad};
//!
//! // 填充
//! let data = b"Hello"; // 5 字节
//! let padded = pkcs7_pad(data, 16); // 填充 11 字节，每个字节值为 0x0B
//!
//! // 去填充
//! let unpadded = pkcs7_unpad(&padded).expect("Invalid padding");
//! assert_eq!(unpadded, b"Hello");
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::Error;

/// SM4 分组大小（128 位 = 16 字节）
pub const SM4_BLOCK_SIZE: usize = 16;

/// 填充类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingType {
    /// 无填充
    NoPadding,
    /// PKCS#5 填充（与 PKCS#7 相同）
    Pkcs5Padding,
    /// PKCS#7 填充
    Pkcs7Padding,
}

/// PKCS#7 填充（也适用于 PKCS#5）
///
/// # 参数
/// - `data`: 待填充的数据
/// - `block_size`: 分组大小（通常为 16）
///
/// # 返回
/// 填充后的数据
///
/// # 示例
///
/// ```
/// use libsmx::sm4::padding::pkcs7_pad;
///
/// let data = b"Hello";
/// let padded = pkcs7_pad(data, 16);
/// assert_eq!(padded.len(), 16);
/// assert_eq!(padded[5..], [0x0B; 11]); // 11 个 0x0B
/// ```
#[cfg(feature = "alloc")]
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    debug_assert!(block_size > 0 && block_size <= 255);

    let padding_len = block_size - (data.len() % block_size);
    let mut padded = Vec::with_capacity(data.len() + padding_len);
    padded.extend_from_slice(data);

    // 填充 padding_len 个字节，每个字节值为 padding_len
    for _ in 0..padding_len {
        padded.push(padding_len as u8);
    }

    padded
}

/// PKCS#7 去填充（也适用于 PKCS#5）
///
/// # 参数
/// - `data`: 已填充的数据
///
/// # 返回
/// - `Ok(Vec<u8>)`: 去填充后的原始数据
/// - `Err(Error::InvalidPadding)`: 填充无效
///
/// # 验证规则
/// 1. 最后一个字节的值 N 必须在 1-16 范围内
/// 2. 最后 N 个字节的值都必须是 N
///
/// # 示例
///
/// ```
/// use libsmx::sm4::padding::pkcs7_unpad;
///
/// let padded = vec![b'H', b'e', b'l', b'l', b'o', 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B];
/// let unpadded = pkcs7_unpad(&padded).expect("Valid padding");
/// assert_eq!(unpadded, b"Hello");
/// ```
#[cfg(feature = "alloc")]
pub fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Err(Error::InvalidPadding);
    }

    let padding_len = data[data.len() - 1] as usize;

    // 验证填充长度是否合法（1-16）
    if padding_len == 0 || padding_len > SM4_BLOCK_SIZE {
        return Err(Error::InvalidPadding);
    }

    // 验证数据长度是否足够
    if data.len() < padding_len {
        return Err(Error::InvalidPadding);
    }

    // 验证所有填充字节的值是否都等于 padding_len
    for i in 0..padding_len {
        if data[data.len() - 1 - i] != padding_len as u8 {
            return Err(Error::InvalidPadding);
        }
    }

    Ok(data[..data.len() - padding_len].to_vec())
}

/// PKCS#5 填充（与 PKCS#7 相同）
#[cfg(feature = "alloc")]
pub fn pkcs5_pad(data: &[u8]) -> Vec<u8> {
    pkcs7_pad(data, SM4_BLOCK_SIZE)
}

/// PKCS#5 去填充（与 PKCS#7 相同）
#[cfg(feature = "alloc")]
pub fn pkcs5_unpad(data: &[u8]) -> Result<Vec<u8>, Error> {
    pkcs7_unpad(data)
}

/// 无填充 - 仅验证数据长度
///
/// # 错误
/// 当数据长度不是 16 字节的整数倍时返回 `Error::InvalidInputLength`
#[cfg(feature = "alloc")]
pub fn no_padding_pad(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() % SM4_BLOCK_SIZE != 0 {
        return Err(Error::InvalidInputLength);
    }
    Ok(data.to_vec())
}

/// 无填充 - 直接返回数据
///
/// # 错误
/// 当数据长度不是 16 字节的整数倍时返回 `Error::InvalidInputLength`
#[cfg(feature = "alloc")]
pub fn no_padding_unpad(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() % SM4_BLOCK_SIZE != 0 {
        return Err(Error::InvalidInputLength);
    }
    Ok(data.to_vec())
}

/// 通用填充函数
///
/// # 参数
/// - `data`: 待填充的数据
/// - `padding`: 填充类型
///
/// # 返回
/// 填充后的数据
#[cfg(feature = "alloc")]
pub fn pad(data: &[u8], padding: PaddingType) -> Result<Vec<u8>, Error> {
    match padding {
        PaddingType::NoPadding => no_padding_pad(data),
        PaddingType::Pkcs5Padding => Ok(pkcs5_pad(data)),
        PaddingType::Pkcs7Padding => Ok(pkcs7_pad(data, SM4_BLOCK_SIZE)),
    }
}

/// 通用去填充函数
///
/// # 参数
/// - `data`: 已填充的数据
/// - `padding`: 填充类型
///
/// # 返回
/// 去填充后的原始数据
#[cfg(feature = "alloc")]
pub fn unpad(data: &[u8], padding: PaddingType) -> Result<Vec<u8>, Error> {
    match padding {
        PaddingType::NoPadding => no_padding_unpad(data),
        PaddingType::Pkcs5Padding => pkcs5_unpad(data),
        PaddingType::Pkcs7Padding => pkcs7_unpad(data),
    }
}

// ====================================================================================
// 测试
// ====================================================================================

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_pkcs7_pad_basic() {
        // 5 字节数据，需要填充 11 字节
        let data = b"Hello";
        let padded = pkcs7_pad(data, SM4_BLOCK_SIZE);
        assert_eq!(padded.len(), 16);
        assert_eq!(&padded[0..5], b"Hello");
        for &byte in &padded[5..] {
            assert_eq!(byte, 0x0B); // 11
        }
    }

    #[test]
    fn test_pkcs7_pad_exact_block() {
        // 16 字节数据，需要填充 16 字节
        let data = [0u8; 16];
        let padded = pkcs7_pad(&data, SM4_BLOCK_SIZE);
        assert_eq!(padded.len(), 32);
        for &byte in &padded[16..] {
            assert_eq!(byte, 0x10); // 16
        }
    }

    #[test]
    fn test_pkcs7_pad_empty() {
        // 空数据，需要填充 16 字节
        let data: &[u8] = &[];
        let padded = pkcs7_pad(data, SM4_BLOCK_SIZE);
        assert_eq!(padded.len(), 16);
        for &byte in &padded {
            assert_eq!(byte, 0x10); // 16
        }
    }

    #[test]
    fn test_pkcs7_unpad_valid() {
        // 有效的 PKCS#7 填充
        let padded = vec![
            b'H', b'e', b'l', b'l', b'o', 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
            0x0B, 0x0B,
        ];
        let unpadded = pkcs7_unpad(&padded).expect("Should unpad successfully");
        assert_eq!(unpadded, b"Hello");
    }

    #[test]
    fn test_pkcs7_unpad_exact_block() {
        // 32 字节数据，最后 16 字节是填充
        let mut padded = vec![0u8; 16];
        padded.extend_from_slice(&[0x10; 16]);
        let unpadded = pkcs7_unpad(&padded).expect("Should unpad successfully");
        assert_eq!(unpadded.len(), 16);
    }

    #[test]
    fn test_pkcs7_unpad_invalid_padding_value() {
        // 填充值超过 16
        let mut padded = vec![0u8; 15];
        padded.push(0x11); // 17，超过最大值
        assert_eq!(pkcs7_unpad(&padded), Err(Error::InvalidPadding));
    }

    #[test]
    fn test_pkcs7_unpad_zero_padding() {
        // 填充值为 0（无效）
        let mut padded = vec![0u8; 15];
        padded.push(0x00);
        assert_eq!(pkcs7_unpad(&padded), Err(Error::InvalidPadding));
    }

    #[test]
    fn test_pkcs7_unpad_inconsistent_padding() {
        // 填充值不一致
        let padded = vec![
            b'H', b'e', b'l', b'l', b'o', 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
            0x0B, 0x0A,
        ];
        assert_eq!(pkcs7_unpad(&padded), Err(Error::InvalidPadding));
    }

    #[test]
    fn test_pkcs7_unpad_too_short() {
        // 数据长度小于填充值
        let padded = vec![0x05, 0x05, 0x05]; // 声称有 5 个填充字节，但只有 3 个字节
        assert_eq!(pkcs7_unpad(&padded), Err(Error::InvalidPadding));
    }

    #[test]
    fn test_pkcs7_unpad_empty() {
        // 空数据
        let data: &[u8] = &[];
        assert_eq!(pkcs7_unpad(data), Err(Error::InvalidPadding));
    }

    #[test]
    fn test_pkcs5_pad_unpad() {
        // PKCS#5 填充/去填充往返测试
        let data = b"Test PKCS#5 padding";
        let padded = pkcs5_pad(data);
        let unpadded = pkcs5_unpad(&padded).expect("Should unpad successfully");
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_no_padding_valid() {
        // 有效长度（16 的倍数）
        let data = [0u8; 32];
        assert!(no_padding_pad(&data).is_ok());
        assert!(no_padding_unpad(&data).is_ok());
    }

    #[test]
    fn test_no_padding_invalid() {
        // 无效长度（不是 16 的倍数）
        let data = b"Hello";
        assert_eq!(no_padding_pad(data), Err(Error::InvalidInputLength));
        assert_eq!(no_padding_unpad(data), Err(Error::InvalidInputLength));
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        // 通用填充/去填充往返测试
        for padding in [PaddingType::Pkcs5Padding, PaddingType::Pkcs7Padding] {
            let data = b"Roundtrip test data";
            let padded = pad(data, padding).expect("Should pad successfully");
            let unpadded = unpad(&padded, padding).expect("Should unpad successfully");
            assert_eq!(unpadded, data);
        }
    }

    #[test]
    fn test_various_data_lengths() {
        // 测试各种数据长度
        for len in 0..50 {
            let data: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let padded = pkcs7_pad(&data, SM4_BLOCK_SIZE);
            assert_eq!(padded.len() % SM4_BLOCK_SIZE, 0);

            let unpadded = pkcs7_unpad(&padded).expect("Should unpad successfully");
            assert_eq!(unpadded, data);
        }
    }
}
