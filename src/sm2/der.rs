//! SM2 签名与密钥 DER 编解码
//!
//! ## 签名格式
//! TLS 使用 ASN.1 DER 格式表示签名：
//! ```text
//! SEQUENCE {
//!     INTEGER r,
//!     INTEGER s
//! }
//! ```
//! 而 libsmx 内部使用原始 `r||s`（64 字节）。本模块提供两者互转。
//!
//! ## 私钥格式
//! - **SEC1**（RFC 5915）：`ECPrivateKey SEQUENCE { version INTEGER(1), privateKey OCTET STRING, ... }`
//! - **PKCS#8**（RFC 5958）：`PrivateKeyInfo SEQUENCE { version INTEGER(0), algorithm, privateKey OCTET STRING(SEC1) }`
//!
//! ## 公钥 SPKI 格式
//! rustls `SigningKey::public_key()` 需要 `SubjectPublicKeyInfoDer`：
//! 使用 x509-cert 的 SubjectPublicKeyInfo 结构：
//! ```text
//! SubjectPublicKeyInfo {
//!   algorithm: AlgorithmIdentifier {
//!     algorithm: OID id-ecPublicKey (1.2.840.10045.2.1)
//!     parameters: OID SM2 (1.2.156.10197.1.301)
//!   },
//!   subjectPublicKey: BIT STRING (04 || x(32B) || y(32B))
//! }
//! ```

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::Error;
use crate::sm2::PrivateKey;
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::{ObjectIdentifier, SubjectPublicKeyInfo};

/// 将原始签名 `r||s`（64 字节）编码为 DER SEQUENCE
///
/// 输出格式：`30 <len> 02 <rlen> <r> 02 <slen> <s>`
#[cfg(feature = "alloc")]
pub fn sig_to_der(raw: &[u8; 64]) -> Vec<u8> {
    let r = &raw[..32];
    let s = &raw[32..];

    let r_enc = encode_integer32(r);
    let s_enc = encode_integer32(s);

    let inner_len = r_enc.len() + s_enc.len();
    let mut der = Vec::with_capacity(2 + inner_len);
    der.push(0x30); // SEQUENCE tag
    der.push(inner_len as u8); // SEQUENCE length（inner < 256 字节）
    der.extend_from_slice(&r_enc);
    der.extend_from_slice(&s_enc);
    der
}

/// 将 DER 编码签名解码为原始 `r||s`（64 字节）
///
/// # 错误
/// 格式不合法时返回 `Error::InvalidSignature`
pub fn sig_from_der(der: &[u8]) -> Result<[u8; 64], Error> {
    let err = || Error::InvalidSignature;

    // SEQUENCE tag
    let (tag, rest) = split_first(der).ok_or_else(err)?;
    if *tag != 0x30 {
        return Err(err());
    }

    // SEQUENCE length
    let (seq_len, rest) = split_first(rest).ok_or_else(err)?;
    let seq_len = *seq_len as usize;
    if rest.len() < seq_len {
        return Err(err());
    }
    let body = &rest[..seq_len];

    // 解析 r
    let (r_bytes, body) = decode_integer32(body).ok_or_else(err)?;

    // 解析 s
    let (s_bytes, body) = decode_integer32(body).ok_or_else(err)?;

    // 不应有多余数据
    if !body.is_empty() {
        return Err(err());
    }

    // r 和 s 都必须是正整数，不超过 32 字节
    if r_bytes.is_empty() || r_bytes.len() > 33 || s_bytes.is_empty() || s_bytes.len() > 33 {
        return Err(err());
    }

    let mut raw = [0u8; 64];
    // Reason: DER INTEGER 可能有前缀 0x00（最高位保护），去除后左对齐写入 32 字节槽
    let r_stripped = strip_leading_zero(r_bytes);
    let s_stripped = strip_leading_zero(s_bytes);
    if r_stripped.len() > 32 || s_stripped.len() > 32 {
        return Err(err());
    }
    let r_off = 32 - r_stripped.len();
    let s_off = 32 - s_stripped.len();
    raw[r_off..32].copy_from_slice(r_stripped);
    raw[32 + s_off..64].copy_from_slice(s_stripped);

    Ok(raw)
}

// ── 内部辅助 ──────────────────────────────────────────────────────────────────

/// 将 32 字节大端整数编码为 DER INTEGER（带 tag 0x02 和 length）
#[cfg(feature = "alloc")]
fn encode_integer32(bytes: &[u8]) -> Vec<u8> {
    // 去除前导零（至少保留 1 字节）
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let val = &bytes[start..];

    // 最高位为 1 时需补 0x00，防止被解析为负数
    let needs_pad = val[0] & 0x80 != 0;
    let val_len = val.len() + if needs_pad { 1 } else { 0 };

    let mut enc = Vec::with_capacity(2 + val_len);
    enc.push(0x02); // INTEGER tag
    enc.push(val_len as u8); // length
    if needs_pad {
        enc.push(0x00);
    }
    enc.extend_from_slice(val);
    enc
}

/// 从字节流中解析一个 DER INTEGER，返回 (value_bytes, 剩余字节)
fn decode_integer32(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (tag, rest) = split_first(data)?;
    if *tag != 0x02 {
        return None;
    }
    let (len, rest) = split_first(rest)?;
    let len = *len as usize;
    if rest.len() < len {
        return None;
    }
    Some((&rest[..len], &rest[len..]))
}

/// 去除前导 0x00 字节
fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b != 0) {
        Some(i) => &bytes[i..],
        None => &bytes[bytes.len().saturating_sub(1)..], // 全零时保留末字节
    }
}

fn split_first(data: &[u8]) -> Option<(&u8, &[u8])> {
    data.split_first()
}

// ── DER 长度解码 ──────────────────────────────────────────────────────────────

/// 解析 DER 长度字段，返回 (length, 剩余字节)
///
/// 支持：单字节（< 0x80）、两字节（0x81 nn）、三字节（0x82 nn nn）
fn parse_length(data: &[u8]) -> Option<(usize, &[u8])> {
    let (first, rest) = data.split_first()?;
    if *first < 0x80 {
        // Reason: 最高位为 0 时，本字节直接表示长度
        Some((*first as usize, rest))
    } else if *first == 0x81 {
        let (len, rest) = rest.split_first()?;
        Some((*len as usize, rest))
    } else if *first == 0x82 {
        if rest.len() < 2 {
            return None;
        }
        let len = (rest[0] as usize) << 8 | rest[1] as usize;
        Some((len, &rest[2..]))
    } else if *first == 0x83 {
        // 支持 3 字节长度编码
        if rest.len() < 3 {
            return None;
        }
        let len = ((rest[0] as usize) << 16) | ((rest[1] as usize) << 8) | rest[2] as usize;
        Some((len, &rest[3..]))
    } else {
        // 不支持更长或不定长编码
        None
    }
}

/// 解析一个 TLV（tag-length-value），返回 (value_bytes, 剩余字节)
pub fn parse_tlv(data: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    let (tag, rest) = data.split_first()?;
    if *tag != expected_tag {
        return None;
    }
    let (len, rest) = parse_length(rest)?;
    if rest.len() < len {
        return None;
    }
    Some((&rest[..len], &rest[len..]))
}

/// 解析任意一个 TLV（不检查 tag），返回 (full_tlv_bytes, 剩余字节)
pub fn parse_tlv_any_full(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (_tag, rest) = data.split_first()?;
    let (first, _) = rest.split_first()?;
    let len_len = if *first < 0x80 {
        1
    } else if *first == 0x81 {
        2
    } else if *first == 0x82 {
        3
    } else if *first == 0x83 {
        4 // 3 字节长度编码
    } else {
        return None;
    };
    let (len, _) = parse_length(rest)?;
    let total_len = 1 + len_len + len;
    if data.len() < total_len {
        return None;
    }
    Some((&data[..total_len], &data[total_len..]))
}

// ── 私钥 DER 解析 ─────────────────────────────────────────────────────────────

/// 从 SEC1 DER 解析 SM2 私钥（RFC 5915）
///
/// 格式：
/// ```text
/// ECPrivateKey ::= SEQUENCE {
///     version    INTEGER { ecPrivkeyVer1(1) },
///     privateKey OCTET STRING,          -- 32 字节原始私钥
///     [0] ECParameters OPTIONAL,
///     [1] BIT STRING OPTIONAL
/// }
/// ```
///
/// # 错误
/// DER 格式不合法或私钥范围不合法时返回 `Error::InvalidPrivateKey`
pub fn private_key_from_sec1_der(der: &[u8]) -> Result<PrivateKey, Error> {
    let err = || Error::InvalidPrivateKey;

    // 解析外层 SEQUENCE
    let (seq_body, _) = parse_tlv(der, 0x30).ok_or_else(err)?;

    // version INTEGER，值应为 1（ecPrivkeyVer1）
    let (ver_bytes, rest) = parse_tlv(seq_body, 0x02).ok_or_else(err)?;
    if ver_bytes != [0x01] {
        return Err(err());
    }

    // privateKey OCTET STRING（32 字节）
    let (key_bytes, _rest) = parse_tlv(rest, 0x04).ok_or_else(err)?;
    if key_bytes.len() != 32 {
        return Err(err());
    }
    let key_arr: &[u8; 32] = key_bytes.try_into().map_err(|_| err())?;

    PrivateKey::from_bytes(key_arr)
}

/// 将私钥编码为 SEC1 DER 格式（RFC 5915）
///
/// 格式：
/// ```text
/// ECPrivateKey ::= SEQUENCE {
///     version    INTEGER { ecPrivkeyVer1(1) },
///     privateKey OCTET STRING,          -- 32 字节原始私钥
///     [0] ECParameters OPTIONAL,
///     [1] BIT STRING OPTIONAL
/// }
/// ```
#[cfg(feature = "alloc")]
pub fn private_key_to_sec1_der(priv_key: &PrivateKey) -> Vec<u8> {
    // version INTEGER = 1：02 01 01
    // privateKey OCTET STRING：04 20 <32 bytes>
    let mut der = Vec::with_capacity(2 + 3 + 2 + 32);
    der.push(0x30);
    der.push(0x25);
    der.push(0x02);
    der.push(0x01);
    der.push(0x01);
    der.push(0x04);
    der.push(0x20);
    der.extend_from_slice(priv_key.as_bytes());
    der
}

/// 将私钥编码为 PKCS#8 DER 格式（RFC 5958）
///
/// 格式：
/// ```text
/// PrivateKeyInfo ::= SEQUENCE {
///     version              INTEGER (0),
///     algorithm            AlgorithmIdentifier SEQUENCE { ... },
///     privateKey           OCTET STRING (SEC1 DER)
/// }
/// ```
/// 解析 SM2 私钥的 PKCS#8 格式（RFC 5958）
#[cfg(feature = "alloc")]
pub fn private_key_to_pkcs8_der(priv_key: &PrivateKey) -> Vec<u8> {
    let sec1 = private_key_to_sec1_der(priv_key);
    // AlgorithmIdentifier：SM2公钥算法
    let alg_id_der = crate::sm2::SM2_SPKI_ALGORITHM.to_der().unwrap();
    // version INTEGER = 0：02 01 00
    let version: &[u8] = &[0x02, 0x01, 0x00];
    // privateKey OCTET STRING 包装 sec1
    let mut priv_oct = Vec::with_capacity(2 + sec1.len());
    priv_oct.push(0x04);
    priv_oct.push(sec1.len() as u8);
    priv_oct.extend_from_slice(&sec1);
    // inner = version + alg_id + priv_oct
    let inner_len = version.len() + alg_id_der.len() + priv_oct.len();
    let mut der = Vec::with_capacity(2 + inner_len);
    der.push(0x30);
    der.push(inner_len as u8);
    der.extend_from_slice(version);
    der.extend_from_slice(&alg_id_der);
    der.extend_from_slice(&priv_oct);
    der
}

/// 从 PKCS#8 DER 解析 SM2 私钥（RFC 5958）
///
/// 格式：
/// ```text
/// PrivateKeyInfo ::= SEQUENCE {
///     version              INTEGER (0),
///     algorithm            AlgorithmIdentifier SEQUENCE { ... },
///     privateKey           OCTET STRING (SEC1 DER)
/// }
/// ```
///
/// # 错误
/// DER 格式不合法或私钥范围不合法时返回 `Error::InvalidPrivateKey`
pub fn private_key_from_pkcs8_der(der: &[u8]) -> Result<PrivateKey, Error> {
    let err = || Error::InvalidPrivateKey;

    // 解析外层 SEQUENCE（PrivateKeyInfo）
    let (seq_body, _) = parse_tlv(der, 0x30).ok_or_else(err)?;

    // version INTEGER，值应为 0
    let (ver_bytes, rest) = parse_tlv(seq_body, 0x02).ok_or_else(err)?;
    if ver_bytes != [0x00] {
        return Err(err());
    }

    // AlgorithmIdentifier SEQUENCE（跳过，不验证 OID）
    let (_, rest) = parse_tlv(rest, 0x30).ok_or_else(err)?;

    // privateKey OCTET STRING（内含 SEC1 DER）
    let (sec1_der, _) = parse_tlv(rest, 0x04).ok_or_else(err)?;

    private_key_from_sec1_der(sec1_der)
}

// ── SM2 公钥 SPKI DER 编码 ────────────────────────────────────────────────────

/// 将 SM2 公钥（65 字节，04||x||y）编码为 SubjectPublicKeyInfo DER
///
/// 使用 x509-cert 的 SubjectPublicKeyInfo 结构，格式符合 RFC 5480 标准。
///
/// # 参数
/// - `pub_key`: SM2 公钥（65 字节未压缩格式：0x04 || X(32B) || Y(32B)）
///
/// # 返回
/// DER 编码的 SubjectPublicKeyInfo
///
/// # 示例
/// ```no_run
/// use libsmx::sm2::generate_keypair;
/// use libsmx::sm2::der::public_key_to_spki_der;
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
///
/// let mut rng = StdRng::seed_from_u64(12345);
/// let (_, pub_key) = generate_keypair(&mut rng);
/// let spki_der = public_key_to_spki_der(&pub_key);
/// ```
#[cfg(feature = "alloc")]
pub fn public_key_to_spki_der(pub_key: &[u8; 65]) -> Vec<u8> {
    use x509_cert::der::asn1::BitStringRef;

    // 创建 BIT STRING（公钥数据）
    // BitStringRef::new 第一个参数是 unused_bits（0），第二个参数是字节切片
    let subject_public_key = BitStringRef::new(0, pub_key.as_slice())
        .expect("BitStringRef creation should not fail for valid data");

    // 创建 SubjectPublicKeyInfo
    let spki = SubjectPublicKeyInfo {
        algorithm: crate::sm2::SM2_SPKI_ALGORITHM,
        subject_public_key,
    };

    // 编码为 DER
    spki.to_der().expect("SPKI encoding failed")
}

/// 从 SubjectPublicKeyInfo DER 解析 SM2 公钥
///
/// 使用 x509-cert 的 SubjectPublicKeyInfo 结构解析，格式符合 RFC 5480 标准。
///
/// # 参数
/// - `der`: DER 编码的 SubjectPublicKeyInfo
///
/// # 返回
/// - `Ok([u8; 65])`: SM2 公钥（65 字节未压缩格式：0x04 || X(32B) || Y(32B)）
/// - `Err(Error)`: 解析失败
///
/// # 错误
/// DER 格式不合法或公钥格式不合法时返回 `Error::InvalidPublicKey`
pub fn public_key_from_spki_der(der: &[u8]) -> Result<[u8; 65], Error> {
    // 使用 x509-cert 的 SubjectPublicKeyInfo 结构解析
    use x509_cert::der::asn1::BitString;
    let spki: SubjectPublicKeyInfo<ObjectIdentifier, BitString> =
        SubjectPublicKeyInfo::from_der(der).map_err(|_| Error::InvalidPublicKey)?;

    // 验证算法 OID（id-ecPublicKey）
    if spki.algorithm.oid != crate::sm2::EC_PUBKEY_OID {
        return Err(Error::InvalidPublicKey);
    }

    // 验证参数 OID（SM2 曲线）
    match spki.algorithm.parameters {
        Some(oid) if oid == crate::sm2::SM2_CURVE_OID => {}
        _ => return Err(Error::InvalidPublicKey),
    }

    // 提取公钥数据
    let pub_key_bytes: &[u8] = spki
        .subject_public_key
        .as_bytes()
        .ok_or(Error::InvalidPublicKey)?;

    // 验证公钥长度（应为 65 字节：0x04 || X(32B) || Y(32B)）
    if pub_key_bytes.len() != 65 {
        return Err(Error::InvalidPublicKey);
    }

    let mut result = [0u8; 65];
    result.copy_from_slice(pub_key_bytes);
    Ok(result)
}

// ── DER 编码辅助函数 ─────────────────────────────────────────────────────

/// 编码 INTEGER（单字节）
/// 
/// 直接使用手写的 DER 编码，避免临时值问题
#[cfg(feature = "alloc")]
pub fn encode_integer(val: u8) -> Result<Vec<u8>, Error> {
    // 直接构造 DER 编码：tag 0x02 + length 0x01 + value
    Ok(vec![0x02, 0x01, val])
}

/// 编码 OCTET STRING
/// 
/// 使用 x509_cert::der::asn1::OctetStringRef 类型进行编码
#[cfg(feature = "alloc")]
pub fn encode_octet_string(data: &[u8]) -> Result<Vec<u8>, Error> {
    use x509_cert::der::asn1::OctetStringRef;
    // OctetStringRef 可以直接从字节切片创建
    let octet_ref = OctetStringRef::new(data).map_err(|_| Error::DerEncodeError { 
        field: "octet_string", 
        reason: "encoding failed" 
    })?;
    octet_ref.to_der().map_err(|_| Error::DerEncodeError { 
        field: "octet_string", 
        reason: "encoding der failed"
    })
}

/// 包装为 SEQUENCE
/// 
/// 直接将内容字节包装为 SEQUENCE（tag 0x30 + length + content）
/// 注意：此函数假设 content 已经是有效的 DER 编码内容
#[cfg(feature = "alloc")]
pub fn wrap_sequence(content: Vec<u8>) -> Vec<u8> {
    let mut result = vec![0x30];
    // 简化处理，假设长度小于 65536
    if content.len() < 128 {
        result.push(content.len() as u8);
    } else if content.len() < 256 {
        result.push(0x81);
        result.push(content.len() as u8);
    } else {
        result.push(0x82);
        result.push((content.len() >> 8) as u8);
        result.push((content.len() & 0xFF) as u8);
    }
    result.extend(content);
    result
}

/// 包装为 SET
/// 
/// 直接将内容字节包装为 SET（tag 0x31 + length + content）
/// 注意：此函数假设 content 已经是有效的 DER 编码内容
#[cfg(feature = "alloc")]
pub fn wrap_set(content: Vec<u8>) -> Vec<u8> {
    let mut result = vec![0x31];
    // 简化处理，假设长度小于 65536
    if content.len() < 128 {
        result.push(content.len() as u8);
    } else if content.len() < 256 {
        result.push(0x81);
        result.push(content.len() as u8);
    } else {
        result.push(0x82);
        result.push((content.len() >> 8) as u8);
        result.push((content.len() & 0xFF) as u8);
    }
    result.extend(content);
    result
}

/// 包装为显式标签（Context-specific constructed）
/// 
/// 用于包装 [n] EXPLICIT 类型的字段
/// 
/// # 参数
/// - `tag`: 标签号（0-30）
/// - `content`: 标签内的内容字节（必须是有效的 DER 编码）
/// 
/// # 返回
/// DER 编码的显式标签（tag 0xA0+n + length + content）
#[cfg(feature = "alloc")]
pub fn wrap_explicit_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    // 直接构造 DER 编码：tag + length + content
    let mut result = vec![0xA0 | tag];
    encode_length(&mut result, content.len()).expect("DER length encoding failed");
    result.extend_from_slice(content);
    result
}

/// DER 长度编码（支持短形式和长形式）
/// 
/// 这是内部辅助函数，用于 `wrap_explicit_tag` 和 cms 模块
#[cfg(feature = "alloc")]
pub fn encode_length(out: &mut Vec<u8>, len: usize) -> Result<(), Error> {
    if len < 128 {
        // 短形式
        out.push(len as u8);
    } else {
        // 长形式
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
        bytes.reverse();

        let num_bytes = bytes.len();
        if num_bytes > 126 {
            return Err(Error::InvalidInput);
        }

        out.push(0x80 | num_bytes as u8);
        out.extend(bytes);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_raw(r: [u8; 32], s: [u8; 32]) -> [u8; 64] {
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&r);
        raw[32..].copy_from_slice(&s);
        raw
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_der_roundtrip_basic() {
        let r = [0x01u8; 32];
        let s = [0x02u8; 32];
        let raw = make_raw(r, s);
        let der = sig_to_der(&raw);
        let recovered = sig_from_der(&der).unwrap();
        assert_eq!(recovered, raw);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_der_roundtrip_high_bit_set() {
        // r/s 最高位为 1，需要 DER 填充 0x00
        let mut r = [0u8; 32];
        r[0] = 0x80; // 最高位为 1
        let mut s = [0u8; 32];
        s[0] = 0xFF;
        let raw = make_raw(r, s);
        let der = sig_to_der(&raw);
        // 验证 DER 中有 0x00 填充
        let recovered = sig_from_der(&der).unwrap();
        assert_eq!(recovered, raw);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_der_roundtrip_leading_zeros() {
        // r 前有大量前导零
        let mut r = [0u8; 32];
        r[31] = 0x42; // 只有最后一字节非零
        let s = [0x01u8; 32];
        let raw = make_raw(r, s);
        let der = sig_to_der(&raw);
        let recovered = sig_from_der(&der).unwrap();
        assert_eq!(recovered, raw);
    }

    #[test]
    fn test_der_invalid_tag() {
        // 非 SEQUENCE tag
        let bad = [0x10, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00];
        assert!(sig_from_der(&bad).is_err());
    }

    #[test]
    fn test_der_truncated() {
        let bad = [0x30, 0x10]; // length 声明 16 字节但无内容
        assert!(sig_from_der(&bad).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_der_structure() {
        // 验证 DER 字节结构符合 ASN.1 规范
        let r = [0x01u8; 32];
        let s = [0x01u8; 32];
        let raw = make_raw(r, s);
        let der = sig_to_der(&raw);
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert_eq!(der[2], 0x02); // INTEGER tag for r
                                  // 长度字段合理（r/s 各最多 33 字节 + 2 字节头 = 35，×2 + 2 = 72）
        assert!(der.len() <= 72);
        assert!(der.len() >= 8);
    }

    // ── 私钥 DER 解析测试 ──────────────────────────────────────────────────────

    // 已知 SM2 私钥原始字节（与其他测试共用）
    const RAW_KEY: [u8; 32] = [
        0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f,
        0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7,
        0xc5, 0xb8,
    ];

    /// 构造最小 SEC1 DER（只有 version + privateKey 字段）
    #[cfg(feature = "alloc")]
    fn make_sec1_der(key: &[u8; 32]) -> alloc::vec::Vec<u8> {
        // version INTEGER = 1：02 01 01
        // privateKey OCTET STRING：04 20 <32 bytes>
        // inner = 3 + 2 + 32 = 37 bytes → SEQUENCE 30 25 ...
        let mut der = alloc::vec![0x30u8, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
        der.extend_from_slice(key);
        der
    }

    /// 构造最小 PKCS#8 DER（包含虚拟 AlgorithmIdentifier OID）
    #[cfg(feature = "alloc")]
    fn make_pkcs8_der(key: &[u8; 32]) -> alloc::vec::Vec<u8> {
        let sec1 = make_sec1_der(key);
        // AlgorithmIdentifier 最小化：30 06 06 01 00 06 01 00（两个 OID，各 1 字节占位）
        let alg_id: &[u8] = &[0x30, 0x06, 0x06, 0x01, 0x00, 0x06, 0x01, 0x00];
        // version INTEGER = 0：02 01 00
        let version: &[u8] = &[0x02, 0x01, 0x00];
        // privateKey OCTET STRING 包装 sec1
        let mut priv_oct = alloc::vec![0x04u8, sec1.len() as u8];
        priv_oct.extend_from_slice(&sec1);
        // inner = version + alg_id + priv_oct
        let inner_len = version.len() + alg_id.len() + priv_oct.len();
        let mut der = alloc::vec![0x30u8, inner_len as u8];
        der.extend_from_slice(version);
        der.extend_from_slice(alg_id);
        der.extend_from_slice(&priv_oct);
        der
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_sec1_der_roundtrip() {
        let der = make_sec1_der(&RAW_KEY);
        let key = private_key_from_sec1_der(&der).expect("SEC1 解析应成功");
        assert_eq!(key.as_bytes(), &RAW_KEY);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pkcs8_der_roundtrip() {
        let der = make_pkcs8_der(&RAW_KEY);
        let key = private_key_from_pkcs8_der(&der).expect("PKCS#8 解析应成功");
        assert_eq!(key.as_bytes(), &RAW_KEY);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_private_key_to_sec1_der() {
        use crate::sm2::PrivateKey;
        let key = PrivateKey::from_bytes(&RAW_KEY).unwrap();
        let der = private_key_to_sec1_der(&key);
        let recovered = private_key_from_sec1_der(&der).expect("SEC1 解析应成功");
        assert_eq!(recovered.as_bytes(), &RAW_KEY);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_private_key_to_pkcs8_der() {
        use crate::sm2::PrivateKey;
        let key = PrivateKey::from_bytes(&RAW_KEY).unwrap();
        let der = private_key_to_pkcs8_der(&key);
        let recovered = private_key_from_pkcs8_der(&der).expect("PKCS#8 解析应成功");
        assert_eq!(recovered.as_bytes(), &RAW_KEY);
    }

    #[test]
    fn test_sec1_der_invalid_tag() {
        // 首字节不是 SEQUENCE tag
        let bad = [0x02u8, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20, 0x00];
        assert!(private_key_from_sec1_der(&bad).is_err());
    }

    #[test]
    fn test_sec1_der_wrong_version() {
        // version 应为 1，此处给 0；最后 32 字节填充为 RAW_KEY
        let mut der = [0u8; 39];
        der[0] = 0x30;
        der[1] = 0x25; // SEQUENCE length 37
        der[2] = 0x02;
        der[3] = 0x01;
        der[4] = 0x00; // version = 0（错误，应为 1）
        der[5] = 0x04;
        der[6] = 0x20; // OCTET STRING 32 字节
        der[7..39].copy_from_slice(&RAW_KEY);
        assert!(private_key_from_sec1_der(&der).is_err());
    }

    #[test]
    fn test_sec1_der_key_too_short() {
        // privateKey 只有 16 字节（不足 32）
        let der = [
            0x30, 0x15, // SEQUENCE 21 字节
            0x02, 0x01, 0x01, // version = 1
            0x04, 0x10, // OCTET STRING 16 字节
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert!(private_key_from_sec1_der(&der).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pkcs8_der_invalid_outer_tag() {
        let mut der = make_pkcs8_der(&RAW_KEY);
        der[0] = 0x04; // 破坏外层 SEQUENCE tag
        assert!(private_key_from_pkcs8_der(&der).is_err());
    }

    // ── SPKI DER 测试 ──────────────────────────────────────────────────────────

    #[cfg(feature = "alloc")]
    #[test]
    fn test_spki_der_structure() {
        use crate::sm2::PrivateKey;
        let pri = PrivateKey::from_bytes(&RAW_KEY).unwrap();
        let pub_key = pri.public_key();
        let spki = public_key_to_spki_der(&pub_key);

        // 外层 SEQUENCE
        assert_eq!(spki[0], 0x30, "外层 tag 应为 SEQUENCE");
        // BIT STRING 内包含 04||x||y（65字节）
        // 确认公钥原始字节出现在 SPKI 中
        let pos = spki.windows(65).position(|w| w == pub_key);
        assert!(pos.is_some(), "SPKI 应包含原始公钥字节");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_spki_der_roundtrip() {
        use crate::sm2::PrivateKey;
        let pri = PrivateKey::from_bytes(&RAW_KEY).unwrap();
        let pub_key = pri.public_key();
        let spki = public_key_to_spki_der(&pub_key);
        let recovered = public_key_from_spki_der(&spki).expect("SPKI 解析应成功");
        assert_eq!(recovered, pub_key);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_spki_der_oid_ec() {
        use crate::sm2::PrivateKey;
        let pri = PrivateKey::from_bytes(&RAW_KEY).unwrap();
        let pub_key = pri.public_key();
        let spki = public_key_to_spki_der(&pub_key);
        // 使用 oid 模块的常量验证
        assert!(
            spki.windows(crate::sm2::EC_PUBKEY_OID.as_bytes().len())
                .any(|w| w == crate::sm2::EC_PUBKEY_OID.as_bytes()),
            "SPKI 应包含 id-ecPublicKey OID"
        );
    }
}
