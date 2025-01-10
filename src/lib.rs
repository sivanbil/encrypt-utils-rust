/// src/lib.rs

// 这个库提供生成和解码注册码的功能。
// 注册码用于验证用户身份和授权，包含用户信息和有效期。
// 使用 SM2 国密算法对注册码进行加密和解密，确保安全性。

use chrono::{Utc, Duration}; // 用于处理日期和时间
use smcrypto::sm2; // 用于 SM2 加密和解密
use base64; // 用于 base64 编码和解码
use std::fs;
use smcrypto::sm3::sm3_hash; // SM3 哈希算法
use rand::Rng;
use std::str;
// 生成注册码
//
// 参数：
//   email: 邮箱地址
//   days: 有效期天数
//   public_key: SM2 公钥
//
// 返回值：
//   注册码字符串
pub fn generate_code(email: &str, days: i64, public_key: &str) -> String {
    let enc_ctx = sm2::Encrypt::new(public_key);

    // 计算有效期
    let now = Utc::now();
    let expire_time = now + Duration::days(days);

    // 将 email 和有效期拼接成字符串
    let data = format!("{}|{}", email, expire_time.to_rfc3339());

    // 加密数据
    let encrypted_data = enc_ctx.encrypt(data.as_bytes());

    // 先进行 hex 编码
    let encrypted_hex = hex::encode(encrypted_data);

    // 再进行 base64 编码
    let code = base64::encode(encrypted_hex);

    code
}

// 解码注册码
//
// 参数：
//   code: 注册码字符串
//   private_key: SM2 私钥
//
// 返回值：
//   (邮箱地址, 有效期截止时间)
pub fn decode_code(code: &str, private_key: &str) -> (String, chrono::DateTime<Utc>) {
    let dec_ctx = sm2::Decrypt::new(private_key);

    // 先进行 base64 解码
    let encrypted_hex = base64::decode(code).expect("Decoding base64 failed");

    // 再进行 hex 解码
    let encrypted_data = hex::decode(String::from_utf8(encrypted_hex).expect("Invalid UTF-8")).expect("Decoding hex failed");

    // 解密数据
    let decrypted_data = dec_ctx.decrypt(&encrypted_data);
    let data = String::from_utf8(decrypted_data).expect("Invalid UTF-8");

    // 解析 email 和有效期
    let parts: Vec<&str> = data.split('|').collect();
    if parts.len() == 2 {
        let email = parts[0].to_string();
        let expire_time = chrono::DateTime::parse_from_rfc3339(parts[1])
            .expect("Invalid expire time format")
            .with_timezone(&Utc); // 确保时区正确
        (email, expire_time)
    } else {
        panic!("Invalid code format");
    }
}

pub fn read_key_file(key_path: String) -> String {
    let hex = fs::read_to_string(key_path).expect("Reading key failed");

    let bytes = hex::decode(hex).expect("Decoding key failed");

    String::from_utf8(bytes).expect("Invalid UTF-8")
}




// 生成随机字符串函数
#[cfg(feature = "password")]
pub fn generate_random_string(length: usize) -> String {
    let charset: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let random_string: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect();
    random_string
}

// 加密密码函数
#[cfg(feature = "password")]
pub fn encrypt_password(password: &str, salt: &str) -> String {
    // 将密码和盐值拼接
    let data = format!("{}{}", password, salt);

    // 使用 SM3 哈希算法进行加密
    let hash_result = sm3_hash(data.as_bytes());

    // 将加密结果转换为 Base64 字符串
    base64::encode(hash_result)
}

// 验证密码函数
#[cfg(feature = "password")]
pub fn verify_password(password: &str, salt: &str, encrypted_password: &str) -> bool {
    // 重新加密密码
    let new_encrypted_password = encrypt_password(password, salt);

    // 比较两个加密结果是否相同
    new_encrypted_password == encrypted_password
}