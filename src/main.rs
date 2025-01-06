// src/main.rs

// regitry-code 工具
//
// 这个命令行工具使用 SM2 国密算法进行加密、解密和生成注册码。
//
// 功能：
//   * 生成 SM2 密钥对
//   * 使用公钥加密字符串
//   * 使用私钥解密字符串
//   * 生成注册码（包含用户信息和有效期，使用 SM2 加密）
//   * 解码注册码
use clap::{Parser, ArgGroup}; // 用于解析命令行参数
use chrono::{Utc, Duration}; // 用于处理日期和时间
use smcrypto::sm2; // 用于 SM2 加密和解密
use std::fs; // 用于文件操作
use rand::thread_rng; // 用于生成随机数
use rand::distributions::Alphanumeric; // 用于生成随机字符
use rand::Rng; // 用于生成随机数
use base64; // 用于 base64 编码和解码
use regitry_code::{generate_code,decode_code}; // 从 regitry_code 库中导入函数

#[derive(Parser)]
#[clap(name = "sm2-tool")]
#[clap(version = "1.0")]
#[clap(about = "A command line tool for SM2 encryption and decryption")]
struct Cli {
    /// Generate a new SM2 key pair
    #[clap(long)]
    generate_keypair: bool,

    /// Public key file for encryption
    #[clap(long, value_name = "FILE")]
    public_key: Option<String>,

    /// Private key file for decryption
    #[clap(long, value_name = "FILE")]
    private_key: Option<String>,

    /// String to encrypt
    #[clap(long, value_name = "STRING")]
    encrypt_str: Option<String>,

    /// Hex-encoded string to decrypt
    #[clap(long, value_name = "HEX")]
    decrypt_hex: Option<String>,

    /// Register code with email and days valid
    #[clap(long, value_names = &["EMAIL"])]
    register_code: Option<String>,

    #[clap(long, value_parser = clap::value_parser!(i64))]
    days: Option<i64>,

    /// Decode register code
    #[clap(long, value_name = "CODE")]
    decode_code: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    if cli.generate_keypair {
        let (sk, pk) = sm2::gen_keypair();
        fs::write("private.key", hex::encode(sk.into_bytes())).expect("Writing private key failed");
        fs::write("public.key", hex::encode(pk.into_bytes())).expect("Writing public key failed");
        println!("Generated key pair");
    }

    // Moved the register code logic here to avoid multiple mutable borrows of public_key
    if let Some(email) = cli.register_code.clone() { // clone email here
        if let Some(public_key) = cli.public_key.clone() {
            if let Some(days) = cli.days {
                let pk_hex = fs::read_to_string(public_key).expect("Reading public key failed");
                let pk_bytes = hex::decode(pk_hex).expect("Decoding public key failed");
                let pk_value = String::from_utf8(pk_bytes).expect("Invalid UTF-8");

                let code = generate_code(&email, days, &pk_value); // Pass email and pk_value
                println!("Register code: {}", code);
            }
        }
    }

    if let Some(public_key) = cli.public_key {
        if let Some(encrypt_str) = cli.encrypt_str {
            let pk_hex = fs::read_to_string(public_key).expect("Reading public key failed");
            let pk_bytes = hex::decode(pk_hex).expect("Decoding public key failed");
            let pk_value = String::from_utf8(pk_bytes).expect("Invalid UTF-8");
            let enc_ctx = sm2::Encrypt::new(&pk_value);
            let enc = enc_ctx.encrypt(encrypt_str.as_bytes());
            println!("Encrypted (hex): {}", hex::encode(enc));
        }
    }

    // Moved the decode code logic here to avoid multiple mutable borrows of private_key
    if let Some(code) = cli.decode_code.clone() { // clone code here
        if let Some(private_key) = cli.private_key.clone() {
            let sk_hex = fs::read_to_string(private_key).expect("Reading private key failed");
            let sk_bytes = hex::decode(sk_hex).expect("Decoding private key failed");
            let sk_value = String::from_utf8(sk_bytes).expect("Invalid UTF-8");

            let (email, expire_time) = decode_code(&code, &sk_value); // Pass code and sk_value
            println!("Email: {}", email);
            println!("Expire time: {}", expire_time);
        }
    }

    if let Some(private_key) = cli.private_key {
        if let Some(decrypt_hex) = cli.decrypt_hex {
            let sk_hex = fs::read_to_string(private_key).expect("Reading private key failed");
            let sk_bytes = hex::decode(sk_hex).expect("Decoding private key failed");
            let sk_value = String::from_utf8(sk_bytes).expect("Invalid UTF-8");
            let dec_ctx = sm2::Decrypt::new(&sk_value);
            let enc_bytes = hex::decode(decrypt_hex).expect("Decoding encrypted data failed");
            let dec = dec_ctx.decrypt(&enc_bytes);
            println!("Decrypted: {}", String::from_utf8(dec).expect("Invalid UTF-8"));
        }
    }
}
