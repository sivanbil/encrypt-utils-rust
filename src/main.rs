use clap::{Parser, ArgGroup};
use chrono::{Utc, Duration};
use smcrypto::sm2;
use std::fs;
use rand::thread_rng;
use rand::distributions::Alphanumeric;
use rand::Rng;
use base64;

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

fn generate_code(email: &str, days: i64, public_key: &str) -> String {
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

fn decode_code(encrypted_code: &str, private_key: &str) -> (String, chrono::DateTime<Utc>) {
    // 将私钥转换为十六进制字符串
    let sk_hex = private_key;

    let dec_ctx = sm2::Decrypt::new(&sk_hex); // 直接使用十六进制字符串

    // 先进行 base64 解码
    let encrypted_hex = base64::decode(encrypted_code).expect("Decoding base64 failed");
    // 解密数据
    let encrypted_data = hex::decode(encrypted_hex).expect("Decoding encrypted code failed");
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