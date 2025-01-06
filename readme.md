# regitry-code

## 概述

regitry-code 是一个使用 SM2 国密算法进行加密、解密和生成注册码的命令行工具。

## 功能

*   生成 SM2 密钥对
*   使用公钥加密字符串
*   使用私钥解密字符串
*   生成注册码（包含用户信息和有效期，使用 SM2 加密）
*   解码注册码


##  regitry-code 库

除了命令行工具外，`regitry-code` 还提供了一个库，其中包含 `generate_code` 和 `decode_code` 两个函数，可以方便地在其他 Rust 项目中使用。

### 如何引入

要在您的 Rust 项目中使用 `regitry_code` 库，您需要将其添加为依赖项。在您的 `Cargo.toml` 文件的 `[dependencies]` 部分添加以下一行：

```toml
regitry_code = { version="0.1.0" }  # 假设 regitry-code 库位于您的项目的上级目录
```

### 如何使用

引入 `regitry-code` 库后，您就可以在您的 Rust 代码中使用 `generate_code` 和 `decode_code` 函数了。

**`generate_code` 函数**

```rust
use regitry_code::generate_code;

fn main() {
    let email = "test@example.com";
    let days = 30;
    let public_key = "your_public_key"; 

    let code = generate_code(email, days, public_key);
    println!("Register code: {}", code);
}
```

**`decode_code` 函数**

```rust
use regitry_code::decode_code;

fn main() {
    let code = "your_register_code";
    let private_key = "your_private_key";

    let (email, expire_time) = decode_code(code, private_key);
    println!("Email: {}", email);
    println!("Expire time: {}", expire_time);
}
```