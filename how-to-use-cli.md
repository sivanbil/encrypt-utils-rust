
# regitry-code 使用方法

## 概述

regitry-code 是一个使用 SM2 国密算法进行加密、解密和生成注册码的命令行工具。

## 功能

*   生成 SM2 密钥对
*   使用公钥加密字符串
*   使用私钥解密字符串
*   生成注册码（包含用户信息和有效期，使用 SM2 加密）
*   解码注册码

## 使用方法

### 编译

首先，您需要使用 Rust 编译器编译 regitry-code 工具：

```bash
cargo build --release
```

这将在 `target/release` 目录下生成可执行文件 `regitry-code.exe`。

### 生成密钥对

```bash
regitry-code.exe --generate-keypair
```

这将在当前目录下生成 `private.key` 和 `public.key` 两个文件，分别存储私钥和公钥。

### 加密字符串

```bash
regitry-code.exe --encrypt-str "要加密的字符串" --public-key public.key
```

这将使用 `public.key` 中的公钥加密指定的字符串，并将加密结果以十六进制格式输出到控制台。

### 解密字符串

```bash
regitry-code.exe --decrypt-hex "十六进制加密字符串" --private-key private.key
```

这将使用 `private.key` 中的私钥解密指定的十六进制加密字符串，并将解密结果输出到控制台。

### 生成注册码

```bash
regitry-code.exe --register-code "邮箱地址" --days 有效天数 --public-key public.key
```

这将使用 `public.key` 中的公钥加密邮箱地址和有效期信息，生成一个注册码，并输出到控制台。

### 解码注册码

```bash
regitry-code.exe --decode-code "注册码" --private-key private.key
```

这将使用 `private.key` 中的私钥解密注册码，并输出邮箱地址和有效期信息。

## 示例

```bash
# 生成密钥对
regitry-code.exe --generate-keypair

# 加密字符串
regitry-code.exe --encrypt-str "hello world" --public-key public.key

# 解密字符串
regitry-code.exe --decrypt-hex "加密后的十六进制字符串" --private-key private.key

# 生成注册码
regitry-code.exe --register-code "test@example.com" --days 30 --public-key public.key

# 解码注册码
regitry-code.exe --decode-code "生成的注册码" --private-key private.key
```
