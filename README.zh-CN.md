# TLS Crypto Symmetric

[![PHP Version](https://img.shields.io/badge/php-%5E8.1-777BB4?style=flat-square&logo=php)](https://www.php.net)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)](https://github.com/tourze/php-monorepo)
[![Code Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen?style=flat-square)](https://codecov.io)

[English](README.md) | [中文](README.zh-CN.md)

TLS对称加密算法实现

## 安装

```bash
composer require tourze/tls-crypto-symmetric
```

## 快速开始

```php
use Tourze\TLSCryptoSymmetric\Cipher\AesGcm;

// 创建 AES-GCM 密码器，使用 256 位密钥
$cipher = new AesGcm(256);

// 准备数据
$plaintext = 'Hello, World!';
$key = random_bytes($cipher->getKeyLength());
$iv = random_bytes($cipher->getIVLength());
$aad = 'additional authenticated data';

// 加密
$ciphertext = $cipher->encrypt($plaintext, $key, $iv, $aad, $tag);

// 解密
$decrypted = $cipher->decrypt($ciphertext, $key, $iv, $aad, $tag);

echo $decrypted; // Hello, World!
```

## 支持的算法

- **AES-CBC**: 分组密码的密码块链接模式
- **AES-CTR**: 分组密码的计数器模式
- **AES-GCM**: 认证加密的 Galois/Counter 模式
- **ChaCha20-Poly1305**: 流密码与 Poly1305 认证
- **3DES**: 三重数据加密标准

## 使用示例

### AES-GCM（推荐）

```php
use Tourze\TLSCryptoSymmetric\Cipher\AesGcm;

$cipher = new AesGcm(256); // 128、192 或 256 位
$key = random_bytes($cipher->getKeyLength());
$iv = random_bytes($cipher->getIVLength());

$ciphertext = $cipher->encrypt('敏感数据', $key, $iv, null, $tag);
$plaintext = $cipher->decrypt($ciphertext, $key, $iv, null, $tag);
```

### ChaCha20-Poly1305

```php
use Tourze\TLSCryptoSymmetric\Cipher\ChaCha20Poly1305;

$cipher = new ChaCha20Poly1305();
$key = random_bytes($cipher->getKeyLength());
$iv = random_bytes($cipher->getIVLength());

$ciphertext = $cipher->encrypt('消息', $key, $iv, 'aad', $tag);
$plaintext = $cipher->decrypt($ciphertext, $key, $iv, 'aad', $tag);
```

### AES-CBC

```php
use Tourze\TLSCryptoSymmetric\Cipher\AesCbc;

$cipher = new AesCbc(256);
$key = random_bytes($cipher->getKeyLength());
$iv = random_bytes($cipher->getIVLength());

$ciphertext = $cipher->encrypt('数据', $key, $iv);
$plaintext = $cipher->decrypt($ciphertext, $key, $iv);
```

## API 参考

### CipherInterface

所有密码实现都遵循 `CipherInterface` 接口：

```php
interface CipherInterface
{
    public function getName(): string;
    public function getKeyLength(): int;
    public function getIVLength(): int;
    public function getBlockSize(): int;
    public function encrypt(string $plaintext, string $key, string $iv, ?string $aad = null, ?string &$tag = null): string;
    public function decrypt(string $ciphertext, string $key, string $iv, ?string $aad = null, ?string $tag = null): string;
}
```

### 异常处理

库会为加密/解密错误抛出 `CipherException` 异常：

```php
use Tourze\TLSCryptoSymmetric\Exception\CipherException;

try {
    $result = $cipher->encrypt($data, $key, $iv);
} catch (CipherException $e) {
    echo '加密失败: ' . $e->getMessage();
}
```

## 系统要求

- PHP 8.1 或更高版本
- OpenSSL 扩展

## 许可证

MIT 许可证。更多信息请参阅 [LICENSE](LICENSE)。
