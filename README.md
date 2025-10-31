# TLS Crypto Symmetric

[![PHP Version](https://img.shields.io/badge/php-%5E8.1-777BB4?style=flat-square&logo=php)](https://www.php.net)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)](https://github.com/tourze/php-monorepo)
[![Code Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen?style=flat-square)](https://codecov.io)

[English](README.md) | [中文](README.zh-CN.md)

TLS symmetric encryption algorithms implementation for PHP. This library provides a comprehensive set of symmetric encryption algorithms commonly used in TLS protocols.

## Installation

```bash
composer require tourze/tls-crypto-symmetric
```

## Quick Start

```php
use Tourze\TLSCryptoSymmetric\Cipher\AesGcm;

// Create AES-GCM cipher with 256-bit key
$cipher = new AesGcm(256);

// Prepare data
$plaintext = 'Hello, World!';
$key = random_bytes($cipher->getKeyLength());
$iv = random_bytes($cipher->getIVLength());
$aad = 'additional authenticated data';

// Encrypt
$ciphertext = $cipher->encrypt($plaintext, $key, $iv, $aad, $tag);

// Decrypt
$decrypted = $cipher->decrypt($ciphertext, $key, $iv, $aad, $tag);

echo $decrypted; // Hello, World!
```

## Supported Algorithms

- **AES-CBC**: Block cipher with Cipher Block Chaining mode
- **AES-CTR**: Block cipher with Counter mode
- **AES-GCM**: Authenticated encryption with Galois/Counter Mode
- **ChaCha20-Poly1305**: Stream cipher with Poly1305 authentication
- **3DES**: Triple Data Encryption Standard

## Usage Examples

### AES-GCM (Recommended)

```php
use Tourze\TLSCryptoSymmetric\Cipher\AesGcm;

$cipher = new AesGcm(256); // 128, 192, or 256 bits
$key = random_bytes($cipher->getKeyLength());
$iv = random_bytes($cipher->getIVLength());

$ciphertext = $cipher->encrypt('sensitive data', $key, $iv, null, $tag);
$plaintext = $cipher->decrypt($ciphertext, $key, $iv, null, $tag);
```

### ChaCha20-Poly1305

```php
use Tourze\TLSCryptoSymmetric\Cipher\ChaCha20Poly1305;

$cipher = new ChaCha20Poly1305();
$key = random_bytes($cipher->getKeyLength());
$iv = random_bytes($cipher->getIVLength());

$ciphertext = $cipher->encrypt('message', $key, $iv, 'aad', $tag);
$plaintext = $cipher->decrypt($ciphertext, $key, $iv, 'aad', $tag);
```

### AES-CBC

```php
use Tourze\TLSCryptoSymmetric\Cipher\AesCbc;

$cipher = new AesCbc(256);
$key = random_bytes($cipher->getKeyLength());
$iv = random_bytes($cipher->getIVLength());

$ciphertext = $cipher->encrypt('data', $key, $iv);
$plaintext = $cipher->decrypt($ciphertext, $key, $iv);
```

## API Reference

### CipherInterface

All cipher implementations follow the `CipherInterface`:

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

### Exception Handling

The library throws `CipherException` for encryption/decryption errors:

```php
use Tourze\TLSCryptoSymmetric\Exception\CipherException;

try {
    $result = $cipher->encrypt($data, $key, $iv);
} catch (CipherException $e) {
    echo 'Encryption failed: ' . $e->getMessage();
}
```

## Requirements

- PHP 8.1 or higher
- OpenSSL extension

## License

MIT License. See [LICENSE](LICENSE) for more information.