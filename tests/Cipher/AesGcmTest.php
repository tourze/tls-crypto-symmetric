<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoSymmetric\Tests\Cipher;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoSymmetric\Cipher\AesGcm;
use Tourze\TLSCryptoSymmetric\Exception\CipherException;

/**
 * @internal
 */
#[CoversClass(AesGcm::class)]
final class AesGcmTest extends TestCase
{
    /**
     * 测试AES-128-GCM
     */
    public function testAes128Gcm(): void
    {
        $cipher = new AesGcm(128);

        // 测试获取名称
        $this->assertEquals('aes-128-gcm', $cipher->getName());

        // 测试获取密钥长度
        $this->assertEquals(16, $cipher->getKeyLength()); // 128位 = 16字节

        // 测试获取IV长度
        $this->assertEquals(12, $cipher->getIVLength());

        // 测试获取块大小
        $this->assertEquals(16, $cipher->getBlockSize());

        // 测试加密和解密

        // 确保密钥和IV长度为正整数
        $keyLength = $cipher->getKeyLength();
        $ivLength = $cipher->getIVLength();
        $this->assertGreaterThan(0, $keyLength);
        $this->assertGreaterThan(0, $ivLength);
        $key = random_bytes(max(1, $cipher->getKeyLength()));
        $iv = random_bytes(max(1, $cipher->getIVLength()));
        $plaintext = 'Hello, World!';
        $aad = 'Additional Data';

        $tag = null;
        $ciphertext = $cipher->encrypt($plaintext, $key, $iv, $aad, $tag);

        $this->assertNotEmpty($ciphertext);
        $this->assertNotEquals($plaintext, $ciphertext);
        $this->assertNotNull($tag);
        $this->assertNotEmpty($tag);

        $decrypted = $cipher->decrypt($ciphertext, $key, $iv, $aad, $tag);
        $this->assertEquals($plaintext, $decrypted);
    }

    /**
     * 测试AES-256-GCM
     */
    public function testAes256Gcm(): void
    {
        $cipher = new AesGcm(256);

        // 测试获取名称
        $this->assertEquals('aes-256-gcm', $cipher->getName());

        // 测试获取密钥长度
        $this->assertEquals(32, $cipher->getKeyLength()); // 256位 = 32字节

        // 测试加密和解密

        // 确保密钥和IV长度为正整数
        $keyLength = $cipher->getKeyLength();
        $ivLength = $cipher->getIVLength();
        $this->assertGreaterThan(0, $keyLength);
        $this->assertGreaterThan(0, $ivLength);
        $key = random_bytes(max(1, $cipher->getKeyLength()));
        $iv = random_bytes(max(1, $cipher->getIVLength()));
        $plaintext = 'Hello, World!';
        $aad = 'Additional Data';

        $tag = null;
        $ciphertext = $cipher->encrypt($plaintext, $key, $iv, $aad, $tag);

        $decrypted = $cipher->decrypt($ciphertext, $key, $iv, $aad, $tag);
        $this->assertEquals($plaintext, $decrypted);
    }

    /**
     * 测试不同密钥的加密结果不同
     */
    public function testDifferentKeys(): void
    {
        $cipher = new AesGcm(256);

        $key1 = random_bytes(max(1, $cipher->getKeyLength()));
        $key2 = random_bytes(max(1, $cipher->getKeyLength()));
        $iv = random_bytes(max(1, $cipher->getIVLength()));
        $plaintext = 'Hello, World!';

        $tag1 = null;
        $ciphertext1 = $cipher->encrypt($plaintext, $key1, $iv, null, $tag1);

        $tag2 = null;
        $ciphertext2 = $cipher->encrypt($plaintext, $key2, $iv, null, $tag2);

        $this->assertNotEquals($ciphertext1, $ciphertext2);
        $this->assertNotEquals($tag1, $tag2);
    }

    /**
     * 测试不同IV的加密结果不同
     */
    public function testDifferentIVs(): void
    {
        $cipher = new AesGcm(256);

        // 确保密钥和IV长度为正整数
        $keyLength = $cipher->getKeyLength();
        $ivLength = $cipher->getIVLength();
        $this->assertGreaterThan(0, $keyLength);
        $this->assertGreaterThan(0, $ivLength);
        $key = random_bytes(max(1, $cipher->getKeyLength()));
        $iv1 = random_bytes(max(1, $cipher->getIVLength()));
        $iv2 = random_bytes(max(1, $cipher->getIVLength()));
        $plaintext = 'Hello, World!';

        $tag1 = null;
        $ciphertext1 = $cipher->encrypt($plaintext, $key, $iv1, null, $tag1);

        $tag2 = null;
        $ciphertext2 = $cipher->encrypt($plaintext, $key, $iv2, null, $tag2);

        $this->assertNotEquals($ciphertext1, $ciphertext2);
        $this->assertNotEquals($tag1, $tag2);
    }

    /**
     * 测试篡改密文后解密失败
     */
    public function testTamperedCiphertext(): void
    {
        $cipher = new AesGcm(256);

        // 确保密钥和IV长度为正整数
        $keyLength = $cipher->getKeyLength();
        $ivLength = $cipher->getIVLength();
        $this->assertGreaterThan(0, $keyLength);
        $this->assertGreaterThan(0, $ivLength);
        $key = random_bytes(max(1, $cipher->getKeyLength()));
        $iv = random_bytes(max(1, $cipher->getIVLength()));
        $plaintext = 'Hello, World!';

        $tag = null;
        $ciphertext = $cipher->encrypt($plaintext, $key, $iv, null, $tag);

        // 篡改密文
        $tamperedCiphertext = $ciphertext;
        $tamperedCiphertext[0] = chr(ord($tamperedCiphertext[0]) ^ 1);

        $this->expectException(CipherException::class);
        $cipher->decrypt($tamperedCiphertext, $key, $iv, null, $tag);
    }

    /**
     * 测试篡改AAD后解密失败
     */
    public function testTamperedAAD(): void
    {
        $cipher = new AesGcm(256);

        // 确保密钥和IV长度为正整数
        $keyLength = $cipher->getKeyLength();
        $ivLength = $cipher->getIVLength();
        $this->assertGreaterThan(0, $keyLength);
        $this->assertGreaterThan(0, $ivLength);
        $key = random_bytes(max(1, $cipher->getKeyLength()));
        $iv = random_bytes(max(1, $cipher->getIVLength()));
        $plaintext = 'Hello, World!';
        $aad = 'Additional Data';

        $tag = null;
        $ciphertext = $cipher->encrypt($plaintext, $key, $iv, $aad, $tag);

        $this->expectException(CipherException::class);
        $cipher->decrypt($ciphertext, $key, $iv, 'Tampered AAD', $tag);
    }

    /**
     * 测试篡改TAG后解密失败
     */
    public function testTamperedTag(): void
    {
        $cipher = new AesGcm(256);

        // 确保密钥和IV长度为正整数
        $keyLength = $cipher->getKeyLength();
        $ivLength = $cipher->getIVLength();
        $this->assertGreaterThan(0, $keyLength);
        $this->assertGreaterThan(0, $ivLength);
        $key = random_bytes(max(1, $cipher->getKeyLength()));
        $iv = random_bytes(max(1, $cipher->getIVLength()));
        $plaintext = 'Hello, World!';

        $tag = null;
        $ciphertext = $cipher->encrypt($plaintext, $key, $iv, null, $tag);

        // 篡改TAG
        $tamperedTag = $tag;
        $this->assertNotNull($tamperedTag, 'Tag should not be null');
        $tamperedTag[0] = chr(ord($tamperedTag[0]) ^ 1);

        $this->expectException(CipherException::class);
        $cipher->decrypt($ciphertext, $key, $iv, null, $tamperedTag);
    }

    /**
     * 测试无TAG解密失败
     */
    public function testMissingTag(): void
    {
        $cipher = new AesGcm(256);

        // 确保密钥和IV长度为正整数
        $keyLength = $cipher->getKeyLength();
        $ivLength = $cipher->getIVLength();
        $this->assertGreaterThan(0, $keyLength);
        $this->assertGreaterThan(0, $ivLength);
        $key = random_bytes(max(1, $cipher->getKeyLength()));
        $iv = random_bytes(max(1, $cipher->getIVLength()));
        $plaintext = 'Hello, World!';

        $tag = null;
        $ciphertext = $cipher->encrypt($plaintext, $key, $iv, null, $tag);

        $this->expectException(CipherException::class);
        $cipher->decrypt($ciphertext, $key, $iv, null, null);
    }

    /**
     * 测试密钥长度不匹配异常
     */
    public function testInvalidKeyLength(): void
    {
        $cipher = new AesGcm(256);
        $key = random_bytes(max(1, $cipher->getKeyLength() - 1)); // 少一个字节
        $iv = random_bytes(max(1, $cipher->getIVLength()));
        $plaintext = 'Hello, World!';

        $this->expectException(CipherException::class);
        $cipher->encrypt($plaintext, $key, $iv);
    }

    /**
     * 测试IV长度不匹配异常
     */
    public function testInvalidIVLength(): void
    {
        $cipher = new AesGcm(256);

        // 确保密钥和IV长度为正整数
        $keyLength = $cipher->getKeyLength();
        $ivLength = $cipher->getIVLength();
        $this->assertGreaterThan(0, $keyLength);
        $this->assertGreaterThan(0, $ivLength);
        $key = random_bytes(max(1, $cipher->getKeyLength()));
        $iv = random_bytes(max(1, $cipher->getIVLength() - 1)); // 少一个字节
        $plaintext = 'Hello, World!';

        $this->expectException(CipherException::class);
        $cipher->encrypt($plaintext, $key, $iv);
    }

    /**
     * 测试无效的密钥大小
     */
    public function testInvalidKeySize(): void
    {
        $this->expectException(CipherException::class);
        new AesGcm(123);
    }

    /**
     * 专门测试 encrypt 方法
     */
    public function testEncrypt(): void
    {
        $cipher = new AesGcm(256);

        // 确保密钥和IV长度为正整数
        $keyLength = $cipher->getKeyLength();
        $ivLength = $cipher->getIVLength();
        $this->assertGreaterThan(0, $keyLength);
        $this->assertGreaterThan(0, $ivLength);
        $key = random_bytes(max(1, $cipher->getKeyLength()));
        $iv = random_bytes(max(1, $cipher->getIVLength()));
        $plaintext = 'Test GCM encryption';
        $aad = 'Additional data';
        $tag = null;

        $ciphertext = $cipher->encrypt($plaintext, $key, $iv, $aad, $tag);

        $this->assertNotEmpty($ciphertext);
        $this->assertNotEquals($plaintext, $ciphertext);
        $this->assertIsString($ciphertext);
        $this->assertNotNull($tag);
        $this->assertNotEmpty($tag);
    }

    /**
     * 专门测试 decrypt 方法
     */
    public function testDecrypt(): void
    {
        $cipher = new AesGcm(256);

        // 确保密钥和IV长度为正整数
        $keyLength = $cipher->getKeyLength();
        $ivLength = $cipher->getIVLength();
        $this->assertGreaterThan(0, $keyLength);
        $this->assertGreaterThan(0, $ivLength);
        $key = random_bytes(max(1, $cipher->getKeyLength()));
        $iv = random_bytes(max(1, $cipher->getIVLength()));
        $plaintext = 'Test GCM decryption';
        $aad = 'Additional data';
        $tag = null;

        $ciphertext = $cipher->encrypt($plaintext, $key, $iv, $aad, $tag);
        $decrypted = $cipher->decrypt($ciphertext, $key, $iv, $aad, $tag);

        $this->assertEquals($plaintext, $decrypted);
        $this->assertIsString($decrypted);
    }
}
