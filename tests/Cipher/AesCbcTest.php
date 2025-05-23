<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoSymmetric\Tests\Cipher;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoSymmetric\Cipher\AesCbc;
use Tourze\TLSCryptoSymmetric\Exception\CipherException;

/**
 * AES-CBC测试类
 */
class AesCbcTest extends TestCase
{
    /**
     * 测试AES-128-CBC
     */
    public function testAes128Cbc(): void
    {
        $cipher = new AesCbc(128);

        // 测试获取名称
        $this->assertEquals('aes-128-cbc', $cipher->getName());

        // 测试获取密钥长度
        $this->assertEquals(16, $cipher->getKeyLength()); // 128位 = 16字节

        // 测试获取IV长度
        $this->assertEquals(16, $cipher->getIVLength());

        // 测试获取块大小
        $this->assertEquals(16, $cipher->getBlockSize());

        // 测试加密和解密
        $key = random_bytes($cipher->getKeyLength());
        $iv = random_bytes($cipher->getIVLength());
        $plaintext = 'Hello, World!';

        $ciphertext = $cipher->encrypt($plaintext, $key, $iv);

        $this->assertNotEmpty($ciphertext);
        $this->assertNotEquals($plaintext, $ciphertext);

        $decrypted = $cipher->decrypt($ciphertext, $key, $iv);
        $this->assertEquals($plaintext, $decrypted);
    }

    /**
     * 测试AES-256-CBC
     */
    public function testAes256Cbc(): void
    {
        $cipher = new AesCbc(256);

        // 测试获取名称
        $this->assertEquals('aes-256-cbc', $cipher->getName());

        // 测试获取密钥长度
        $this->assertEquals(32, $cipher->getKeyLength()); // 256位 = 32字节

        // 测试加密和解密
        $key = random_bytes($cipher->getKeyLength());
        $iv = random_bytes($cipher->getIVLength());
        $plaintext = 'Hello, World!';

        $ciphertext = $cipher->encrypt($plaintext, $key, $iv);

        $decrypted = $cipher->decrypt($ciphertext, $key, $iv);
        $this->assertEquals($plaintext, $decrypted);
    }

    /**
     * 测试AES-192-CBC
     */
    public function testAes192Cbc(): void
    {
        $cipher = new AesCbc(192);

        // 测试获取名称
        $this->assertEquals('aes-192-cbc', $cipher->getName());

        // 测试获取密钥长度
        $this->assertEquals(24, $cipher->getKeyLength()); // 192位 = 24字节

        // 测试加密和解密
        $key = random_bytes($cipher->getKeyLength());
        $iv = random_bytes($cipher->getIVLength());
        $plaintext = 'Hello, World!';

        $ciphertext = $cipher->encrypt($plaintext, $key, $iv);

        $decrypted = $cipher->decrypt($ciphertext, $key, $iv);
        $this->assertEquals($plaintext, $decrypted);
    }

    /**
     * 测试不同密钥的加密结果不同
     */
    public function testDifferentKeys(): void
    {
        $cipher = new AesCbc(256);

        $key1 = random_bytes($cipher->getKeyLength());
        $key2 = random_bytes($cipher->getKeyLength());
        $iv = random_bytes($cipher->getIVLength());
        $plaintext = 'Hello, World!';

        $ciphertext1 = $cipher->encrypt($plaintext, $key1, $iv);
        $ciphertext2 = $cipher->encrypt($plaintext, $key2, $iv);

        $this->assertNotEquals($ciphertext1, $ciphertext2);
    }

    /**
     * 测试不同IV的加密结果不同
     */
    public function testDifferentIVs(): void
    {
        $cipher = new AesCbc(256);

        $key = random_bytes($cipher->getKeyLength());
        $iv1 = random_bytes($cipher->getIVLength());
        $iv2 = random_bytes($cipher->getIVLength());
        $plaintext = 'Hello, World!';

        $ciphertext1 = $cipher->encrypt($plaintext, $key, $iv1);
        $ciphertext2 = $cipher->encrypt($plaintext, $key, $iv2);

        $this->assertNotEquals($ciphertext1, $ciphertext2);
    }

    /**
     * 测试不同的明文产生不同的密文
     */
    public function testDifferentPlaintexts(): void
    {
        $cipher = new AesCbc(256);

        $key = random_bytes($cipher->getKeyLength());
        $iv = random_bytes($cipher->getIVLength());
        $plaintext1 = 'Hello, World!';
        $plaintext2 = 'Hello, OpenSSL!';

        $ciphertext1 = $cipher->encrypt($plaintext1, $key, $iv);
        $ciphertext2 = $cipher->encrypt($plaintext2, $key, $iv);

        $this->assertNotEquals($ciphertext1, $ciphertext2);
    }

    /**
     * 测试错误的密钥解密失败
     */
    public function testWrongKey(): void
    {
        $cipher = new AesCbc(256);

        $key1 = random_bytes($cipher->getKeyLength());
        $key2 = random_bytes($cipher->getKeyLength());
        $iv = random_bytes($cipher->getIVLength());
        $plaintext = 'Hello, World!';

        try {
            $ciphertext = $cipher->encrypt($plaintext, $key1, $iv);

            $decrypted = $cipher->decrypt($ciphertext, $key2, $iv);
            // 如果不抛出异常，至少要确保解密结果与原文不同
            $this->assertNotEquals($plaintext, $decrypted);
        } catch (CipherException $e) {
            // 在某些环境中，使用错误密钥解密可能会抛出异常
            // 这种情况下我们只需确认异常被抛出即可
            $this->assertTrue(true);
        }
    }

    /**
     * 测试错误的IV解密失败
     */
    public function testWrongIV(): void
    {
        $cipher = new AesCbc(256);

        $key = random_bytes($cipher->getKeyLength());
        $iv1 = random_bytes($cipher->getIVLength());
        $iv2 = random_bytes($cipher->getIVLength());
        $plaintext = 'Hello, World!';

        try {
            $ciphertext = $cipher->encrypt($plaintext, $key, $iv1);

            $decrypted = $cipher->decrypt($ciphertext, $key, $iv2);
            // 如果不抛出异常，至少要确保解密结果与原文不同
            $this->assertNotEquals($plaintext, $decrypted);
        } catch (CipherException $e) {
            // 在某些环境中，使用错误IV解密可能会抛出异常
            // 这种情况下我们只需确认异常被抛出即可
            $this->assertTrue(true);
        }
    }

    /**
     * 测试密钥长度不匹配异常
     */
    public function testInvalidKeyLength(): void
    {
        $cipher = new AesCbc(256);
        $key = random_bytes($cipher->getKeyLength() - 1); // 少一个字节
        $iv = random_bytes($cipher->getIVLength());
        $plaintext = 'Hello, World!';

        $this->expectException(CipherException::class);
        $cipher->encrypt($plaintext, $key, $iv);
    }

    /**
     * 测试IV长度不匹配异常
     */
    public function testInvalidIVLength(): void
    {
        $cipher = new AesCbc(256);
        $key = random_bytes($cipher->getKeyLength());
        $iv = random_bytes($cipher->getIVLength() - 1); // 少一个字节
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
        new AesCbc(123); // 不是128、192或256
    }

    /**
     * 测试长明文加密解密
     */
    public function testLongPlaintext(): void
    {
        $cipher = new AesCbc(256);

        $key = random_bytes($cipher->getKeyLength());
        $iv = random_bytes($cipher->getIVLength());
        $plaintext = str_repeat('Long plaintext for testing AES-CBC encryption and decryption. ', 50);

        $ciphertext = $cipher->encrypt($plaintext, $key, $iv);
        $decrypted = $cipher->decrypt($ciphertext, $key, $iv);

        $this->assertEquals($plaintext, $decrypted);
    }

    /**
     * 测试空明文加密解密
     */
    public function testEmptyPlaintext(): void
    {
        $cipher = new AesCbc(256);

        $key = random_bytes($cipher->getKeyLength());
        $iv = random_bytes($cipher->getIVLength());
        $plaintext = '';

        $ciphertext = $cipher->encrypt($plaintext, $key, $iv);
        $decrypted = $cipher->decrypt($ciphertext, $key, $iv);

        $this->assertEquals($plaintext, $decrypted);
    }
}
