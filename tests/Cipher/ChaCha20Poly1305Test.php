<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoSymmetric\Tests\Cipher;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoSymmetric\Cipher\ChaCha20Poly1305;
use Tourze\TLSCryptoSymmetric\Exception\CipherException;

/**
 * @internal
 */
#[CoversClass(ChaCha20Poly1305::class)]
final class ChaCha20Poly1305Test extends TestCase
{
    /**
     * 测试基本属性
     */
    public function testBasicProperties(): void
    {
        $cipher = new ChaCha20Poly1305();

        // 测试获取名称
        $this->assertEquals('chacha20-poly1305', $cipher->getName());

        // 测试获取密钥长度
        $this->assertEquals(32, $cipher->getKeyLength()); // 256位 = 32字节

        // 测试获取IV长度
        $this->assertEquals(12, $cipher->getIVLength());

        // 测试获取块大小
        $this->assertEquals(1, $cipher->getBlockSize()); // 流密码
    }

    /**
     * 测试加密和解密
     */
    public function testEncryptDecrypt(): void
    {
        $cipher = new ChaCha20Poly1305();

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
     * 测试不同密钥的加密结果不同
     */
    public function testDifferentKeys(): void
    {
        $cipher = new ChaCha20Poly1305();

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
        $cipher = new ChaCha20Poly1305();

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
        $cipher = new ChaCha20Poly1305();

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
        $cipher = new ChaCha20Poly1305();

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
        $cipher = new ChaCha20Poly1305();

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
        $cipher = new ChaCha20Poly1305();

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
        $cipher = new ChaCha20Poly1305();
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
        $cipher = new ChaCha20Poly1305();

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
     * 专门测试 decrypt 方法
     */
    public function testDecrypt(): void
    {
        $cipher = new ChaCha20Poly1305();

        // 确保密钥和IV长度为正整数
        $keyLength = $cipher->getKeyLength();
        $ivLength = $cipher->getIVLength();
        $this->assertGreaterThan(0, $keyLength);
        $this->assertGreaterThan(0, $ivLength);
        $key = random_bytes(max(1, $cipher->getKeyLength()));
        $iv = random_bytes(max(1, $cipher->getIVLength()));
        $plaintext = 'Test ChaCha20Poly1305 decryption';
        $aad = 'Test AAD';
        $tag = null;

        $ciphertext = $cipher->encrypt($plaintext, $key, $iv, $aad, $tag);
        $decrypted = $cipher->decrypt($ciphertext, $key, $iv, $aad, $tag);

        $this->assertEquals($plaintext, $decrypted);
        $this->assertIsString($decrypted);
    }
}
