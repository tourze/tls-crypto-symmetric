<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoSymmetric\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSCryptoSymmetric\Exception\CipherException;
use Tourze\TLSCryptoSymmetric\Exception\CryptoException;

/**
 * @internal
 * 测试抽象异常基类 CryptoException，通过具体子类 CipherException 进行测试
 */
#[CoversClass(CryptoException::class)]
final class CryptoExceptionTest extends AbstractExceptionTestCase
{
    public function testException(): void
    {
        $message = 'Test crypto exception';
        $code = 123;
        $previous = new \Exception('Previous exception');

        // 使用具体子类测试抽象基类
        $exception = new CipherException($message, $code, $previous);

        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertInstanceOf(CryptoException::class, $exception);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testExceptionWithDefaults(): void
    {
        // 使用具体子类测试抽象基类
        $exception = new CipherException();

        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertInstanceOf(CryptoException::class, $exception);
        $this->assertEquals('', $exception->getMessage());
        $this->assertEquals(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }
}
