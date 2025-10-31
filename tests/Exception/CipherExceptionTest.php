<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoSymmetric\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSCryptoSymmetric\Exception\CipherException;
use Tourze\TLSCryptoSymmetric\Exception\CryptoException;

/**
 * @internal
 */
#[CoversClass(CipherException::class)]
final class CipherExceptionTest extends AbstractExceptionTestCase
{
    public function testException(): void
    {
        $message = 'Test cipher exception';
        $code = 456;
        $previous = new \Exception('Previous exception');

        $exception = new CipherException($message, $code, $previous);

        $this->assertInstanceOf(CryptoException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testExceptionWithDefaults(): void
    {
        $exception = new CipherException();

        $this->assertInstanceOf(CryptoException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals('', $exception->getMessage());
        $this->assertEquals(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }
}
