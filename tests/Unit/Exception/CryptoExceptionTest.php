<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoSymmetric\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoSymmetric\Exception\CryptoException;

/**
 * @covers \Tourze\TLSCryptoSymmetric\Exception\CryptoException
 */
class CryptoExceptionTest extends TestCase
{
    public function testException(): void
    {
        $message = 'Test crypto exception';
        $code = 123;
        $previous = new \Exception('Previous exception');

        $exception = new CryptoException($message, $code, $previous);

        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testExceptionWithDefaults(): void
    {
        $exception = new CryptoException();

        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals('', $exception->getMessage());
        $this->assertEquals(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }
}