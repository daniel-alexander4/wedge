<?php

declare(strict_types=1);

namespace Wedge\Rp\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Wedge\Rp\Kernel;
use Wedge\Rp\SshKeygenUnavailable;

final class KernelTest extends TestCase
{
    private const NAMESPACE_ = 'http://127.0.0.1:9414';
    private const CHALLENGE = 'AbCdEfGhIjKlMnOpQrStUvWx';

    private static ?KeyPair $key = null;
    private static ?KeyPair $other = null;
    private static string $sig = '';

    public static function setUpBeforeClass(): void
    {
        if (!KeyPair::available()) {
            self::markTestSkipped('ssh-keygen not installed');
        }
        self::$key = new KeyPair('alice@test');
        self::$other = new KeyPair('mallory@test');
        self::$sig = self::$key->sign(self::CHALLENGE, self::NAMESPACE_);
    }

    public static function tearDownAfterClass(): void
    {
        self::$key?->cleanup();
        self::$other?->cleanup();
    }

    public function testAcceptsGoodSignature(): void
    {
        $outcome = Kernel::verifySignature(self::CHALLENGE, self::$sig, 'alice', self::$key->publicKey, self::NAMESPACE_);
        $this->assertTrue($outcome['ok'], $outcome['detail']);
    }

    /** @return iterable<string, array{0: callable(): array{ok: bool, detail: string}}> */
    public static function tamperedInputs(): iterable
    {
        yield 'wrong namespace' => [fn () => Kernel::verifySignature(self::CHALLENGE, self::$sig, 'alice', self::$key->publicKey, 'http://evil.example')];
        yield 'wrong challenge' => [fn () => Kernel::verifySignature('NotWhatWasSigned123', self::$sig, 'alice', self::$key->publicKey, self::NAMESPACE_)];
        yield 'wrong key' => [fn () => Kernel::verifySignature(self::CHALLENGE, self::$sig, 'alice', self::$other->publicKey, self::NAMESPACE_)];
        yield 'garbage signature' => [fn () => Kernel::verifySignature(self::CHALLENGE, "-----BEGIN SSH SIGNATURE-----\ngarbage\n-----END SSH SIGNATURE-----", 'alice', self::$key->publicKey, self::NAMESPACE_)];
        yield 'unarmored signature' => [fn () => Kernel::verifySignature(self::CHALLENGE, 'AAAA-not-armored', 'alice', self::$key->publicKey, self::NAMESPACE_)];
        yield 'invalid principal' => [fn () => Kernel::verifySignature(self::CHALLENGE, self::$sig, 'has space', self::$key->publicKey, self::NAMESPACE_)];
        yield 'malformed public key' => [fn () => Kernel::verifySignature(self::CHALLENGE, self::$sig, 'alice', 'one-field', self::NAMESPACE_)];
    }

    #[DataProvider('tamperedInputs')]
    public function testRejectsTamperedInputs(callable $verify): void
    {
        $this->assertFalse($verify()['ok']);
    }

    public function testIgnoresPublicKeyComment(): void
    {
        [$keytype, $keydata] = Kernel::splitPublicKey(self::$key->publicKey);
        $outcome = Kernel::verifySignature(self::CHALLENGE, self::$sig, 'alice', "{$keytype} {$keydata} another@host", self::NAMESPACE_);
        $this->assertTrue($outcome['ok'], $outcome['detail']);
    }

    public function testMissingKeygenThrows(): void
    {
        putenv('SSH_KEYGEN_PATH=/nonexistent/ssh-keygen');
        try {
            $this->expectException(SshKeygenUnavailable::class);
            Kernel::verifySignature(self::CHALLENGE, self::$sig, 'alice', self::$key->publicKey, self::NAMESPACE_);
        } finally {
            putenv('SSH_KEYGEN_PATH');
        }
    }

    public function testAncientKeygenThrows(): void
    {
        $fake = sys_get_temp_dir() . '/wedge-rp-fake-' . bin2hex(random_bytes(6));
        file_put_contents($fake, "#!/bin/sh\necho 'ssh-keygen: unknown option -- Y' >&2\nexit 1\n");
        chmod($fake, 0755);
        putenv("SSH_KEYGEN_PATH={$fake}");
        try {
            $this->expectException(SshKeygenUnavailable::class);
            Kernel::verifySignature(self::CHALLENGE, self::$sig, 'alice', self::$key->publicKey, self::NAMESPACE_);
        } finally {
            putenv('SSH_KEYGEN_PATH');
            @unlink($fake);
        }
    }

    public function testSplitPublicKeyAndSameKey(): void
    {
        $this->assertSame(['ssh-ed25519', 'AAAAC3Nza'], Kernel::splitPublicKey('ssh-ed25519 AAAAC3Nza comment here'));
        $this->assertNull(Kernel::splitPublicKey('just-one-field'));
        $this->assertNull(Kernel::splitPublicKey(''));
        $this->assertTrue(Kernel::sameKey('ssh-ed25519 AAAAC3Nza a@b', 'ssh-ed25519 AAAAC3Nza c@d'));
        $this->assertFalse(Kernel::sameKey('ssh-ed25519 AAAAC3Nza', 'ssh-ed25519 AAAAC3Nzb'));
    }
}
