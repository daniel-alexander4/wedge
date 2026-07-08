<?php

declare(strict_types=1);

namespace Wedge\Rp\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Wedge\Rp\MemoryStore;
use Wedge\Rp\RequestStore;
use Wedge\Rp\SqliteStore;

final class StoreTest extends TestCase
{
    /** @return array<string, mixed> */
    private static function record(array $overrides = []): array
    {
        return array_merge([
            'requestId' => 'req1',
            'challenge' => 'AbCdEfGhIjKlMnOpQrStUvWx',
            'namespace' => 'http://127.0.0.1:9414',
            'username' => '',
            'browserNonce' => 'nonce',
            'claimToken' => '',
            'status' => 'pending',
            'authenticatedUsername' => '',
            'expiresAt' => microtime(true) + 60,
        ], $overrides);
    }

    /** @return iterable<string, array{0: callable(): RequestStore}> */
    public static function stores(): iterable
    {
        yield 'MemoryStore' => [fn (): RequestStore => new MemoryStore()];
        yield 'SqliteStore' => [fn (): RequestStore => new SqliteStore(
            sys_get_temp_dir() . '/wedge-rp-test-' . bin2hex(random_bytes(6)) . '.db',
        )];
    }

    #[DataProvider('stores')]
    public function testPutGetRoundtrip(callable $make): void
    {
        $store = $make();
        $store->put(self::record());
        $rec = $store->get('req1');
        $this->assertNotNull($rec);
        $this->assertSame('AbCdEfGhIjKlMnOpQrStUvWx', $rec['challenge']);
        $this->assertSame('pending', $rec['status']);
        $this->assertNull($store->get('nope'));
    }

    #[DataProvider('stores')]
    public function testExpiredIsGone(callable $make): void
    {
        $store = $make();
        $store->put(self::record(['expiresAt' => microtime(true) - 1]));
        $this->assertNull($store->get('req1'));
        $this->assertFalse($store->setAuthenticated('req1', 'alice'));
    }

    #[DataProvider('stores')]
    public function testSetAuthenticatedOnlyFromPending(callable $make): void
    {
        $store = $make();
        $store->put(self::record());
        $this->assertTrue($store->setAuthenticated('req1', 'alice'));
        $this->assertFalse($store->setAuthenticated('req1', 'mallory'));
        $rec = $store->get('req1');
        $this->assertSame('authenticated', $rec['status']);
        $this->assertSame('alice', $rec['authenticatedUsername']);
    }

    #[DataProvider('stores')]
    public function testTakeIsSingleUse(callable $make): void
    {
        $store = $make();
        $store->put(self::record());
        $this->assertNull($store->takeAuthenticated('req1'), 'pending record must not be takeable');
        $store->setAuthenticated('req1', 'alice');
        $taken = $store->takeAuthenticated('req1');
        $this->assertSame('alice', $taken['authenticatedUsername']);
        $this->assertNull($store->takeAuthenticated('req1'), 'record taken twice');
        $this->assertNull($store->get('req1'));
    }

    public function testSqliteStateSharedAcrossInstances(): void
    {
        // Two store objects on one path model two FPM / php -S workers.
        $path = sys_get_temp_dir() . '/wedge-rp-test-' . bin2hex(random_bytes(6)) . '.db';
        $workerA = new SqliteStore($path);
        $workerB = new SqliteStore($path);
        $workerA->put(self::record());
        $this->assertNotNull($workerB->get('req1'));
        $this->assertTrue($workerB->setAuthenticated('req1', 'alice'));
        $this->assertSame('alice', $workerA->takeAuthenticated('req1')['authenticatedUsername']);
        $this->assertNull($workerB->takeAuthenticated('req1'), 'exactly one winner across instances');
    }
}
