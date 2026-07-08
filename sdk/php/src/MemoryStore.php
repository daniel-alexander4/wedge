<?php

declare(strict_types=1);

namespace Wedge\Rp;

/**
 * In-process store — for tests and resident runtimes (Swoole, FrankenPHP
 * worker mode) only. Under classic per-request PHP (FPM, php -S) every
 * request gets a fresh process and this store forgets everything; use
 * SqliteStore there.
 */
final class MemoryStore implements RequestStore
{
    /** @var array<string, array<string, mixed>> */
    private array $records = [];

    private function prune(float $now): void
    {
        foreach ($this->records as $id => $rec) {
            if ($rec['expiresAt'] <= $now) {
                unset($this->records[$id]);
            }
        }
    }

    public function put(array $record): void
    {
        $this->prune(microtime(true));
        $this->records[$record['requestId']] = $record;
    }

    public function get(string $requestId): ?array
    {
        $this->prune(microtime(true));

        return $this->records[$requestId] ?? null;
    }

    public function setAuthenticated(string $requestId, string $username): bool
    {
        $this->prune(microtime(true));
        $rec = $this->records[$requestId] ?? null;
        if ($rec === null || $rec['status'] !== 'pending') {
            return false;
        }
        $this->records[$requestId]['status'] = 'authenticated';
        $this->records[$requestId]['authenticatedUsername'] = $username;

        return true;
    }

    public function takeAuthenticated(string $requestId): ?array
    {
        $this->prune(microtime(true));
        $rec = $this->records[$requestId] ?? null;
        if ($rec === null || $rec['status'] !== 'authenticated') {
            return null;
        }
        unset($this->records[$requestId]);

        return $rec;
    }
}
