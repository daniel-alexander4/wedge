<?php

declare(strict_types=1);

namespace Wedge\Rp;

/**
 * Pending sign-in state.
 *
 * Every wedge sign-in is one record keyed by requestId, carrying the
 * challenge and the single-use tokens that gate session minting. Single-use
 * is enforced structurally: takeAuthenticated() removes the record
 * atomically, so no second session can ever be minted from the same sign-in
 * (spec §5.4, §8.3), and a challenge dies with its record.
 *
 * PHP handles every request in its own process, so the store IS the shared
 * state — WedgeRP requires one explicitly (SqliteStore for real deployments;
 * MemoryStore only for tests and resident runtimes like Swoole/FrankenPHP).
 * setAuthenticated and takeAuthenticated must stay atomic across every
 * process sharing the store.
 *
 * Record shape (associative array):
 *   requestId, challenge, namespace (strings)
 *   username               — asserted at start, '' for keyless
 *   browserNonce           — browser-binding cookie value, '' for app-initiated
 *   claimToken             — single-use claim token, '' for core flow
 *   status                 — 'pending' | 'authenticated'
 *   authenticatedUsername  — the account that verified, '' until then
 *   expiresAt              — epoch seconds (float)
 *
 * @phpstan-type RequestRecord array{
 *   requestId: string, challenge: string, namespace: string, username: string,
 *   browserNonce: string, claimToken: string, status: string,
 *   authenticatedUsername: string, expiresAt: float
 * }
 */
interface RequestStore
{
    /** @param array<string, mixed> $record Insert a new record. */
    public function put(array $record): void;

    /**
     * The live record, or null if unknown or expired.
     *
     * @return array<string, mixed>|null
     */
    public function get(string $requestId): ?array;

    /**
     * Atomically move a live record from "pending" to "authenticated",
     * recording the verified account. False if it was not pending.
     */
    public function setAuthenticated(string $requestId, string $username): bool;

    /**
     * Atomically remove and return a live "authenticated" record; null
     * otherwise. At most one caller ever receives a given record.
     *
     * @return array<string, mixed>|null
     */
    public function takeAuthenticated(string $requestId): ?array;
}
