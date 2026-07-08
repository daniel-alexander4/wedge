<?php

declare(strict_types=1);

namespace Wedge\Rp;

/**
 * Framework-neutral wedge relying-party engine.
 *
 * Implements every RP-side requirement of the wedge protocol v1
 * (docs/wedge-spec-v1.md) as plain-data handlers — arrays in, arrays out. An
 * adapter (Handler for vanilla PHP, Psr15Middleware, the Laravel service
 * provider, or ~60 lines of your own routing) translates HTTP to these calls;
 * nothing in this class touches superglobals or a framework.
 *
 * The host application supplies what the spec deliberately leaves out of
 * scope: how accounts and their registered public keys are stored (the
 * findKeys / findUserByPublicKey callbacks) and how a session is minted (the
 * adapters' login callback).
 *
 * Port of sdk/python/wedge_rp/core.py — keep semantics in lockstep with the
 * Python/Node/Go engines, and origin normalization/equivalence consistent
 * with wedge's internal/policy (a security boundary).
 *
 * PHP-specific departures, deliberate: no in-engine rate limiter or verify
 * semaphore (each request is its own short-lived process — bound request
 * rates at the web server / FPM layer), and the store is REQUIRED (an
 * in-memory default would silently break under per-request PHP).
 */
final class WedgeRP
{
    // /.well-known/wedge.json and /wedge/app-start are fixed by the spec
    // (§4, §9); the rest are this package's defaults — challenge/verify are
    // published via discovery, start/status/claim are wired to wedge.js.
    public const DISCOVERY_PATH = '/.well-known/wedge.json';
    public const START_PATH = '/wedge/start';
    public const CHALLENGE_PATH = '/wedge/challenge';
    public const VERIFY_PATH = '/wedge/verify';
    public const STATUS_PATH = '/wedge/status';
    public const APP_START_PATH = '/wedge/app-start';
    public const CLAIM_PATH = '/wedge/claim';
    public const SCRIPT_PATH = '/wedge/wedge.js';

    public const BINDING_COOKIE = 'wedge_flow';

    // Security boundary: byte-identical to the authenticator's validation
    // (spec §6.2, wedge's internal/policy) — keep all copies consistent.
    public const CHALLENGE_RE = '/^[A-Za-z0-9_-]{16,256}$/';
    public const REQUEST_ID_RE = '/^[A-Za-z0-9._-]{1,128}$/';

    public const DEFAULT_CHALLENGE_TTL = 180.0; // seconds

    private readonly string $origin;
    /** @var (callable(string): (array<string>|string|null))|null */
    private $findKeys;
    /** @var (callable(string): (array{0: string, 1: array<string>|string}|null))|null */
    private $findUserByPublicKey;

    /**
     * @param string $origin The site's canonical origin exactly as browsers
     *   reach it (https://example.com, http://127.0.0.1:8080). Under the
     *   protocol's namespace==origin rule this string IS the signature
     *   namespace, so it must be configured explicitly — never derived from
     *   a Host header an attacker can influence.
     * @param RequestStore $store SqliteStore for real deployments;
     *   MemoryStore only for tests / resident runtimes.
     * @param (callable(string): (array<string>|string|null))|null $findKeys
     *   username => registered public key line(s). Enables username-carrying
     *   sign-in.
     * @param (callable(string): (array{0: string, 1: array<string>|string}|null))|null $findUserByPublicKey
     *   public key line => [username, keys] for the account that registered
     *   it (compare with Kernel::sameKey; type+data, comments ignored).
     *   Enables keyless sign-in and the app-initiated flow. The posted key
     *   is only ever a selector: verification runs strictly against the keys
     *   you return (spec §5.2).
     */
    public function __construct(
        string $origin,
        private readonly RequestStore $store,
        ?callable $findKeys = null,
        ?callable $findUserByPublicKey = null,
        private readonly float $challengeTtl = self::DEFAULT_CHALLENGE_TTL,
        private readonly float $verifyTimeout = Kernel::DEFAULT_TIMEOUT,
    ) {
        if ($findKeys === null && $findUserByPublicKey === null) {
            throw new \InvalidArgumentException('supply findKeys and/or findUserByPublicKey');
        }
        $this->origin = self::normalizeOrigin($origin);
        $this->findKeys = $findKeys;
        $this->findUserByPublicKey = $findUserByPublicKey;
    }

    // -- origin helpers ------------------------------------------------------

    /**
     * Normalize to scheme://host[:port] (mirrors wedge's
     * policy.NormalizeOrigin and the other ports: explicit ports are kept
     * exactly as written, no path). Throws for anything that isn't a plain
     * http(s) origin.
     */
    public static function normalizeOrigin(string $value): string
    {
        $parts = parse_url(trim($value));
        $scheme = strtolower($parts['scheme'] ?? '');
        $host = strtolower($parts['host'] ?? '');
        if (($scheme !== 'http' && $scheme !== 'https') || $host === '') {
            throw new \InvalidArgumentException("not an http(s) origin: {$value}");
        }
        $origin = "{$scheme}://{$host}";
        if (isset($parts['port'])) {
            $origin .= ':' . $parts['port'];
        }

        return $origin;
    }

    /**
     * The origin plus its localhost↔127.0.0.1 alias with the same scheme and
     * port (spec §6.1; mirrors wedge's policy.EquivalentOrigins).
     *
     * @return array<string>
     */
    public static function equivalentOrigins(string $origin): array
    {
        $origins = [$origin];
        $parts = parse_url($origin);
        $alias = ['localhost' => '127.0.0.1', '127.0.0.1' => 'localhost'][$parts['host'] ?? ''] ?? null;
        if ($alias !== null) {
            $alt = "{$parts['scheme']}://{$alias}";
            if (isset($parts['port'])) {
                $alt .= ':' . $parts['port'];
            }
            $origins[] = $alt;
        }

        return $origins;
    }

    public function origin(): string
    {
        return $this->origin;
    }

    public function usesHttps(): bool
    {
        return str_starts_with($this->origin, 'https://');
    }

    public function challengeTtl(): float
    {
        return $this->challengeTtl;
    }

    /**
     * Whether an Origin/Referer header value matches this site (alias-aware).
     * Adapters should reject browser-facing POSTs that fail this.
     */
    public function isSameOrigin(?string $value): bool
    {
        if ($value === null || $value === '') {
            return false;
        }
        try {
            $candidate = self::normalizeOrigin($value);
        } catch (\InvalidArgumentException) {
            return false;
        }

        return in_array($candidate, self::equivalentOrigins($this->origin), true);
    }

    /** The wedge:// link the browser opens for this request (spec §3). */
    public function signLink(string $requestId): string
    {
        return 'wedge://sign?v=1&origin=' . rawurlencode($this->origin)
            . '&request_id=' . rawurlencode($requestId);
    }

    // -- helpers ---------------------------------------------------------------

    /** n CSPRNG bytes as unpadded base64url (token_urlsafe / base64url shape). */
    private static function token(int $bytes): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    /** Constant-time, length-proof string equality. */
    private static function constantTimeEquals(string $known, string $given): bool
    {
        return hash_equals(hash('sha256', $known, true), hash('sha256', $given, true));
    }

    /** @return array<string, mixed> */
    private function mint(string $username, string $browserNonce, string $claimToken): array
    {
        $record = [
            'requestId' => self::token(18),
            'challenge' => self::token(24),
            'namespace' => $this->origin,
            'username' => $username,
            'browserNonce' => $browserNonce,
            'claimToken' => $claimToken,
            'status' => 'pending',
            'authenticatedUsername' => '',
            'expiresAt' => microtime(true) + $this->challengeTtl,
        ];
        $this->store->put($record);

        return $record;
    }

    /** @return array<string, mixed>|null */
    private function live(mixed $requestId): ?array
    {
        if (!is_string($requestId) || !preg_match(self::REQUEST_ID_RE, $requestId)) {
            return null;
        }

        return $this->store->get($requestId);
    }

    /** @return array{ok: false, error: string} */
    private static function error(string $message): array
    {
        return ['ok' => false, 'error' => $message];
    }

    // -- endpoint handlers --------------------------------------------------------

    /**
     * GET /.well-known/wedge.json (spec §4).
     *
     * @return array<string, mixed>
     */
    public function discovery(): array
    {
        return [
            'version' => 1,
            'namespace' => $this->origin,
            'challenge_url' => $this->origin . self::CHALLENGE_PATH,
            'verify_url' => $this->origin . self::VERIFY_PATH,
        ];
    }

    /**
     * POST /wedge/start (browser-facing; shape is the RP's choice, spec
     * §5.4). null/'' username starts a keyless flow. The returned
     * browserNonce must be set as an HttpOnly cookie — it is the browser
     * binding that later gates session minting.
     *
     * @return array{status: int, body: array<string, mixed>, browserNonce: ?string}
     */
    public function start(?string $username = null): array
    {
        $username ??= '';
        if ($username !== '') {
            if (!preg_match(Kernel::PRINCIPAL_RE, $username)) {
                return ['status' => 400, 'body' => self::error('invalid username'), 'browserNonce' => null];
            }
            if ($this->findKeys === null) {
                return ['status' => 400, 'body' => self::error('username sign-in is not supported'), 'browserNonce' => null];
            }
        } elseif ($this->findUserByPublicKey === null) {
            return ['status' => 400, 'body' => self::error('username required'), 'browserNonce' => null];
        }
        $nonce = self::token(24);
        $record = $this->mint($username, $nonce, '');

        return [
            'status' => 200,
            'body' => [
                'ok' => true,
                'request_id' => $record['requestId'],
                'link' => $this->signLink($record['requestId']),
            ],
            'browserNonce' => $nonce,
        ];
    }

    /**
     * GET <challenge_url>?request_id=… (spec §5.1).
     *
     * @return array{status: int, body: array<string, mixed>}
     */
    public function challenge(mixed $requestId): array
    {
        $record = $this->live($requestId);
        if ($record === null || $record['status'] !== 'pending') {
            return ['status' => 404, 'body' => self::error('unknown request')];
        }

        return [
            'status' => 200,
            'body' => ['challenge' => $record['challenge'], 'namespace' => $record['namespace']],
        ];
    }

    /**
     * POST /wedge/app-start (spec §8.1; path fixed in v1). Rejected with an
     * explanatory error when the host has no keyless account lookup — the RP
     * is then a conforming Core-only implementation (spec §8).
     *
     * @return array{status: int, body: array<string, mixed>}
     */
    public function appStart(): array
    {
        if ($this->findUserByPublicKey === null) {
            return ['status' => 404, 'body' => self::error('app-initiated sign-in is not supported by this site')];
        }
        $claimToken = self::token(24);
        $record = $this->mint('', '', $claimToken);
        $claimUrl = $this->origin . self::CLAIM_PATH
            . '?request_id=' . rawurlencode($record['requestId'])
            . '&claim=' . rawurlencode($claimToken);

        return [
            'status' => 200,
            'body' => [
                'ok' => true,
                'request_id' => $record['requestId'],
                'challenge' => $record['challenge'],
                'namespace' => $record['namespace'],
                'claim_url' => $claimUrl,
            ],
        ];
    }

    /**
     * POST <verify_url> (spec §5.2; cookieless JSON from the authenticator).
     *
     * Verifies against the *stored* challenge and the account's *registered*
     * keys — the echoed challenge field is ignored and a posted public_key is
     * only an account selector. A failed verify consumes nothing, so the
     * authenticator may retry with its next key.
     *
     * @param mixed $body The decoded JSON request body.
     *
     * @return array{status: int, body: array<string, mixed>}
     */
    public function verify(mixed $body): array
    {
        if (!is_array($body)) {
            return ['status' => 400, 'body' => self::error('malformed request body')];
        }
        $record = $this->live($body['request_id'] ?? null);
        if ($record === null || $record['status'] !== 'pending') {
            return ['status' => 404, 'body' => self::error('unknown request')];
        }
        $namespace = $body['namespace'] ?? null;
        if (!is_string($namespace) || !$this->isSameOrigin($namespace)) {
            return ['status' => 400, 'body' => self::error('namespace mismatch')];
        }
        $signature = $body['signature'] ?? null;
        if (!is_string($signature) || !str_starts_with(ltrim($signature), '-----BEGIN SSH SIGNATURE-----')) {
            return ['status' => 400, 'body' => self::error('malformed signature')];
        }

        $resolved = $this->resolveCandidates($record, $body['public_key'] ?? null);
        if (isset($resolved['status'])) {
            return $resolved; // error short-circuit
        }
        [$username, $keys] = $resolved;

        try {
            foreach ($keys as $storedKey) {
                // -n gets the namespace string the authenticator actually
                // signed (it echoes what we minted; alias variants of our
                // origin are equivalent by §6.1 but the bytes must match).
                $outcome = Kernel::verifySignature(
                    $record['challenge'],
                    $signature,
                    $username,
                    $storedKey,
                    $namespace,
                    $this->verifyTimeout,
                );
                if ($outcome['ok']) {
                    if (!$this->store->setAuthenticated($record['requestId'], $username)) {
                        return ['status' => 404, 'body' => self::error('unknown request')];
                    }

                    return ['status' => 200, 'body' => ['ok' => true]];
                }
            }
        } catch (SshKeygenUnavailable $e) {
            return ['status' => 503, 'body' => self::error($e->getMessage())];
        }

        return ['status' => 401, 'body' => self::error('signature verification failed')];
    }

    /**
     * The [username, keys] to verify against, or a {status, body} error.
     *
     * @param array<string, mixed> $record
     *
     * @return array{0: string, 1: array<string>}|array{status: int, body: array<string, mixed>}
     */
    private function resolveCandidates(array $record, mixed $postedKey): array
    {
        if ($record['username'] !== '') {
            $keys = ($this->findKeys)($record['username']);
            if (is_string($keys)) {
                $keys = [$keys];
            }
            if ($keys === null || $keys === []) {
                return ['status' => 401, 'body' => self::error('no account matches')];
            }

            return [$record['username'], array_values($keys)];
        }
        // Keyless: the posted public key is REQUIRED (spec §8.2) and is only
        // a selector — verification runs against the stored keys.
        if (!is_string($postedKey) || Kernel::splitPublicKey($postedKey) === null) {
            return ['status' => 400, 'body' => self::error('public_key required')];
        }
        $match = ($this->findUserByPublicKey)($postedKey);
        if ($match === null) {
            return ['status' => 401, 'body' => self::error('no account matches key')];
        }
        [$username, $keys] = $match;
        if (is_string($keys)) {
            $keys = [$keys];
        }
        if (!is_string($username) || !preg_match(Kernel::PRINCIPAL_RE, $username) || $keys === []) {
            return ['status' => 401, 'body' => self::error('no account matches key')];
        }

        return [$username, array_values($keys)];
    }

    /**
     * GET /wedge/status?request_id=… (browser-facing, spec §5.4). A non-null
     * username means the browser binding checked out and the request was
     * atomically consumed — the adapter must mint the host session NOW (this
     * is the only moment it can).
     *
     * @return array{body: array{status: string}, username: ?string}
     */
    public function status(mixed $requestId, ?string $browserNonce): array
    {
        $record = $this->live($requestId);
        if ($record === null) {
            return ['body' => ['status' => 'expired'], 'username' => null];
        }
        if ($record['browserNonce'] === '') {
            // App-initiated requests complete via /wedge/claim, never polling.
            return ['body' => ['status' => 'pending'], 'username' => null];
        }
        if ($browserNonce === null || $browserNonce === ''
            || !self::constantTimeEquals($record['browserNonce'], $browserNonce)) {
            return ['body' => ['status' => 'pending'], 'username' => null];
        }
        if ($record['status'] !== 'authenticated') {
            return ['body' => ['status' => $record['status']], 'username' => null];
        }
        $taken = $this->store->takeAuthenticated($record['requestId']);
        if ($taken === null || $taken['authenticatedUsername'] === '') {
            return ['body' => ['status' => 'pending'], 'username' => null];
        }

        return ['body' => ['status' => 'authenticated'], 'username' => $taken['authenticatedUsername']];
    }

    /**
     * GET /wedge/claim?request_id=…&claim=… (spec §8.3). Returns the username
     * to mint a session for, or null (adapter redirects to a login or error
     * page — never minting). The record is removed (= the claim is marked
     * used) *before* the username is returned.
     */
    public function claim(mixed $requestId, ?string $claimToken): ?string
    {
        $record = $this->live($requestId);
        if ($record === null
            || $record['claimToken'] === ''
            || $record['status'] !== 'authenticated'
            || $claimToken === null || $claimToken === ''
            || !self::constantTimeEquals($record['claimToken'], $claimToken)) {
            return null;
        }
        $taken = $this->store->takeAuthenticated($record['requestId']);
        if ($taken === null || $taken['authenticatedUsername'] === '') {
            return null;
        }

        return $taken['authenticatedUsername'];
    }
}
