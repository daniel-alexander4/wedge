<?php

declare(strict_types=1);

namespace Wedge\Rp\Tests;

/**
 * Spec-conformance tests for the WedgeRP engine — a test-for-test port of
 * sdk/python/tests/test_core.py, sdk/node/tests/core.test.js, and
 * sdk/go/wedgerp/wedgerp_test.go (keep the four suites in lockstep). Each
 * test names the wedge-spec-v1.md requirement it pins down; signatures are
 * real SSHSIG made by ssh-keygen.
 */

use PHPUnit\Framework\TestCase;
use Wedge\Rp\Kernel;
use Wedge\Rp\MemoryStore;
use Wedge\Rp\WedgeRP;

final class WedgeRPTest extends TestCase
{
    private const ORIGIN = 'http://127.0.0.1:9414';

    private static ?KeyPair $alice = null;
    private static ?KeyPair $mallory = null;

    public static function setUpBeforeClass(): void
    {
        if (!KeyPair::available()) {
            self::markTestSkipped('ssh-keygen not installed');
        }
        self::$alice = new KeyPair('alice@test');
        self::$mallory = new KeyPair('mallory@test');
    }

    public static function tearDownAfterClass(): void
    {
        self::$alice?->cleanup();
        self::$mallory?->cleanup();
    }

    private function makeRP(array $overrides = []): WedgeRP
    {
        $users = ['alice' => self::$alice->publicKey];
        $args = array_merge([
            'origin' => self::ORIGIN,
            'store' => new MemoryStore(),
            'findKeys' => fn (string $u) => $users[$u] ?? null,
            'findUserByPublicKey' => function (string $posted) use ($users) {
                foreach ($users as $name => $key) {
                    if (Kernel::sameKey($key, $posted)) {
                        return [$name, [$key]];
                    }
                }

                return null;
            },
        ], $overrides);

        return new WedgeRP(
            origin: $args['origin'],
            store: $args['store'],
            findKeys: $args['findKeys'],
            findUserByPublicKey: $args['findUserByPublicKey'],
            challengeTtl: $args['challengeTtl'] ?? WedgeRP::DEFAULT_CHALLENGE_TTL,
            registrationUrl: $args['registrationUrl'] ?? null,
        );
    }

    /** @return array{0: string, 1: string, 2: string} [requestId, challenge, nonce] */
    private function startAndFetch(WedgeRP $rp, ?string $username = null): array
    {
        $started = $rp->start($username);
        $this->assertSame(200, $started['status']);
        $rid = $started['body']['request_id'];
        $ch = $rp->challenge($rid);
        $this->assertSame(200, $ch['status']);

        return [$rid, $ch['body']['challenge'], $started['browserNonce']];
    }

    /** @return array<string, string> */
    private function verifyBody(string $rid, string $challenge, ?KeyPair $key = null, string $namespace = self::ORIGIN): array
    {
        $signer = $key ?? self::$alice;

        return [
            'request_id' => $rid,
            'challenge' => $challenge,
            'namespace' => $namespace,
            'signature' => $signer->sign($challenge, $namespace),
            'public_key' => $signer->publicKey,
        ];
    }

    // -- discovery (§4) + link (§3) ------------------------------------------------

    public function testDiscoveryDocument(): void
    {
        $doc = $this->makeRP()->discovery();
        $this->assertSame(1, $doc['version']);
        $this->assertSame(self::ORIGIN, $doc['namespace']); // namespace == canonical origin (§6.1)
        $this->assertSame(self::ORIGIN . '/wedge/challenge', $doc['challenge_url']);
        $this->assertSame(self::ORIGIN . '/wedge/verify', $doc['verify_url']);
        $this->assertArrayNotHasKey('registration_url', $doc); // OPTIONAL — absent unless configured
    }

    public function testDiscoveryRegistrationUrl(): void
    {
        $doc = $this->makeRP(['registrationUrl' => self::ORIGIN . '/register'])->discovery();
        $this->assertSame(self::ORIGIN . '/register', $doc['registration_url']);
        // Must be same-origin with the site (spec §4) — a foreign URL is a
        // configuration error, rejected at construction.
        $this->expectException(\InvalidArgumentException::class);
        $this->makeRP(['registrationUrl' => 'https://evil.example/register']);
    }

    public function testSignLinkFormat(): void
    {
        $started = $this->makeRP()->start();
        $rid = $started['body']['request_id'];
        $this->assertSame(
            'wedge://sign?v=1&origin=http%3A%2F%2F127.0.0.1%3A9414&request_id=' . $rid,
            $started['body']['link'],
        );
    }

    // -- start ----------------------------------------------------------------------

    public function testKeylessStartNeedsSelectorCallback(): void
    {
        $rp = $this->makeRP(['findUserByPublicKey' => null]);
        $started = $rp->start();
        $this->assertSame(400, $started['status']);
        $this->assertNull($started['browserNonce']);
    }

    public function testUsernameStartNeedsFindKeys(): void
    {
        $rp = $this->makeRP(['findKeys' => null]);
        $this->assertSame(400, $rp->start('alice')['status']);
    }

    // -- challenge (§5.1, §6.2) --------------------------------------------------------

    public function testChallengeUnknownRequest(): void
    {
        $this->assertSame(404, $this->makeRP()->challenge('nope')['status']);
    }

    public function testChallengeFormat(): void
    {
        [, $challenge] = $this->startAndFetch($this->makeRP(), 'alice');
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{16,256}$/', $challenge);
    }

    public function testChallengeGoneAfterAuthentication(): void
    {
        $rp = $this->makeRP();
        [$rid, $challenge] = $this->startAndFetch($rp, 'alice');
        $this->assertSame(200, $rp->verify($this->verifyBody($rid, $challenge))['status']);
        $this->assertSame(404, $rp->challenge($rid)['status']); // used → 404 (§5.1)
    }

    // -- verify (§5.2) --------------------------------------------------------------------

    public function testVerifyHappyPathUsernameFlow(): void
    {
        $rp = $this->makeRP();
        [$rid, $challenge] = $this->startAndFetch($rp, 'alice');
        $result = $rp->verify($this->verifyBody($rid, $challenge));
        $this->assertSame(200, $result['status']);
        $this->assertSame(['ok' => true], $result['body']);
    }

    public function testVerifyUnknownRequest(): void
    {
        $rp = $this->makeRP();
        [, $challenge] = $this->startAndFetch($rp, 'alice');
        $this->assertSame(404, $rp->verify($this->verifyBody('unknown-id', $challenge))['status']);
    }

    public function testVerifyChecksStoredChallengeNotEcho(): void
    {
        // RP MUST verify against the challenge it stored, never the echoed
        // field (§5.2 item 2) — a wrong echo with a good signature still passes.
        $rp = $this->makeRP();
        [$rid, $challenge] = $this->startAndFetch($rp, 'alice');
        $body = $this->verifyBody($rid, $challenge);
        $body['challenge'] = 'Definitely_Not_The_Challenge';
        $this->assertSame(200, $rp->verify($body)['status']);
    }

    public function testVerifyRejectsSignatureOverWrongChallenge(): void
    {
        $rp = $this->makeRP();
        [$rid] = $this->startAndFetch($rp, 'alice');
        $body = $this->verifyBody($rid, 'NotTheMintedChallenge123'); // signature over wrong bytes
        $this->assertSame(401, $rp->verify($body)['status']);
    }

    public function testVerifyNamespaceMismatch(): void
    {
        $rp = $this->makeRP();
        [$rid, $challenge] = $this->startAndFetch($rp, 'alice');
        $result = $rp->verify($this->verifyBody($rid, $challenge, namespace: 'http://evil.example'));
        $this->assertSame(400, $result['status']);
        $this->assertSame('namespace mismatch', $result['body']['error']);
    }

    public function testVerifyAcceptsLocalhostAliasNamespace(): void
    {
        // localhost ↔ 127.0.0.1 with same scheme/port are equivalent (§6.1);
        // -n must get the alias string the authenticator actually signed.
        $rp = $this->makeRP();
        [$rid, $challenge] = $this->startAndFetch($rp, 'alice');
        $body = $this->verifyBody($rid, $challenge, namespace: 'http://localhost:9414');
        $this->assertSame(200, $rp->verify($body)['status']);
    }

    public function testFailedVerifyConsumesNothing(): void
    {
        // A failed verify MUST NOT consume the challenge or request (§5.2) —
        // the authenticator's try-next-key depends on it.
        $rp = $this->makeRP();
        [$rid, $challenge] = $this->startAndFetch($rp, 'alice');
        $bad = $this->verifyBody($rid, $challenge, self::$mallory);
        unset($bad['public_key']); // username-carrying flow resolves the account's keys
        $this->assertSame(401, $rp->verify($bad)['status']);
        $this->assertSame(200, $rp->verify($this->verifyBody($rid, $challenge))['status']);
    }

    public function testRequestSingleUseAtVerify(): void
    {
        $rp = $this->makeRP();
        [$rid, $challenge] = $this->startAndFetch($rp, 'alice');
        $good = $this->verifyBody($rid, $challenge);
        $this->assertSame(200, $rp->verify($good)['status']);
        $this->assertSame(404, $rp->verify($good)['status']); // replay of the same verify
    }

    public function testKeylessVerifyRequiresPublicKey(): void
    {
        // public_key is REQUIRED when the pending request carries no username
        // (§8.2) — it is the account selector.
        $rp = $this->makeRP();
        [$rid, $challenge] = $this->startAndFetch($rp);
        $body = $this->verifyBody($rid, $challenge);
        unset($body['public_key']);
        $result = $rp->verify($body);
        $this->assertSame(400, $result['status']);
        $this->assertSame('public_key required', $result['body']['error']);
    }

    public function testPostedKeyIsSelectorOnly(): void
    {
        // Posting alice's public key with mallory's signature MUST fail:
        // verification runs against the stored key, never the posted one (§5.2).
        $rp = $this->makeRP();
        [$rid, $challenge] = $this->startAndFetch($rp);
        $body = $this->verifyBody($rid, $challenge, self::$mallory);
        $body['public_key'] = self::$alice->publicKey;
        $this->assertSame(401, $rp->verify($body)['status']);
    }

    public function testUnregisteredKeyNoAccount(): void
    {
        $rp = $this->makeRP();
        [$rid, $challenge] = $this->startAndFetch($rp);
        $result = $rp->verify($this->verifyBody($rid, $challenge, self::$mallory));
        $this->assertSame(401, $result['status']);
        $this->assertSame('no account matches key', $result['body']['error']);
        $this->assertSame('unknown_key', $result['body']['code']); // machine-readable (§5.2)
    }

    public function testSignatureFailureCarriesNoCode(): void
    {
        // unknown_key marks "no account for this key" only — a bad signature
        // against a *registered* key MUST NOT carry it (§5.2).
        $rp = $this->makeRP();
        [$rid, $challenge] = $this->startAndFetch($rp);
        $body = $this->verifyBody($rid, $challenge, self::$mallory);
        $body['public_key'] = self::$alice->publicKey;
        $result = $rp->verify($body);
        $this->assertSame(401, $result['status']);
        $this->assertArrayNotHasKey('code', $result['body']);
    }

    // -- status + browser binding (§5.4) -------------------------------------------------

    public function testStatusRequiresBrowserBinding(): void
    {
        // Only the initiating browser (nonce bearer) can convert an
        // authenticated request into a session; everyone else sees pending.
        $rp = $this->makeRP();
        [$rid, $challenge, $nonce] = $this->startAndFetch($rp, 'alice');
        $rp->verify($this->verifyBody($rid, $challenge));
        $this->assertSame(['body' => ['status' => 'pending'], 'username' => null], $rp->status($rid, null));
        $this->assertSame(['body' => ['status' => 'pending'], 'username' => null], $rp->status($rid, 'wrong-nonce'));
        $this->assertSame(['body' => ['status' => 'authenticated'], 'username' => 'alice'], $rp->status($rid, $nonce));
    }

    public function testStatusSingleUse(): void
    {
        $rp = $this->makeRP();
        [$rid, $challenge, $nonce] = $this->startAndFetch($rp, 'alice');
        $rp->verify($this->verifyBody($rid, $challenge));
        $this->assertSame('alice', $rp->status($rid, $nonce)['username']);
        $this->assertSame(['body' => ['status' => 'expired'], 'username' => null], $rp->status($rid, $nonce));
    }

    public function testStatusPendingAndExpired(): void
    {
        $rp = $this->makeRP();
        [$rid, , $nonce] = $this->startAndFetch($rp, 'alice');
        $this->assertSame(['body' => ['status' => 'pending'], 'username' => null], $rp->status($rid, $nonce));
        $this->assertSame(['body' => ['status' => 'expired'], 'username' => null], $rp->status('unknown', $nonce));
    }

    public function testTtlExpiry(): void
    {
        $rp = $this->makeRP(['challengeTtl' => 0.05]);
        [$rid, $challenge, $nonce] = $this->startAndFetch($rp, 'alice');
        usleep(100_000);
        $this->assertSame(404, $rp->challenge($rid)['status']);
        $this->assertSame(404, $rp->verify($this->verifyBody($rid, $challenge))['status']);
        $this->assertSame('expired', $rp->status($rid, $nonce)['body']['status']);
    }

    // -- app-initiated flow (§8) --------------------------------------------------------------

    /** @return array<string, mixed> the app-start body after a successful verify */
    private function appStartAndVerify(WedgeRP $rp): array
    {
        $started = $rp->appStart();
        $this->assertSame(200, $started['status']);
        $body = $started['body'];
        $verify = $this->verifyBody($body['request_id'], $body['challenge']);
        $this->assertSame(200, $rp->verify($verify)['status']);

        return $body;
    }

    private static function claimTokenOf(string $claimUrl): string
    {
        parse_str((string) parse_url($claimUrl, PHP_URL_QUERY), $query);

        return $query['claim'];
    }

    public function testAppStartResponseShape(): void
    {
        $started = $this->makeRP()->appStart();
        $this->assertSame(200, $started['status']);
        $body = $started['body'];
        $this->assertTrue($body['ok']);
        $this->assertSame(self::ORIGIN, $body['namespace']);
        $this->assertStringStartsWith(self::ORIGIN . '/wedge/claim?', $body['claim_url']);
        $this->assertStringContainsString($body['request_id'], $body['claim_url']);
    }

    public function testAppStartRejectedWithoutSelector(): void
    {
        // RPs that need a pre-asserted username MUST reject app-start with an
        // explanatory error (§8.1); Core-only remains conforming (§8).
        $rp = $this->makeRP(['findUserByPublicKey' => null]);
        $started = $rp->appStart();
        $this->assertSame(404, $started['status']);
        $this->assertStringContainsString('not supported', $started['body']['error']);
    }

    public function testClaimHappyPathSingleUse(): void
    {
        $rp = $this->makeRP();
        $body = $this->appStartAndVerify($rp);
        $token = self::claimTokenOf($body['claim_url']);
        $this->assertSame('alice', $rp->claim($body['request_id'], $token));
        $this->assertNull($rp->claim($body['request_id'], $token)); // single-use (§8.3)
    }

    public function testClaimRejectsWrongTokenAndUnauthenticated(): void
    {
        $rp = $this->makeRP();
        $fresh = $rp->appStart()['body'];
        $this->assertNull($rp->claim($fresh['request_id'], self::claimTokenOf($fresh['claim_url']))); // not yet authenticated
        $done = $this->appStartAndVerify($rp);
        $this->assertNull($rp->claim($done['request_id'], 'wrong-token'));
        $this->assertSame('alice', $rp->claim($done['request_id'], self::claimTokenOf($done['claim_url'])));
    }

    public function testAppRequestNotPollableViaStatus(): void
    {
        // App-initiated requests have no browser binding; polling must never
        // mint (§8: the claim token is the substitute for the binding).
        $rp = $this->makeRP();
        $body = $this->appStartAndVerify($rp);
        $this->assertSame(['body' => ['status' => 'pending'], 'username' => null], $rp->status($body['request_id'], 'anything'));
    }

    // -- construction --------------------------------------------------------------------------

    public function testRequiresALookupCallback(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new WedgeRP(origin: self::ORIGIN, store: new MemoryStore());
    }

    public function testRejectsNonOrigin(): void
    {
        foreach (['ftp://x', 'not a url', ''] as $origin) {
            try {
                new WedgeRP(origin: $origin, store: new MemoryStore(), findKeys: fn () => null);
                $this->fail("origin {$origin} accepted");
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    // -- PHP-specific additions --------------------------------------------------------------

    public function testNormalizeOriginPreservesExplicitDefaultPorts(): void
    {
        // spec §6.1: no default-port elision.
        $this->assertSame('http://example.com:80', WedgeRP::normalizeOrigin('http://example.com:80'));
        $this->assertSame('https://example.com:443', WedgeRP::normalizeOrigin('https://example.com:443/'));
        $this->assertSame('http://example.com:8080', WedgeRP::normalizeOrigin('http://Example.com:8080/path'));
        $this->assertSame('http://example.com', WedgeRP::normalizeOrigin('http://example.com'));
    }
}
