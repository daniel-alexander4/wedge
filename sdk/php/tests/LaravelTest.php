<?php

declare(strict_types=1);

namespace Wedge\Rp\Tests;

use Illuminate\Http\Request;
use Orchestra\Testbench\TestCase;
use Wedge\Rp\Kernel;
use Wedge\Rp\Laravel\WedgeServiceProvider;
use Wedge\Rp\MemoryStore;
use Wedge\Rp\WedgeRP;

/**
 * The Laravel adapter exercised inside a real (testbench) application: full
 * core flow and app-initiated claim flow over the provider's routes.
 */
final class LaravelTest extends TestCase
{
    private const ORIGIN = 'http://127.0.0.1:9414';

    private static ?KeyPair $alice = null;

    /** @var array<string> */
    public static array $logins = [];

    public static function setUpBeforeClass(): void
    {
        if (!KeyPair::available()) {
            self::markTestSkipped('ssh-keygen not installed');
        }
        self::$alice = new KeyPair('alice@test');
    }

    public static function tearDownAfterClass(): void
    {
        self::$alice?->cleanup();
    }

    protected function setUp(): void
    {
        self::$logins = [];
        parent::setUp();
    }

    protected function getPackageProviders($app): array
    {
        return [WedgeServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $users = ['alice' => self::$alice->publicKey];
        $app->singleton(WedgeRP::class, fn () => new WedgeRP(
            origin: self::ORIGIN,
            store: new MemoryStore(),
            findKeys: fn (string $u) => $users[$u] ?? null,
            findUserByPublicKey: function (string $posted) use ($users) {
                foreach ($users as $name => $key) {
                    if (Kernel::sameKey($key, $posted)) {
                        return [$name, [$key]];
                    }
                }

                return null;
            },
        ));
        $app->singleton('wedge.login', fn () => function (string $username, Request $r): void {
            self::$logins[] = $username;
        });
        $app['config']->set('wedge.redirect_to', '/home');
        $app['config']->set('wedge.failure_redirect', '/login');
    }

    public function testDiscoveryServed(): void
    {
        $this->getJson(WedgeRP::DISCOVERY_PATH)
            ->assertOk()
            ->assertJson(['version' => 1, 'namespace' => self::ORIGIN]);
    }

    public function testCoreFlowMintsSessionForBoundBrowser(): void
    {
        $start = $this->postJson(WedgeRP::START_PATH, ['username' => 'alice']);
        $start->assertOk();
        $rid = $start->json('request_id');
        $nonce = $start->getCookie(WedgeRP::BINDING_COOKIE, decrypt: false)->getValue();
        $this->assertNotSame('', $nonce);

        $challenge = $this->getJson(WedgeRP::CHALLENGE_PATH . '?request_id=' . $rid)->json('challenge');
        $this->postJson(WedgeRP::VERIFY_PATH, [
            'request_id' => $rid,
            'challenge' => $challenge,
            'namespace' => self::ORIGIN,
            'signature' => self::$alice->sign($challenge, self::ORIGIN),
        ])->assertOk()->assertJson(['ok' => true]);

        // Unbound browser (no cookie) must stay pending and mint nothing.
        $this->getJson(WedgeRP::STATUS_PATH . '?request_id=' . $rid)
            ->assertOk()->assertJson(['status' => 'pending']);
        $this->assertSame([], self::$logins);

        // The bound browser converts it exactly once. (withCredentials():
        // Laravel's json() test helpers drop cookies without it.)
        $this->withCredentials()->withUnencryptedCookie(WedgeRP::BINDING_COOKIE, $nonce)
            ->getJson(WedgeRP::STATUS_PATH . '?request_id=' . $rid)
            ->assertOk()->assertJson(['status' => 'authenticated', 'redirect' => '/home']);
        $this->assertSame(['alice'], self::$logins);

        $this->withCredentials()->withUnencryptedCookie(WedgeRP::BINDING_COOKIE, $nonce)
            ->getJson(WedgeRP::STATUS_PATH . '?request_id=' . $rid)
            ->assertJson(['status' => 'expired']);
        $this->assertSame(['alice'], self::$logins);
    }

    public function testAppInitiatedClaimFlowSingleUse(): void
    {
        $started = $this->postJson(WedgeRP::APP_START_PATH, []);
        $started->assertOk();
        $this->postJson(WedgeRP::VERIFY_PATH, [
            'request_id' => $started->json('request_id'),
            'challenge' => $started->json('challenge'),
            'namespace' => $started->json('namespace'),
            'signature' => self::$alice->sign($started->json('challenge'), $started->json('namespace')),
            'public_key' => self::$alice->publicKey,
        ])->assertOk();

        $claimPath = substr($started->json('claim_url'), strlen(self::ORIGIN));
        $claim = $this->get($claimPath);
        $claim->assertStatus(303);
        $claim->assertRedirect('/home');
        $claim->assertHeader('Referrer-Policy', 'no-referrer');
        $this->assertSame(['alice'], self::$logins);

        // Single-use: the same claim URL never mints twice.
        $this->get($claimPath)->assertRedirect('/login');
        $this->assertSame(['alice'], self::$logins);
    }

    public function testCrossOriginStartRejected(): void
    {
        $this->postJson(WedgeRP::START_PATH, [], ['Origin' => 'http://evil.example'])
            ->assertStatus(403);
    }

    public function testWedgeJsServed(): void
    {
        $response = $this->get(WedgeRP::SCRIPT_PATH);
        $response->assertOk();
        $this->assertStringContainsString('window.Wedge', $response->getContent());
    }

}
