<?php

declare(strict_types=1);

namespace Wedge\Rp\Laravel;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Wedge\Rp\WedgeRP;

/**
 * Laravel adapter, wired through package auto-discovery. Activate it by
 * binding a configured WedgeRP in a provider of your app:
 *
 *     $this->app->singleton(WedgeRP::class, fn () => new WedgeRP(
 *         origin: config('app.url'),
 *         store: new SqliteStore(storage_path('app/wedge.db')),
 *         findKeys: fn (string $u) => User::where('name', $u)->value('ssh_public_key'),
 *         findUserByPublicKey: ...,
 *     ));
 *     $this->app->singleton('wedge.login', fn () => fn (string $username, Request $r) =>
 *         auth()->login(User::where('name', $username)->firstOrFail()));
 *
 * The provider registers nothing until WedgeRP is bound, so merely installing
 * the package changes no behavior.
 */
final class WedgeServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        if (!$this->app->bound(WedgeRP::class)) {
            return;
        }
        $rp = $this->app->make(WedgeRP::class);
        $login = $this->app->bound('wedge.login') ? $this->app->make('wedge.login') : null;
        if ($login === null) {
            throw new \RuntimeException("bind 'wedge.login' (fn (string \$username, Request \$r): void) alongside WedgeRP");
        }
        $redirectTo = config('wedge.redirect_to', '/');
        $failureRedirect = config('wedge.failure_redirect', '/');

        // Deliberately NO middleware group: the authenticator posts without
        // CSRF tokens (spec §5.2 is cookieless), and the binding cookie must
        // round-trip raw — outside EncryptCookies both set and read are
        // consistent.
        Route::group([], function () use ($rp, $login, $redirectTo, $failureRedirect): void {
            Route::get(WedgeRP::DISCOVERY_PATH, fn () => response()->json($rp->discovery()));

            Route::post(WedgeRP::START_PATH, function (Request $request) use ($rp) {
                $originHeader = $request->header('Origin', '');
                if ($originHeader !== '' && !$rp->isSameOrigin($originHeader)) {
                    return response()->json(['ok' => false, 'error' => 'cross-origin request'], 403);
                }
                $result = $rp->start($request->json('username'));
                $response = response()->json($result['body'], $result['status']);
                if ($result['browserNonce'] !== null) {
                    $response->withCookie(cookie(
                        name: WedgeRP::BINDING_COOKIE,
                        value: $result['browserNonce'],
                        minutes: (int) ceil($rp->challengeTtl() / 60),
                        path: '/',
                        secure: $rp->usesHttps(),
                        httpOnly: true,
                        sameSite: 'strict',
                    ));
                }

                return $response;
            });

            Route::get(WedgeRP::CHALLENGE_PATH, function (Request $request) use ($rp) {
                $result = $rp->challenge($request->query('request_id'));

                return response()->json($result['body'], $result['status']);
            });

            Route::post(WedgeRP::VERIFY_PATH, function (Request $request) use ($rp) {
                $result = $rp->verify($request->json()->all());

                return response()->json($result['body'], $result['status']);
            });

            Route::get(WedgeRP::STATUS_PATH, function (Request $request) use ($rp, $login, $redirectTo) {
                $result = $rp->status(
                    $request->query('request_id'),
                    $request->cookie(WedgeRP::BINDING_COOKIE),
                );
                $body = $result['body'];
                if ($result['username'] !== null) {
                    $login($result['username'], $request);
                    $body['redirect'] = is_callable($redirectTo) ? $redirectTo($result['username']) : $redirectTo;
                }

                return response()->json($body);
            });

            Route::post(WedgeRP::APP_START_PATH, function () use ($rp) {
                $result = $rp->appStart();

                return response()->json($result['body'], $result['status']);
            });

            Route::get(WedgeRP::CLAIM_PATH, function (Request $request) use ($rp, $login, $redirectTo, $failureRedirect) {
                $username = $rp->claim($request->query('request_id'), $request->query('claim'));
                if ($username === null) {
                    return redirect($failureRedirect, 303)->header('Referrer-Policy', 'no-referrer');
                }
                $login($username, $request);
                $landing = is_callable($redirectTo) ? $redirectTo($username) : $redirectTo;

                return redirect($landing, 303)->header('Referrer-Policy', 'no-referrer');
            });

            Route::get(WedgeRP::SCRIPT_PATH, fn () => response(
                file_get_contents(__DIR__ . '/../../wedge.js'),
                200,
                ['Content-Type' => 'text/javascript; charset=utf-8'],
            ));
        });
    }
}
