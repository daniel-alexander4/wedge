<?php

declare(strict_types=1);

namespace Wedge\Rp;

/**
 * Vanilla-PHP adapter — one call in your front controller:
 *
 *     if (Wedge\Rp\Handler::handle($rp, [
 *         'login' => fn (string $username) => $_SESSION['user'] = $username,
 *         'redirectTo' => '/',
 *     ])) {
 *         return; // a wedge endpoint handled the request
 *     }
 *
 * Reads superglobals, emits via header()/echo, and returns whether the
 * request was one of the wedge endpoints. Options:
 *   login           — REQUIRED. callable(string $username): void, called at
 *                     the one moment a session may be minted. Establish your
 *                     app's session here and nothing else (session_start()
 *                     before calling handle() if you use $_SESSION).
 *   redirectTo      — path (or callable(string $username): string) the
 *                     browser lands on after sign-in. Default '/'.
 *   failureRedirect — where /wedge/claim sends the browser when a claim is
 *                     invalid (it never mints a session on failure).
 *                     Default '/'.
 */
final class Handler
{
    /** @param array{login: callable, redirectTo?: string|callable, failureRedirect?: string} $options */
    public static function handle(WedgeRP $rp, array $options): bool
    {
        $login = $options['login'] ?? null;
        if (!is_callable($login)) {
            throw new \InvalidArgumentException('Handler needs a login callable');
        }
        $redirectTo = $options['redirectTo'] ?? '/';
        $failureRedirect = $options['failureRedirect'] ?? '/';
        $landing = static fn (string $username): string => is_callable($redirectTo) ? $redirectTo($username) : $redirectTo;

        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';

        $json = static function (int $status, array $body): void {
            http_response_code($status);
            header('Content-Type: application/json');
            echo json_encode($body);
        };

        switch ("{$method} {$path}") {
            case 'GET ' . WedgeRP::DISCOVERY_PATH:
                $json(200, $rp->discovery());

                return true;

            case 'POST ' . WedgeRP::START_PATH:
                // Browser-facing POST: reject cross-site initiations outright.
                $originHeader = $_SERVER['HTTP_ORIGIN'] ?? '';
                if ($originHeader !== '' && !$rp->isSameOrigin($originHeader)) {
                    $json(403, ['ok' => false, 'error' => 'cross-origin request']);

                    return true;
                }
                $body = json_decode(file_get_contents('php://input') ?: '{}', true);
                $username = is_array($body) && is_string($body['username'] ?? null) ? $body['username'] : null;
                $result = $rp->start($username);
                if ($result['browserNonce'] !== null) {
                    setcookie(WedgeRP::BINDING_COOKIE, $result['browserNonce'], [
                        'expires' => time() + (int) $rp->challengeTtl(),
                        'path' => '/',
                        'httponly' => true,
                        'samesite' => 'Strict',
                        'secure' => $rp->usesHttps(),
                    ]);
                }
                $json($result['status'], $result['body']);

                return true;

            case 'GET ' . WedgeRP::CHALLENGE_PATH:
                $result = $rp->challenge($_GET['request_id'] ?? null);
                $json($result['status'], $result['body']);

                return true;

            case 'POST ' . WedgeRP::VERIFY_PATH:
                // Authenticator-facing: cookieless JSON (spec §5.2).
                $body = json_decode(file_get_contents('php://input') ?: '', true);
                $result = $rp->verify($body);
                $json($result['status'], $result['body']);

                return true;

            case 'GET ' . WedgeRP::STATUS_PATH:
                $result = $rp->status($_GET['request_id'] ?? null, $_COOKIE[WedgeRP::BINDING_COOKIE] ?? null);
                $body = $result['body'];
                if ($result['username'] !== null) {
                    $login($result['username']);
                    $body['redirect'] = $landing($result['username']);
                }
                $json(200, $body);

                return true;

            case 'POST ' . WedgeRP::APP_START_PATH:
                $result = $rp->appStart();
                $json($result['status'], $result['body']);

                return true;

            case 'GET ' . WedgeRP::CLAIM_PATH:
                // The claim URL is a bearer secret: never let it leak via
                // Referer, never render it into page content (spec §8.3) —
                // redirect-only.
                header('Referrer-Policy: no-referrer');
                $username = $rp->claim($_GET['request_id'] ?? null, is_string($_GET['claim'] ?? null) ? $_GET['claim'] : null);
                if ($username === null) {
                    http_response_code(303);
                    header('Location: ' . $failureRedirect);

                    return true;
                }
                $login($username);
                http_response_code(303);
                header('Location: ' . $landing($username));

                return true;

            case 'GET ' . WedgeRP::SCRIPT_PATH:
                header('Content-Type: text/javascript; charset=utf-8');
                readfile(__DIR__ . '/../wedge.js');

                return true;
        }

        return false;
    }
}
