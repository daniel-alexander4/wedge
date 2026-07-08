<?php

declare(strict_types=1);

namespace Wedge\Rp;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 adapter for Slim/Mezzio-style pipelines. Requires the host app to
 * have psr/http-server-middleware + a PSR-17 response factory installed (see
 * composer.json "suggest") — this class is only autoloaded when you use it.
 *
 *     $app->add(new Wedge\Rp\Psr15Middleware($rp, $responseFactory, [
 *         'login' => fn (string $username) => $_SESSION['user'] = $username,
 *         'redirectTo' => '/',
 *     ]));
 */
final class Psr15Middleware implements MiddlewareInterface
{
    /** @param array{login: callable, redirectTo?: string|callable, failureRedirect?: string} $options */
    public function __construct(
        private readonly WedgeRP $rp,
        private readonly ResponseFactoryInterface $responses,
        private readonly array $options,
    ) {
        if (!is_callable($options['login'] ?? null)) {
            throw new \InvalidArgumentException('Psr15Middleware needs a login callable');
        }
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $rp = $this->rp;
        $login = $this->options['login'];
        $redirectTo = $this->options['redirectTo'] ?? '/';
        $failureRedirect = $this->options['failureRedirect'] ?? '/';
        $landing = static fn (string $u): string => is_callable($redirectTo) ? $redirectTo($u) : $redirectTo;

        $method = $request->getMethod();
        $path = $request->getUri()->getPath();
        $query = $request->getQueryParams();
        $cookies = $request->getCookieParams();

        $json = function (int $status, array $body, array $headers = []): ResponseInterface {
            $response = $this->responses->createResponse($status)
                ->withHeader('Content-Type', 'application/json');
            foreach ($headers as $name => $value) {
                $response = $response->withHeader($name, $value);
            }
            $response->getBody()->write((string) json_encode($body));

            return $response;
        };
        $redirect = function (string $location): ResponseInterface {
            return $this->responses->createResponse(303)
                ->withHeader('Location', $location)
                ->withHeader('Referrer-Policy', 'no-referrer');
        };

        switch ("{$method} {$path}") {
            case 'GET ' . WedgeRP::DISCOVERY_PATH:
                return $json(200, $rp->discovery());

            case 'POST ' . WedgeRP::START_PATH:
                $originHeader = $request->getHeaderLine('Origin');
                if ($originHeader !== '' && !$rp->isSameOrigin($originHeader)) {
                    return $json(403, ['ok' => false, 'error' => 'cross-origin request']);
                }
                $body = json_decode((string) $request->getBody(), true);
                $username = is_array($body) && is_string($body['username'] ?? null) ? $body['username'] : null;
                $result = $rp->start($username);
                $headers = [];
                if ($result['browserNonce'] !== null) {
                    $headers['Set-Cookie'] = sprintf(
                        '%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict%s',
                        WedgeRP::BINDING_COOKIE,
                        $result['browserNonce'],
                        (int) $rp->challengeTtl(),
                        $rp->usesHttps() ? '; Secure' : '',
                    );
                }

                return $json($result['status'], $result['body'], $headers);

            case 'GET ' . WedgeRP::CHALLENGE_PATH:
                $result = $rp->challenge($query['request_id'] ?? null);

                return $json($result['status'], $result['body']);

            case 'POST ' . WedgeRP::VERIFY_PATH:
                $result = $rp->verify(json_decode((string) $request->getBody(), true));

                return $json($result['status'], $result['body']);

            case 'GET ' . WedgeRP::STATUS_PATH:
                $result = $rp->status($query['request_id'] ?? null, $cookies[WedgeRP::BINDING_COOKIE] ?? null);
                $body = $result['body'];
                if ($result['username'] !== null) {
                    $login($result['username']);
                    $body['redirect'] = $landing($result['username']);
                }

                return $json(200, $body);

            case 'POST ' . WedgeRP::APP_START_PATH:
                $result = $rp->appStart();

                return $json($result['status'], $result['body']);

            case 'GET ' . WedgeRP::CLAIM_PATH:
                $username = $rp->claim(
                    $query['request_id'] ?? null,
                    is_string($query['claim'] ?? null) ? $query['claim'] : null,
                );
                if ($username === null) {
                    return $redirect($failureRedirect);
                }
                $login($username);

                return $redirect($landing($username));

            case 'GET ' . WedgeRP::SCRIPT_PATH:
                $response = $this->responses->createResponse(200)
                    ->withHeader('Content-Type', 'text/javascript; charset=utf-8');
                $response->getBody()->write((string) file_get_contents(__DIR__ . '/../wedge.js'));

                return $response;
        }

        return $handler->handle($request);
    }
}
