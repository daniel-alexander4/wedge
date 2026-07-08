# wedge-rp — add "Sign in with wedge" to your PHP site

[wedge](https://github.com/daniel-alexander4/wedge) is SSH-key web
authentication: your users sign a per-login challenge with the SSH key already
in their ssh-agent, and your site verifies it the same way `sshd` would — no
passwords, no WebAuthn ceremony, no cloud. This package is the relying-party
(server) side of the [wedge protocol v1](../../docs/wedge-spec-v1.md).

- **Zero runtime dependencies.** `composer.json` requires PHP only; the one
  external requirement is the `ssh-keygen` binary (OpenSSH 8.1+). wedge-rp
  implements no cryptography of its own.
- **PHP ≥8.3.** Framework-neutral engine with three adapters: a vanilla-PHP
  front-controller handler, a PSR-15 middleware, and a Laravel service
  provider (auto-discovered).
- **MIT.**

Two PHP realities are designed in rather than papered over: every request is
its own process, so the request store is a **required constructor argument**
(`SqliteStore` for real deployments — an in-memory default would silently
break under FPM), and there is **no in-engine rate limiter** — bound request
rates at the web server / FPM layer, where PHP actually does that job.

## Add it to a Laravel app (~10 minutes)

```
composer require wedge/wedge-rp
```

The provider is auto-discovered but registers nothing until you bind a
configured engine — do that in `AppServiceProvider::register()`:

```php
use Wedge\Rp\{WedgeRP, SqliteStore, Kernel};

$this->app->singleton(WedgeRP::class, fn () => new WedgeRP(
    origin: config('app.url'),          // your canonical origin — it becomes
    store: new SqliteStore(             // the signature namespace; never
        storage_path('app/wedge.db'),   // derive it from a Host header
    ),
    findKeys: fn (string $u) => User::where('name', $u)->value('ssh_public_key'),
    findUserByPublicKey: function (string $posted) {
        foreach (User::whereNotNull('ssh_public_key')->get() as $user) {
            if (Kernel::sameKey($user->ssh_public_key, $posted)) {
                return [$user->name, [$user->ssh_public_key]];
            }
        }
        return null;
    },
));
$this->app->singleton('wedge.login', fn () => function (string $username, $request) {
    auth()->login(User::where('name', $username)->firstOrFail());
});
```

And on your login page:

```html
<script src="/wedge/wedge.js"></script>
<button id="wedge-btn">Sign in with wedge</button>
<script>Wedge.attach(document.getElementById("wedge-btn"));</script>
```

That's the whole integration. A visitor clicks the button, their wedge app
opens and asks for a tap, and the page reloads signed in. Users who have the
wedge app can also start from the app itself (app-initiated flow) — that
works automatically because you supplied `findUserByPublicKey`.

## Vanilla PHP (~the same 10 minutes)

One call early in your front controller:

```php
use Wedge\Rp\{WedgeRP, SqliteStore, Handler, Kernel};

$rp = new WedgeRP(
    origin: 'https://example.com',
    store: new SqliteStore('/var/lib/myapp/wedge.db'),
    findKeys: fn (string $u) => $users[$u] ?? null,
    findUserByPublicKey: /* Kernel::sameKey scan, as above */,
);

session_start();
if (Handler::handle($rp, [
    'login' => fn (string $username) => $_SESSION['user'] = $username,
    'redirectTo' => '/',
])) {
    return; // a wedge endpoint handled this request
}
```

Runnable version: `examples/demo.php` —

```
WEDGE_DEMO_USERS=you:$HOME/.ssh/id_ed25519.pub \
PHP_CLI_SERVER_WORKERS=4 php -S 127.0.0.1:9414 examples/demo.php
```

Slim/Mezzio pipelines: `new Wedge\Rp\Psr15Middleware($rp, $responseFactory,
['login' => ...])` (needs `psr/http-server-middleware` + a PSR-17 factory —
see composer `suggest`).

## Deployment notes

- **`ssh-keygen` must be on PATH** (package `openssh-client` on
  Debian/Ubuntu); overridable via `SSH_KEYGEN_PATH`. Missing or pre-8.1
  surfaces as a 503 with `SshKeygenUnavailable`. **`proc_open` must be
  enabled** — shared hosting that disables it cannot run an RP at all (the
  protocol *is* `ssh-keygen`). POSIX only; the kernel's pipe handling doesn't
  work on Windows.
- **Multiple hosts behind one origin?** Implement the four-method
  `RequestStore` interface over storage you already share (SQL, Redis); its
  two mutating methods are the single-use guarantees and must stay atomic.
  On a single host, `SqliteStore` covers any number of FPM workers.
- Serve over **HTTPS** in production; the binding cookie is `Secure`
  automatically when your origin is https.

## Registering keys

How users enroll public keys is your application's concern (the protocol
scopes it out, like WebAuthn does). Validate submissions with
`Kernel::splitPublicKey()`; the posted key in a keyless sign-in is only ever
a *selector* — wedge-rp verifies strictly against the keys your callback
returns.

## Tests

```
composer install && composer test
```

The suite signs with a real throwaway ed25519 key via `ssh-keygen -Y sign`,
and the Laravel adapter runs full flows inside a real (testbench) app. The
conformance tests in `tests/WedgeRPTest.php` are a test-for-test port of the
Python, Node, and Go packages' — keep the four suites in lockstep.
