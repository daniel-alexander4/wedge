<?php

declare(strict_types=1);

/**
 * Minimal wedge relying party — vanilla PHP, the Handler integration pattern,
 * and the e2e harness for the wedge-rp test drive. Run under the built-in
 * server; multiple workers prove the shared SqliteStore across processes:
 *
 *   WEDGE_DEMO_USERS=dan:$HOME/.ssh/id_ed25519.pub \
 *   WEDGE_DEMO_DB=/tmp/wedge-demo.db \
 *   PHP_CLI_SERVER_WORKERS=4 php -S 127.0.0.1:9414 examples/demo.php
 *
 * Then point the wedge app at http://127.0.0.1:9414 and open /login.
 * PHP native sessions are file-backed, so they too are shared across the
 * workers.
 */

require __DIR__ . '/../vendor/autoload.php';

use Wedge\Rp\Handler;
use Wedge\Rp\Kernel;
use Wedge\Rp\SqliteStore;
use Wedge\Rp\WedgeRP;

$users = [];
foreach (explode(',', getenv('WEDGE_DEMO_USERS') ?: '') as $spec) {
    if ($spec === '') {
        continue;
    }
    [$name, $keyPath] = explode(':', $spec, 2);
    $users[$name] = trim((string) file_get_contents($keyPath));
}
if ($users === []) {
    fwrite(STDERR, "set WEDGE_DEMO_USERS=name:pubkey_path[,name:path...]\n");
    exit(2);
}
$db = getenv('WEDGE_DEMO_DB') ?: sys_get_temp_dir() . '/wedge-rp-demo.db';
$origin = getenv('WEDGE_DEMO_ORIGIN') ?: 'http://127.0.0.1:9414';

$rp = new WedgeRP(
    origin: $origin,
    store: new SqliteStore($db),
    findKeys: fn (string $u) => $users[$u] ?? null,
    findUserByPublicKey: function (string $posted) use ($users) {
        foreach ($users as $name => $key) {
            if (Kernel::sameKey($key, $posted)) {
                return [$name, [$key]];
            }
        }

        return null;
    },
);

session_start();

if (Handler::handle($rp, [
    'login' => function (string $username): void {
        $_SESSION['user'] = $username;
    },
    'redirectTo' => '/',
    'failureRedirect' => '/login',
])) {
    return;
}

$page = static function (string $body): void {
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><meta charset="utf-8"><title>wedge-rp demo</title>'
        . '<body style="font-family: system-ui; max-width: 40rem; margin: 4rem auto">'
        . $body . '</body>';
};

switch (parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)) {
    case '/login':
        $page(<<<'HTML'
            <h1>wedge-rp demo (PHP)</h1>
            <p><input id="u" placeholder="username (optional)"></p>
            <p><button id="b">Sign in with wedge</button></p>
            <p id="msg"></p>
            <script src="/wedge/wedge.js"></script>
            <script>
            Wedge.attach(document.getElementById("b"), {
              usernameInput: "#u",
              onStatus: function (s) { document.getElementById("msg").textContent = s; },
              onError: function (e) { document.getElementById("msg").textContent = e.message; },
            });
            </script>
            HTML);

        return;

    case '/logout':
        unset($_SESSION['user']);
        http_response_code(303);
        header('Location: /');

        return;

    case '/':
        $who = $_SESSION['user'] ?? null;
        $page($who !== null
            ? '<h1>Signed in as ' . htmlspecialchars($who) . '</h1><p><a href="/logout">Log out</a></p>'
            : '<h1>Signed out</h1><p><a href="/login">Sign in with wedge</a></p>');

        return;

    default:
        http_response_code(404);
        header('Content-Type: text/plain');
        echo 'not found';
}
