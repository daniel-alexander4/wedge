<?php

declare(strict_types=1);

namespace Wedge\Rp;

/**
 * SQLite-backed store (PDO) — the recommended store for classic per-request
 * PHP: every FPM worker / php -S worker shares the file, and BEGIN IMMEDIATE
 * keeps the single-use transitions atomic across processes. WAL keeps readers
 * and writers from blocking each other.
 */
final class SqliteStore implements RequestStore
{
    private \PDO $db;

    public function __construct(string $path)
    {
        $this->db = new \PDO('sqlite:' . $path, options: [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
        ]);
        // busy_timeout FIRST: it installs the wait-on-contention handler, and
        // the very next statement (the WAL switch) contends when several
        // processes open the same store at once.
        $this->db->exec('PRAGMA busy_timeout=5000');
        $this->db->exec('PRAGMA journal_mode=WAL');
        $this->db->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS wedge_requests (
                request_id TEXT PRIMARY KEY,
                challenge TEXT NOT NULL,
                namespace TEXT NOT NULL,
                username TEXT NOT NULL,
                browser_nonce TEXT NOT NULL,
                claim_token TEXT NOT NULL,
                status TEXT NOT NULL,
                authenticated_username TEXT NOT NULL,
                expires_at REAL NOT NULL
            )
            SQL);
    }

    /** @return array<string, mixed> */
    private static function record(array $row): array
    {
        return [
            'requestId' => $row['request_id'],
            'challenge' => $row['challenge'],
            'namespace' => $row['namespace'],
            'username' => $row['username'],
            'browserNonce' => $row['browser_nonce'],
            'claimToken' => $row['claim_token'],
            'status' => $row['status'],
            'authenticatedUsername' => $row['authenticated_username'],
            'expiresAt' => (float) $row['expires_at'],
        ];
    }

    public function put(array $record): void
    {
        $this->db->prepare('DELETE FROM wedge_requests WHERE expires_at <= ?')
            ->execute([microtime(true)]);
        $this->db->prepare('INSERT OR REPLACE INTO wedge_requests VALUES (?,?,?,?,?,?,?,?,?)')
            ->execute([
                $record['requestId'],
                $record['challenge'],
                $record['namespace'],
                $record['username'],
                $record['browserNonce'],
                $record['claimToken'],
                $record['status'],
                $record['authenticatedUsername'],
                $record['expiresAt'],
            ]);
    }

    public function get(string $requestId): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM wedge_requests WHERE request_id = ? AND expires_at > ?');
        $stmt->execute([$requestId, microtime(true)]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);

        return $row === false ? null : self::record($row);
    }

    public function setAuthenticated(string $requestId, string $username): bool
    {
        $stmt = $this->db->prepare(
            "UPDATE wedge_requests SET status='authenticated', authenticated_username=?"
            . " WHERE request_id=? AND status='pending' AND expires_at > ?",
        );
        $stmt->execute([$username, $requestId, microtime(true)]);

        return $stmt->rowCount() === 1;
    }

    public function takeAuthenticated(string $requestId): ?array
    {
        $this->db->exec('BEGIN IMMEDIATE');
        try {
            $stmt = $this->db->prepare(
                "SELECT * FROM wedge_requests WHERE request_id = ?"
                . " AND status='authenticated' AND expires_at > ?",
            );
            $stmt->execute([$requestId, microtime(true)]);
            $row = $stmt->fetch(\PDO::FETCH_ASSOC);
            if ($row === false) {
                $this->db->exec('ROLLBACK');

                return null;
            }
            $this->db->prepare('DELETE FROM wedge_requests WHERE request_id = ?')->execute([$requestId]);
            $this->db->exec('COMMIT');

            return self::record($row);
        } catch (\Throwable $e) {
            $this->db->exec('ROLLBACK');
            throw $e;
        }
    }
}
