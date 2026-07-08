<?php

declare(strict_types=1);

namespace Wedge\Rp\Tests;

/**
 * A real throwaway ed25519 keypair, able to sign — the suites exercise the
 * actual ssh-keygen binary end to end (no mocked crypto), same discipline as
 * the Python/Node/Go suites.
 */
final class KeyPair
{
    public readonly string $dir;
    public readonly string $keyPath;
    public readonly string $publicKey;

    public static function available(): bool
    {
        // Any exit code proves the binary exists; a missing one makes the
        // array-form proc_open fail outright.
        $process = @proc_open(['ssh-keygen', '-?'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) {
            return false;
        }
        foreach ($pipes as $pipe) {
            fclose($pipe);
        }
        proc_close($process);

        return true;
    }

    public function __construct(string $comment = 'wedge-rp-test')
    {
        $this->dir = sys_get_temp_dir() . '/wedge-rp-test-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0700);
        $this->keyPath = $this->dir . '/key';
        $out = self::run(['ssh-keygen', '-t', 'ed25519', '-N', '', '-C', $comment, '-q', '-f', $this->keyPath], '');
        if ($out === null) {
            throw new \RuntimeException('ssh-keygen -t ed25519 failed');
        }
        $this->publicKey = trim((string) file_get_contents($this->keyPath . '.pub'));
    }

    /** Armored SSHSIG over the challenge bytes, like the wedge app makes. */
    public function sign(string $challenge, string $namespace): string
    {
        $out = self::run(['ssh-keygen', '-Y', 'sign', '-f', $this->keyPath, '-n', $namespace], $challenge);
        if ($out === null) {
            throw new \RuntimeException('ssh-keygen -Y sign failed');
        }

        return $out;
    }

    public function cleanup(): void
    {
        @unlink($this->keyPath);
        @unlink($this->keyPath . '.pub');
        @rmdir($this->dir);
    }

    /** Run argv with stdin, return stdout or null on failure. */
    private static function run(array $argv, string $stdin): ?string
    {
        $process = @proc_open($argv, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) {
            return null;
        }
        fwrite($pipes[0], $stdin);
        fclose($pipes[0]);
        $stdout = (string) stream_get_contents($pipes[1]);
        stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return proc_close($process) === 0 ? $stdout : null;
    }
}
