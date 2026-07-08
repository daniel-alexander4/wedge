<?php

declare(strict_types=1);

namespace Wedge\Rp;

/**
 * Signature-verification kernel: shells out to `ssh-keygen -Y verify`
 * (OpenSSH 8.1+), so wedge-rp implements no cryptography of its own —
 * verification behaves exactly like sshd's allowed_signers handling. Only
 * public keys and signatures pass through here; private keys never leave the
 * user's ssh-agent.
 *
 * Port of sdk/python/wedge_rp/kernel.py — keep the validation rules in
 * lockstep. POSIX-only: stream_select on proc_open pipes does not work on
 * Windows, and an RP runs server-side anyway.
 */
final class Kernel
{
    /**
     * The principal is the first token of an allowed_signers line, so it must
     * be a single inert token: no whitespace, and none of the characters
     * ssh-keygen treats as comments, quoting, or patterns ("#", '"', "*",
     * "?", ",").
     */
    public const PRINCIPAL_RE = '/^[A-Za-z0-9._@+=-]{1,256}$/';

    private const KEYTYPE_RE = '/^[A-Za-z0-9@.\-]{1,64}$/';
    private const KEYDATA_RE = '/^[A-Za-z0-9+\/=]{1,16384}$/';
    private const SIG_HEADER = '-----BEGIN SSH SIGNATURE-----';
    private const MAX_SIGNATURE_BYTES = 65536;

    public const DEFAULT_TIMEOUT = 10.0; // seconds per ssh-keygen run

    /**
     * The ssh-keygen to exec, overridable for tests via SSH_KEYGEN_PATH
     * (same convention as the other wedge-rp kernels and wedge itself).
     */
    public static function keygenBinary(): string
    {
        $override = getenv('SSH_KEYGEN_PATH');

        return $override !== false && $override !== '' ? $override : 'ssh-keygen';
    }

    /**
     * The [keytype, base64data] of an OpenSSH public-key line, dropping any
     * trailing comment; null if the line doesn't look like a public key.
     *
     * @return array{0: string, 1: string}|null
     */
    public static function splitPublicKey(string $publicKey): ?array
    {
        $fields = preg_split('/\s+/', trim($publicKey), -1, PREG_SPLIT_NO_EMPTY);
        if ($fields === false || count($fields) < 2) {
            return null;
        }
        if (!preg_match(self::KEYTYPE_RE, $fields[0]) || !preg_match(self::KEYDATA_RE, $fields[1])) {
            return null;
        }

        return [$fields[0], $fields[1]];
    }

    /**
     * Whether two public-key lines denote the same key (type + data; comments
     * and surrounding whitespace ignored). Use it to implement the
     * findUserByPublicKey callback.
     */
    public static function sameKey(string $a, string $b): bool
    {
        $pa = self::splitPublicKey($a);
        $pb = self::splitPublicKey($b);

        return $pa !== null && $pa === $pb;
    }

    /**
     * Verify an armored SSHSIG $signature over the exact bytes of $challenge,
     * made with $namespace, against $publicKey.
     *
     * A failed verification is a normal outcome: ['ok' => false, 'detail' =>
     * reason]. A broken environment (missing or pre-8.1 ssh-keygen) throws
     * SshKeygenUnavailable instead.
     *
     * @return array{ok: bool, detail: string}
     *
     * @throws SshKeygenUnavailable
     */
    public static function verifySignature(
        string $challenge,
        string $signature,
        string $principal,
        string $publicKey,
        string $namespace,
        float $timeout = self::DEFAULT_TIMEOUT,
    ): array {
        if (!preg_match(self::PRINCIPAL_RE, $principal)) {
            return ['ok' => false, 'detail' => 'invalid principal'];
        }
        $key = self::splitPublicKey($publicKey);
        if ($key === null) {
            return ['ok' => false, 'detail' => 'malformed public key'];
        }
        if (!str_starts_with(ltrim($signature), self::SIG_HEADER) || strlen($signature) > self::MAX_SIGNATURE_BYTES) {
            return ['ok' => false, 'detail' => 'malformed signature'];
        }
        if ($namespace === '' || str_contains($namespace, "\n") || str_contains($namespace, "\0")) {
            return ['ok' => false, 'detail' => 'invalid namespace'];
        }

        $dir = sys_get_temp_dir() . '/wedge-rp-' . bin2hex(random_bytes(8));
        if (!mkdir($dir, 0700)) {
            throw new \RuntimeException('could not create temp dir');
        }
        try {
            $allowed = $dir . '/allowed_signers';
            $sigfile = $dir . '/challenge.sig';
            file_put_contents($allowed, "{$principal} {$key[0]} {$key[1]}\n");
            file_put_contents($sigfile, trim($signature) . "\n");

            // Array command form: no shell, arguments are argv entries. A
            // missing binary makes proc_open warn and return false.
            $process = @proc_open(
                [self::keygenBinary(), '-Y', 'verify', '-f', $allowed, '-I', $principal, '-n', $namespace, '-s', $sigfile],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $pipes,
            );
            if (!is_resource($process)) {
                throw new SshKeygenUnavailable('ssh-keygen not found — install openssh-client');
            }

            fwrite($pipes[0], $challenge);
            fclose($pipes[0]);
            stream_set_blocking($pipes[1], false);
            stream_set_blocking($pipes[2], false);

            $stdout = '';
            $stderr = '';
            $deadline = microtime(true) + $timeout;
            $timedOut = false;
            while (true) {
                $status = proc_get_status($process);
                $read = [$pipes[1], $pipes[2]];
                $write = null;
                $except = null;
                $remaining = $deadline - microtime(true);
                if ($remaining <= 0) {
                    $timedOut = true;
                    break;
                }
                if (stream_select($read, $write, $except, 0, (int) (min($remaining, 0.2) * 1000000)) > 0) {
                    foreach ($read as $stream) {
                        $chunk = stream_get_contents($stream);
                        if ($chunk !== false) {
                            if ($stream === $pipes[1]) {
                                $stdout .= $chunk;
                            } else {
                                $stderr .= $chunk;
                            }
                        }
                    }
                }
                if (!$status['running']) {
                    // Drain whatever arrived after the last select.
                    $stdout .= (string) stream_get_contents($pipes[1]);
                    $stderr .= (string) stream_get_contents($pipes[2]);
                    break;
                }
            }
            fclose($pipes[1]);
            fclose($pipes[2]);
            if ($timedOut) {
                proc_terminate($process, 9);
                proc_close($process);

                return ['ok' => false, 'detail' => 'verification timed out'];
            }
            $exitCode = $status['running'] ? proc_close($process) : $status['exitcode'];
            if (!$status['running']) {
                proc_close($process);
            }

            $stdout = trim($stdout);
            $stderr = trim($stderr);
            if ($exitCode === 0) {
                return ['ok' => true, 'detail' => $stdout !== '' ? $stdout : 'signature verified'];
            }
            // Array-form proc_open exec failure surfaces as exit code 127
            // with no stderr from the tool itself.
            if ($exitCode === 127 || $exitCode === -1) {
                throw new SshKeygenUnavailable('ssh-keygen not found — install openssh-client');
            }
            if (str_contains($stderr, 'unknown option') || str_starts_with(strtolower($stderr), 'usage:')) {
                throw new SshKeygenUnavailable('ssh-keygen lacks -Y verify — OpenSSH 8.1+ required');
            }

            return ['ok' => false, 'detail' => $stderr !== '' ? $stderr : ($stdout !== '' ? $stdout : 'signature verification failed')];
        } finally {
            @unlink($dir . '/allowed_signers');
            @unlink($dir . '/challenge.sig');
            @rmdir($dir);
        }
    }
}
