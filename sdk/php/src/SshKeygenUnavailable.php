<?php

declare(strict_types=1);

namespace Wedge\Rp;

/**
 * ssh-keygen is missing or too old for `-Y verify` (needs OpenSSH 8.1+) — a
 * server misconfiguration, not a bad login.
 */
final class SshKeygenUnavailable extends \RuntimeException
{
}
