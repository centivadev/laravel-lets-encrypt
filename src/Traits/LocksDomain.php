<?php

namespace Daanra\LaravelLetsEncrypt\Traits;

use Illuminate\Queue\Middleware\WithoutOverlapping;

trait LocksDomain
{
    /**
     * One lock per domain, shared by every job that talks to the ACME server or writes the
     * certificate files, so two chains never run for the same domain at once. A job that finds the
     * lock taken is dropped, not delayed. The lock expires so that a worker killed mid-job
     * (deployment, out of memory) cannot block its domain forever.
     */
    protected function domainLock(string $domain): array
    {
        return [
            (new WithoutOverlapping('ssl-cert-gen:'.$domain))
                ->shared()
                ->dontRelease()
                ->expireAfter((int) config('lets_encrypt.job_lock_expires_after', 600)),
        ];
    }
}
