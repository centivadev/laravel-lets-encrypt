<?php

namespace Daanra\LaravelLetsEncrypt\Interfaces;

interface LetsEncryptCertificateFailed
{
    public function getException(): \Throwable;

    /**
     * The domain the failing job worked on, or null when it is not tied to one.
     */
    public function getDomain(): ?string;

    /**
     * The identifier the caller gave the issuance attempt (see PendingCertificate::setAttemptId()).
     */
    public function getAttemptId(): ?string;
}
