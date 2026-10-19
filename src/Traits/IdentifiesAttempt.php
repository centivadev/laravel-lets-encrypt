<?php

namespace Daanra\LaravelLetsEncrypt\Traits;

trait IdentifiesAttempt
{
    /** @var string|null */
    protected $domain;

    /** @var string|null */
    protected $attemptId;

    public function getDomain(): ?string
    {
        return $this->domain;
    }

    public function getAttemptId(): ?string
    {
        return $this->attemptId;
    }
}
