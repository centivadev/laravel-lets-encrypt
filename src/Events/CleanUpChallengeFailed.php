<?php

namespace Daanra\LaravelLetsEncrypt\Events;

use Daanra\LaravelLetsEncrypt\Interfaces\LetsEncryptCertificateFailed;
use Daanra\LaravelLetsEncrypt\Traits\IdentifiesAttempt;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class CleanUpChallengeFailed implements LetsEncryptCertificateFailed
{
    use Dispatchable, IdentifiesAttempt, InteractsWithSockets, SerializesModels;

    /** @var \Throwable */
    protected $exception;

    /**
     * Create a new event instance.
     *
     * @return void
     */
    public function __construct(\Throwable $exception, ?string $domain = null, ?string $attemptId = null)
    {
        $this->exception = $exception;
        $this->domain = $domain;
        $this->attemptId = $attemptId;
    }

    public function getException(): \Throwable
    {
        return $this->exception;
    }
}
