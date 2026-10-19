<?php

namespace Daanra\LaravelLetsEncrypt\Events;

use Daanra\LaravelLetsEncrypt\Interfaces\LetsEncryptCertificateFailed;
use Daanra\LaravelLetsEncrypt\Models\LetsEncryptCertificate;
use Daanra\LaravelLetsEncrypt\Traits\IdentifiesAttempt;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class RequestCertificateFailed implements LetsEncryptCertificateFailed
{
    use Dispatchable, IdentifiesAttempt, InteractsWithSockets, SerializesModels;

    /** @var \Throwable */
    protected $exception;

    /** @var LetsEncryptCertificate */
    protected $certificate;

    /**
     * Create a new event instance.
     *
     * @return void
     */
    public function __construct(\Throwable $exception, LetsEncryptCertificate $certificate, ?string $attemptId = null)
    {
        $this->exception = $exception;
        $this->certificate = $certificate;
        $this->domain = $certificate->domain;
        $this->attemptId = $attemptId;
    }

    public function getException(): \Throwable
    {
        return $this->exception;
    }

    public function getCertificate(): LetsEncryptCertificate
    {
        return $this->certificate;
    }
}
