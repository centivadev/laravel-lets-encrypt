<?php

namespace Daanra\LaravelLetsEncrypt\Events;

use Daanra\LaravelLetsEncrypt\Models\LetsEncryptCertificate;
use Daanra\LaravelLetsEncrypt\Traits\IdentifiesAttempt;
use DateTimeImmutable;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Dispatched once the four certificate files are stored and the model is saved, with the dates
 * and identifiers read from the issued certificate itself rather than assumed from a lifetime.
 */
class CertificateStored
{
    use Dispatchable, IdentifiesAttempt, InteractsWithSockets, SerializesModels;

    /** @var LetsEncryptCertificate */
    protected $certificate;

    /** @var DateTimeImmutable */
    protected $notBefore;

    /** @var DateTimeImmutable */
    protected $notAfter;

    /** @var string */
    protected $serialNumber;

    /** @var string|null */
    protected $authorityKeyIdentifier;

    public function __construct(
        LetsEncryptCertificate $certificate,
        DateTimeImmutable $notBefore,
        DateTimeImmutable $notAfter,
        string $serialNumber,
        ?string $authorityKeyIdentifier,
        ?string $attemptId = null
    ) {
        $this->certificate = $certificate;
        $this->notBefore = $notBefore;
        $this->notAfter = $notAfter;
        $this->serialNumber = $serialNumber;
        $this->authorityKeyIdentifier = $authorityKeyIdentifier;
        $this->domain = $certificate->domain;
        $this->attemptId = $attemptId;
    }

    public function getCertificate(): LetsEncryptCertificate
    {
        return $this->certificate;
    }

    public function getNotBefore(): DateTimeImmutable
    {
        return $this->notBefore;
    }

    public function getNotAfter(): DateTimeImmutable
    {
        return $this->notAfter;
    }

    /**
     * Uppercase hexadecimal, without separators.
     */
    public function getSerialNumber(): string
    {
        return $this->serialNumber;
    }

    /**
     * Key identifier of the issuing authority, uppercase hexadecimal without separators. Together
     * with the serial number, it identifies the certificate for ACME Renewal Information (RFC 9773).
     */
    public function getAuthorityKeyIdentifier(): ?string
    {
        return $this->authorityKeyIdentifier;
    }
}
