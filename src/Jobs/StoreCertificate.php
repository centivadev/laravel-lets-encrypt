<?php

namespace Daanra\LaravelLetsEncrypt\Jobs;

use Daanra\LaravelLetsEncrypt\AcmePhp\Ssl\Certificate;
use Daanra\LaravelLetsEncrypt\AcmePhp\Ssl\Exception\CertificateParsingException;
use Daanra\LaravelLetsEncrypt\AcmePhp\Ssl\PrivateKey;
use Daanra\LaravelLetsEncrypt\Contracts\PathGenerator;
use Daanra\LaravelLetsEncrypt\Encoders\PemEncoder;
use Daanra\LaravelLetsEncrypt\Events\CertificateStored;
use Daanra\LaravelLetsEncrypt\Events\StoreCertificateFailed;
use Daanra\LaravelLetsEncrypt\Exceptions\FailedToStoreCertificate;
use Daanra\LaravelLetsEncrypt\Models\LetsEncryptCertificate;
use Daanra\LaravelLetsEncrypt\Support\PathGeneratorFactory;
use Daanra\LaravelLetsEncrypt\Traits\LocksDomain;
use Daanra\LaravelLetsEncrypt\Traits\Retryable;
use DateTimeImmutable;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Storage;

class StoreCertificate implements ShouldQueue
{
    use Dispatchable, Queueable, InteractsWithQueue, SerializesModels, Retryable, LocksDomain;

    /**
     * @var Certificate
     */
    protected $certificate;

    /**
     * @var LetsEncryptCertificate
     */
    protected $dbCertificate;

    /**
     * @var PrivateKey
     */
    protected $privateKey;

    /** @var string|null */
    protected $attemptId;


    public function __construct(LetsEncryptCertificate $dbCertificate, Certificate $certificate, PrivateKey $privateKey, ?int $tries = null, ?int $retryAfter = null, $retryList = [], ?string $attemptId = null)
    {
        $this->dbCertificate = $dbCertificate;
        $this->certificate = $certificate;
        $this->privateKey = $privateKey;
        $this->tries = $tries;
        $this->retryAfter = $retryAfter;
        $this->retryList = $retryList;
        $this->attemptId = $attemptId;
    }

    /**
     * This is the job that actually writes the files to disk: the most sensitive point in
     * the whole chain.
     */
    public function middleware(): array
    {
        return $this->domainLock($this->dbCertificate->domain);
    }

    /**
     * Stores four files on disk: 'fullchain.pem', 'chain.pem', 'cert.pem' and 'privkey.pem', then
     * dispatches CertificateStored.
     */
    public function handle()
    {
        $certPem = PemEncoder::encode($this->certificate->getPEM());
        // Read before anything is written: a certificate whose dates cannot be read is not stored.
        $parsed = $this->parse($certPem);
        $chainPem = collect($this->certificate->getIssuerChain())
            ->reduce(function (string $carry, Certificate $certificate): string {
                return $carry . PemEncoder::encode($certificate->getPEM());
            }, '');

        $fullChainPem = $certPem . $chainPem;

        $privkeyPem = PemEncoder::encode($this->privateKey->getPEM());

        $factory = PathGeneratorFactory::create();

        $this->storeInPossiblyNonExistingDirectory($factory, 'cert', $certPem);
        $this->storeInPossiblyNonExistingDirectory($factory, 'chain', $chainPem);
        $this->storeInPossiblyNonExistingDirectory($factory, 'fullchain', $fullChainPem);
        $this->storeInPossiblyNonExistingDirectory($factory, 'privkey', $privkeyPem, 'private');
        $this->dbCertificate->last_renewed_at = now();
        $this->dbCertificate->created = true;
        $this->dbCertificate->save();

        event(new CertificateStored(
            $this->dbCertificate,
            (new DateTimeImmutable())->setTimestamp($parsed['validFrom_time_t']),
            (new DateTimeImmutable())->setTimestamp($parsed['validTo_time_t']),
            strtoupper($parsed['serialNumberHex']),
            $this->authorityKeyIdentifier($parsed),
            $this->attemptId
        ));
    }

    /**
     * @throws CertificateParsingException
     */
    protected function parse(string $certPem): array
    {
        $parsed = openssl_x509_parse($certPem);

        if (! is_array($parsed) || ! isset($parsed['validFrom_time_t'], $parsed['validTo_time_t'], $parsed['serialNumberHex'])) {
            throw new CertificateParsingException('Unable to read the dates and serial number of the certificate issued for '.$this->dbCertificate->domain);
        }

        return $parsed;
    }

    /**
     * OpenSSL prints the extension as "keyid:AB:CD:..." (1.x) or "AB:CD:..." (3.x).
     */
    protected function authorityKeyIdentifier(array $parsed): ?string
    {
        $value = $parsed['extensions']['authorityKeyIdentifier'] ?? null;

        if (! is_string($value) || ! preg_match('/[0-9A-F]{2}(?::[0-9A-F]{2})*/i', $value, $matches)) {
            return null;
        }

        return strtoupper(str_replace(':', '', $matches[0]));
    }

    /**
     * Creates the directory if it does not exist yet to prevent an error.
     * @param PathGenerator $generator
     * @param string $filename
     * @param string $contents
     * @throws FailedToStoreCertificate
     */
    protected function storeInPossiblyNonExistingDirectory(PathGenerator $generator, string $filename, string $contents, ?string $visibility = null): void
    {
        $path = $generator->getCertificatePath($this->dbCertificate->domain, $filename . '.pem');
        $directory = File::dirname($path);
        $fs = Storage::disk(config('lets_encrypt.certificate_disk'));
        if (! $fs->exists($directory)) {
            $fs->makeDirectory($directory);
        }

        $this->dbCertificate[$filename . '_path'] = $path;

        if ($fs->put($path, $contents, $visibility ?? []) === false) {
            throw new FailedToStoreCertificate($path);
        }
    }

    /**
     * Handle a job failure.
     *
     * @return void
     */
    public function failed(\Throwable $exception)
    {
        event(new StoreCertificateFailed($exception, $this->dbCertificate, $this->attemptId));
    }
}
