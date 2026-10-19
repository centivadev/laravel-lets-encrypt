<?php

namespace Daanra\LaravelLetsEncrypt\Jobs;

use Daanra\LaravelLetsEncrypt\AcmePhp\Ssl\CertificateRequest;
use Daanra\LaravelLetsEncrypt\AcmePhp\Ssl\DistinguishedName;
use Daanra\LaravelLetsEncrypt\AcmePhp\Ssl\Generator\KeyPairGenerator;
use Daanra\LaravelLetsEncrypt\Events\RequestCertificateFailed;
use Daanra\LaravelLetsEncrypt\Facades\LetsEncrypt;
use Daanra\LaravelLetsEncrypt\Models\LetsEncryptCertificate;
use Daanra\LaravelLetsEncrypt\Traits\LocksDomain;
use Daanra\LaravelLetsEncrypt\Traits\Retryable;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

class RequestCertificate implements ShouldQueue
{
    use Dispatchable, Queueable, InteractsWithQueue, SerializesModels, Retryable, LocksDomain;

    /** @var LetsEncryptCertificate */
    protected $certificate;

    /** @var bool */
    protected $sync;

    /** @var string|null */
    protected $attemptId;


    public function __construct(LetsEncryptCertificate $certificate, ?int $tries = null, ?int $retryAfter = null, $retryList = [], ?string $attemptId = null)
    {
        $this->sync = false;
        $this->certificate = $certificate;
        $this->tries = $tries;
        $this->retryAfter = $retryAfter;
        $this->retryList = $retryList;
        $this->attemptId = $attemptId;
    }

    public function middleware(): array
    {
        return $this->domainLock($this->certificate->domain);
    }

    public function handle()
    {
        $distinguishedName = new DistinguishedName($this->certificate->domain, null, null, null, null, null, null, $this->certificate->subject_alternative_names);
        $csr = new CertificateRequest($distinguishedName, (new KeyPairGenerator())->generateKeyPair());
        $client = LetsEncrypt::createClient();
        $certificateResponse = $client->requestCertificate($this->certificate->domain, $csr);
        $certificate = $certificateResponse->getCertificate();
        $privateKey = $csr->getKeyPair()->getPrivateKey();

        if ($this->sync) {
            StoreCertificate::dispatchSync($this->certificate, $certificate, $privateKey, $this->tries, $this->retryAfter, $this->retryList, $this->attemptId);
        } else {
            StoreCertificate::dispatch($this->certificate, $certificate, $privateKey, $this->tries, $this->retryAfter, $this->retryList, $this->attemptId);
        }
    }

    protected function setSync(bool $sync)
    {
        $this->sync = $sync;
    }

    public static function dispatchNow(LetsEncryptCertificate $certificate)
    {
        $job = new static($certificate);
        $job->setSync(true);
        app(Dispatcher::class)->dispatchSync($job);
    }

    /**
     * Handle a job failure.
     *
     * @return void
     */
    public function failed(\Throwable $exception)
    {
        event(new RequestCertificateFailed($exception, $this->certificate, $this->attemptId));
    }
}
