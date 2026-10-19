<?php

namespace Daanra\LaravelLetsEncrypt\Tests\Jobs;

use Daanra\LaravelLetsEncrypt\AcmePhp\Core\AcmeClient;
use Daanra\LaravelLetsEncrypt\AcmePhp\Core\Exception\Protocol\ChallengeFailedException;
use Daanra\LaravelLetsEncrypt\AcmePhp\Core\Protocol\AuthorizationChallenge;
use Daanra\LaravelLetsEncrypt\AcmePhp\Ssl\Certificate;
use Daanra\LaravelLetsEncrypt\AcmePhp\Ssl\CertificateRequest;
use Daanra\LaravelLetsEncrypt\AcmePhp\Ssl\CertificateResponse;
use Daanra\LaravelLetsEncrypt\AcmePhp\Ssl\Exception\CertificateParsingException;
use Daanra\LaravelLetsEncrypt\AcmePhp\Ssl\Generator\KeyPairGenerator;
use Daanra\LaravelLetsEncrypt\Events\CertificateStored;
use Daanra\LaravelLetsEncrypt\Events\RegisterAccountFailed;
use Daanra\LaravelLetsEncrypt\Events\RequestAuthorizationFailed;
use Daanra\LaravelLetsEncrypt\Events\RequestCertificateFailed;
use Daanra\LaravelLetsEncrypt\Events\StoreCertificateFailed;
use Daanra\LaravelLetsEncrypt\Facades\LetsEncrypt;
use Daanra\LaravelLetsEncrypt\Jobs\RegisterAccount;
use Daanra\LaravelLetsEncrypt\Jobs\RequestAuthorization;
use Daanra\LaravelLetsEncrypt\Jobs\RequestCertificate;
use Daanra\LaravelLetsEncrypt\Jobs\StoreCertificate;
use Daanra\LaravelLetsEncrypt\Models\LetsEncryptCertificate;
use Daanra\LaravelLetsEncrypt\Tests\TestCase;
use Exception;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Queue\Middleware\WithoutOverlapping;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Storage;
use Mockery;

class IssuanceChainTest extends TestCase
{
    private const APEX_TOKEN = 'apex-token';

    private const WWW_TOKEN = 'www-token';

    public function setUp(): void
    {
        parent::setUp();

        // A real queue and worker, as on the hosts: a sync queue would run each job inside the
        // previous one, under its lock.
        config(['queue.default' => 'database', 'queue.failed.driver' => 'null']);
        Schema::create('jobs', function (Blueprint $table) {
            $table->id();
            $table->string('queue')->index();
            $table->longText('payload');
            $table->unsignedTinyInteger('attempts');
            $table->unsignedInteger('reserved_at')->nullable();
            $table->unsignedInteger('available_at');
            $table->unsignedInteger('created_at');
        });
        Storage::fake();
    }

    private function work(): void
    {
        Artisan::call('queue:work', ['--stop-when-empty' => true, '--tries' => 3]);
    }

    public function test_the_certificate_is_requested_once_every_challenge_is_valid()
    {
        Event::fake([CertificateStored::class]);
        [$issued, $issuerKeyId] = $this->issueCertificate();
        $client = $this->clientWithChallenges();
        $client->shouldReceive('challengeAuthorization')->twice()->ordered()
            ->andReturnUsing(function (AuthorizationChallenge $challenge) {
                Storage::assertExists('public/.well-known/acme-challenge/'.$challenge->getToken());

                return ['status' => 'valid'];
            });
        $client->shouldReceive('requestCertificate')->once()->ordered()
            ->andReturnUsing(fn (string $domain, CertificateRequest $csr) => new CertificateResponse($csr, $issued));

        LetsEncrypt::certificate('example.com')->setAttemptId('attempt-1')->create();
        $this->work();

        Storage::assertMissing('public/.well-known/acme-challenge/'.self::APEX_TOKEN);
        Storage::assertMissing('public/.well-known/acme-challenge/'.self::WWW_TOKEN);
        Storage::assertExists('letsencrypt/certificates/example.com/fullchain.pem');
        Event::assertDispatched(CertificateStored::class, function (CertificateStored $event) use ($issuerKeyId) {
            return $event->getDomain() === 'example.com'
                && $event->getAttemptId() === 'attempt-1'
                && $event->getSerialNumber() === '1A2B3C4D'
                && $event->getAuthorityKeyIdentifier() === $issuerKeyId
                && $event->getNotAfter()->getTimestamp() - $event->getNotBefore()->getTimestamp() === 90 * 86400;
        });
    }

    public function test_an_invalid_challenge_ends_the_chain_without_a_retry()
    {
        Event::fake([RequestAuthorizationFailed::class]);
        $client = $this->clientWithChallenges();
        $client->shouldReceive('challengeAuthorization')->once()->andThrow(new ChallengeFailedException(['status' => 'invalid']));
        $client->shouldNotReceive('requestCertificate');

        LetsEncrypt::certificate('example.com')->setAttemptId('attempt-2')->create();
        $this->work();

        Storage::assertMissing('public/.well-known/acme-challenge/'.self::APEX_TOKEN);
        Storage::assertMissing('public/.well-known/acme-challenge/'.self::WWW_TOKEN);
        Event::assertDispatchedTimes(RequestAuthorizationFailed::class, 1);
        Event::assertDispatched(RequestAuthorizationFailed::class, function (RequestAuthorizationFailed $event) {
            return $event->getDomain() === 'example.com'
                && $event->getAttemptId() === 'attempt-2'
                && $event->getException() instanceof ChallengeFailedException;
        });
    }

    public function test_every_job_that_talks_to_the_acme_server_shares_an_expiring_lock()
    {
        config(['lets_encrypt.job_lock_expires_after' => 321]);
        $certificate = LetsEncryptCertificate::create(['domain' => 'example.com']);
        [$issued] = $this->issueCertificate();
        $privateKey = (new KeyPairGenerator())->generateKeyPair()->getPrivateKey();

        $jobs = [
            new RequestAuthorization($certificate),
            new RequestCertificate($certificate),
            new StoreCertificate($certificate, $issued, $privateKey),
        ];

        foreach ($jobs as $job) {
            [$lock] = $job->middleware();
            $this->assertInstanceOf(WithoutOverlapping::class, $lock);
            $this->assertSame('ssl-cert-gen:example.com', $lock->key);
            $this->assertTrue($lock->shareKey);
            $this->assertSame(321, $lock->expiresAfter);
        }
    }

    public function test_a_certificate_whose_dates_cannot_be_read_is_not_stored()
    {
        $certificate = LetsEncryptCertificate::create(['domain' => 'example.com']);
        $privateKey = (new KeyPairGenerator())->generateKeyPair()->getPrivateKey();

        try {
            (new StoreCertificate($certificate, new Certificate('not a certificate'), $privateKey))->handle();
            $this->fail('An unreadable certificate must not be stored.');
        } catch (CertificateParsingException $exception) {
            $this->assertSame([], Storage::allFiles());
        }
    }

    public function test_every_failure_event_identifies_the_attempt()
    {
        Event::fake();
        $certificate = LetsEncryptCertificate::create(['domain' => 'example.com']);
        [$issued] = $this->issueCertificate();
        $privateKey = (new KeyPairGenerator())->generateKeyPair()->getPrivateKey();

        (new RegisterAccount(null, null, null, [], 'example.com', 'attempt-3'))->failed(new Exception());
        (new RequestCertificate($certificate, null, null, [], 'attempt-3'))->failed(new Exception());
        (new StoreCertificate($certificate, $issued, $privateKey, null, null, [], 'attempt-3'))->failed(new Exception());

        foreach ([RegisterAccountFailed::class, RequestCertificateFailed::class, StoreCertificateFailed::class] as $event) {
            Event::assertDispatched($event, fn ($event) => $event->getDomain() === 'example.com' && $event->getAttemptId() === 'attempt-3');
        }
    }

    /**
     * An ACME client that registers the account and offers an http-01 challenge for the apex and
     * the www name, next to a dns-01 one the chain must ignore.
     */
    private function clientWithChallenges(): Mockery\MockInterface
    {
        $client = Mockery::mock(AcmeClient::class);
        $client->shouldReceive('registerAccount');
        $client->shouldReceive('requestAuthorization')->with('example.com')->andReturn([
            [
                new AuthorizationChallenge('example.com', 'pending', 'dns-01', 'https://acme.test/dns', 'dns-token', 'dns-payload'),
                new AuthorizationChallenge('example.com', 'pending', 'http-01', 'https://acme.test/apex', self::APEX_TOKEN, 'apex-payload'),
            ],
            [
                new AuthorizationChallenge('www.example.com', 'pending', 'http-01', 'https://acme.test/www', self::WWW_TOKEN, 'www-payload'),
            ],
        ]);
        LetsEncrypt::partialMock()->shouldReceive('createClient')->andReturn($client);

        return $client;
    }

    /**
     * A 90-day certificate for example.com, serial 1A2B3C4D, signed by a throwaway authority, and the
     * key identifier of that authority as CertificateStored reports it.
     *
     * @return array{Certificate, string}
     */
    private function issueCertificate(): array
    {
        $config = tempnam(sys_get_temp_dir(), 'openssl');
        file_put_contents($config, implode("\n", [
            '[req]', 'distinguished_name = dn', '[dn]',
            '[authority]', 'basicConstraints = critical, CA:true', 'subjectKeyIdentifier = hash',
            '[leaf]', 'authorityKeyIdentifier = keyid', 'subjectKeyIdentifier = hash',
        ]));
        $options = fn (string $section) => ['config' => $config, 'x509_extensions' => $section, 'digest_alg' => 'sha256'];
        $newKey = fn () => openssl_pkey_new(['config' => $config, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        $authorityKey = $newKey();
        $authority = openssl_csr_sign(openssl_csr_new(['commonName' => 'Test authority'], $authorityKey, $options('authority')), null, $authorityKey, 365, $options('authority'));
        $leafKey = $newKey();
        $leaf = openssl_csr_sign(openssl_csr_new(['commonName' => 'example.com'], $leafKey, $options('leaf')), $authority, $authorityKey, 90, $options('leaf'), 0x1A2B3C4D);
        unlink($config);

        openssl_x509_export($authority, $authorityPem);
        openssl_x509_export($leaf, $leafPem);
        $authorityKeyId = strtoupper(str_replace(':', '', openssl_x509_parse($authorityPem)['extensions']['subjectKeyIdentifier']));

        return [new Certificate($leafPem, new Certificate($authorityPem)), $authorityKeyId];
    }
}
