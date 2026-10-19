<?php

namespace Daanra\LaravelLetsEncrypt\Jobs;

use Daanra\LaravelLetsEncrypt\AcmePhp\Core\Exception\Protocol\ChallengeFailedException;
use Daanra\LaravelLetsEncrypt\AcmePhp\Core\Protocol\AuthorizationChallenge;
use Daanra\LaravelLetsEncrypt\Events\RequestAuthorizationFailed;
use Daanra\LaravelLetsEncrypt\Exceptions\FailedToMoveChallengeException;
use Daanra\LaravelLetsEncrypt\Facades\LetsEncrypt;
use Daanra\LaravelLetsEncrypt\Models\LetsEncryptCertificate;
use Daanra\LaravelLetsEncrypt\Support\PathGeneratorFactory;
use Daanra\LaravelLetsEncrypt\Traits\LocksDomain;
use Daanra\LaravelLetsEncrypt\Traits\Retryable;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

class RequestAuthorization implements ShouldQueue
{
    use Dispatchable, Queueable, InteractsWithQueue, SerializesModels, Retryable, LocksDomain;

    /** @var LetsEncryptCertificate */
    protected $certificate;

    /** @var string|null */
    protected $attemptId;


    public function __construct(LetsEncryptCertificate $certificate, ?int $tries = null, ?int $retryAfter = null, $retryList = [], ?string $attemptId = null)
    {
        $this->certificate = $certificate;
        $this->tries = $tries;
        $this->retryAfter = $retryAfter;
        $this->retryList = $retryList;
        $this->attemptId = $attemptId;
    }

    /**
     * Out of the array of challenges we have, we want to find the HTTP challenge, because that's the
     * easiest one to solve in this scenario.
     * @param AuthorizationChallenge[] $challenges
     * @return AuthorizationChallenge
     */
    protected function getHttpChallenge(array $challenges): AuthorizationChallenge
    {
        return collect($challenges)->first(function (AuthorizationChallenge $challenge): bool {
            return Str::startsWith($challenge->getType(), 'http');
        });
    }

    /**
     * Stores the HTTP-01 challenge at the appropriate place on disk.
     * @param AuthorizationChallenge $challenge
     * @throws FailedToMoveChallengeException
     */
    protected function placeChallenge(AuthorizationChallenge $challenge): void
    {
        $path = PathGeneratorFactory::create()->getChallengePath($challenge->getToken());
        $success = Storage::disk(config('lets_encrypt.challenge_disk'))->put($path, $challenge->getPayload());

        if ($success === false) {
            throw new FailedToMoveChallengeException($path);
        }
    }

    /**
     * Removes a challenge file. A file left behind is harmless, so failing to remove it must never
     * fail the authorization.
     */
    protected function removeChallenge(AuthorizationChallenge $challenge): void
    {
        $path = PathGeneratorFactory::create()->getChallengePath($challenge->getToken());

        rescue(fn () => Storage::disk(config('lets_encrypt.challenge_disk'))->delete($path));
    }

    public function middleware(): array
    {
        return $this->domainLock($this->certificate->domain);
    }

    /**
     * Places the challenges and waits for Let's Encrypt to validate them, so that RequestCertificate,
     * next in the chain, always finds every authorization valid.
     */
    public function handle()
    {
        $client = LetsEncrypt::createClient();
        $challenges = array_map(
            fn (array $challenges) => $this->getHttpChallenge($challenges),
            $client->requestAuthorization($this->certificate->domain)
        );

        try {
            foreach ($challenges as $challenge) {
                $this->placeChallenge($challenge);
            }

            foreach ($challenges as $challenge) {
                $client->challengeAuthorization($challenge);
            }
        } catch (ChallengeFailedException $exception) {
            // An invalid challenge stays invalid: a retry would open a new authorization and count
            // one more failure against the Let's Encrypt limits.
            $this->fail($exception);
        } finally {
            foreach ($challenges as $challenge) {
                $this->removeChallenge($challenge);
            }
        }
    }

    public static function dispatchNow(LetsEncryptCertificate $certificate)
    {
        app(Dispatcher::class)->dispatchSync(new static($certificate));
    }

    /**
     * Handle a job failure.
     *
     * @return void
     */
    public function failed(\Throwable $exception)
    {
        event(new RequestAuthorizationFailed($exception, $this->certificate, $this->attemptId));
    }
}
