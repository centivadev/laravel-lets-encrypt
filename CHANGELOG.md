# Changelog

All notable changes to `daanra/laravel-lets-encrypt` will be documented in this file

## V13.1.0

- Add a `CertificateStored` event, dispatched once the certificate files are stored, with the
  validity dates, serial number and authority key identifier read from the issued certificate, and
  the attempt identifier. A certificate whose dates cannot be read is no longer stored
- Add `PendingCertificate::setAttemptId()`, passed to every job of the chain and returned by every
  event it dispatches
- Add `getDomain()` and `getAttemptId()` to the `LetsEncryptCertificateFailed` interface and to every
  failure event
- `RequestAuthorization` now validates its challenges itself and removes the challenge files, valid or
  not, before the chain moves on to `RequestCertificate`, which no longer races the validation and
  relies on worker retries. A challenge found invalid fails the job at once, without a retry that
  would count one more failed authorization against the Let's Encrypt rate limits.
  `ChallengeAuthorization` and `CleanUpChallenge` are no longer dispatched and are deprecated
- The per-domain lock shared by `RequestAuthorization`, `RequestCertificate` and `StoreCertificate`
  now expires (`job_lock_expires_after`, 600 seconds by default), so a worker killed while holding
  it no longer blocks its domain forever
- Declare nullable parameters explicitly: implicitly nullable types are deprecated since PHP 8.4

## V13.0.1

- Fix a fatal error thrown by `AcmeClient::requestOrder()` whenever the ACME server
  lists a `dns-persist-01` challenge among a domain's authorizations: it has no
  `token` field, and the code assumed every challenge did. `dns-persist-01` is never
  consumed by `RequestAuthorization::getHttpChallenge()` (which only keeps `http-01`),
  so it is now safely skipped instead of crashing the whole authorization request
- Fix a `\ArgumentCountError` thrown every time the `StoreCertificate` job hit its
  final failure: `StoreCertificateFailed` requires a `LetsEncryptCertificate` as its
  second constructor argument, but `StoreCertificate::failed()` only passed the
  exception
- Harden ACME account key pair permissions: the private key is now `chmod`'d to
  `0600` and the public key to `0644` right after generation (best effort; never
  blocks key generation if `chmod` is unsupported by the filesystem)
- Force `private` Flysystem visibility when storing `privkey.pem` (domain certificate
  private key), independently of the consuming application's default disk
  visibility; `cert.pem`, `chain.pem` and `fullchain.pem` are unaffected and remain
  public
- Fix `chain.pem` being written with the leaf certificate instead of the issuer
  chain (`StoreCertificate` reused the `cert` PEM variable by mistake)

## V13.0.0

- Support Laravel 11, 12 and 13
- Require PHP 8.2+
- Add a `WithoutOverlapping` shared queue middleware (keyed per domain) to
  `RequestAuthorization`, `RequestCertificate` and `StoreCertificate` to prevent
  concurrent ACME jobs from racing on the same domain
- Migrate `phpunit.xml.dist` to the PHPUnit 10+ schema and drop the automatic coverage report (it made `vendor/bin/phpunit` fail outright without a coverage driver)
- Replace deprecated `@test` / `@doesNotPerformAssertions` doc-comment annotations with native PHPUnit attributes
- Update CI to test PHP 8.2-8.5 against Laravel 11-13 and modernize the GitHub Actions used

## V0.1.0

- Initial release
