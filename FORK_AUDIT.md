# `laravel-lets-encrypt` fork audit — August 31, 2026

This document answers three questions: why this fork exists, what it gains or
loses compared to the official upstream (`Daanra/laravel-lets-encrypt`), and
which security/reliability fixes were applied during this audit.

Usage context: this package is consumed by a Laravel application via
`composer.json` (`repositories.vcs` pointing to the fork, `require
"daanra/laravel-lets-encrypt": "^13.0"`), with `composer.lock` pinned to an
exact commit rather than a floating tag.

## 1. Why this fork exists

Exact divergence point from official upstream: commit `6bcfe1b`
("Update PHPUnit") — the last hash strictly identical in both histories.

No commit or CHANGELOG entry explicitly states the reason for the fork. It is
reconstructed from the history and the consuming application's code:

- **Main reason**: the consuming application identified that three
  certificate-generation code paths could run concurrently on the same domain
  without a shared lock. The fork introduces a `WithoutOverlapping` middleware
  (commit `a17a6ed`) to close this gap — a feature upstream still lacks today.
- **Secondary reason**: keeping up with PHP/Laravel compatibility faster than
  upstream (which has slowed down significantly).

### Commits specific to the fork

| Commit | Date | Summary |
|---|---|---|
| `08180bb`, `9c04c72` | 2023 | Added support for requesting "www.domain" in addition to "domain" in ACME authorization requests (`AcmeClient::requestAuthorization`, `RequestAuthorization::handle`) |
| `078fac3` | — | Laravel 12 support |
| `4dda732` | — | Explicit `webmozart/assert` dependency |
| `a17a6ed` | 2026-08-26 | Added the `WithoutOverlapping('ssl-cert-gen:'.$domain)` anti-overlap middleware to `RequestAuthorization`, `RequestCertificate`, `StoreCertificate` |
| `4e025a4` | 2026-08-26 | Laravel 13 / PHP 8.2+ support, CI modernization, PHPUnit 10+ migration |

## 2. Fork vs upstream: which one is "better"?

Nuanced answer — neither is strictly superior.

**Upstream (`Daanra/laravel-lets-encrypt`, latest tag `v0.5.7` from
2026-01-13, plus an untagged commit `eef1d7d`) had two things the fork
lacked** before this audit:

- `a738270` (2026-01-13): fix for the `StoreCertificateFailed` bug — **fixed
  in this fork by this audit** (see §3).
- `c3e9e22` / `b79e943` (Nov. 2025): `Bus::chain` support in
  `RequestAuthorization::handle()`, for chaining Laravel jobs. A convenience
  feature, not critical, **not ported** (no identified need) — see the
  follow-up checklist.

**The fork has several things upstream doesn't**:

- PHP 8.2+ / Laravel 11-13 explicitly required (upstream stays on a very wide
  `^7.2|^8.0` PHP range and hasn't raised its floor).
- The `WithoutOverlapping` anti-overlap middleware — the fork's raison
  d'être, still absent from upstream.
- A modernized CI (PHP 8.2-8.5 × Laravel 11-13 matrix, PHPUnit 10+ migration,
  replacement of deprecated GitHub Actions) — upstream kept its old PHPUnit
  schema and a narrower CI.
- Automatic "www.domain" support, absent upstream.
- As of this audit: the `dns-persist-01` fix (see §3), which neither codebase
  had before today.

**Conclusion**: staying on this fork remains justified. Switching back to
upstream would lose the anti-overlap lock (a critical business feature) for
no net benefit, since the one real fix upstream had ahead of the fork
(`StoreCertificateFailed`) is now caught up here.

## 3. Fixes applied during this audit

Five changes, all independent, all verified by direct code inspection, with
no impact on the existing test suite (14 tests, 31 assertions, still green
after applying them).

### 3.1 Fix `dns-persist-01` (priority — was blocking certificate issuance)

**The problem**: Let's Encrypt introduced a new ACME challenge on February
18, 2026, `dns-persist-01` ([official announcement](https://letsencrypt.org/2026/02/18/dns-persist-01),
IETF draft [`draft-ietf-acme-dns-persist-01`](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-persist/),
ratified by the CA/Browser Forum in October 2025, production rollout planned
for Q2 2026). Unlike `http-01`/`dns-01`/`tls-alpn-01`, this challenge has no
`token` field in its JSON schema (it uses `issuer-domain-names` and an
`accounturi` instead).

`AcmeClient::requestOrder()` (`src/AcmePhp/Core/AcmeClient.php`) looped over
*all* challenges returned by the ACME server and called
`createAuthorizationChallenge()` for each one, which accesses
`$response['token']` without any check (twice). As soon as an ACME server
(staging or production) lists `dns-persist-01` among the challenges offered
for a domain — which can already happen on staging today — this access
triggers a fatal PHP error (converted into an exception by Laravel's default
error handler), and it does so on the very first ACME call of an
authorization request, whether for issuance or renewal.

**Fix** — skip challenges without a `token` before building them, since
`RequestAuthorization::getHttpChallenge()` only ever keeps `http-01`
challenges anyway:

```diff
foreach ($authorizationsResponse['challenges'] as $challenge) {
+    if (empty($challenge['token']) || ! is_string($challenge['token'])) {
+        continue;
+    }
    $authorizationsChallenges[$domain][] = $this->createAuthorizationChallenge($authorizationsResponse['identifier']['value'], $challenge);
}
```

File: `src/AcmePhp/Core/AcmeClient.php`.

### 3.2 Fix `StoreCertificate::failed()`

`src/Jobs/StoreCertificate.php::failed()` called
`event(new StoreCertificateFailed($exception))` with a single argument, while
the event's constructor requires a mandatory second parameter
(`LetsEncryptCertificate $certificate`, inherited from an upstream fix this
fork never caught up on). Result: a fatal `\ArgumentCountError` on every
final failure of the job that writes `privkey.pem` — exactly when error
handling is supposed to kick in.

```diff
 public function failed(\Throwable $exception)
 {
-    event(new StoreCertificateFailed($exception));
+    event(new StoreCertificateFailed($exception, $this->dbCertificate));
 }
```

### 3.3 Hardening ACME account key pair permissions

`LetsEncrypt::getKeyPair()` generated the ACME account key pair and wrote it
via plain `file_put_contents()`, never restricting its permissions — they
depended entirely on the system umask. With a permissive umask (022), the
account's private key would end up world-readable.

Added "best effort" hardening (`@chmod`, fails silently with no impact on key
generation) right after writing:

```php
@chmod($publicKeyPath, 0644);
@chmod($privateKeyPath, 0600);
```

This fix only protects keys generated **after** this patch — keys already
deployed with a permissive umask are not retroactively corrected (see the
follow-up checklist).

### 3.4 Forced "private" visibility for `privkey.pem`

`StoreCertificate::storeInPossiblyNonExistingDirectory()` wrote `privkey.pem`
(the domain certificate's private key, the most sensitive file this package
produces) via `Storage::put()` with no explicit visibility — protection
depended entirely on the consuming application's Laravel disk configuration,
with no guarantee by default for a consumer that didn't configure it
explicitly.

```diff
-$this->storeInPossiblyNonExistingDirectory($factory, 'privkey', $privkeyPem);
+$this->storeInPossiblyNonExistingDirectory($factory, 'privkey', $privkeyPem, 'private');
```

`cert.pem`, `chain.pem` and `fullchain.pem` are unaffected (public by
nature). Passing visibility directly into `put()` is atomic (no window where
the file would be readable before being hardened) and works regardless of the
Flysystem driver (local, S3, ...).

### 3.5 Fix `chain.pem` written with the wrong content

Discovered while re-reading `StoreCertificate::handle()` during this audit
(a pre-existing bug, unrelated to the fixes above): `chain.pem` was written
with `$certPem` (the domain certificate) instead of `$chainPem` (the issuer
chain), likely a copy-paste mistake. Concrete impact: any use of `chain.pem`
expecting the intermediate chain (e.g. nginx's `ssl_trusted_certificate` for
OCSP stapling) actually received a copy of the leaf certificate.
`fullchain.pem` was unaffected (it's built separately from
`$certPem . $chainPem`).

```diff
 $this->storeInPossiblyNonExistingDirectory($factory, 'cert', $certPem);
-$this->storeInPossiblyNonExistingDirectory($factory, 'chain', $certPem);
+$this->storeInPossiblyNonExistingDirectory($factory, 'chain', $chainPem);
```

## 4. Unfixed findings (out of scope for this audit)

- `config/lets_encrypt.php` defaults to Let's Encrypt's **staging**
  environment, with a plain comment reminding to switch to production. This
  is a generic configuration footgun in the package.
- The fork's `composer.json` keeps the original package name
  `daanra/laravel-lets-encrypt` while being installed from a separate GitHub
  remote via `repositories.vcs`. This works today because `composer.lock`
  pins an exact commit, but remains fragile long-term if a transitive
  dependency were ever to require the real upstream package.
- No test covers `AcmeClient::requestOrder()`/`createAuthorizationChallenge()`
  or `StoreCertificate::failed()`/`getKeyPair()` — the current suite
  systematically fakes the queue and bus (`Queue::fake()`/`Bus::fake()`), so
  these code paths are never actually exercised by tests.
- No `exec`/`shell_exec`/`proc_open` anywhere in `src/` — already a good
  practice in place, worth preserving (all crypto goes through PHP's native
  `openssl_*` functions).

## 5. Follow-up checklist

- [ ] Review the diff on this branch (`fix/dns-persist-01-and-security-hardening`)
      and merge into `master`
- [ ] Push to `origin` (`git push`) — **not done automatically by this audit**
- [ ] Create/tag a `v13.0.1` release on GitHub
- [ ] Update the consuming application's `composer.lock` to pin the new
      commit/tag, and redeploy — the `dns-persist-01` fix unblocks
      certificate issuance in a real environment, not just a theoretical case
- [ ] One-off manual `chmod` of ACME account keys already deployed in
      production (the patch only fixes future key generations)
- [ ] Consider renaming the composer package to avoid future confusion with
      `daanra/laravel-lets-encrypt`
- [ ] Consider porting `Bus::chain` from upstream if a need for custom job
      chaining arises
- [ ] Periodically check upstream now that the remote exists:
      `git fetch upstream && git log upstream/master --oneline`

## 6. Verification performed

- `vendor/bin/phpunit`: 14 tests, 31 assertions, green after all 5 changes.
- `php -l` on the 3 modified files: no syntax errors.
- `upstream` remote added (`https://github.com/Daanra/laravel-lets-encrypt.git`),
  no `fetch`/`push` executed.
- Work done on branch `fix/dns-persist-01-and-security-hardening`, nothing
  pushed to `origin` or `upstream`.
