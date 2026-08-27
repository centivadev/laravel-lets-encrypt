# Changelog

All notable changes to `daanra/laravel-lets-encrypt` will be documented in this file

## V13.0.0

- Support Laravel 11, 12 and 13
- Require PHP 8.2+
- Migrate `phpunit.xml.dist` to the PHPUnit 10+ schema and drop the automatic coverage report (it made `vendor/bin/phpunit` fail outright without a coverage driver)
- Replace deprecated `@test` / `@doesNotPerformAssertions` doc-comment annotations with native PHPUnit attributes
- Update CI to test PHP 8.2-8.5 against Laravel 11-13 and modernize the GitHub Actions used

## V0.1.0

- Initial release
