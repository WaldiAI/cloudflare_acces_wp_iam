<?php

use IamLab\CloudflareAccessWpIam\Plugin;
use PHPUnit\Framework\TestCase;

final class PluginTest extends TestCase
{
    protected function setUp(): void
    {
        $GLOBALS['cfawpiam_test_options'] = [];
        $GLOBALS['cfawpiam_test_transients'] = [];
        unset($_SERVER['HTTP_CF_ACCESS_JWT_ASSERTION'], $_COOKIE['CF_Authorization']);
    }

    public function testTeamHostNormalizationAndValidationAreStrict(): void
    {
        self::assertSame('team.cloudflareaccess.com', $this->invoke('normalizeHost', ' HTTPS://TEAM.cloudflareaccess.com/ '));
        self::assertTrue($this->invoke('isValidTeamDomain', 'team.cloudflareaccess.com'));
        self::assertFalse($this->invoke('isValidTeamDomain', 'team.cloudflareaccess.com.evil.example'));
        self::assertFalse($this->invoke('isValidTeamDomain', 'cloudflareaccess.com'));
    }

    public function testClaimsRequireTheExpectedIdentityAndAudienceFields(): void
    {
        $GLOBALS['cfawpiam_test_options']['cfawpiam_settings'] = [
            'team_domain' => 'team.cloudflareaccess.com',
            'audience' => str_repeat('a', 64),
        ];

        $claims = (object) [
            'iss' => 'https://team.cloudflareaccess.com',
            'aud' => [str_repeat('a', 64)],
            'type' => 'app',
            'exp' => 200,
            'iat' => 100,
            'nbf' => 100,
            'email' => 'user@example.com',
            'sub' => 'subject-1',
            'identity_nonce' => 'nonce-1',
        ];

        self::assertTrue($this->invoke('claimsAreValid', $claims));

        $claims->type = 'org';
        self::assertFalse($this->invoke('claimsAreValid', $claims));

        $claims->type = 'app';
        $claims->aud = ['wrong'];
        self::assertFalse($this->invoke('claimsAreValid', $claims));
        self::assertSame('jwt_audience_mismatch', $this->invoke('claimsValidationError', $claims));

        $claims->aud = [str_repeat('a', 64)];
        $claims->iss = 'https://other.cloudflareaccess.com';
        self::assertSame('jwt_issuer_mismatch', $this->invoke('claimsValidationError', $claims));
    }

    public function testAccessJwtDiagnosticsDoNotExposeTokenValues(): void
    {
        unset($_SERVER['HTTP_CF_ACCESS_JWT_ASSERTION'], $_COOKIE['CF_Authorization']);
        self::assertSame(
            ['token' => '', 'error' => 'jwt_header_and_cookie_missing'],
            $this->invoke('accessJwtResult')
        );

        $_SERVER['HTTP_CF_ACCESS_JWT_ASSERTION'] = 'not-a-jwt';
        self::assertSame(
            ['token' => '', 'error' => 'jwt_format_invalid'],
            $this->invoke('accessJwtResult')
        );

        $_SERVER['HTTP_CF_ACCESS_JWT_ASSERTION'] = 'header.payload.signature';
        self::assertSame(
            ['token' => 'header.payload.signature', 'error' => ''],
            $this->invoke('accessJwtResult')
        );

        unset($_SERVER['HTTP_CF_ACCESS_JWT_ASSERTION']);
    }

    public function testJwtHeaderAcceptsMissingOptionalTypeButStillRequiresRs256(): void
    {
        $withoutType = 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZC0xIn0.payload.signature';
        self::assertSame(
            ['kid' => 'kid-1', 'error' => ''],
            $this->invoke('jwtHeaderResult', $withoutType)
        );

        $wrongAlgorithm = 'eyJhbGciOiJIUzI1NiIsImtpZCI6ImtpZC0xIn0.payload.signature';
        self::assertSame(
            ['kid' => '', 'error' => 'jwt_algorithm_invalid'],
            $this->invoke('jwtHeaderResult', $wrongAlgorithm)
        );
    }

    public function testGroupIdentifiersSupportCloudflareStringAndObjectForms(): void
    {
        $groups = [
            'wp-readers',
            ['id' => 'group-id', 'name' => 'WP-Admins', 'email' => 'admins@example.com'],
            ['name' => 'WP-Admins'],
            null,
        ];

        self::assertSame(
            ['wp-readers', 'group-id', 'WP-Admins', 'admins@example.com'],
            $this->invoke('groupIdentifiers', $groups)
        );
    }

    public function testHighestMatchingRoleWins(): void
    {
        $GLOBALS['cfawpiam_test_options']['cfawpiam_role_map'] = [
            'subscriber' => ['everyone'],
            'editor' => ['writers'],
            'administrator' => ['admins'],
        ];

        self::assertSame('administrator', $this->invoke('mappedRole', ['EVERYONE', 'admins']));
        self::assertSame('', $this->invoke('mappedRole', ['unknown']));
    }

    public function testConfigImportReplacesMappingsAndAllowsRemoval(): void
    {
        $GLOBALS['cfawpiam_test_options']['cfawpiam_role_map'] = [
            'administrator' => ['old-admins'],
            'editor' => ['old-editors'],
        ];

        $result = Plugin::applyConfig([
            'team_domain' => 'team.cloudflareaccess.com',
            'audience' => str_repeat('b', 64),
            'fallback_role' => 'deny',
            'existing_user_mode' => 'deny',
            'enforce_managed_rest' => true,
            'logout_mode' => 'app',
            'groups' => [
                'administrator' => [],
                'editor' => ['new-editors'],
            ],
        ]);

        self::assertTrue($result);
        self::assertSame(['editor' => ['new-editors']], $GLOBALS['cfawpiam_test_options']['cfawpiam_role_map']);
    }

    public function testConfigRejectsArbitraryJwksEndpointAndPrivilegedFallback(): void
    {
        $base = [
            'team_domain' => 'team.cloudflareaccess.com',
            'audience' => str_repeat('c', 64),
        ];

        $endpoint = Plugin::applyConfig($base + ['jwks_url' => 'https://evil.example/keys']);
        self::assertInstanceOf(WP_Error::class, $endpoint);
        self::assertSame('invalid_jwks_url', $endpoint->get_error_code());

        $fallback = Plugin::applyConfig($base + ['fallback_role' => 'administrator']);
        self::assertInstanceOf(WP_Error::class, $fallback);
        self::assertSame('invalid_fallback_role', $fallback->get_error_code());
    }

    public function testLegacyUpgradeAllowsOnlyTheAlreadyAuthenticatedUserToLinkOnce(): void
    {
        $GLOBALS['cfawpiam_test_options']['cfawpiam_settings'] = [
            'team_domain' => 'team.cloudflareaccess.com',
            'audience' => str_repeat('d', 64),
        ];

        $this->invoke('maybeUpgrade');

        self::assertSame(2, $GLOBALS['cfawpiam_test_options']['cfawpiam_schema_version']);
        self::assertSame('1', $GLOBALS['cfawpiam_test_options']['cfawpiam_legacy_link_pending']);
        self::assertTrue($this->invoke('legacyLinkAllowed', new WP_User(10), new WP_User(10), 'administrator'));
        self::assertFalse($this->invoke('legacyLinkAllowed', new WP_User(10), new WP_User(11), 'administrator'));
        self::assertFalse($this->invoke('legacyLinkAllowed', new WP_User(10), new WP_User(10), ''));
    }

    private function invoke(string $method, ...$arguments)
    {
        $reflection = new ReflectionMethod(Plugin::class, $method);
        $reflection->setAccessible(true);

        return $reflection->invoke(null, ...$arguments);
    }
}
