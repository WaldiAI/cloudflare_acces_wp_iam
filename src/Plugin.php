<?php

namespace IamLab\CloudflareAccessWpIam;

use Exception;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

final class Plugin
{
    private const SETTINGS_OPTION = 'cfawpiam_settings';
    private const ROLE_MAP_OPTION = 'cfawpiam_role_map';
    private const JWKS_CACHE_KEY = 'cfawpiam_cloudflare_jwks';

    public static function boot(): void
    {
        add_action('admin_menu', [self::class, 'registerSettingsPage']);
        add_action('admin_init', [self::class, 'saveSettings']);
        add_action('login_init', [self::class, 'loginFromAccessToken'], 1);
        add_action('admin_init', [self::class, 'loginFromAccessToken'], 1);
        add_filter('logout_redirect', [self::class, 'redirectAfterLogout'], 99, 3);
    }

    private static function defaults(): array
    {
        return [
            'team_domain' => '',
            'jwks_url' => '',
            'jwt_header' => 'Cf-Access-Jwt-Assertion',
            'issuer' => '',
            'audience' => '',
            'fallback_role' => 'subscriber',
            'logout_mode' => 'app',
        ];
    }

    private static function settings(): array
    {
        return array_merge(self::defaults(), (array) get_option(self::SETTINGS_OPTION, []));
    }

    public static function registerSettingsPage(): void
    {
        add_options_page(
            'Cloudflare Access WP IAM',
            'Cloudflare Access WP IAM',
            'manage_options',
            'cloudflare-access-wp-iam',
            [self::class, 'renderSettingsPage']
        );
    }

    public static function saveSettings(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (empty($_POST['cfawpiam_save']) || !check_admin_referer('cfawpiam_save_settings')) {
            return;
        }

        $importJson = self::postedString('config_json', '');

        if ($importJson !== '') {
            $decoded = json_decode($importJson, true);

            if (!is_array($decoded)) {
                add_settings_error('cfawpiam', 'invalid_json', 'Config import failed: invalid JSON.', 'error');
                return;
            }

            $result = self::applyConfig($decoded);

            if (is_wp_error($result)) {
                add_settings_error('cfawpiam', 'config_import_failed', 'Config import failed: ' . $result->get_error_message(), 'error');
                return;
            }

            add_settings_error('cfawpiam', 'config_imported', 'Config imported.', 'updated');
            return;
        }

        $settings = self::settings();
        $settings['team_domain'] = self::normalizeHost(self::postedString('team_domain', $settings['team_domain']));
        $settings['jwks_url'] = esc_url_raw(self::postedString('jwks_url', $settings['jwks_url']));
        $settings['jwt_header'] = sanitize_text_field(self::postedString('jwt_header', $settings['jwt_header']));
        $settings['issuer'] = esc_url_raw(self::postedString('issuer', $settings['issuer']));
        $settings['audience'] = sanitize_text_field(self::postedString('audience', $settings['audience']));
        $settings['fallback_role'] = sanitize_key(self::postedString('fallback_role', $settings['fallback_role']));
        $settings['logout_mode'] = sanitize_key(self::postedString('logout_mode', $settings['logout_mode']));

        if (!get_role($settings['fallback_role'])) {
            $settings['fallback_role'] = 'subscriber';
        }

        if (!in_array($settings['logout_mode'], ['disabled', 'app', 'team'], true)) {
            $settings['logout_mode'] = 'app';
        }

        update_option(self::SETTINGS_OPTION, $settings, false);

        $roleMap = (array) get_option(self::ROLE_MAP_OPTION, []);

        foreach (self::supportedRoles() as $role => $label) {
            $raw = self::postedString('groups_' . $role, '');

            if ($raw === '') {
                continue;
            }

            $roleMap[$role] = self::splitIdentifiers($raw);
        }

        update_option(self::ROLE_MAP_OPTION, $roleMap, false);
        delete_transient(self::JWKS_CACHE_KEY);

        add_settings_error('cfawpiam', 'saved', 'Settings saved.', 'updated');
    }

    /**
     * Apply configuration from automation tools such as MainWP Code Snippets.
     *
     * Accepted keys:
     * team_domain, jwks_url, jwt_header, issuer, audience, fallback_role,
     * logout_mode, groups.
     *
     * Group values are stored as plain configuration, not secrets.
     *
     * @param array $config
     * @return true|\WP_Error
     */
    public static function applyConfig(array $config)
    {
        $settings = self::settings();

        if (array_key_exists('team_domain', $config)) {
            $settings['team_domain'] = self::normalizeHost((string) $config['team_domain']);
        }

        if (array_key_exists('jwks_url', $config)) {
            $settings['jwks_url'] = esc_url_raw((string) $config['jwks_url']);
        }

        if (array_key_exists('jwt_header', $config)) {
            $settings['jwt_header'] = sanitize_text_field((string) $config['jwt_header']);
        }

        if (array_key_exists('issuer', $config)) {
            $settings['issuer'] = esc_url_raw((string) $config['issuer']);
        }

        if (array_key_exists('audience', $config)) {
            $settings['audience'] = sanitize_text_field((string) $config['audience']);
        }

        if (array_key_exists('fallback_role', $config)) {
            $settings['fallback_role'] = sanitize_key((string) $config['fallback_role']);
        }

        if (array_key_exists('logout_mode', $config)) {
            $settings['logout_mode'] = sanitize_key((string) $config['logout_mode']);
        }

        if ($settings['team_domain'] === '') {
            return new \WP_Error('missing_team_domain', 'team_domain is required.');
        }

        if ($settings['jwks_url'] === '') {
            return new \WP_Error('missing_jwks_url', 'jwks_url is required.');
        }

        if ($settings['issuer'] === '') {
            return new \WP_Error('missing_issuer', 'issuer is required.');
        }

        if ($settings['audience'] === '') {
            return new \WP_Error('missing_audience', 'audience is required.');
        }

        if (!get_role($settings['fallback_role'])) {
            return new \WP_Error('invalid_fallback_role', 'fallback_role is not a valid WordPress role.');
        }

        if (!in_array($settings['logout_mode'], ['disabled', 'app', 'team'], true)) {
            return new \WP_Error('invalid_logout_mode', 'logout_mode must be one of: disabled, app, team.');
        }

        $roleMap = null;

        if (array_key_exists('groups', $config)) {
            if (!is_array($config['groups'])) {
                return new \WP_Error('invalid_groups', 'groups must be an object keyed by WordPress role.');
            }

            $roleMap = [];

            foreach ($config['groups'] as $role => $identifiers) {
                $role = sanitize_key((string) $role);

                if (!array_key_exists($role, self::supportedRoles())) {
                    return new \WP_Error('invalid_group_role', 'Unsupported role in groups: ' . $role);
                }

                if (is_string($identifiers)) {
                    $identifiers = self::splitIdentifiers($identifiers);
                }

                if (!is_array($identifiers)) {
                    return new \WP_Error('invalid_group_values', 'Group values for role ' . $role . ' must be an array or string.');
                }

                $identifiers = array_values(array_filter(array_map(static function ($value): string {
                    return trim((string) $value);
                }, $identifiers)));

                if ($identifiers) {
                    $roleMap[$role] = $identifiers;
                }
            }
        }

        update_option(self::SETTINGS_OPTION, $settings, false);

        if ($roleMap !== null) {
            update_option(self::ROLE_MAP_OPTION, $roleMap, false);
        }

        delete_transient(self::JWKS_CACHE_KEY);

        return true;
    }

    public static function renderSettingsPage(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $settings = self::settings();
        $roleMap = (array) get_option(self::ROLE_MAP_OPTION, []);

        settings_errors('cfawpiam');
        ?>
        <div class="wrap">
            <h1>Cloudflare Access WP IAM</h1>
            <p>Use Cloudflare Access as the IAM gateway for WordPress. Works with Okta, Google Workspace, Entra ID, and other Cloudflare Access IdPs.</p>

            <form method="post">
                <?php wp_nonce_field('cfawpiam_save_settings'); ?>

                <h2>Cloudflare Access</h2>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">Team domain</th>
                        <td>
                            <input type="text" name="team_domain" class="regular-text" value="<?php echo esc_attr($settings['team_domain']); ?>" placeholder="team.cloudflareaccess.com" />
                            <p class="description">Example: your-team.cloudflareaccess.com</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">JWKS URL</th>
                        <td>
                            <input type="url" name="jwks_url" class="regular-text" value="<?php echo esc_attr($settings['jwks_url']); ?>" placeholder="https://team.cloudflareaccess.com/cdn-cgi/access/certs" />
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">JWT header</th>
                        <td>
                            <input type="text" name="jwt_header" class="regular-text" value="<?php echo esc_attr($settings['jwt_header']); ?>" />
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Issuer</th>
                        <td>
                            <input type="url" name="issuer" class="regular-text" value="<?php echo esc_attr($settings['issuer']); ?>" placeholder="https://team.cloudflareaccess.com" />
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Audience</th>
                        <td>
                            <input type="text" name="audience" class="regular-text" value="<?php echo esc_attr($settings['audience']); ?>" placeholder="Cloudflare Access AUD tag" autocomplete="off" />
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Fallback role</th>
                        <td>
                            <select name="fallback_role"><?php wp_dropdown_roles($settings['fallback_role']); ?></select>
                            <p class="description">Used only when a new WordPress user is created and no mapped group matches.</p>
                        </td>
                    </tr>
                </table>

                <h2>Group to Role Mapping</h2>
                <p>Paste Google group emails, Cloudflare group names, or group IDs. Use one value per line. These values are configuration, not secrets.</p>
                <table class="form-table" role="presentation">
                    <?php foreach (self::supportedRoles() as $role => $label): ?>
                        <tr>
                            <th scope="row"><?php echo esc_html($label); ?></th>
                            <td>
                                <textarea name="groups_<?php echo esc_attr($role); ?>" class="large-text code" rows="3" placeholder="wp-admins"><?php echo esc_textarea(self::roleMapTextareaValue($roleMap, $role)); ?></textarea>
                                <p class="description"><?php echo !empty($roleMap[$role]) ? 'Configured.' : 'Not configured.'; ?></p>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>

                <h2>Logout</h2>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">Logout mode</th>
                        <td>
                            <select name="logout_mode">
                                <option value="app" <?php selected($settings['logout_mode'], 'app'); ?>>WordPress + Cloudflare application logout</option>
                                <option value="team" <?php selected($settings['logout_mode'], 'team'); ?>>WordPress + Cloudflare team logout</option>
                                <option value="disabled" <?php selected($settings['logout_mode'], 'disabled'); ?>>WordPress only</option>
                            </select>
                        </td>
                    </tr>
                </table>

                <h2>Fleet config import</h2>
                <p>Paste JSON generated for MainWP or bulk deployments. Do not include API tokens, client secrets, SAML responses, JWTs, or cookies.</p>
                <textarea name="config_json" class="large-text code" rows="14" placeholder="<?php echo esc_attr(self::exampleConfigJson($settings)); ?>"></textarea>
                <p class="description">If this field is not empty, JSON import takes priority over the fields above.</p>

                <p><button type="submit" name="cfawpiam_save" value="1" class="button button-primary">Save settings</button></p>
            </form>
        </div>
        <?php
    }

    public static function loginFromAccessToken(): void
    {
        if (self::isLogoutRequest()) {
            return;
        }

        $jwt = self::accessJwt();

        if ($jwt === '') {
            return;
        }

        $payload = self::verifiedPayload($jwt);

        if (!$payload || empty($payload->email)) {
            return;
        }

        $email = sanitize_email((string) $payload->email);

        if (!$email || !is_email($email)) {
            return;
        }

        $currentUser = wp_get_current_user();

        if ($currentUser && $currentUser->exists() && strtolower((string) $currentUser->user_email) === strtolower($email)) {
            self::applyMappedRole($currentUser, (string) $payload->email);
            return;
        }

        $user = get_user_by('email', $email);

        if (!$user) {
            $userId = wp_create_user($email, wp_generate_password(64, true, true), $email);

            if (is_wp_error($userId)) {
                return;
            }

            $user = get_user_by('id', $userId);

            if (!$user) {
                return;
            }

            $fallbackRole = self::settings()['fallback_role'];
            $user->set_role($fallbackRole);
        }

        wp_clear_auth_cookie();
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID);

        self::applyMappedRole($user, (string) $payload->email);

        do_action('wp_login', $user->user_login, $user);

        if (defined('DOING_AJAX') && DOING_AJAX) {
            return;
        }

        if (is_admin() && !wp_doing_ajax()) {
            return;
        }

        $redirectTo = isset($_GET['redirect_to']) ? esc_url_raw(wp_unslash($_GET['redirect_to'])) : admin_url();

        wp_safe_redirect($redirectTo ?: admin_url());
        exit;
    }

    public static function redirectAfterLogout($redirectTo, $requestedRedirectTo, $user): string
    {
        $settings = self::settings();

        if ($settings['logout_mode'] === 'disabled') {
            return (string) $redirectTo;
        }

        if ($settings['logout_mode'] === 'team' && $settings['team_domain'] !== '') {
            return 'https://' . $settings['team_domain'] . '/cdn-cgi/access/logout';
        }

        return home_url('/cdn-cgi/access/logout');
    }

    private static function verifiedPayload(string $jwt): ?object
    {
        $keys = self::jwks();

        if (!$keys) {
            return null;
        }

        try {
            $payload = JWT::decode($jwt, JWK::parseKeySet(['keys' => $keys['keys']]));
        } catch (Exception $e) {
            return null;
        }

        return self::claimsAreValid($payload) ? $payload : null;
    }

    private static function claimsAreValid($payload): bool
    {
        if (!is_object($payload)) {
            return false;
        }

        $settings = self::settings();
        $issuer = trim((string) $settings['issuer']);
        $audience = trim((string) $settings['audience']);

        if ($issuer === '' || $audience === '') {
            return false;
        }

        if (($payload->iss ?? '') !== $issuer) {
            return false;
        }

        $aud = $payload->aud ?? [];

        if (is_string($aud)) {
            $aud = [$aud];
        }

        return is_array($aud) && in_array($audience, $aud, true);
    }

    private static function jwks(): ?array
    {
        $cached = get_transient(self::JWKS_CACHE_KEY);

        if (is_array($cached)) {
            return $cached;
        }

        $settings = self::settings();

        if ($settings['jwks_url'] === '') {
            return null;
        }

        $response = wp_remote_get($settings['jwks_url'], ['timeout' => 10]);

        if (is_wp_error($response)) {
            return null;
        }

        $json = json_decode(wp_remote_retrieve_body($response), true);

        if (!is_array($json) || empty($json['keys']) || !is_array($json['keys'])) {
            return null;
        }

        set_transient(self::JWKS_CACHE_KEY, $json, WEEK_IN_SECONDS);

        return $json;
    }

    private static function applyMappedRole($user, string $expectedEmail): void
    {
        $identifiers = self::cloudflareGroupIdentifiers($expectedEmail);
        $roleMap = (array) get_option(self::ROLE_MAP_OPTION, []);

        if (!$identifiers || !$roleMap) {
            return;
        }

        $priority = [
            'administrator' => 5,
            'editor' => 4,
            'author' => 3,
            'contributor' => 2,
            'subscriber' => 1,
        ];

        $bestRole = '';
        $bestScore = 0;
        $normalizedIdentifiers = self::normalizeIdentifiers($identifiers);

        foreach ($roleMap as $role => $storedIdentifiers) {
            if (!isset($priority[$role]) || !is_array($storedIdentifiers)) {
                continue;
            }

            foreach (self::normalizeIdentifiers($storedIdentifiers) as $storedIdentifier) {
                foreach ($normalizedIdentifiers as $identifier) {
                    if (hash_equals($storedIdentifier, $identifier) && $priority[$role] > $bestScore) {
                        $bestRole = $role;
                        $bestScore = $priority[$role];
                    }
                }
            }
        }

        if ($bestRole && get_role($bestRole) && !in_array($bestRole, (array) $user->roles, true)) {
            $wpUser = new \WP_User($user->ID);
            $wpUser->set_role($bestRole);
        }
    }

    private static function cloudflareGroupIdentifiers(string $expectedEmail): array
    {
        if (empty($_COOKIE['CF_Authorization'])) {
            return [];
        }

        $settings = self::settings();

        if ($settings['team_domain'] === '') {
            return [];
        }

        $response = wp_remote_get(
            'https://' . $settings['team_domain'] . '/cdn-cgi/access/get-identity',
            [
                'headers' => [
                    'Cookie' => 'CF_Authorization=' . sanitize_text_field(wp_unslash($_COOKIE['CF_Authorization'])),
                ],
                'timeout' => 10,
            ]
        );

        if (is_wp_error($response)) {
            return [];
        }

        $identity = json_decode(wp_remote_retrieve_body($response), true);

        if (!is_array($identity)) {
            return [];
        }

        if (!empty($identity['email']) && strtolower((string) $identity['email']) !== strtolower($expectedEmail)) {
            return [];
        }

        if (empty($identity['groups']) || !is_array($identity['groups'])) {
            return [];
        }

        $identifiers = [];

        foreach ($identity['groups'] as $group) {
            if (is_string($group)) {
                $identifiers[] = $group;
                continue;
            }

            if (!is_array($group)) {
                continue;
            }

            foreach (['id', 'name', 'email'] as $key) {
                if (!empty($group[$key])) {
                    $identifiers[] = (string) $group[$key];
                }
            }
        }

        return array_values(array_unique(array_filter($identifiers)));
    }

    private static function accessJwt(): string
    {
        $settings = self::settings();
        $serverHeader = 'HTTP_' . str_replace('-', '_', strtoupper($settings['jwt_header']));

        if (empty($_SERVER[$serverHeader])) {
            return '';
        }

        $value = sanitize_text_field(wp_unslash($_SERVER[$serverHeader]));

        if (stripos($value, 'Bearer ') === 0) {
            $value = trim(substr($value, 7));
        }

        return $value;
    }

    private static function isLogoutRequest(): bool
    {
        $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';

        return $action === 'logout' || isset($_GET['loggedout']);
    }

    private static function supportedRoles(): array
    {
        return [
            'administrator' => 'Administrator',
            'editor' => 'Editor',
            'author' => 'Author',
            'contributor' => 'Contributor',
            'subscriber' => 'Subscriber',
        ];
    }

    private static function exampleConfigJson(array $settings): string
    {
        return wp_json_encode([
            'team_domain' => $settings['team_domain'] ?: 'your-team.cloudflareaccess.com',
            'jwks_url' => $settings['jwks_url'] ?: 'https://your-team.cloudflareaccess.com/cdn-cgi/access/certs',
            'jwt_header' => $settings['jwt_header'] ?: 'Cf-Access-Jwt-Assertion',
            'issuer' => $settings['issuer'] ?: 'https://your-team.cloudflareaccess.com',
            'audience' => $settings['audience'] ?: 'Cloudflare Access AUD tag',
            'fallback_role' => $settings['fallback_role'] ?: 'subscriber',
            'logout_mode' => $settings['logout_mode'] ?: 'app',
            'groups' => [
                'administrator' => ['wp-admins'],
                'editor' => ['wp-editors'],
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    private static function roleMapTextareaValue(array $roleMap, string $role): string
    {
        if (empty($roleMap[$role]) || !is_array($roleMap[$role])) {
            return '';
        }

        return implode("\n", array_map('strval', $roleMap[$role]));
    }

    private static function postedString(string $key, string $default): string
    {
        if (!isset($_POST[$key])) {
            return $default;
        }

        return trim((string) wp_unslash($_POST[$key]));
    }

    private static function splitIdentifiers(string $raw): array
    {
        $items = preg_split('/[\r\n,]+/', $raw) ?: [];

        return array_values(array_unique(array_filter(array_map('trim', $items))));
    }

    private static function normalizeIdentifiers(array $identifiers): array
    {
        return array_values(array_unique(array_filter(array_map(static function ($value): string {
            return strtolower(trim((string) $value));
        }, $identifiers))));
    }

    private static function normalizeHost(string $host): string
    {
        $host = preg_replace('#^https?://#', '', trim($host));

        return trim((string) $host, "/ \t\n\r\0\x0B");
    }
}
