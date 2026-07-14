<?php

namespace IamLab\CloudflareAccessWpIam;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Throwable;

final class Plugin
{
    private const SETTINGS_OPTION = 'cfawpiam_settings';
    private const ROLE_MAP_OPTION = 'cfawpiam_role_map';
    private const AUDIT_LOG_OPTION = 'cfawpiam_audit_log';
    private const SCHEMA_VERSION_OPTION = 'cfawpiam_schema_version';
    private const LEGACY_LINK_OPTION = 'cfawpiam_legacy_link_pending';
    private const JWKS_CACHE_KEY = 'cfawpiam_cloudflare_jwks';
    private const JWKS_REFRESH_LOCK_KEY = 'cfawpiam_jwks_refresh_lock';
    private const MANAGED_USER_META = 'cfawpiam_managed';
    private const SUBJECT_META = 'cfawpiam_subject';
    private const JWT_HEADER = 'Cf-Access-Jwt-Assertion';
    private const MAX_TOKEN_BYTES = 32768;
    private const MAX_RESPONSE_BYTES = 262144;
    private const JWKS_TTL = 21600;

    public static function boot(): void
    {
        self::maybeUpgrade();
        add_action('admin_menu', [self::class, 'registerSettingsPage']);
        add_action('admin_init', [self::class, 'saveSettings']);
        add_action('login_init', [self::class, 'loginFromAccessToken'], 1);
        add_action('admin_init', [self::class, 'loginFromAccessToken'], 1);
        add_filter('authenticate', [self::class, 'blockNativeAuthentication'], 99, 3);
        add_filter('allow_password_reset', [self::class, 'allowPasswordReset'], 10, 2);
        add_filter('wp_is_application_passwords_available_for_user', [self::class, 'applicationPasswordsAvailable'], 10, 2);
        add_filter('rest_authentication_errors', [self::class, 'enforceManagedRestAuthentication'], 110);
        add_filter('logout_redirect', [self::class, 'redirectAfterLogout'], 99, 3);
        add_filter('allowed_redirect_hosts', [self::class, 'allowTeamLogoutHost'], 10, 2);
        add_filter('site_status_tests', [self::class, 'registerSiteHealthTests']);
    }

    private static function defaults(): array
    {
        return [
            'team_domain' => '',
            'jwks_url' => '',
            'jwt_header' => self::JWT_HEADER,
            'issuer' => '',
            'audience' => '',
            'fallback_role' => 'deny',
            'existing_user_mode' => 'deny',
            'enforce_managed_rest' => true,
            'logout_mode' => 'app',
        ];
    }

    private static function settings(): array
    {
        $settings = array_merge(self::defaults(), (array) get_option(self::SETTINGS_OPTION, []));
        $settings['team_domain'] = self::normalizeHost(self::scalarString($settings['team_domain']));
        $settings['jwt_header'] = self::JWT_HEADER;

        if (self::isValidTeamDomain($settings['team_domain'])) {
            $settings['issuer'] = 'https://' . $settings['team_domain'];
            $settings['jwks_url'] = $settings['issuer'] . '/cdn-cgi/access/certs';
        } else {
            $settings['issuer'] = '';
            $settings['jwks_url'] = '';
        }

        $settings['audience'] = self::scalarString($settings['audience']);
        $settings['fallback_role'] = self::scalarString($settings['fallback_role']);
        $settings['existing_user_mode'] = self::scalarString($settings['existing_user_mode']);
        $settings['logout_mode'] = self::scalarString($settings['logout_mode']);

        if (!in_array($settings['fallback_role'], ['deny', 'subscriber'], true)) {
            $settings['fallback_role'] = 'deny';
        }

        if (!in_array($settings['existing_user_mode'], ['deny', 'link'], true)) {
            $settings['existing_user_mode'] = 'deny';
        }

        if (!in_array($settings['logout_mode'], ['disabled', 'app', 'team'], true)) {
            $settings['logout_mode'] = 'app';
        }

        $settings['enforce_managed_rest'] = self::toBool($settings['enforce_managed_rest']);

        return $settings;
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

        if (empty($_POST['cfawpiam_save'])) {
            return;
        }

        check_admin_referer('cfawpiam_save_settings');

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

        $groups = [];

        foreach (self::supportedRoles() as $role => $label) {
            $groups[$role] = self::splitIdentifiers(self::postedString('groups_' . $role, ''));
        }

        $result = self::applyConfig([
            'team_domain' => self::postedString('team_domain', ''),
            'jwt_header' => self::JWT_HEADER,
            'audience' => self::postedString('audience', ''),
            'fallback_role' => self::postedString('fallback_role', 'deny'),
            'existing_user_mode' => self::postedString('existing_user_mode', 'deny'),
            'enforce_managed_rest' => !empty($_POST['enforce_managed_rest']),
            'logout_mode' => self::postedString('logout_mode', 'app'),
            'groups' => $groups,
        ]);

        if (is_wp_error($result)) {
            add_settings_error('cfawpiam', 'save_failed', 'Settings were not saved: ' . $result->get_error_message(), 'error');
            return;
        }

        add_settings_error('cfawpiam', 'saved', 'Settings saved.', 'updated');
    }

    /**
     * Apply configuration from automation tools such as MainWP Code Snippets.
     *
     * Accepted keys: team_domain, jwks_url, jwt_header, issuer, audience,
     * fallback_role, existing_user_mode, enforce_managed_rest, logout_mode,
     * and groups.
     *
     * @param array $config
     * @return true|\WP_Error
     */
    public static function applyConfig(array $config)
    {
        $settings = self::settings();

        foreach (['issuer', 'jwks_url'] as $derivedKey) {
            if (array_key_exists($derivedKey, $config) && !is_scalar($config[$derivedKey]) && $config[$derivedKey] !== null) {
                return new \WP_Error('invalid_' . $derivedKey, $derivedKey . ' must be a scalar value.');
            }
        }

        foreach (['team_domain', 'jwt_header', 'audience', 'fallback_role', 'existing_user_mode', 'logout_mode'] as $key) {
            if (!array_key_exists($key, $config)) {
                continue;
            }

            if (!is_scalar($config[$key]) && $config[$key] !== null) {
                return new \WP_Error('invalid_' . $key, $key . ' must be a scalar value.');
            }

            $settings[$key] = trim((string) $config[$key]);
        }

        $settings['team_domain'] = self::normalizeHost($settings['team_domain']);

        if (!self::isValidTeamDomain($settings['team_domain'])) {
            return new \WP_Error('invalid_team_domain', 'team_domain must be a valid <team>.cloudflareaccess.com hostname.');
        }

        $expectedIssuer = 'https://' . $settings['team_domain'];
        $expectedJwksUrl = $expectedIssuer . '/cdn-cgi/access/certs';

        if (array_key_exists('issuer', $config) && trim((string) $config['issuer']) !== $expectedIssuer) {
            return new \WP_Error('invalid_issuer', 'issuer must exactly match the configured Cloudflare team domain.');
        }

        if (array_key_exists('jwks_url', $config) && trim((string) $config['jwks_url']) !== $expectedJwksUrl) {
            return new \WP_Error('invalid_jwks_url', 'jwks_url must be the Cloudflare certs endpoint for the configured team domain.');
        }

        $settings['issuer'] = $expectedIssuer;
        $settings['jwks_url'] = $expectedJwksUrl;

        if ($settings['jwt_header'] !== self::JWT_HEADER) {
            return new \WP_Error('invalid_jwt_header', 'jwt_header must be Cf-Access-Jwt-Assertion.');
        }

        $settings['audience'] = trim($settings['audience']);

        if (!preg_match('/^[A-Za-z0-9_-]{16,255}$/', $settings['audience'])) {
            return new \WP_Error('invalid_audience', 'audience must be a valid Cloudflare Access AUD tag.');
        }

        $settings['fallback_role'] = sanitize_key($settings['fallback_role']);

        if (!in_array($settings['fallback_role'], ['deny', 'subscriber'], true)) {
            return new \WP_Error('invalid_fallback_role', 'fallback_role must be deny or subscriber.');
        }

        $settings['existing_user_mode'] = sanitize_key($settings['existing_user_mode']);

        if (!in_array($settings['existing_user_mode'], ['deny', 'link'], true)) {
            return new \WP_Error('invalid_existing_user_mode', 'existing_user_mode must be deny or link.');
        }

        $settings['logout_mode'] = sanitize_key($settings['logout_mode']);

        if (!in_array($settings['logout_mode'], ['disabled', 'app', 'team'], true)) {
            return new \WP_Error('invalid_logout_mode', 'logout_mode must be disabled, app, or team.');
        }

        if (array_key_exists('enforce_managed_rest', $config)) {
            if (!is_scalar($config['enforce_managed_rest']) && $config['enforce_managed_rest'] !== null) {
                return new \WP_Error('invalid_enforce_managed_rest', 'enforce_managed_rest must be a boolean-like scalar value.');
            }

            $settings['enforce_managed_rest'] = self::toBool($config['enforce_managed_rest']);
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

                if (count($identifiers) > 200) {
                    return new \WP_Error('too_many_group_values', 'A role may contain at most 200 group identifiers.');
                }

                $clean = [];

                foreach ($identifiers as $identifier) {
                    if (!is_scalar($identifier)) {
                        return new \WP_Error('invalid_group_identifier', 'Group identifiers must be scalar values.');
                    }

                    $identifier = trim((string) $identifier);

                    if ($identifier === '') {
                        continue;
                    }

                    if (strlen($identifier) > 255 || preg_match('/[\x00-\x1F\x7F]/', $identifier)) {
                        return new \WP_Error('invalid_group_identifier', 'Group identifiers must be at most 255 characters and contain no control characters.');
                    }

                    $clean[] = $identifier;
                }

                $clean = array_values(array_unique($clean));

                if ($clean) {
                    $roleMap[$role] = $clean;
                }
            }
        }

        update_option(self::SETTINGS_OPTION, $settings, false);

        if ($roleMap !== null) {
            update_option(self::ROLE_MAP_OPTION, $roleMap, false);
        }

        delete_transient(self::JWKS_CACHE_KEY);
        delete_transient(self::JWKS_REFRESH_LOCK_KEY);
        self::audit('configuration_updated', ['user_id' => get_current_user_id()]);

        return true;
    }

    public static function renderSettingsPage(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $settings = self::settings();
        $roleMap = (array) get_option(self::ROLE_MAP_OPTION, []);
        $auditLog = array_slice((array) get_option(self::AUDIT_LOG_OPTION, []), 0, 20);

        settings_errors('cfawpiam');
        ?>
        <div class="wrap">
            <h1>Cloudflare Access WP IAM</h1>
            <p>Cloudflare Access is the trust boundary. Managed WordPress accounts can only authenticate through a verified Access identity.</p>

            <form method="post">
                <?php wp_nonce_field('cfawpiam_save_settings'); ?>

                <h2>Cloudflare Access</h2>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">Team domain</th>
                        <td>
                            <input type="text" name="team_domain" class="regular-text" value="<?php echo esc_attr($settings['team_domain']); ?>" placeholder="team.cloudflareaccess.com" />
                            <p class="description">Only a valid &lt;team&gt;.cloudflareaccess.com hostname is accepted.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">JWKS URL</th>
                        <td><input type="url" class="regular-text" value="<?php echo esc_attr($settings['jwks_url']); ?>" readonly /></td>
                    </tr>
                    <tr>
                        <th scope="row">JWT header</th>
                        <td><input type="text" class="regular-text" value="<?php echo esc_attr(self::JWT_HEADER); ?>" readonly /></td>
                    </tr>
                    <tr>
                        <th scope="row">Issuer</th>
                        <td><input type="url" class="regular-text" value="<?php echo esc_attr($settings['issuer']); ?>" readonly /></td>
                    </tr>
                    <tr>
                        <th scope="row">Audience</th>
                        <td><input type="text" name="audience" class="regular-text" value="<?php echo esc_attr($settings['audience']); ?>" placeholder="Cloudflare Access AUD tag" autocomplete="off" /></td>
                    </tr>
                    <tr>
                        <th scope="row">No mapped group</th>
                        <td>
                            <select name="fallback_role">
                                <option value="deny" <?php selected($settings['fallback_role'], 'deny'); ?>>Deny access and remove managed roles</option>
                                <option value="subscriber" <?php selected($settings['fallback_role'], 'subscriber'); ?>>Allow as Subscriber</option>
                            </select>
                            <p class="description">Privileged fallback roles are intentionally not supported.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Existing WordPress accounts</th>
                        <td>
                            <select name="existing_user_mode">
                                <option value="deny" <?php selected($settings['existing_user_mode'], 'deny'); ?>>Do not link automatically</option>
                                <option value="link" <?php selected($settings['existing_user_mode'], 'link'); ?>>Allow one-time verified email linking</option>
                            </select>
                            <p class="description">Keep this set to deny for break-glass accounts. Linking requires a mapped group and permanently binds the account to the Cloudflare subject.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Managed REST access</th>
                        <td>
                            <label><input type="checkbox" name="enforce_managed_rest" value="1" <?php checked($settings['enforce_managed_rest']); ?> /> Require a valid Cloudflare JWT for authenticated REST requests by managed users</label>
                            <p class="description">Browser requests may use the validated CF_Authorization application cookie when the Access header is not present.</p>
                        </td>
                    </tr>
                </table>

                <h2>Group to Role Mapping</h2>
                <p>Use exact group IDs, names, or emails returned by Cloudflare. Clearing a field removes its mapping.</p>
                <table class="form-table" role="presentation">
                    <?php foreach (self::supportedRoles() as $role => $label): ?>
                        <tr>
                            <th scope="row"><?php echo esc_html($label); ?></th>
                            <td><textarea name="groups_<?php echo esc_attr($role); ?>" class="large-text code" rows="3" placeholder="wp-<?php echo esc_attr($role); ?>s"><?php echo esc_textarea(self::roleMapTextareaValue($roleMap, $role)); ?></textarea></td>
                        </tr>
                    <?php endforeach; ?>
                </table>

                <h2>Logout</h2>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">Logout mode</th>
                        <td>
                            <select name="logout_mode">
                                <option value="app" <?php selected($settings['logout_mode'], 'app'); ?>>Cloudflare logout through the application domain</option>
                                <option value="team" <?php selected($settings['logout_mode'], 'team'); ?>>Cloudflare logout through the team domain</option>
                                <option value="disabled" <?php selected($settings['logout_mode'], 'disabled'); ?>>WordPress only</option>
                            </select>
                            <p class="description">Both Cloudflare URLs revoke the Access session; they differ in which browser-domain cookie is cleared immediately.</p>
                        </td>
                    </tr>
                </table>

                <h2>Fleet config import</h2>
                <p>Do not include API tokens, client secrets, SAML responses, JWTs, or cookies.</p>
                <textarea name="config_json" class="large-text code" rows="16" placeholder="<?php echo esc_attr(self::exampleConfigJson($settings)); ?>"></textarea>
                <p><button type="submit" name="cfawpiam_save" value="1" class="button button-primary">Save settings</button></p>
            </form>

            <h2>Recent IAM security events</h2>
            <?php if (!$auditLog): ?>
                <p>No security events recorded.</p>
            <?php else: ?>
                <table class="widefat striped">
                    <thead><tr><th>Time (UTC)</th><th>Event</th><th>User ID</th><th>Details</th></tr></thead>
                    <tbody>
                    <?php foreach ($auditLog as $entry): ?>
                        <tr>
                            <td><?php echo esc_html((string) ($entry['time'] ?? '')); ?></td>
                            <td><?php echo esc_html((string) ($entry['event'] ?? '')); ?></td>
                            <td><?php echo esc_html((string) ($entry['user_id'] ?? '')); ?></td>
                            <td><?php echo esc_html(self::auditDetails($entry)); ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
        <?php
    }

    public static function loginFromAccessToken(): void
    {
        if ((defined('WP_CLI') && WP_CLI) || self::isLogoutRequest()) {
            return;
        }

        $currentUser = wp_get_current_user();
        $currentManaged = $currentUser && $currentUser->exists() && self::isManagedUser($currentUser);
        $tokenResult = self::accessJwtResult();
        $jwt = $tokenResult['token'];

        if ($jwt === '') {
            self::audit('access_token_rejected', [
                'user_id' => $currentManaged ? $currentUser->ID : 0,
                'error' => $tokenResult['error'],
            ], true);

            if ($currentManaged) {
                self::denyAccess('A Cloudflare Access token is required for this managed account.');
            }
            return;
        }

        $verification = self::verifiedPayloadResult($jwt);

        if (is_wp_error($verification)) {
            self::audit('access_token_rejected', [
                'user_id' => $currentManaged ? $currentUser->ID : 0,
                'error' => $verification->get_error_code(),
            ], true);

            if ($currentManaged) {
                self::denyAccess('The Cloudflare Access token could not be verified.');
            }
            return;
        }

        $payload = $verification;

        $email = sanitize_email((string) $payload->email);
        $subject = trim((string) $payload->sub);

        if (!$email || !is_email($email) || $subject === '') {
            if ($currentManaged) {
                self::denyAccess('The verified Cloudflare identity is incomplete.');
            }
            return;
        }

        if ($currentUser && $currentUser->exists() && strtolower((string) $currentUser->user_email) !== strtolower($email)) {
            self::audit('wordpress_cloudflare_identity_mismatch', ['user_id' => $currentUser->ID], true);
            self::denyAccess('The active WordPress and Cloudflare identities do not match.');
        }

        $authorization = self::identityAndRole($payload, $email, $jwt);

        if (is_wp_error($authorization)) {
            self::audit('identity_lookup_failed', [
                'user_id' => $currentUser && $currentUser->exists() ? $currentUser->ID : 0,
                'error' => $authorization->get_error_code(),
            ], true);
            self::denyAccess('Cloudflare identity and group membership could not be verified.');
        }

        $mappedRole = $authorization['mapped_role'];
        $targetRole = $authorization['target_role'];
        $user = get_user_by('email', $email);
        $isNewUser = false;
        $sessionsRevoked = false;

        if (!$user) {
            if ($targetRole === '') {
                self::audit('access_denied_no_mapped_group', ['user_id' => 0], true);
                self::denyAccess('Your Cloudflare identity is not mapped to a WordPress role.');
            }

            $user = self::createManagedUser($email, $subject, $targetRole);

            if (is_wp_error($user)) {
                self::audit('jit_provisioning_failed', ['error' => $user->get_error_code()], true);
                self::denyAccess('The managed WordPress account could not be created.');
            }

            $isNewUser = true;
        } elseif (self::isManagedUser($user)) {
            $boundSubject = (string) get_user_meta($user->ID, self::SUBJECT_META, true);

            if ($boundSubject === '' || !hash_equals($boundSubject, $subject)) {
                self::revokeManagedAccess($user, 'cloudflare_subject_mismatch');
                self::denyAccess('The Cloudflare subject does not match the account binding. An administrator must rebind the account.');
            }
        } else {
            $settings = self::settings();
            $legacyLink = self::legacyLinkAllowed($currentUser, $user, $mappedRole);

            if (($settings['existing_user_mode'] !== 'link' && !$legacyLink) || $mappedRole === '') {
                self::audit('existing_user_link_denied', ['user_id' => $user->ID], true);
                self::denyAccess('This existing WordPress account is not linked to Cloudflare Access.');
            }

            $binding = self::markManaged($user, $subject, true);

            if (is_wp_error($binding)) {
                self::audit('existing_user_binding_failed', ['user_id' => $user->ID, 'error' => $binding->get_error_code()]);
                self::denyAccess('The WordPress account could not be bound to Cloudflare Access.');
            }

            if ($legacyLink) {
                delete_option(self::LEGACY_LINK_OPTION);
                self::audit('legacy_upgrade_link_completed', ['user_id' => $user->ID]);
            }

            $sessionsRevoked = true;
        }

        if ($targetRole === '') {
            self::revokeManagedAccess($user, 'no_mapped_group');
            self::denyAccess('Your Cloudflare identity is not mapped to a WordPress role.');
        }

        $sync = self::syncManagedRole($user, $targetRole);

        if (is_wp_error($sync)) {
            self::revokeManagedAccess($user, 'invalid_target_role');
            self::denyAccess('The mapped WordPress role is unavailable.');
        }

        $sessionsRevoked = $sessionsRevoked || $sync['sessions_revoked'];

        $sameCurrentUser = $currentUser && $currentUser->exists() && (int) $currentUser->ID === (int) $user->ID;
        $establishSession = !$sameCurrentUser || $sessionsRevoked;

        if ($establishSession) {
            wp_clear_auth_cookie();
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID, false, is_ssl());
            do_action('wp_login', $user->user_login, $user);
        }

        if (defined('DOING_AJAX') && DOING_AJAX) {
            return;
        }

        if (is_admin() && !wp_doing_ajax()) {
            return;
        }

        if ($isNewUser || $establishSession || self::isLoginRequest()) {
            $redirectTo = isset($_GET['redirect_to']) ? esc_url_raw(wp_unslash($_GET['redirect_to'])) : admin_url();
            wp_safe_redirect($redirectTo ?: admin_url());
            exit;
        }
    }

    public static function blockNativeAuthentication($user, $username, $password)
    {
        if ($user instanceof \WP_User && self::isManagedUser($user)) {
            self::audit('native_authentication_blocked', ['user_id' => $user->ID], true);
            return new \WP_Error('cfawpiam_sso_required', 'This account is managed by Cloudflare Access and cannot use a native WordPress password.');
        }

        return $user;
    }

    public static function applicationPasswordsAvailable($available, $user): bool
    {
        if ($user instanceof \WP_User && self::isManagedUser($user)) {
            return false;
        }

        return (bool) $available;
    }

    public static function allowPasswordReset($allow, $userId): bool
    {
        $user = get_userdata((int) $userId);

        if ($user instanceof \WP_User && self::isManagedUser($user)) {
            return false;
        }

        return (bool) $allow;
    }

    public static function enforceManagedRestAuthentication($result)
    {
        if (is_wp_error($result)) {
            return $result;
        }

        $user = wp_get_current_user();

        if (!$user || !$user->exists() || !self::isManagedUser($user) || !self::settings()['enforce_managed_rest']) {
            return $result;
        }

        $jwt = self::accessJwt();
        $payload = $jwt !== '' ? self::verifiedPayload($jwt) : null;

        if (!$payload || strtolower((string) $payload->email) !== strtolower((string) $user->user_email)) {
            return new \WP_Error('cfawpiam_rest_access_required', 'A valid Cloudflare Access token is required for this managed REST request.', ['status' => 403]);
        }

        $boundSubject = (string) get_user_meta($user->ID, self::SUBJECT_META, true);

        if ($boundSubject === '' || !hash_equals($boundSubject, (string) $payload->sub)) {
            self::revokeManagedAccess($user, 'rest_subject_mismatch');
            return new \WP_Error('cfawpiam_subject_mismatch', 'The Cloudflare subject does not match this managed account.', ['status' => 403]);
        }

        $authorization = self::identityAndRole($payload, (string) $user->user_email, $jwt);

        if (is_wp_error($authorization)) {
            self::audit('rest_identity_lookup_failed', ['user_id' => $user->ID, 'error' => $authorization->get_error_code()], true);
            return new \WP_Error('cfawpiam_identity_unavailable', 'Cloudflare group membership could not be verified.', ['status' => 503]);
        }

        if ($authorization['target_role'] === '') {
            self::revokeManagedAccess($user, 'rest_no_mapped_group');
            return new \WP_Error('cfawpiam_role_required', 'The Cloudflare identity is not mapped to a WordPress role.', ['status' => 403]);
        }

        $sync = self::syncManagedRole($user, $authorization['target_role']);

        if (is_wp_error($sync)) {
            self::revokeManagedAccess($user, 'rest_invalid_target_role');
            return new \WP_Error('cfawpiam_invalid_role', 'The mapped WordPress role is unavailable.', ['status' => 403]);
        }

        if ($sync['changed']) {
            wp_set_current_user(0);
            return new \WP_Error('cfawpiam_role_changed', 'Your WordPress role changed. Reload through Cloudflare Access before retrying.', ['status' => 409]);
        }

        return $result;
    }

    public static function redirectAfterLogout($redirectTo, $requestedRedirectTo, $user): string
    {
        $settings = self::settings();

        if ($settings['logout_mode'] === 'disabled') {
            return (string) $redirectTo;
        }

        if ($settings['logout_mode'] === 'team' && self::isValidTeamDomain($settings['team_domain'])) {
            return 'https://' . $settings['team_domain'] . '/cdn-cgi/access/logout';
        }

        return home_url('/cdn-cgi/access/logout');
    }

    public static function allowTeamLogoutHost($hosts, $host): array
    {
        $hosts = (array) $hosts;
        $settings = self::settings();

        if ($settings['logout_mode'] === 'team' && self::isValidTeamDomain($settings['team_domain'])) {
            $hosts[] = $settings['team_domain'];
        }

        return array_values(array_unique($hosts));
    }

    private static function verifiedPayload(string $jwt): ?object
    {
        $result = self::verifiedPayloadResult($jwt);

        return is_wp_error($result) ? null : $result;
    }

    /**
     * @return object|\WP_Error
     */
    private static function verifiedPayloadResult(string $jwt)
    {
        $headerResult = self::jwtHeaderResult($jwt);
        $kid = $headerResult['kid'];

        if ($kid === '') {
            return new \WP_Error($headerResult['error'], 'The JWT header is invalid.');
        }

        $keys = self::jwks(false);

        if (!$keys) {
            return new \WP_Error('jwks_unavailable', 'Cloudflare signing keys could not be loaded.');
        }

        if (!self::jwksContainsKid($keys, $kid)) {
            if (get_transient(self::JWKS_REFRESH_LOCK_KEY)) {
                return new \WP_Error('jwks_refresh_locked', 'The signing-key refresh is temporarily locked.');
            }

            set_transient(self::JWKS_REFRESH_LOCK_KEY, 1, 60);
            $keys = self::jwks(true);
        }

        if (!$keys || !self::jwksContainsKid($keys, $kid)) {
            return new \WP_Error('jwt_signing_key_missing', 'The JWT signing key was not found.');
        }

        try {
            $payload = JWT::decode($jwt, JWK::parseKeySet($keys));
        } catch (BeforeValidException $e) {
            return new \WP_Error('jwt_not_yet_valid', 'The JWT is not valid yet.');
        } catch (ExpiredException $e) {
            return new \WP_Error('jwt_expired', 'The JWT has expired.');
        } catch (SignatureInvalidException $e) {
            return new \WP_Error('jwt_signature_invalid', 'The JWT signature is invalid.');
        } catch (Throwable $e) {
            return new \WP_Error('jwt_decode_failed', 'The JWT could not be decoded.');
        }

        $claimsError = self::claimsValidationError($payload);

        return $claimsError === ''
            ? $payload
            : new \WP_Error($claimsError, 'The JWT claims are invalid.');
    }

    private static function claimsAreValid($payload): bool
    {
        return self::claimsValidationError($payload) === '';
    }

    private static function claimsValidationError($payload): string
    {
        if (!is_object($payload)) {
            return 'jwt_payload_invalid';
        }

        $settings = self::settings();

        if ($settings['issuer'] === '' || $settings['audience'] === '') {
            return 'jwt_configuration_incomplete';
        }

        if (($payload->iss ?? '') !== $settings['issuer']) {
            return 'jwt_issuer_mismatch';
        }

        if (($payload->type ?? '') !== 'app') {
            return 'jwt_type_invalid';
        }

        foreach (['exp', 'iat', 'nbf'] as $claim) {
            if (!isset($payload->{$claim}) || !is_numeric($payload->{$claim})) {
                return 'jwt_time_claim_invalid';
            }
        }

        if ((float) $payload->exp <= (float) $payload->iat || (float) $payload->nbf > (float) $payload->exp) {
            return 'jwt_time_window_invalid';
        }

        if (empty($payload->email) || !is_string($payload->email) || strlen($payload->email) > 254) {
            return 'jwt_email_invalid';
        }

        if (empty($payload->sub) || !is_string($payload->sub) || strlen($payload->sub) > 255) {
            return 'jwt_subject_invalid';
        }

        if (empty($payload->identity_nonce) || !is_string($payload->identity_nonce) || strlen($payload->identity_nonce) > 512) {
            return 'jwt_identity_nonce_invalid';
        }

        $audience = $payload->aud ?? [];
        $audience = is_string($audience) ? [$audience] : $audience;

        if (!is_array($audience) || count($audience) > 20) {
            return 'jwt_audience_invalid';
        }

        foreach ($audience as $item) {
            if (!is_string($item) || strlen($item) > 255) {
                return 'jwt_audience_invalid';
            }
        }

        return in_array($settings['audience'], $audience, true) ? '' : 'jwt_audience_mismatch';
    }

    private static function jwks(bool $forceRefresh): ?array
    {
        if ($forceRefresh) {
            delete_transient(self::JWKS_CACHE_KEY);
        } else {
            $cached = get_transient(self::JWKS_CACHE_KEY);

            if (is_array($cached)) {
                $cached = self::sanitizeJwks($cached);
                if ($cached) {
                    return $cached;
                }
            }
        }

        $settings = self::settings();

        if ($settings['jwks_url'] === '') {
            return null;
        }

        $response = wp_safe_remote_get($settings['jwks_url'], [
            'timeout' => 5,
            'redirection' => 0,
            'limit_response_size' => self::MAX_RESPONSE_BYTES,
        ]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }

        $json = json_decode(wp_remote_retrieve_body($response), true);
        $json = is_array($json) ? self::sanitizeJwks($json) : null;

        if (!$json) {
            return null;
        }

        set_transient(self::JWKS_CACHE_KEY, $json, self::JWKS_TTL);

        return $json;
    }

    private static function sanitizeJwks(array $jwks): ?array
    {
        if (empty($jwks['keys']) || !is_array($jwks['keys'])) {
            return null;
        }

        $keys = [];
        $seenKids = [];

        foreach (array_slice($jwks['keys'], 0, 10) as $key) {
            if (!is_array($key)) {
                continue;
            }

            if (($key['kty'] ?? '') !== 'RSA' || ($key['alg'] ?? '') !== 'RS256' || ($key['use'] ?? '') !== 'sig') {
                continue;
            }

            if (!isset($key['kid'], $key['n'], $key['e'])
                || !is_string($key['kid'])
                || !is_string($key['n'])
                || !is_string($key['e'])
                || $key['kid'] === ''
                || strlen($key['kid']) > 255
                || strlen($key['n']) > 4096
                || strlen($key['e']) > 16
                || !preg_match('/^[A-Za-z0-9_-]+$/', $key['n'])
                || !preg_match('/^[A-Za-z0-9_-]+$/', $key['e'])) {
                continue;
            }

            $modulus = self::base64UrlDecode($key['n']);
            $exponent = self::base64UrlDecode($key['e']);

            if ($modulus === null || strlen($modulus) < 256 || strlen($modulus) > 1024
                || $exponent === null || strlen($exponent) < 1 || strlen($exponent) > 8) {
                continue;
            }

            if (isset($seenKids[$key['kid']])) {
                return null;
            }

            $seenKids[$key['kid']] = true;

            $keys[] = $key;
        }

        return $keys ? ['keys' => $keys] : null;
    }

    private static function jwksContainsKid(array $jwks, string $kid): bool
    {
        foreach ($jwks['keys'] ?? [] as $key) {
            if (isset($key['kid']) && is_string($key['kid']) && hash_equals($key['kid'], $kid)) {
                return true;
            }
        }

        return false;
    }

    private static function jwtKid(string $jwt): string
    {
        return self::jwtHeaderResult($jwt)['kid'];
    }

    /**
     * The JWT "typ" header is optional under RFC 7519 section 5.1. Security
     * decisions are based on the fixed RS256 algorithm, a bounded key ID,
     * signature verification, and the validated payload claims.
     *
     * @return array{kid: string, error: string}
     */
    private static function jwtHeaderResult(string $jwt): array
    {
        $segments = explode('.', $jwt);

        if (count($segments) !== 3) {
            return ['kid' => '', 'error' => 'jwt_segment_count_invalid'];
        }

        $headerJson = self::base64UrlDecode($segments[0]);

        if ($headerJson === null) {
            return ['kid' => '', 'error' => 'jwt_header_encoding_invalid'];
        }

        $header = json_decode($headerJson, true);

        if (!is_array($header)) {
            return ['kid' => '', 'error' => 'jwt_header_json_invalid'];
        }

        if (($header['alg'] ?? '') !== 'RS256') {
            return ['kid' => '', 'error' => 'jwt_algorithm_invalid'];
        }

        if (!isset($header['kid']) || !is_string($header['kid'])) {
            return ['kid' => '', 'error' => 'jwt_key_id_missing'];
        }

        $kid = trim($header['kid']);

        if ($kid === '' || strlen($kid) > 255 || preg_match('/[\x00-\x1F\x7F]/', $kid)) {
            return ['kid' => '', 'error' => 'jwt_key_id_invalid'];
        }

        return ['kid' => $kid, 'error' => ''];
    }

    private static function identityAndRole(object $payload, string $email, string $jwt = '')
    {
        $identity = self::cloudflareIdentity($email, (string) $payload->sub, $jwt);

        if (is_wp_error($identity)) {
            return $identity;
        }

        $mappedRole = self::mappedRole($identity['groups']);
        $settings = self::settings();
        $targetRole = $mappedRole;

        if ($targetRole === '' && $settings['fallback_role'] === 'subscriber') {
            $targetRole = 'subscriber';
        }

        if ($targetRole !== '' && (!isset(self::rolePriority()[$targetRole]) || !get_role($targetRole))) {
            return new \WP_Error('invalid_target_role', 'The mapped WordPress role is unavailable.');
        }

        return [
            'identity' => $identity,
            'mapped_role' => $mappedRole,
            'target_role' => $targetRole,
        ];
    }

    private static function cloudflareIdentity(string $expectedEmail, string $expectedSubject, string $jwt = '')
    {
        $cookie = self::authorizationCookie();

        if ($cookie === '' && $jwt !== '' && self::isJwtShapeValid($jwt)) {
            $cookie = $jwt;
        }

        if ($cookie === '') {
            return new \WP_Error('missing_authorization_cookie', 'CF_Authorization cookie is required for group verification.');
        }

        $settings = self::settings();

        if (!self::isValidTeamDomain($settings['team_domain'])) {
            return new \WP_Error('invalid_team_domain', 'Cloudflare team domain is not configured.');
        }

        $response = wp_safe_remote_get(
            'https://' . $settings['team_domain'] . '/cdn-cgi/access/get-identity',
            [
                'headers' => ['Cookie' => 'CF_Authorization=' . $cookie],
                'timeout' => 5,
                'redirection' => 0,
                'limit_response_size' => self::MAX_RESPONSE_BYTES,
            ]
        );

        if (is_wp_error($response)) {
            return new \WP_Error('identity_request_failed', 'Cloudflare identity request failed.');
        }

        if (wp_remote_retrieve_response_code($response) !== 200) {
            return new \WP_Error('identity_http_error', 'Cloudflare identity endpoint returned a non-200 status.');
        }

        $identity = json_decode(wp_remote_retrieve_body($response), true);

        if (!is_array($identity)) {
            return new \WP_Error('invalid_identity_json', 'Cloudflare identity response was not valid JSON.');
        }

        if (!empty($identity['service_token_status'])) {
            return new \WP_Error('service_identity_rejected', 'Service-token identities cannot provision WordPress users.');
        }

        if (empty($identity['email']) || strtolower((string) $identity['email']) !== strtolower($expectedEmail)) {
            return new \WP_Error('identity_email_mismatch', 'Cloudflare identity email did not match the JWT.');
        }

        if (empty($identity['user_uuid']) || !is_string($identity['user_uuid']) || !hash_equals($expectedSubject, $identity['user_uuid'])) {
            return new \WP_Error('identity_subject_mismatch', 'Cloudflare identity subject did not match the JWT.');
        }

        if (isset($identity['groups']) && !is_array($identity['groups'])) {
            return new \WP_Error('invalid_identity_groups', 'Cloudflare identity groups were malformed.');
        }

        $groups = $identity['groups'] ?? [];

        if (count($groups) > 2000) {
            return new \WP_Error('too_many_identity_groups', 'Cloudflare identity returned too many groups.');
        }

        return [
            'email' => (string) $identity['email'],
            'subject' => (string) $identity['user_uuid'],
            'groups' => self::groupIdentifiers($groups),
        ];
    }

    private static function groupIdentifiers(array $groups): array
    {
        $identifiers = [];

        foreach ($groups as $group) {
            if (is_string($group)) {
                if (self::isValidIdentifier($group)) {
                    $identifiers[] = $group;
                }
                continue;
            }

            if (!is_array($group)) {
                continue;
            }

            foreach (['id', 'name', 'email'] as $key) {
                if (isset($group[$key]) && is_scalar($group[$key]) && self::isValidIdentifier((string) $group[$key])) {
                    $identifiers[] = (string) $group[$key];
                }
            }
        }

        return array_values(array_unique(array_filter(array_map('trim', $identifiers))));
    }

    private static function mappedRole(array $identifiers): string
    {
        $roleMap = (array) get_option(self::ROLE_MAP_OPTION, []);
        $priority = self::rolePriority();
        $normalizedIdentifiers = self::normalizeIdentifiers($identifiers);
        $bestRole = '';
        $bestScore = 0;

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

        return $bestRole;
    }

    private static function createManagedUser(string $email, string $subject, string $role)
    {
        $userId = wp_insert_user([
            'user_login' => self::uniqueUsername($email, $subject),
            'user_pass' => wp_generate_password(64, true, true),
            'user_email' => $email,
            'role' => $role,
        ]);

        if (is_wp_error($userId)) {
            return $userId;
        }

        $user = get_user_by('id', $userId);

        if (!$user) {
            return new \WP_Error('jit_user_missing', 'The new WordPress user could not be loaded.');
        }

        if (count((array) $user->roles) !== 1 || !in_array($role, (array) $user->roles, true)) {
            $user->set_role('');
            return new \WP_Error('jit_role_assignment_failed', 'The initial WordPress role could not be assigned.');
        }

        $binding = self::markManaged($user, $subject, false);

        if (is_wp_error($binding)) {
            $user->set_role('');
            return $binding;
        }

        self::audit('jit_user_created', ['user_id' => $user->ID, 'to_role' => $role]);

        return $user;
    }

    private static function markManaged($user, string $subject, bool $revokeExistingSessions)
    {
        update_user_meta($user->ID, self::MANAGED_USER_META, '1');
        update_user_meta($user->ID, self::SUBJECT_META, $subject);

        if (get_user_meta($user->ID, self::MANAGED_USER_META, true) !== '1'
            || !hash_equals($subject, (string) get_user_meta($user->ID, self::SUBJECT_META, true))) {
            delete_user_meta($user->ID, self::MANAGED_USER_META);
            delete_user_meta($user->ID, self::SUBJECT_META);
            return new \WP_Error('cloudflare_binding_failed', 'The Cloudflare account binding could not be persisted.');
        }

        self::deleteApplicationPasswords($user->ID);

        if ($revokeExistingSessions) {
            self::destroySessions($user->ID);
        }

        self::audit('user_bound_to_cloudflare', ['user_id' => $user->ID]);

        return true;
    }

    private static function legacyLinkAllowed($currentUser, $targetUser, string $mappedRole): bool
    {
        return $mappedRole !== ''
            && get_option(self::LEGACY_LINK_OPTION, '') === '1'
            && $currentUser instanceof \WP_User
            && $currentUser->exists()
            && $targetUser instanceof \WP_User
            && (int) $currentUser->ID === (int) $targetUser->ID;
    }

    private static function syncManagedRole($user, string $targetRole)
    {
        if (!isset(self::rolePriority()[$targetRole]) || !get_role($targetRole)) {
            return new \WP_Error('invalid_target_role', 'The mapped WordPress role is unavailable.');
        }

        $currentRole = self::highestCurrentRole((array) $user->roles);
        $changed = $currentRole !== $targetRole || count((array) $user->roles) !== 1;
        $downgrade = self::roleScore($targetRole) < self::roleScore($currentRole);
        $sessionsRevoked = false;

        if ($changed) {
            $wpUser = new \WP_User($user->ID);
            $wpUser->set_role($targetRole);
            $reloaded = get_userdata($user->ID);

            if (!($reloaded instanceof \WP_User)
                || count((array) $reloaded->roles) !== 1
                || !in_array($targetRole, (array) $reloaded->roles, true)) {
                self::destroySessions($user->ID);
                self::deleteApplicationPasswords($user->ID);
                self::audit('role_change_failed', ['user_id' => $user->ID, 'to_role' => $targetRole]);
                return new \WP_Error('role_change_failed', 'The WordPress role change could not be persisted.');
            }

            if ($downgrade) {
                self::destroySessions($user->ID);
                self::deleteApplicationPasswords($user->ID);
                $sessionsRevoked = true;
            }

            self::audit('role_changed', [
                'user_id' => $user->ID,
                'from_role' => $currentRole,
                'to_role' => $targetRole,
            ]);
        }

        return ['changed' => $changed, 'sessions_revoked' => $sessionsRevoked];
    }

    private static function revokeManagedAccess($user, string $reason): void
    {
        $currentRole = self::highestCurrentRole((array) $user->roles);
        $wpUser = new \WP_User($user->ID);
        $wpUser->set_role('');
        self::destroySessions($user->ID);
        self::deleteApplicationPasswords($user->ID);
        $reloaded = get_userdata($user->ID);
        $removalFailed = $reloaded instanceof \WP_User && !empty($reloaded->roles);
        self::audit('managed_access_revoked', [
            'user_id' => $user->ID,
            'from_role' => $currentRole,
            'error' => $removalFailed ? $reason . ':role_removal_failed' : $reason,
        ]);
    }

    private static function destroySessions(int $userId): void
    {
        if (class_exists('\WP_Session_Tokens')) {
            \WP_Session_Tokens::get_instance($userId)->destroy_all();
        }
    }

    private static function deleteApplicationPasswords(int $userId): void
    {
        if (class_exists('\WP_Application_Passwords')) {
            $result = \WP_Application_Passwords::delete_all_application_passwords($userId);

            if (is_wp_error($result)) {
                self::audit('application_password_revocation_failed', [
                    'user_id' => $userId,
                    'error' => $result->get_error_code(),
                ]);
            }
        }
    }

    private static function denyAccess(string $message): void
    {
        wp_clear_auth_cookie();
        wp_set_current_user(0);

        if (wp_doing_ajax()) {
            wp_send_json_error(['message' => $message], 403);
        }

        wp_die(esc_html($message), 'Cloudflare Access denied', ['response' => 403]);
    }

    private static function isManagedUser($user): bool
    {
        return $user instanceof \WP_User && get_user_meta($user->ID, self::MANAGED_USER_META, true) === '1';
    }

    private static function accessJwt(): string
    {
        return self::accessJwtResult()['token'];
    }

    /**
     * @return array{token: string, error: string}
     */
    private static function accessJwtResult(): array
    {
        $serverHeader = 'HTTP_' . str_replace('-', '_', strtoupper(self::JWT_HEADER));

        if (!empty($_SERVER[$serverHeader])) {
            if (!is_scalar($_SERVER[$serverHeader])) {
                return ['token' => '', 'error' => 'jwt_header_not_scalar'];
            }

            $value = trim((string) wp_unslash($_SERVER[$serverHeader]));
        } else {
            $value = self::authorizationCookie();

            if ($value === '') {
                return ['token' => '', 'error' => 'jwt_header_and_cookie_missing'];
            }
        }

        if (stripos($value, 'Bearer ') === 0) {
            $value = trim(substr($value, 7));
        }

        if (strlen($value) > self::MAX_TOKEN_BYTES) {
            return ['token' => '', 'error' => 'jwt_too_large'];
        }

        if (!self::isJwtShapeValid($value)) {
            return ['token' => '', 'error' => 'jwt_format_invalid'];
        }

        return ['token' => $value, 'error' => ''];
    }

    private static function authorizationCookie(): string
    {
        if (empty($_COOKIE['CF_Authorization']) || !is_scalar($_COOKIE['CF_Authorization'])) {
            return '';
        }

        $value = trim((string) wp_unslash($_COOKIE['CF_Authorization']));

        if (strlen($value) > self::MAX_TOKEN_BYTES || !self::isJwtShapeValid($value)) {
            return '';
        }

        return $value;
    }

    private static function isJwtShapeValid(string $value): bool
    {
        return (bool) preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $value);
    }

    private static function isLogoutRequest(): bool
    {
        $action = isset($_REQUEST['action']) && is_scalar($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';

        return $action === 'logout' || isset($_GET['loggedout']);
    }

    private static function isLoginRequest(): bool
    {
        return isset($GLOBALS['pagenow']) && $GLOBALS['pagenow'] === 'wp-login.php';
    }

    private static function uniqueUsername(string $email, string $subject): string
    {
        $localPart = strstr($email, '@', true);
        $base = sanitize_user($localPart !== false ? $localPart : 'cf-user', true);
        $base = $base !== '' ? $base : 'cf-user';
        $suffix = '-' . substr(hash('sha256', $subject), 0, 12);
        $candidate = substr($base, 0, 60 - strlen($suffix)) . $suffix;
        $counter = 1;

        while (username_exists($candidate)) {
            $counterSuffix = '-' . $counter;
            $candidate = substr($base, 0, 60 - strlen($suffix) - strlen($counterSuffix)) . $suffix . $counterSuffix;
            $counter++;
        }

        return $candidate;
    }

    private static function rolePriority(): array
    {
        return [
            'administrator' => 5,
            'editor' => 4,
            'author' => 3,
            'contributor' => 2,
            'subscriber' => 1,
        ];
    }

    private static function roleScore(string $role): int
    {
        return self::rolePriority()[$role] ?? 0;
    }

    private static function highestCurrentRole(array $roles): string
    {
        $bestRole = '';
        $bestScore = 0;

        foreach ($roles as $role) {
            if (self::roleScore((string) $role) > $bestScore) {
                $bestRole = (string) $role;
                $bestScore = self::roleScore($bestRole);
            }
        }

        return $bestRole;
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
            'jwt_header' => self::JWT_HEADER,
            'issuer' => $settings['issuer'] ?: 'https://your-team.cloudflareaccess.com',
            'audience' => $settings['audience'] ?: 'Cloudflare Access AUD tag',
            'fallback_role' => $settings['fallback_role'],
            'existing_user_mode' => $settings['existing_user_mode'],
            'enforce_managed_rest' => $settings['enforce_managed_rest'],
            'logout_mode' => $settings['logout_mode'],
            'groups' => [
                'administrator' => ['wp-admins'],
                'editor' => ['wp-editors'],
                'subscriber' => ['wp-subscribers'],
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
        if (!isset($_POST[$key]) || !is_scalar($_POST[$key])) {
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
            return is_scalar($value) ? strtolower(trim((string) $value)) : '';
        }, $identifiers))));
    }

    private static function isValidIdentifier(string $identifier): bool
    {
        $identifier = trim($identifier);

        return $identifier !== ''
            && strlen($identifier) <= 255
            && !preg_match('/[\x00-\x1F\x7F]/', $identifier);
    }

    private static function normalizeHost(string $host): string
    {
        $host = strtolower(trim($host));
        $host = preg_replace('#^https?://#i', '', $host);

        return trim((string) $host, "/ \t\n\r\0\x0B");
    }

    private static function isValidTeamDomain(string $host): bool
    {
        return (bool) preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/', $host);
    }

    private static function toBool($value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        if (!is_scalar($value) && $value !== null) {
            return false;
        }

        return in_array(strtolower(trim((string) $value)), ['1', 'true', 'yes', 'on'], true);
    }

    private static function scalarString($value): string
    {
        return is_scalar($value) || $value === null ? trim((string) $value) : '';
    }

    private static function base64UrlDecode(string $value): ?string
    {
        $padding = strlen($value) % 4;

        if ($padding > 0) {
            $value .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }

    private static function audit(string $event, array $context = [], bool $throttle = false): void
    {
        $event = sanitize_key($event);
        $allowedContext = [];

        foreach (['user_id', 'from_role', 'to_role', 'error'] as $key) {
            if (isset($context[$key]) && is_scalar($context[$key])) {
                $allowedContext[$key] = substr(sanitize_text_field((string) $context[$key]), 0, 120);
            }
        }

        if ($throttle) {
            $throttleKey = 'cfawpiam_audit_' . md5($event . wp_json_encode($allowedContext));
            if (get_transient($throttleKey)) {
                return;
            }
            set_transient($throttleKey, 1, 300);
        }

        $entry = array_merge([
            'time' => gmdate('c'),
            'event' => $event,
            'user_id' => '',
        ], $allowedContext);
        $log = (array) get_option(self::AUDIT_LOG_OPTION, []);
        array_unshift($log, $entry);
        update_option(self::AUDIT_LOG_OPTION, array_slice($log, 0, 50), false);
        do_action('cfawpiam_security_event', $event, $entry);
    }

    private static function auditDetails(array $entry): string
    {
        $details = [];

        foreach (['from_role', 'to_role', 'error'] as $key) {
            if (!empty($entry[$key])) {
                $details[] = $key . '=' . $entry[$key];
            }
        }

        return implode(', ', $details);
    }

    private static function maybeUpgrade(): void
    {
        $schemaVersion = (int) get_option(self::SCHEMA_VERSION_OPTION, 0);

        if ($schemaVersion >= 2) {
            return;
        }

        $storedSettings = get_option(self::SETTINGS_OPTION, null);

        if (is_array($storedSettings) && $storedSettings) {
            update_option(self::LEGACY_LINK_OPTION, '1', false);
        }

        update_option(self::SCHEMA_VERSION_OPTION, 2, false);
    }

    public static function registerSiteHealthTests(array $tests): array
    {
        $tests['direct']['cfawpiam_configuration'] = [
            'label' => 'Cloudflare Access WP IAM configuration',
            'test' => [self::class, 'siteHealthTest'],
        ];

        return $tests;
    }

    public static function siteHealthTest(): array
    {
        $settings = self::settings();
        $roleMap = (array) get_option(self::ROLE_MAP_OPTION, []);
        $issues = [];

        if (!self::isValidTeamDomain($settings['team_domain']) || $settings['audience'] === '') {
            $issues[] = 'Cloudflare team domain or AUD tag is missing.';
        }

        if (!$roleMap && $settings['fallback_role'] === 'deny') {
            $issues[] = 'No group-to-role mappings are configured.';
        }

        if ($settings['existing_user_mode'] === 'link') {
            $issues[] = 'Automatic linking of existing accounts is enabled.';
        }

        if (get_option(self::LEGACY_LINK_OPTION, '') === '1') {
            $issues[] = 'The one-time version 1.x bootstrap link is still pending.';
        }

        if (!$settings['enforce_managed_rest']) {
            $issues[] = 'Managed REST enforcement is disabled.';
        }

        $status = $issues ? 'critical' : 'good';

        return [
            'label' => $issues ? 'Cloudflare Access WP IAM needs attention' : 'Cloudflare Access WP IAM is hardened',
            'status' => $status,
            'badge' => ['label' => 'Security', 'color' => 'blue'],
            'description' => '<p>' . esc_html($issues ? implode(' ', $issues) : 'Required IAM settings and fail-closed controls are enabled.') . '</p>',
            'actions' => '<p><a href="' . esc_url(admin_url('options-general.php?page=cloudflare-access-wp-iam')) . '">Review IAM settings</a></p>',
            'test' => 'cfawpiam_configuration',
        ];
    }
}
