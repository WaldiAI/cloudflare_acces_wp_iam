<?php
/**
 * Plugin Name: Cloudflare Access WP IAM
 * Description: WordPress IAM/SSO gateway using Cloudflare Access JWT, JIT provisioning, and IdP group-to-role mapping.
 * Version: 2.0.2
 * Author: IAM Lab
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 6.5
 * Requires PHP: 8.2
 */

if (!defined('ABSPATH')) {
    exit;
}

if (is_readable(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
} else {
    require_once __DIR__ . '/vendor/firebase/php-jwt/src/JWTExceptionWithPayloadInterface.php';
    require_once __DIR__ . '/vendor/firebase/php-jwt/src/BeforeValidException.php';
    require_once __DIR__ . '/vendor/firebase/php-jwt/src/ExpiredException.php';
    require_once __DIR__ . '/vendor/firebase/php-jwt/src/SignatureInvalidException.php';
    require_once __DIR__ . '/vendor/firebase/php-jwt/src/Key.php';
    require_once __DIR__ . '/vendor/firebase/php-jwt/src/JWK.php';
    require_once __DIR__ . '/vendor/firebase/php-jwt/src/JWT.php';
}

require_once __DIR__ . '/src/Plugin.php';

\IamLab\CloudflareAccessWpIam\Plugin::boot();

if (!function_exists('cfawpiam_apply_config')) {
    /**
     * Apply Cloudflare Access WP IAM configuration from automation tools.
     *
     * Intended for MainWP Code Snippets, deployment scripts, or WP-CLI eval.
     *
     * @param array $config
     * @return true|\WP_Error
     */
    function cfawpiam_apply_config(array $config)
    {
        return \IamLab\CloudflareAccessWpIam\Plugin::applyConfig($config);
    }
}
