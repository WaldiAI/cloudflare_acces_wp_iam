<?php

$GLOBALS['cfawpiam_test_options'] = [];
$GLOBALS['cfawpiam_test_transients'] = [];

class WP_Error
{
    private string $code;
    private string $message;
    private $data;

    public function __construct(string $code = '', string $message = '', $data = null)
    {
        $this->code = $code;
        $this->message = $message;
        $this->data = $data;
    }

    public function get_error_code(): string
    {
        return $this->code;
    }

    public function get_error_message(): string
    {
        return $this->message;
    }

    public function get_error_data()
    {
        return $this->data;
    }
}

class WP_User
{
    public int $ID;

    public function __construct(int $id = 0)
    {
        $this->ID = $id;
    }

    public function exists(): bool
    {
        return $this->ID > 0;
    }
}

function get_option($name, $default = false)
{
    return $GLOBALS['cfawpiam_test_options'][$name] ?? $default;
}

function update_option($name, $value, $autoload = null): bool
{
    $GLOBALS['cfawpiam_test_options'][$name] = $value;
    return true;
}

function delete_option($name): bool
{
    unset($GLOBALS['cfawpiam_test_options'][$name]);
    return true;
}

function get_transient($name)
{
    return $GLOBALS['cfawpiam_test_transients'][$name] ?? false;
}

function set_transient($name, $value, $expiration = 0): bool
{
    $GLOBALS['cfawpiam_test_transients'][$name] = $value;
    return true;
}

function delete_transient($name): bool
{
    unset($GLOBALS['cfawpiam_test_transients'][$name]);
    return true;
}

function sanitize_key($value): string
{
    return preg_replace('/[^a-z0-9_\-]/', '', strtolower((string) $value));
}

function sanitize_text_field($value): string
{
    return trim(strip_tags((string) $value));
}

function wp_unslash($value)
{
    return $value;
}

function wp_json_encode($value, $flags = 0, $depth = 512)
{
    return json_encode($value, $flags, $depth);
}

function get_current_user_id(): int
{
    return 1;
}

function get_role($role)
{
    return in_array($role, ['administrator', 'editor', 'author', 'contributor', 'subscriber'], true)
        ? (object) ['name' => $role]
        : null;
}

function do_action($hook, ...$args): void
{
}

function is_wp_error($value): bool
{
    return $value instanceof WP_Error;
}

require_once dirname(__DIR__) . '/src/Plugin.php';
