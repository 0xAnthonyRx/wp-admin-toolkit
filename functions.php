<?php
/**
 * WP Admin Toolkit - functions.php
 *
 * A collection of security hardening and optimization hooks
 * for WordPress-based web administration.
 *
 * Author : Anthony (0xAnthonyRx)
 * Repo   : https://github.com/0xAnthonyRx/wp-admin-toolkit
 * License: MIT
 *
 * HOW TO USE:
 * Copy individual snippets into your active theme's functions.php,
 * or require this file from your theme/plugin as needed.
 */

// ============================================================
// 1. SECURITY — Remove WordPress Version from All Outputs
// ============================================================
// Exposing the WP version in HTML meta tags and RSS feeds
// gives automated scanners a free fingerprint to match against
// known CVEs. This filter blanks it out everywhere.

function swp_remove_wp_version() {
    return '';
}
add_filter( 'the_generator', 'swp_remove_wp_version' );


// ============================================================
// 2. SECURITY — Disable XML-RPC
// ============================================================
// XML-RPC is a legacy remote-access protocol that is frequently
// abused for brute-force credential stuffing and DDoS
// amplification attacks. Most modern WordPress sites have no
// legitimate need for it. Disabling it at the filter level is
// safer than relying on .htaccess blocks alone because it
// prevents WordPress from even initialising the endpoint.

add_filter( 'xmlrpc_enabled', '__return_false' );


// ============================================================
// 3. SECURITY — Remove Unnecessary HTTP Headers
// ============================================================
// WordPress adds an 'X-Pingback' header pointing to xmlrpc.php
// even after XML-RPC is disabled. Stripping it removes one more
// information-disclosure vector that scanners look for.

function swp_remove_x_pingback_header( $headers ) {
    unset( $headers['X-Pingback'] );
    return $headers;
}
add_filter( 'wp_headers', 'swp_remove_x_pingback_header' );


// ============================================================
// 4. SECURITY — Block Author Enumeration via URL
// ============================================================
// Visiting /?author=1 on a default WordPress install redirects
// to /author/username/ — leaking valid login names to attackers.
// This redirect intercepts that request and returns a 403 before
// any username is exposed.

function swp_block_author_enumeration() {
    if ( isset( $_GET['author'] ) && ! is_admin() ) {
        wp_die(
            'Author enumeration is disabled on this site.',
            'Forbidden',
            array( 'response' => 403 )
        );
    }
}
add_action( 'init', 'swp_block_author_enumeration' );


// ============================================================
// 5. PERFORMANCE — Disable Emoji Scripts
// ============================================================
// WordPress loads a JavaScript file and makes an extra DNS lookup
// purely to render emoji. For a professional/corporate site this
// is unnecessary bloat. Removing it shaves one render-blocking
// request and one external DNS resolution from every page load.

function swp_disable_emojis() {
    remove_action( 'wp_head',             'print_emoji_detection_script', 7 );
    remove_action( 'admin_print_scripts', 'print_emoji_detection_script' );
    remove_action( 'wp_print_styles',     'print_emoji_styles' );
    remove_action( 'admin_print_styles',  'print_emoji_styles' );
    remove_filter( 'the_content_feed',    'wp_staticize_emoji' );
    remove_filter( 'comment_text_rss',    'wp_staticize_emoji' );
    remove_filter( 'wp_mail',             'wp_staticize_emoji_for_email' );
}
add_action( 'init', 'swp_disable_emojis' );


// ============================================================
// 6. BRANDING — Custom Admin Footer
// ============================================================
// Replaces the default "Thank you for creating with WordPress"
// footer text in the dashboard with a client-branded message.
// Useful when handing over an admin panel to a client.

function swp_custom_admin_footer() {
    echo 'Managed by <strong>Anthony</strong> &mdash; Web Administrator';
}
add_filter( 'admin_footer_text', 'swp_custom_admin_footer' );


// ============================================================
// 7. MAINTENANCE — Log Last Content Update Timestamp
// ============================================================
// Every time a post or page is saved, this hook writes a
// human-readable timestamp to a log file in wp-content/.
// Useful for auditing when content was last touched without
// needing database access. The log is append-only and each
// entry records the post ID, title, and editor's username.

function swp_log_content_update( $post_id, $post, $update ) {

    // Skip autosaves and revisions — we only want deliberate saves.
    if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) return;
    if ( wp_is_post_revision( $post_id ) )                return;

    // Only log public-facing post types.
    $tracked_types = array( 'post', 'page' );
    if ( ! in_array( $post->post_type, $tracked_types, true ) ) return;

    $log_file  = WP_CONTENT_DIR . '/content-update.log';
    $timestamp = current_time( 'Y-m-d H:i:s' );
    $user      = wp_get_current_user();
    $username  = $user->user_login ?? 'unknown';
    $action    = $update ? 'UPDATED' : 'CREATED';

    $entry = sprintf(
        "[%s] %s | Post ID: %d | Title: %s | Editor: %s\n",
        $timestamp,
        $action,
        $post_id,
        sanitize_text_field( $post->post_title ),
        sanitize_text_field( $username )
    );

    // FILE_APPEND ensures we never overwrite previous entries.
    // LOCK_EX prevents race conditions on concurrent saves.
    file_put_contents( $log_file, $entry, FILE_APPEND | LOCK_EX );
}
add_action( 'save_post', 'swp_log_content_update', 10, 3 );