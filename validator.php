<?php
/**
 * WP Admin Toolkit - validator.php
 *
 * A lightweight, standalone contact-form validator and sanitizer.
 * Framework-free — works with any PHP 7.4+ environment including
 * WordPress, plain PHP pages, or custom landing pages.
 *
 * Author : Anthony (0xAnthonyRx)
 * Repo   : https://github.com/0xAnthonyRx/wp-admin-toolkit
 * License: MIT
 *
 * HOW TO USE:
 *   require_once 'validator.php';
 *   $result = validate_contact_form( $_POST );
 *   if ( $result['valid'] ) { // send email or save to DB }
 *   else { // return $result['errors'] to the user }
 */


/**
 * Validate and sanitize a contact form submission.
 *
 * @param  array $data  Raw POST data (typically $_POST).
 * @return array {
 *     'valid'  => bool,
 *     'data'   => array  // sanitized values, safe to use downstream
 *     'errors' => array  // field => error message pairs
 * }
 */
function validate_contact_form( array $data ): array {

    $errors = array();
    $clean  = array();

    // --------------------------------------------------------
    // NAME
    // --------------------------------------------------------
    // Strip tags and extra whitespace, then check it is not
    // empty and contains only letters, spaces, hyphens, and
    // apostrophes (covers names like "O'Brien" and "Jean-Paul").

    $name = trim( strip_tags( $data['name'] ?? '' ) );

    if ( $name === '' ) {
        $errors['name'] = 'Name is required.';
    } elseif ( strlen( $name ) < 2 ) {
        $errors['name'] = 'Name must be at least 2 characters.';
    } elseif ( strlen( $name ) > 100 ) {
        $errors['name'] = 'Name must not exceed 100 characters.';
    } elseif ( ! preg_match( "/^[a-zA-Z\s'\-]+$/u", $name ) ) {
        $errors['name'] = 'Name contains invalid characters.';
    } else {
        $clean['name'] = htmlspecialchars( $name, ENT_QUOTES, 'UTF-8' );
    }

    // --------------------------------------------------------
    // EMAIL
    // --------------------------------------------------------
    // filter_var with FILTER_VALIDATE_EMAIL covers the RFC 5322
    // format check. We also normalise to lowercase so that
    // "User@Example.COM" and "user@example.com" are treated
    // as the same address downstream.

    $email = strtolower( trim( strip_tags( $data['email'] ?? '' ) ) );

    if ( $email === '' ) {
        $errors['email'] = 'Email address is required.';
    } elseif ( ! filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
        $errors['email'] = 'Please enter a valid email address.';
    } elseif ( strlen( $email ) > 254 ) {
        // RFC 5321 specifies 254 as the maximum email length.
        $errors['email'] = 'Email address is too long.';
    } else {
        $clean['email'] = $email;
    }

    // --------------------------------------------------------
    // PHONE (optional)
    // --------------------------------------------------------
    // Phone is not required, but if provided it must look like
    // a real number. We allow +, spaces, hyphens, parentheses,
    // and 7-15 digits — covers Nigerian (+234...) and
    // international formats.

    $phone = trim( strip_tags( $data['phone'] ?? '' ) );

    if ( $phone !== '' ) {
        $digits_only = preg_replace( '/\D/', '', $phone );
        if ( ! preg_match( '/^[+\d\s\-().]{7,20}$/', $phone ) ) {
            $errors['phone'] = 'Please enter a valid phone number.';
        } elseif ( strlen( $digits_only ) < 7 || strlen( $digits_only ) > 15 ) {
            $errors['phone'] = 'Phone number must be between 7 and 15 digits.';
        } else {
            $clean['phone'] = htmlspecialchars( $phone, ENT_QUOTES, 'UTF-8' );
        }
    }

    // --------------------------------------------------------
    // MESSAGE
    // --------------------------------------------------------
    // Strip all HTML tags (prevents stored XSS), then enforce
    // a minimum length so we don't receive blank submissions,
    // and a maximum to prevent payload stuffing.

    $message = trim( strip_tags( $data['message'] ?? '' ) );

    if ( $message === '' ) {
        $errors['message'] = 'Message is required.';
    } elseif ( strlen( $message ) < 10 ) {
        $errors['message'] = 'Message must be at least 10 characters.';
    } elseif ( strlen( $message ) > 2000 ) {
        $errors['message'] = 'Message must not exceed 2000 characters.';
    } else {
        $clean['message'] = htmlspecialchars( $message, ENT_QUOTES, 'UTF-8' );
    }

    // --------------------------------------------------------
    // HONEYPOT (spam trap)
    // --------------------------------------------------------
    // A hidden field that real users never fill in. Bots that
    // blindly populate all form fields will trigger this check
    // and get silently rejected — no error shown to discourage
    // probing.

    $honeypot = trim( $data['website'] ?? '' );
    if ( $honeypot !== '' ) {
        // Return a fake "success" so bots think they got through.
        return array(
            'valid'  => true,
            'data'   => array(),
            'errors' => array(),
        );
    }

    return array(
        'valid'  => empty( $errors ),
        'data'   => $clean,
        'errors' => $errors,
    );
}


/**
 * Quick usage example (remove in production).
 *
 * Simulates a POST submission so you can test the validator
 * by running: php validator.php
 */
if ( php_sapi_name() === 'cli' && basename( __FILE__ ) === 'validator.php' ) {

    $test_cases = array(
        'valid submission' => array(
            'name'    => "Anthony O'Brien",
            'email'   => 'anthony@example.com',
            'phone'   => '+234 801 234 5678',
            'message' => 'Hello, I would like to enquire about your services.',
            'website' => '',   // honeypot — intentionally empty
        ),
        'missing fields' => array(
            'name'    => '',
            'email'   => 'not-an-email',
            'phone'   => '',
            'message' => 'Short',
            'website' => '',
        ),
        'bot submission' => array(
            'name'    => 'Bot',
            'email'   => 'bot@spam.com',
            'phone'   => '',
            'message' => 'Buy cheap pills now!!!',
            'website' => 'http://spam.example.com',  // honeypot triggered
        ),
    );

    foreach ( $test_cases as $label => $input ) {
        $result = validate_contact_form( $input );
        echo "\n=== Test: {$label} ===\n";
        echo 'Valid : ' . ( $result['valid'] ? 'YES' : 'NO' ) . "\n";
        if ( ! empty( $result['errors'] ) ) {
            foreach ( $result['errors'] as $field => $msg ) {
                echo "  [{$field}] {$msg}\n";
            }
        }
    }
    echo "\n";
}