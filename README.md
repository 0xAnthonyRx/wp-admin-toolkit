# wp-admin-toolkit

A lightweight PHP utility library for WordPress web administration — covering security hardening, performance optimisation, and form validation.

Built as a practical reference for real-world WordPress admin work.

---

## Contents

| File | Purpose |
|---|---|
| `functions.php` | WordPress hooks and filters — drop snippets into your active theme |
| `validator.php` | Standalone contact form sanitizer and validator |

---

## functions.php — What's Inside

### 1. Remove WordPress Version String
Strips the WP version from HTML meta tags and RSS feeds, preventing automated scanners from fingerprinting the installation against known CVEs.

```php
add_filter( 'the_generator', 'swp_remove_wp_version' );
```

### 2. Disable XML-RPC
XML-RPC is a legacy protocol frequently abused for brute-force and DDoS amplification attacks. Disabled at the filter level — safer than `.htaccess` blocking alone.

```php
add_filter( 'xmlrpc_enabled', '__return_false' );
```

### 3. Remove X-Pingback Header
Strips the `X-Pingback` response header to close a secondary information-disclosure vector that persists even after XML-RPC is disabled.

### 4. Block Author Enumeration
Prevents `/?author=1` URL probing that exposes valid WordPress usernames to attackers. Returns a `403 Forbidden` before any username is revealed.

### 5. Disable Emoji Scripts
Removes WordPress's emoji JavaScript and associated DNS lookup from every page load — reducing render-blocking requests and improving PageSpeed scores.

### 6. Custom Admin Footer Branding
Replaces the default WordPress admin footer text with a custom administrator credit. Useful for client handovers and managed site work.

### 7. Content Update Logger
On every deliberate post/page save, appends a structured entry to `wp-content/content-update.log`:

```
[2025-04-06 14:32:01] UPDATED | Post ID: 42 | Title: About Us | Editor: anthony
```

Uses `FILE_APPEND | LOCK_EX` for safe concurrent writes. Skips autosaves and revisions.

---

## validator.php — What's Inside

A self-contained form validation and sanitisation class. No dependencies — works in any PHP 7.4+ environment.

### Validates
- **Name** — required, 2–100 chars, letters/hyphens/apostrophes only
- **Email** — required, RFC 5322 format via `filter_var`, max 254 chars, normalised to lowercase
- **Phone** — optional, international format (+234...), 7–15 digits
- **Message** — required, 10–2000 chars, stripped of all HTML tags

### Security Features
- `strip_tags()` on all string inputs to prevent stored XSS
- `htmlspecialchars()` on output with `ENT_QUOTES` and `UTF-8`
- **Honeypot field** — silently rejects bot submissions that populate the hidden `website` field
- No regex on email (avoids ReDoS) — uses PHP's native `FILTER_VALIDATE_EMAIL`

### Usage

```php
require_once 'validator.php';

$result = validate_contact_form( $_POST );

if ( $result['valid'] ) {
    // $result['data'] contains sanitized values safe for DB/email
    $name    = $result['data']['name'];
    $email   = $result['data']['email'];
    $message = $result['data']['message'];
} else {
    // Return errors to the user
    foreach ( $result['errors'] as $field => $message ) {
        echo "{$field}: {$message}\n";
    }
}
```

### Test from CLI

```bash
php validator.php
```

Runs three built-in test cases: valid submission, missing/invalid fields, and a honeypot-triggered bot submission.

---

## Security Philosophy

Every snippet in this toolkit follows the principle of **defence in depth** — no single layer is relied upon alone. Version hiding, XML-RPC disabling, and header stripping each address different attacker reconnaissance vectors. The form validator applies input validation, output encoding, and spam trapping as three separate, independent layers.

---

## Requirements

- PHP 7.4 or higher
- WordPress 5.8+ (for `functions.php` hooks)
- `validator.php` has no WordPress dependency

---

## License

MIT — free to use, modify, and include in client projects.

---

*Built by [Anthony](https://github.com/0xAnthonyRx) — DevSecOps & Web Administration*
