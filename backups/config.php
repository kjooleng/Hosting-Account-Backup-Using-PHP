<?php
/**
 * Backup System Configuration
 * Version: 2.1 - With Session Management
 * IMPORTANT: Keep this file secure and outside public web access if possible
 */

// Prevent direct access
if (!defined('ROOT_PATH')) {
    die('Direct access not permitted');
}

// ============================================================================
// AUTHENTICATION CREDENTIALS
// ============================================================================

// Admin username
define('BACKUP_ADMIN_USERNAME', 'admin');

// Admin password hash (use the generator below to create a new hash)
// Default password: 'changeme123' - CHANGE THIS IMMEDIATELY!
define('BACKUP_ADMIN_PASSWORD_HASH', '$2y$10$xJvH8Kx5m9Q7l.LqYiYrMeZ1W2xY3vN4zB5aT6wD7eC8fR9gH0iJ1');

/*
 * PASSWORD HASH GENERATOR
 * =======================
 * Uncomment the lines below, replace 'your_secure_password_here' with your desired password,
 * access this file once through backup.php, copy the hash output,
 * paste it in BACKUP_ADMIN_PASSWORD_HASH above, then comment these lines again.
 * 
 * IMPORTANT: Make sure to comment out these lines after generating your hash!
 */
/*
$newPassword = 'your_secure_password_here';
echo "<html><head><title>Password Hash Generator</title></head><body>";
echo "<h2>Password Hash Generator</h2>";
echo "<p><strong>Your password hash:</strong></p>";
echo "<code style='background:#f0f0f0;padding:10px;display:block;'>";
echo password_hash($newPassword, PASSWORD_BCRYPT);
echo "</code>";
echo "<br><br><p>Copy the hash above and paste it in <code>BACKUP_ADMIN_PASSWORD_HASH</code></p>";
echo "<p style='color:red;'><strong>IMPORTANT:</strong> Comment out the password generator code after use!</p>";
echo "</body></html>";
die();
*/

// ============================================================================
// DATABASE CREDENTIALS
// ============================================================================

define('DB_HOST', 'localhost');
define('DB_NAME', 'your_database_name');
define('DB_USER', 'your_database_user');
define('DB_PASS', 'your_database_password');

// ============================================================================
// SESSION SETTINGS
// ============================================================================

// Session timeout for idle browsing (in seconds)
// Default: 1800 = 30 minutes
define('SESSION_TIMEOUT', 1800);

// Absolute maximum session lifetime (security measure)
// Even active operations will be logged out after this time
// For very large backups, set this to a high value
// Default: 172800 = 48 hours (2 days)
define('SESSION_LIFETIME', 172800);

// Optional: Log session activity for debugging
// Set to false in production for better performance
define('LOG_SESSION_ACTIVITY', false);

// ============================================================================
// BACKUP SETTINGS (OPTIONAL CUSTOMIZATION)
// ============================================================================

// You can override default settings here if needed
// Uncomment and modify as needed:

// Maximum chunk size for backup files (default: 9MB)
// define('MAX_CHUNK_SIZE', 9 * 1024 * 1024);

// Number of files to process per step (default: 10)
// define('FILES_PER_STEP', 10);

// Database rows per batch (default: 500)
// define('DB_ROWS_PER_BATCH', 500);

// Maximum number of backups to keep (default: 5)
// define('MAX_BACKUPS', 5);

// Maximum backup requests per hour (rate limiting) (default: 10)
// define('MAX_REQUESTS_PER_HOUR', 10);

// ============================================================================
// SECURITY NOTES
// ============================================================================

/*
 * IMPORTANT SECURITY RECOMMENDATIONS:
 * 
 * 1. CHANGE DEFAULT PASSWORD
 *    - Use the password generator above to create a strong password
 *    - Password should be 12+ characters with mixed case, numbers, symbols
 * 
 * 2. FILE PERMISSIONS
 *    - Set this file to chmod 600 (read/write for owner only)
 *    - Command: chmod 600 backups/config.php
 * 
 * 3. VERSION CONTROL
 *    - Never commit this file to Git or other version control
 *    - Add to .gitignore: backups/config.php
 * 
 * 4. BACKUP THIS FILE
 *    - Keep a secure backup of this configuration file
 *    - Store credentials in a password manager
 * 
 * 5. HTACCESS PROTECTION
 *    - The .htaccess file protects this directory from web access
 *    - Verify .htaccess is in place: backups/.htaccess
 * 
 * 6. REGULAR UPDATES
 *    - Change password regularly (every 90 days recommended)
 *    - Review access logs for suspicious activity
 * 
 * 7. PRODUCTION DEPLOYMENT
 *    - Consider moving this file outside web root for extra security
 *    - Use environment variables for sensitive data when possible
 */

// ============================================================================
// CONFIGURATION VALIDATION
// ============================================================================

// Validate required constants are defined
if (!defined('BACKUP_ADMIN_USERNAME') || !defined('BACKUP_ADMIN_PASSWORD_HASH')) {
    die('ERROR: Authentication credentials not configured properly.');
}

if (!defined('DB_HOST') || !defined('DB_NAME') || !defined('DB_USER') || !defined('DB_PASS')) {
    die('ERROR: Database credentials not configured properly.');
}

// Warn if default password is still in use
if (BACKUP_ADMIN_PASSWORD_HASH === '$2y$10$xJvH8Kx5m9Q7l.LqYiYrMeZ1W2xY3vN4zB5aT6wD7eC8fR9gH0iJ1') {
    error_log('WARNING: Default password is still in use! Please change it immediately.');
}

// ============================================================================
// END OF CONFIGURATION
// ============================================================================
?>
