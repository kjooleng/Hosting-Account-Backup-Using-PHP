<?php
/**
 * Secured Incremental Backup and Restore Script with Dynamic Progress Bar
 * Version: 2.1 - Windows Compatible + Unlimited Session for Long Backups
 */

// Start session for authentication and CSRF
session_start();

// Define ROOT_PATH first (required by config.php)
define('ROOT_PATH', __DIR__);

// Configuration - Load from secure config file
$configFile = ROOT_PATH . '/backups/config.php';
if (!file_exists($configFile)) {
    die("Configuration file missing. Please create config.php in the backups directory.");
}
require_once $configFile;

// Core configuration
define('BACKUP_DIR', ROOT_PATH . '/backups');
define('MAX_CHUNK_SIZE', 9 * 1024 * 1024);
define('FILES_PER_STEP', 80);
define('DB_ROWS_PER_BATCH', 1000);
define('MAX_EXECUTION_TIME', 50);
define('STATE_FILE', BACKUP_DIR . '/backup_state.json');
define('RESTORE_STATE_FILE', BACKUP_DIR . '/restore_state.json');
define('RATE_LIMIT_FILE', BACKUP_DIR . '/rate_limit.json');
define('MAX_BACKUPS', 5);

// Security settings
define('MAX_REQUESTS_PER_HOUR', 5);

set_time_limit(MAX_EXECUTION_TIME);
$startTime = time();

// ============================================================================
// SECURITY FUNCTIONS
// ============================================================================

/**
 * Check if user is authenticated - NO timeout during active operations
 */
function isAuthenticated() {
    if (!isset($_SESSION['backup_authenticated']) || $_SESSION['backup_authenticated'] !== true) {
        return false;
    }
    
    // Check if any operation is currently running
    $backupState = loadState();
    $restoreState = loadRestoreState();
    $isOperationRunning = ($backupState['status'] === 'running' || $restoreState['status'] === 'running');
    
    // NO timeout if operation is running
    if ($isOperationRunning) {
        $_SESSION['last_activity'] = time(); // Keep session alive
        if (defined('LOG_SESSION_ACTIVITY') && LOG_SESSION_ACTIVITY) {
            error_log("Session kept alive - operation in progress");
        }
        return true;
    }
    
    // Enforce absolute maximum session lifetime
    if (isset($_SESSION['created']) && (time() - $_SESSION['created']) > SESSION_LIFETIME) {
        error_log("Absolute session lifetime exceeded");
        session_destroy();
        return false;
    }
    
    // Normal timeout check for idle sessions
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
        session_destroy();
        return false;
    }
    
    $_SESSION['last_activity'] = time();
    return true;
}

/**
 * Generate CSRF token
 */
function generateCsrfToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify CSRF token
 */
function verifyCsrfToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Validate timestamp format (14 digits only)
 */
function validateTimestamp($timestamp) {
    return is_string($timestamp) && preg_match('/^\d{14}$/', $timestamp) === 1;
}

/**
 * Validate mode parameter
 */
function validateMode($mode) {
    $allowedModes = ['backup', 'restore'];
    return in_array($mode, $allowedModes, true);
}

/**
 * Rate limiting check
 */
function checkRateLimit() {
    $now = time();
    $window = 3600; // 1 hour
    
    if (file_exists(RATE_LIMIT_FILE)) {
        $data = json_decode(file_get_contents(RATE_LIMIT_FILE), true);
        if (!$data) $data = ['requests' => []];
        
        // Filter requests within time window
        $data['requests'] = array_filter($data['requests'], function($timestamp) use ($now, $window) {
            return ($now - $timestamp) < $window;
        });
        
        if (count($data['requests']) >= MAX_REQUESTS_PER_HOUR) {
            error_log("Rate limit exceeded from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            return false;
        }
        
        $data['requests'][] = $now;
    } else {
        $data = ['requests' => [$now]];
    }
    
    file_put_contents(RATE_LIMIT_FILE, json_encode($data));
    return true;
}

/**
 * Sanitize error messages - no path disclosure
 */
function sanitizeError($message) {
    $message = str_replace(ROOT_PATH, '[ROOT]', $message);
    $message = str_replace(BACKUP_DIR, '[BACKUP_DIR]', $message);
    $message = str_replace($_SERVER['DOCUMENT_ROOT'] ?? '', '[DOCUMENT_ROOT]', $message);
    return $message;
}

/**
 * Validate SQL statement - whitelist approach
 */
function isAllowedSqlStatement($statement) {
    $statementUpper = strtoupper(trim($statement));
    
    // Empty or comment-only statements
    if (empty($statementUpper) || strpos($statementUpper, '--') === 0) {
        return true;
    }
    
    // Whitelist of allowed SQL commands
    $allowed = [
        'DROP TABLE IF EXISTS',
        'CREATE TABLE',
        'INSERT INTO',
        'INSERT IGNORE INTO',
        'ALTER TABLE',
        'CREATE INDEX',
        'DROP INDEX'
    ];
    
    foreach ($allowed as $allowedCmd) {
        if (strpos($statementUpper, $allowedCmd) === 0) {
            return true;
        }
    }
    
    return false;
}

/**
 * Detect if running on Windows
 */
function isWindows() {
    return strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
}

/**
 * Normalize file paths for cross-platform compatibility
 */
function normalizePath($path) {
    return str_replace(['\\', '/'], DIRECTORY_SEPARATOR, $path);
}

// ============================================================================
// AUTHENTICATION HANDLING
// ============================================================================

// Handle login
if (isset($_POST['login'])) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if ($username === BACKUP_ADMIN_USERNAME && password_verify($password, BACKUP_ADMIN_PASSWORD_HASH)) {
        $_SESSION['backup_authenticated'] = true;
        $_SESSION['last_activity'] = time();
        $_SESSION['created'] = time(); // Track session creation time
        $_SESSION['username'] = $username;
        
        // Configure PHP session lifetime
        ini_set('session.gc_maxlifetime', SESSION_LIFETIME);
        session_set_cookie_params(SESSION_LIFETIME);
        
        // Regenerate session ID to prevent session fixation
        session_regenerate_id(true);
        
        error_log("Successful login: $username from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        error_log("Failed login attempt: $username from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        $loginError = "Invalid credentials";
        sleep(2); // Slow down brute force attempts
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    error_log("Logout: " . ($_SESSION['username'] ?? 'unknown'));
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Show login form if not authenticated
if (!isAuthenticated()) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Backup System - Login</title>
        <meta name="robots" content="noindex, nofollow">
        <style>
            body { 
                font-family: Arial, sans-serif; 
                display: flex; 
                justify-content: center; 
                align-items: center; 
                height: 100vh; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0;
            }
            .login-box { 
                background: white; 
                padding: 40px; 
                border-radius: 10px; 
                box-shadow: 0 10px 40px rgba(0,0,0,0.2); 
                width: 320px; 
            }
            h2 { margin: 0 0 20px 0; color: #333; text-align: center; }
            input { 
                width: 100%; 
                padding: 12px; 
                margin: 10px 0; 
                border: 1px solid #ddd; 
                border-radius: 5px; 
                box-sizing: border-box;
                font-size: 14px;
            }
            input:focus { border-color: #667eea; outline: none; }
            button { 
                width: 100%; 
                padding: 12px; 
                background: #667eea; 
                color: white; 
                border: none; 
                border-radius: 5px; 
                cursor: pointer;
                font-size: 16px;
                font-weight: bold;
                margin-top: 10px;
            }
            button:hover { background: #5568d3; }
            .error { 
                color: #f44336; 
                background: #ffebee; 
                padding: 10px; 
                border-radius: 5px; 
                margin: 10px 0;
                font-size: 14px;
            }
            .info { color: #666; font-size: 12px; margin-top: 20px; text-align: center; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>🔒 Backup System</h2>
            <?php if (isset($loginError)): ?>
                <div class="error"><?= htmlspecialchars($loginError) ?></div>
            <?php endif; ?>
            <form method="POST" autocomplete="off">
                <input type="text" name="username" placeholder="Username" required autocomplete="username">
                <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
                <button type="submit" name="login">Login</button>
            </form>
            <div class="info">Authorized access only</div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// ============================================================================
// INITIALIZATION
// ============================================================================

// Create backup directory if not exists
if (!is_dir(BACKUP_DIR)) {
    if (isWindows()) {
        mkdir(BACKUP_DIR, 0777, true); // Windows ignores permissions
    } else {
        mkdir(BACKUP_DIR, 0755, true);
    }
}

// Verify directory is writable
if (!is_writable(BACKUP_DIR)) {
    die("Backup directory is not writable. Please check permissions.");
}

// Create .htaccess to protect backup directory
$htaccessPath = BACKUP_DIR . '/.htaccess';
if (!file_exists($htaccessPath)) {
    $htaccessContent = "# Protect backup files\n";
    $htaccessContent .= "Order Deny,Allow\n";
    $htaccessContent .= "Deny from all\n";
    $htaccessContent .= "<Files \"config.php\">\n";
    $htaccessContent .= "  Deny from all\n";
    $htaccessContent .= "</Files>\n";
    file_put_contents($htaccessPath, $htaccessContent);
}

// ============================================================================
// AJAX ENDPOINTS
// ============================================================================

// AJAX endpoint for getting status
if (isset($_GET['ajax']) && $_GET['ajax'] === 'status') {
    header('Content-Type: application/json');
    
    // Keep session alive during active operations
    if (isset($_SESSION['last_activity'])) {
        $_SESSION['last_activity'] = time();
    }
    
    $mode = isset($_GET['mode']) && validateMode($_GET['mode']) ? $_GET['mode'] : 'backup';
    
    if ($mode === 'restore') {
        $state = loadRestoreState();
    } else {
        $state = loadState();
    }
    
    if ($state['status'] === 'completed' && $mode === 'backup' && !isset($state['verification'])) {
        $state['verification'] = verifyBackup($state);
    }
    
    $state['backup_list'] = getBackupList();
    
    // Add session info
    $state['session_info'] = [
        'expires_in' => 0,
        'protected' => false
    ];
    
    if (isset($_SESSION['last_activity'])) {
        $isOperationRunning = ($state['status'] === 'running');
        if ($isOperationRunning) {
            $state['session_info']['protected'] = true;
            $state['session_info']['expires_in'] = -1; // Never expires
        } else {
            $remaining = SESSION_TIMEOUT - (time() - $_SESSION['last_activity']);
            $state['session_info']['expires_in'] = max(0, $remaining);
        }
    }
    
    echo json_encode($state);
    exit;
}

// AJAX endpoint for processing backup/restore step
if (isset($_GET['ajax']) && $_GET['ajax'] === 'process') {
    header('Content-Type: application/json');
    
    // Keep session alive
    if (isset($_SESSION['last_activity'])) {
        $_SESSION['last_activity'] = time();
    }
    
    $mode = isset($_GET['mode']) && validateMode($_GET['mode']) ? $_GET['mode'] : 'backup';
    
    if ($mode === 'restore') {
        $state = loadRestoreState();
        if ($state['status'] === 'running') {
            processRestoreStep($state, $startTime);
            saveRestoreState($state);
        }
    } else {
        $state = loadState();
        if ($state['status'] === 'running') {
            processBackupStep($state, $startTime);
            saveState($state);
            
            if ($state['status'] === 'completed') {
                cleanupOldBackups();
            }
        }
    }
    
    echo json_encode(['status' => 'ok', 'state' => $state]);
    exit;
}

// ============================================================================
// MAIN ROUTING
// ============================================================================

$mode = isset($_GET['mode']) && validateMode($_GET['mode']) ? $_GET['mode'] : 'backup';

if ($mode === 'restore') {
    $state = loadRestoreState();
} else {
    $state = loadState();
}

// Handle manual actions (with CSRF protection)
if (isset($_GET['action'])) {
    $action = $_GET['action'];
    
    // Verify CSRF token for state-changing operations
    if (!isset($_GET['token']) || !verifyCsrfToken($_GET['token'])) {
        error_log("CSRF token validation failed for action: $action");
        die("Security token validation failed. Please try again.");
    }
    
    switch ($action) {
        case 'start':
            if (!checkRateLimit()) {
                die("Rate limit exceeded. Please wait before starting a new backup.");
            }
            $state = resetState();
            saveState($state);
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
            
        case 'cancel':
            if ($mode === 'restore') {
                $state = getDefaultRestoreState();
                saveRestoreState($state);
            } else {
                $state = getDefaultState();
                saveState($state);
            }
            header('Location: ' . $_SERVER['PHP_SELF'] . ($mode === 'restore' ? '?mode=restore' : ''));
            exit;
            
        case 'diagnostic':
            $report = generateDiagnosticReport($state);
            $csrfToken = generateCsrfToken();
            echo "<!DOCTYPE html><html><head><title>Diagnostic Report</title><style>body{font-family:Arial;max-width:800px;margin:50px auto;padding:20px;}button{padding:10px 20px;background:#2196F3;color:white;border:none;border-radius:5px;cursor:pointer;}</style></head><body>";
            echo "<h1>Diagnostic Report</h1>";
            echo "<pre>";
            print_r($report);
            echo "</pre>";
            echo '<br><a href="' . htmlspecialchars($_SERVER['PHP_SELF']) . '"><button>Back to Backup</button></a>';
            echo "</body></html>";
            exit;
            
        case 'delete':
            if (isset($_GET['timestamp']) && validateTimestamp($_GET['timestamp'])) {
                deleteBackup($_GET['timestamp']);
            } else {
                error_log("Invalid delete attempt with timestamp: " . ($_GET['timestamp'] ?? 'none'));
            }
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
            
        case 'start_restore':
            if (isset($_GET['timestamp']) && validateTimestamp($_GET['timestamp'])) {
                if (!checkRateLimit()) {
                    die("Rate limit exceeded. Please wait before starting a restore.");
                }
                $state = initializeRestore($_GET['timestamp']);
                saveRestoreState($state);
            } else {
                error_log("Invalid restore attempt with timestamp: " . ($_GET['timestamp'] ?? 'none'));
            }
            header('Location: ' . $_SERVER['PHP_SELF'] . '?mode=restore');
            exit;
            
        default:
            error_log("Unknown action attempted: $action");
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
    }
}

// Display UI
if ($mode === 'restore') {
    displayRestoreUI($state);
} else {
    displayUI($state);
}

// ============================================================================
// STATE MANAGEMENT FUNCTIONS
// ============================================================================

function loadState() {
    if (file_exists(STATE_FILE)) {
        $state = json_decode(file_get_contents(STATE_FILE), true);
        return $state ?: getDefaultState();
    }
    return getDefaultState();
}

function saveState($state) {
    file_put_contents(STATE_FILE, json_encode($state, JSON_PRETTY_PRINT));
}

function loadRestoreState() {
    if (file_exists(RESTORE_STATE_FILE)) {
        $state = json_decode(file_get_contents(RESTORE_STATE_FILE), true);
        return $state ?: getDefaultRestoreState();
    }
    return getDefaultRestoreState();
}

function saveRestoreState($state) {
    file_put_contents(RESTORE_STATE_FILE, json_encode($state, JSON_PRETTY_PRINT));
}

function getDefaultState() {
    return [
        'status' => 'idle',
        'stage' => 'files',
        'timestamp' => date('YmdHis'),
        'files' => [
            'file_list' => [],
            'list_built' => false,
            'processed' => 0,
            'total' => 0,
            'current_chunk' => 1,
            'current_chunk_size' => 0,
            'chunks' => []
        ],
        'database' => [
            'current_table' => '',
            'table_index' => 0,
            'row_offset' => 0,
            'processed_rows' => 0,
            'total_rows' => 0,
            'current_chunk' => 1,
            'current_chunk_size' => 0,
            'chunks' => []
        ],
        'error' => null
    ];
}

function getDefaultRestoreState() {
    return [
        'status' => 'idle',
        'stage' => 'files',
        'timestamp' => '',
        'files' => [
            'chunks' => [],
            'current_chunk_index' => 0,
            'processed' => 0,
            'total' => 0,
            'current_zip' => null,
            'file_list' => [],
            'current_file_index' => 0
        ],
        'database' => [
            'chunks' => [],
            'current_chunk_index' => 0,
            'processed_statements' => 0,
            'total_statements' => 0,
            'current_position' => 0
        ],
        'error' => null
    ];
}

function resetState() {
    $state = getDefaultState();
    $state['status'] = 'running';
    $state['timestamp'] = date('YmdHis');
    
    $state['files']['file_list'] = buildFileList(ROOT_PATH);
    $state['files']['list_built'] = true;
    $state['files']['total'] = count($state['files']['file_list']);
    
    return $state;
}

function initializeRestore($timestamp) {
    $state = getDefaultRestoreState();
    $state['status'] = 'running';
    $state['timestamp'] = $timestamp;
    
    $files = scandir(BACKUP_DIR);
    foreach ($files as $file) {
        if (preg_match('/^files_' . preg_quote($timestamp, '/') . '_chunk\d+\.zip$/', $file)) {
            $state['files']['chunks'][] = $file;
        }
        if (preg_match('/^database_' . preg_quote($timestamp, '/') . '_chunk\d+\.sql$/', $file)) {
            $state['database']['chunks'][] = $file;
        }
    }
    
    sort($state['files']['chunks']);
    sort($state['database']['chunks']);
    
    $totalFiles = 0;
    foreach ($state['files']['chunks'] as $chunk) {
        $zip = new ZipArchive();
        if ($zip->open(BACKUP_DIR . '/' . $chunk) === true) {
            $totalFiles += $zip->numFiles;
            $zip->close();
        }
    }
    $state['files']['total'] = $totalFiles;
    
    $totalStatements = 0;
    foreach ($state['database']['chunks'] as $chunk) {
        $content = file_get_contents(BACKUP_DIR . '/' . $chunk);
        $totalStatements += countSqlStatements($content);
    }
    $state['database']['total_statements'] = $totalStatements;
    
    return $state;
}

// ============================================================================
// BACKUP MANAGEMENT FUNCTIONS
// ============================================================================

function getBackupList() {
    $backups = [];
    
    if (!is_dir(BACKUP_DIR)) {
        return $backups;
    }
    
    $files = scandir(BACKUP_DIR);
    $timestamps = [];
    
    foreach ($files as $file) {
        if (preg_match('/^(files|database)_(\d{14})_chunk\d+\.(zip|sql)$/', $file, $matches)) {
            $timestamp = $matches[2];
            if (!isset($timestamps[$timestamp])) {
                $timestamps[$timestamp] = [
                    'timestamp' => $timestamp,
                    'date' => date('Y-m-d H:i:s', strtotime($timestamp)),
                    'files' => [],
                    'total_size' => 0
                ];
            }
            $timestamps[$timestamp]['files'][] = $file;
            $timestamps[$timestamp]['total_size'] += filesize(BACKUP_DIR . '/' . $file);
        }
    }
    
    krsort($timestamps);
    
    return array_values($timestamps);
}

function deleteBackup($timestamp) {
    if (!validateTimestamp($timestamp)) {
        error_log("Invalid timestamp format in deleteBackup: " . $timestamp);
        return 0;
    }
    
    $files = scandir(BACKUP_DIR);
    $deletedCount = 0;
    
    foreach ($files as $file) {
        if (preg_match('/^(files|database)_' . preg_quote($timestamp, '/') . '_chunk\d+\.(zip|sql)$/', $file)) {
            $filePath = BACKUP_DIR . '/' . $file;
            
            // Security: ensure file is within BACKUP_DIR
            $realPath = realpath($filePath);
            if ($realPath && strpos($realPath, realpath(BACKUP_DIR)) === 0) {
                if (unlink($filePath)) {
                    $deletedCount++;
                }
            }
        }
    }
    
    error_log("Deleted backup $timestamp: $deletedCount files removed by " . ($_SESSION['username'] ?? 'unknown'));
    return $deletedCount;
}

function cleanupOldBackups() {
    $backups = getBackupList();
    
    if (count($backups) <= MAX_BACKUPS) {
        return;
    }
    
    $toDelete = array_slice($backups, MAX_BACKUPS);
    
    foreach ($toDelete as $backup) {
        deleteBackup($backup['timestamp']);
    }
}

function formatFileSize($bytes) {
    $units = ['B', 'KB', 'MB', 'GB'];
    $i = 0;
    
    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }
    
    return round($bytes, 2) . ' ' . $units[$i];
}

function buildFileList($path) {
    $fileList = [];
    
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        
        foreach ($iterator as $file) {
            try {
                $filePath = $file->getPathname();
                
                // Normalize paths for cross-platform comparison
                $normalizedFilePath = str_replace('\\', '/', $filePath);
                $normalizedBackupDir = str_replace('\\', '/', BACKUP_DIR);
                
                if (strpos($normalizedFilePath, $normalizedBackupDir) === 0) {
                    continue;
                }
                
                if ($file->isFile()) {
                    $fileList[] = $filePath;
                }
            } catch (Exception $e) {
                error_log("Error accessing file: " . sanitizeError($e->getMessage()));
            }
        }
    } catch (Exception $e) {
        error_log("Error building file list: " . sanitizeError($e->getMessage()));
    }
    
    return $fileList;
}

// ============================================================================
// BACKUP PROCESSING FUNCTIONS
// ============================================================================

function processBackupStep(&$state, $startTime) {
    try {
        if ($state['stage'] === 'files') {
            processFilesStep($state, $startTime);
            
            if ($state['files']['processed'] >= $state['files']['total']) {
                $state['stage'] = 'database';
                $state['database']['total_rows'] = countDatabaseRows();
            }
        } elseif ($state['stage'] === 'database') {
            processDatabaseStep($state, $startTime);
            
            if ($state['database']['current_table'] === 'completed') {
                $state['status'] = 'completed';
            }
        }
    } catch (Exception $e) {
        $state['status'] = 'error';
        $state['error'] = sanitizeError($e->getMessage());
        error_log("Backup error: " . $e->getMessage());
    }
}

function processFilesStep(&$state, $startTime) {
    if (!$state['files']['list_built']) {
        $state['files']['file_list'] = buildFileList(ROOT_PATH);
        $state['files']['list_built'] = true;
        $state['files']['total'] = count($state['files']['file_list']);
    }
    
    $zipFile = BACKUP_DIR . '/files_' . $state['timestamp'] . '_chunk' . $state['files']['current_chunk'] . '.zip';
    $zip = new ZipArchive();
    $zipOpen = false;
    
    try {
        if (!is_writable(BACKUP_DIR)) {
            throw new Exception("Backup directory is not writable");
        }
        
        $fileExists = file_exists($zipFile);
        
        if (!$fileExists || $state['files']['current_chunk_size'] === 0) {
            if ($fileExists) {
                unlink($zipFile);
            }
            $result = $zip->open($zipFile, ZipArchive::CREATE);
        } else {
            $result = $zip->open($zipFile);
            if ($result !== true) {
                if ($fileExists) {
                    unlink($zipFile);
                }
                $state['files']['current_chunk_size'] = 0;
                $result = $zip->open($zipFile, ZipArchive::CREATE);
            }
        }
        
        if ($result !== true) {
            throw new Exception("Failed to open ZIP file");
        }
        
        $zipOpen = true;
        $filesProcessed = 0;
        $processedCount = $state['files']['processed'];
        
        for ($i = $processedCount; $i < count($state['files']['file_list']); $i++) {
            $filePath = $state['files']['file_list'][$i];
            
            if (!file_exists($filePath) || !is_readable($filePath)) {
                $state['files']['processed']++;
                continue;
            }
            
            $fileSize = filesize($filePath);
            
            if ($zipOpen) {
                $zip->close();
                $zipOpen = false;
            }
            
            clearstatcache(true, $zipFile);
            $currentZipSize = file_exists($zipFile) ? filesize($zipFile) : 0;
            
            if ($currentZipSize > 0 && ($currentZipSize + $fileSize) >= MAX_CHUNK_SIZE) {
                $state['files']['chunks'][] = basename($zipFile);
                $state['files']['current_chunk']++;
                $state['files']['current_chunk_size'] = 0;
                
                $zipFile = BACKUP_DIR . '/files_' . $state['timestamp'] . '_chunk' . $state['files']['current_chunk'] . '.zip';
                
                if (file_exists($zipFile)) {
                    unlink($zipFile);
                }
                $result = $zip->open($zipFile, ZipArchive::CREATE);
            } else {
                if (file_exists($zipFile)) {
                    $result = $zip->open($zipFile);
                } else {
                    $result = $zip->open($zipFile, ZipArchive::CREATE);
                }
            }
            
            if ($result !== true) {
                throw new Exception("Failed to open ZIP file");
            }
            
            $zipOpen = true;
            
            // FIX: Normalize paths for cross-platform compatibility (Windows/Linux)
            $normalizedFilePath = str_replace('\\', '/', $filePath);
            $normalizedRootPath = str_replace('\\', '/', ROOT_PATH);
            
            // Remove root path and leading slash to get relative path
            $relativePath = str_replace($normalizedRootPath . '/', '', $normalizedFilePath);
            
            // Additional safeguard: if path still starts with drive letter, remove it
            if (preg_match('/^[A-Za-z]:/', $relativePath)) {
                $relativePath = ltrim(str_replace($normalizedRootPath, '', $normalizedFilePath), '/');
            }
            
            if (!$zip->addFile($filePath, $relativePath)) {
                error_log("Failed to add file to ZIP: " . sanitizeError($filePath));
            }
            
            $state['files']['processed']++;
            $filesProcessed++;
            
            if ($zipOpen) {
                $zip->close();
                $zipOpen = false;
            }
            
            clearstatcache(true, $zipFile);
            if (file_exists($zipFile)) {
                $state['files']['current_chunk_size'] = filesize($zipFile);
            } else {
                $state['files']['current_chunk_size'] = 0;
            }
            
            if ($filesProcessed >= FILES_PER_STEP || (time() - $startTime) >= (MAX_EXECUTION_TIME - 10)) {
                break;
            }
            
            if ($i + 1 < count($state['files']['file_list'])) {
                if (file_exists($zipFile)) {
                    $result = $zip->open($zipFile);
                } else {
                    $result = $zip->open($zipFile, ZipArchive::CREATE);
                }
                
                if ($result === true) {
                    $zipOpen = true;
                } else {
                    break;
                }
            }
        }
        
    } finally {
        if ($zipOpen) {
            $zip->close();
        }
    }
    
    if ($state['files']['processed'] >= $state['files']['total']) {
        clearstatcache(true, $zipFile);
        if (file_exists($zipFile) && filesize($zipFile) > 0) {
            $state['files']['chunks'][] = basename($zipFile);
        }
    }
}

function countDatabaseRows() {
    try {
        $pdo = getDatabaseConnection();
        $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
        $total = 0;
        
        foreach ($tables as $table) {
            $count = $pdo->query("SELECT COUNT(*) FROM `$table`")->fetchColumn();
            $total += $count;
        }
        
        return $total;
    } catch (Exception $e) {
        error_log("Error counting database rows: " . sanitizeError($e->getMessage()));
        return 0;
    }
}

function processDatabaseStep(&$state, $startTime) {
    $pdo = getDatabaseConnection();
    $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
    
    if (empty($state['database']['current_table'])) {
        $state['database']['current_table'] = $tables[0];
        $state['database']['table_index'] = 0;
    }
    
    $currentTable = $state['database']['current_table'];
    $sqlFile = BACKUP_DIR . '/database_' . $state['timestamp'] . '_chunk' . $state['database']['current_chunk'] . '.sql';
    
    if ($state['database']['row_offset'] === 0) {
        $createTable = $pdo->query("SHOW CREATE TABLE `$currentTable`")->fetch(PDO::FETCH_ASSOC);
        $sql = "\n\n-- Table: $currentTable\n";
        $sql .= "DROP TABLE IF EXISTS `$currentTable`;\n";
        $sql .= $createTable['Create Table'] . ";\n\n";
        
        $currentSize = file_exists($sqlFile) ? filesize($sqlFile) : 0;
        if ($currentSize > 0 && ($currentSize + strlen($sql)) >= MAX_CHUNK_SIZE) {
            $state['database']['chunks'][] = basename($sqlFile);
            $state['database']['current_chunk']++;
            $state['database']['current_chunk_size'] = 0;
            $sqlFile = BACKUP_DIR . '/database_' . $state['timestamp'] . '_chunk' . $state['database']['current_chunk'] . '.sql';
        }
        
        file_put_contents($sqlFile, $sql, FILE_APPEND);
    }
    
    $offset = $state['database']['row_offset'];
    $stmt = $pdo->query("SELECT * FROM `$currentTable` LIMIT " . DB_ROWS_PER_BATCH . " OFFSET $offset");
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    if (!empty($rows)) {
        $sql = "";
        foreach ($rows as $row) {
            $values = array_map(function($v) use ($pdo) {
                return $v === null ? 'NULL' : $pdo->quote($v);
            }, array_values($row));
            
            $insertStatement = "INSERT INTO `$currentTable` VALUES (" . implode(', ', $values) . ");\n";
            
            $currentSize = filesize($sqlFile);
            if (($currentSize + strlen($sql) + strlen($insertStatement)) >= MAX_CHUNK_SIZE) {
                if (!empty($sql)) {
                    file_put_contents($sqlFile, $sql, FILE_APPEND);
                    $sql = "";
                }
                
                $state['database']['chunks'][] = basename($sqlFile);
                $state['database']['current_chunk']++;
                $state['database']['current_chunk_size'] = 0;
                $sqlFile = BACKUP_DIR . '/database_' . $state['timestamp'] . '_chunk' . $state['database']['current_chunk'] . '.sql';
            }
            
            $sql .= $insertStatement;
            $state['database']['processed_rows']++;
        }
        
        if (!empty($sql)) {
            file_put_contents($sqlFile, $sql, FILE_APPEND);
        }
        
        $state['database']['row_offset'] += count($rows);
        clearstatcache(true, $sqlFile);
        $state['database']['current_chunk_size'] = filesize($sqlFile);
    }
    
    if (count($rows) < DB_ROWS_PER_BATCH) {
        $state['database']['table_index']++;
        $state['database']['row_offset'] = 0;
        
        if ($state['database']['table_index'] >= count($tables)) {
            $state['database']['current_table'] = 'completed';
            clearstatcache(true, $sqlFile);
            if (file_exists($sqlFile) && filesize($sqlFile) > 0) {
                $state['database']['chunks'][] = basename($sqlFile);
            }
        } else {
            $state['database']['current_table'] = $tables[$state['database']['table_index']];
        }
    }
}

function getDatabaseConnection() {
    static $pdo = null;
    
    if ($pdo === null) {
        try {
            $pdo = new PDO(
                "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
                DB_USER,
                DB_PASS,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_EMULATE_PREPARES => false
                ]
            );
        } catch (PDOException $e) {
            error_log("Database connection failed: " . sanitizeError($e->getMessage()));
            throw new Exception("Database connection failed");
        }
    }
    
    return $pdo;
}

// ============================================================================
// RESTORE PROCESSING FUNCTIONS (WITH SECURITY)
// ============================================================================

function processRestoreStep(&$state, $startTime) {
    try {
        if ($state['stage'] === 'files') {
            processFilesRestoreStep($state, $startTime);
            
            if ($state['files']['current_chunk_index'] >= count($state['files']['chunks'])) {
                $state['stage'] = 'database';
            }
        } elseif ($state['stage'] === 'database') {
            processDatabaseRestoreStep($state, $startTime);
            
            if ($state['database']['current_chunk_index'] >= count($state['database']['chunks'])) {
                $state['status'] = 'completed';
            }
        }
    } catch (Exception $e) {
        $state['status'] = 'error';
        $state['error'] = sanitizeError($e->getMessage());
        error_log("Restore error: " . $e->getMessage());
    }
}

function processFilesRestoreStep(&$state, $startTime) {
    if ($state['files']['current_chunk_index'] >= count($state['files']['chunks'])) {
        return;
    }
    
    $chunkFile = $state['files']['chunks'][$state['files']['current_chunk_index']];
    $zipPath = BACKUP_DIR . '/' . $chunkFile;
    
    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        throw new Exception("Failed to open ZIP file");
    }
    
    if (empty($state['files']['file_list'])) {
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $state['files']['file_list'][] = $zip->getNameIndex($i);
        }
    }
    
    $filesProcessed = 0;
    $startIndex = $state['files']['current_file_index'];
    
    for ($i = $startIndex; $i < count($state['files']['file_list']); $i++) {
        $fileName = $state['files']['file_list'][$i];
        $targetPath = ROOT_PATH . '/' . $fileName;
        
        // Security: ensure target path is within ROOT_PATH
        $realTarget = realpath(dirname($targetPath));
        if ($realTarget === false || strpos($realTarget, realpath(ROOT_PATH)) !== 0) {
            error_log("Security: Blocked file extraction outside root: " . sanitizeError($targetPath));
            continue;
        }
        
        $dir = dirname($targetPath);
        if (!is_dir($dir)) {
            if (isWindows()) {
                mkdir($dir, 0777, true);
            } else {
                mkdir($dir, 0755, true);
            }
        }
        
        $fileContent = $zip->getFromName($fileName);
        if ($fileContent !== false) {
            file_put_contents($targetPath, $fileContent);
            $state['files']['processed']++;
            $filesProcessed++;
        }
        
        $state['files']['current_file_index'] = $i + 1;
        
        if ($filesProcessed >= FILES_PER_STEP || (time() - $startTime) >= (MAX_EXECUTION_TIME - 10)) {
            $zip->close();
            return;
        }
    }
    
    $zip->close();
    
    $state['files']['current_chunk_index']++;
    $state['files']['file_list'] = [];
    $state['files']['current_file_index'] = 0;
}

/**
 * Process database restore step - SECURED with SQL validation
 */
function processDatabaseRestoreStep(&$state, $startTime) {
    if ($state['database']['current_chunk_index'] >= count($state['database']['chunks'])) {
        return;
    }
    
    $chunkFile = $state['database']['chunks'][$state['database']['current_chunk_index']];
    $sqlPath = BACKUP_DIR . '/' . $chunkFile;
    
    $pdo = getDatabaseConnection();
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    $content = file_get_contents($sqlPath);
    $currentPos = $state['database']['current_position'];
    
    $statementsProcessed = 0;
    $contentLength = strlen($content);
    
    while ($currentPos < $contentLength && $statementsProcessed < DB_ROWS_PER_BATCH) {
        // Skip whitespace and comments
        while ($currentPos < $contentLength) {
            $char = substr($content, $currentPos, 1);
            
            if ($char === ' ' || $char === "\n" || $char === "\r" || $char === "\t") {
                $currentPos++;
                continue;
            }
            
            if (substr($content, $currentPos, 3) === '-- ') {
                $endOfLine = strpos($content, "\n", $currentPos);
                if ($endOfLine === false) {
                    $currentPos = $contentLength;
                    break;
                } else {
                    $currentPos = $endOfLine + 1;
                    continue;
                }
            }
            
            if (substr($content, $currentPos, 2) === '/*') {
                $endComment = strpos($content, '*/', $currentPos + 2);
                if ($endComment === false) {
                    $currentPos = $contentLength;
                    break;
                } else {
                    $currentPos = $endComment + 2;
                    continue;
                }
            }
            
            break;
        }
        
        if ($currentPos >= $contentLength) {
            break;
        }
        
        $statementStart = $currentPos;
        $statementEnd = findStatementEnd($content, $currentPos, $contentLength);
        
        if ($statementEnd === false) {
            break;
        }
        
        $statement = substr($content, $statementStart, $statementEnd - $statementStart + 1);
        $statement = trim($statement);
        
        if (!empty($statement)) {
            // SECURITY: Validate statement before execution
            if (!isAllowedSqlStatement($statement)) {
                error_log("SECURITY: Blocked unauthorized SQL statement: " . substr($statement, 0, 100));
                $currentPos = $statementEnd + 1;
                continue;
            }
            
            try {
                $statementUpper = strtoupper(substr($statement, 0, 50));
                
                if (strpos($statementUpper, 'DROP TABLE') !== false) {
                    $pdo->exec($statement);
                }
                elseif (strpos($statementUpper, 'CREATE TABLE') !== false) {
                    $pdo->exec($statement);
                }
                elseif (strpos($statementUpper, 'INSERT INTO') !== false) {
                    if (strpos($statementUpper, 'INSERT IGNORE') === false) {
                        $statement = preg_replace('/^INSERT INTO/i', 'INSERT IGNORE INTO', $statement);
                    }
                    $pdo->exec($statement);
                }
                else {
                    $pdo->exec($statement);
                }
                
                $state['database']['processed_statements']++;
                $statementsProcessed++;
                
            } catch (PDOException $e) {
                $errorMsg = $e->getMessage();
                error_log("SQL Error: " . sanitizeError($errorMsg) . " - Statement: " . substr($statement, 0, 100));
            }
        }
        
        $currentPos = $statementEnd + 1;
        
        if ((time() - $startTime) >= (MAX_EXECUTION_TIME - 10)) {
            $state['database']['current_position'] = $currentPos;
            return;
        }
    }
    
    if ($currentPos >= $contentLength) {
        $state['database']['current_chunk_index']++;
        $state['database']['current_position'] = 0;
    } else {
        $state['database']['current_position'] = $currentPos;
    }
}

function findStatementEnd($content, $startPos, $contentLength) {
    $pos = $startPos;
    $inString = false;
    $stringChar = null;
    $escaped = false;
    
    while ($pos < $contentLength) {
        $char = $content[$pos];
        
        if ($escaped) {
            $escaped = false;
            $pos++;
            continue;
        }
        
        if ($char === '\\') {
            $escaped = true;
            $pos++;
            continue;
        }
        
        if (!$inString && ($char === "'" || $char === '"')) {
            $inString = true;
            $stringChar = $char;
            $pos++;
            continue;
        }
        
        if ($inString && $char === $stringChar) {
            $inString = false;
            $stringChar = null;
            $pos++;
            continue;
        }
        
        if (!$inString && $char === ';') {
            return $pos;
        }
        
        $pos++;
    }
    
    return false;
}

function countSqlStatements($content) {
    $count = 0;
    $pos = 0;
    $contentLength = strlen($content);
    
    while ($pos < $contentLength) {
        while ($pos < $contentLength) {
            $char = substr($content, $pos, 1);
            
            if ($char === ' ' || $char === "\n" || $char === "\r" || $char === "\t") {
                $pos++;
                continue;
            }
            
            if (substr($content, $pos, 3) === '-- ') {
                $endOfLine = strpos($content, "\n", $pos);
                if ($endOfLine === false) break;
                $pos = $endOfLine + 1;
                continue;
            }
            
            if (substr($content, $pos, 2) === '/*') {
                $endComment = strpos($content, '*/', $pos + 2);
                if ($endComment === false) break;
                $pos = $endComment + 2;
                continue;
            }
            
            break;
        }
        
        if ($pos >= $contentLength) break;
        
        $statementEnd = findStatementEnd($content, $pos, $contentLength);
        if ($statementEnd === false) break;
        
        $count++;
        $pos = $statementEnd + 1;
    }
    
    return $count;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function verifyBackup($state) {
    $verification = [
        'missing_files' => [],
        'total_checked' => 0,
        'found_in_backup' => 0
    ];
    
    if (empty($state['files']['chunks'])) {
        return $verification;
    }
    
    $samplesToCheck = [];
    $totalFiles = count($state['files']['file_list']);
    
    for ($i = 0; $i < min(10, $totalFiles); $i++) {
        $samplesToCheck[] = $state['files']['file_list'][$i];
    }
    
    for ($i = max(0, $totalFiles - 10); $i < $totalFiles; $i++) {
        if (!in_array($state['files']['file_list'][$i], $samplesToCheck)) {
            $samplesToCheck[] = $state['files']['file_list'][$i];
        }
    }
    
    foreach ($samplesToCheck as $filePath) {
        $verification['total_checked']++;
        $found = false;
        
        // Normalize for comparison
        $normalizedFilePath = str_replace('\\', '/', $filePath);
        $normalizedRootPath = str_replace('\\', '/', ROOT_PATH);
        $relativePath = str_replace($normalizedRootPath . '/', '', $normalizedFilePath);
        
        foreach ($state['files']['chunks'] as $chunkName) {
            $zipPath = BACKUP_DIR . '/' . $chunkName;
            if (file_exists($zipPath)) {
                $zip = new ZipArchive();
                if ($zip->open($zipPath) === true) {
                    if ($zip->locateName($relativePath) !== false) {
                        $found = true;
                        $zip->close();
                        break;
                    }
                    $zip->close();
                }
            }
        }
        
        if ($found) {
            $verification['found_in_backup']++;
        } else {
            $verification['missing_files'][] = $relativePath;
        }
    }
    
    return $verification;
}

function generateDiagnosticReport($state) {
    $report = [
        'system_info' => [
            'php_version' => PHP_VERSION,
            'os' => PHP_OS,
            'is_windows' => isWindows(),
            'max_execution_time' => ini_get('max_execution_time'),
            'memory_limit' => ini_get('memory_limit'),
            'session_lifetime' => SESSION_LIFETIME,
        ],
        'directories_scanned' => [],
        'sample_files' => [],
        'potential_issues' => []
    ];
    
    $dirs = [];
    foreach ($state['files']['file_list'] as $file) {
        $dir = dirname($file);
        if (!in_array($dir, $dirs)) {
            $dirs[] = $dir;
        }
    }
    $report['directories_scanned'] = array_slice($dirs, 0, 20);
    
    $report['sample_files'] = array_slice($state['files']['file_list'], 0, 10);
    
    if ($state['files']['total'] === 0) {
        $report['potential_issues'][] = "No files found to backup";
    }
    
    if ($state['files']['processed'] < $state['files']['total']) {
        $report['potential_issues'][] = "Backup incomplete: " . 
            ($state['files']['total'] - $state['files']['processed']) . " files not processed";
    }
    
    return $report;
}

// ============================================================================
// UI DISPLAY FUNCTIONS
// ============================================================================

/**
 * Display backup UI with dynamic AJAX progress bar
 */
function displayUI($state) {
    $filesProgress = $state['files']['total'] > 0 
        ? ($state['files']['processed'] / $state['files']['total']) * 100 
        : 0;
    
    $dbProgress = $state['database']['total_rows'] > 0 
        ? ($state['database']['processed_rows'] / $state['database']['total_rows']) * 100 
        : 0;
    
    $overallProgress = ($filesProgress + $dbProgress) / 2;
    
    $verification = null;
    if ($state['status'] === 'completed') {
        $verification = verifyBackup($state);
    }
    
    $backupList = getBackupList();
    $csrfToken = generateCsrfToken();
    
    // Session info
    $sessionAge = isset($_SESSION['created']) ? (time() - $_SESSION['created']) : 0;
    $lastActivity = isset($_SESSION['last_activity']) ? (time() - $_SESSION['last_activity']) : 0;
    $sessionRemaining = SESSION_TIMEOUT - $lastActivity;
    
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Backup Progress</title>
        <meta name="robots" content="noindex, nofollow">
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
            .header { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }
            .header h1 { margin: 0; color: #333; font-size: 24px; }
            .logout-btn { padding: 8px 16px; background: #f44336; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 14px; }
            .logout-btn:hover { background: #d32f2f; }
            .progress-container { width: 100%; background: #f0f0f0; border-radius: 5px; margin: 20px 0; position: relative; }
            .progress-bar { 
                height: 30px; 
                background: linear-gradient(90deg, #4CAF50, #45a049); 
                border-radius: 5px; 
                text-align: center; 
                line-height: 30px; 
                color: white; 
                transition: width 0.5s ease-in-out;
                box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
            }
            .progress-bar.animated {
                background: linear-gradient(90deg, #4CAF50, #45a049, #4CAF50);
                background-size: 200% 100%;
                animation: shimmer 2s infinite;
            }
            @keyframes shimmer {
                0% { background-position: 200% 0; }
                100% { background-position: -200% 0; }
            }
            .status { padding: 15px; margin: 10px 0; border-radius: 5px; transition: all 0.3s; background: white; }
            .status.running { border-left: 4px solid #2196F3; }
            .status.completed { border-left: 4px solid #4CAF50; }
            .status.error { border-left: 4px solid #f44336; background: #ffebee; }
            .status.warning { background: #FFF9C4; border-left: 4px solid #FFC107; }
            .details { background: white; padding: 15px; border-radius: 5px; margin: 10px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            button { padding: 10px 20px; margin: 5px; cursor: pointer; border: none; border-radius: 5px; background: #2196F3; color: white; transition: all 0.3s; font-size: 14px; }
            button:hover { background: #1976D2; transform: translateY(-1px); box-shadow: 0 2px 5px rgba(0,0,0,0.2); }
            button:disabled { background: #ccc; cursor: not-allowed; transform: none; }
            button.delete { background: #f44336; }
            button.delete:hover { background: #d32f2f; }
            button.restore { background: #FF9800; }
            button.restore:hover { background: #F57C00; }
            .chunks { font-size: 0.9em; color: #666; margin-top: 10px; }
            .chunk-list { max-height: 100px; overflow-y: auto; background: #f9f9f9; padding: 5px; border-radius: 3px; margin-top: 5px; }
            .verification { background: #f5f5f5; padding: 10px; border-radius: 5px; margin-top: 10px; font-size: 0.9em; }
            .backup-item { background: white; padding: 15px; margin: 10px 0; border-radius: 5px; border: 1px solid #ddd; transition: all 0.3s; }
            .backup-item:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
            .backup-item.current { border-color: #4CAF50; background: #f1f8f4; }
            table { width: 100%; border-collapse: collapse; }
            table td { padding: 8px; border-bottom: 1px solid #eee; }
            table td:first-child { width: 60%; }
            .spinner {
                display: inline-block;
                width: 14px;
                height: 14px;
                border: 2px solid #f3f3f3;
                border-top: 2px solid #2196F3;
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin-left: 10px;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            .user-info { font-size: 14px; color: #666; }
            .session-protected { margin-top: 10px; padding: 8px; background: #E8F5E9; border-radius: 3px; font-size: 0.9em; color: #2E7D32; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔒 Backup & Restore System</h1>
            <div>
                <span class="user-info">👤 <?= htmlspecialchars($_SESSION['username'] ?? 'User') ?></span>
                <button class="logout-btn" onclick="location.href='?logout'">Logout</button>
            </div>
        </div>
        
        <div class="status <?= $state['status'] ?>" id="statusBox">
            <strong>Status:</strong> <span id="statusText"><?= ucfirst($state['status']) ?></span>
            <span id="currentStage" style="<?= $state['status'] !== 'running' ? 'display:none;' : '' ?>">
                - Current Stage: <span id="stageText"><?= ucfirst($state['stage']) ?></span>
                <span class="spinner"></span>
            </span>
            <div id="sessionProtectedMsg" style="display:none;" class="session-protected">
                🔒 <strong>Session protected:</strong> You will stay logged in while backup is running
            </div>
        </div>
        
        <h3>Overall Progress</h3>
        <div class="progress-container">
            <div class="progress-bar <?= $state['status'] === 'running' ? 'animated' : '' ?>" id="overallProgress" style="width: <?= $overallProgress ?>%">
                <span id="overallProgressText"><?= number_format($overallProgress, 1) ?>%</span>
            </div>
        </div>
        
        <div class="details">
            <h4>Files Backup</h4>
            <div class="progress-container">
                <div class="progress-bar <?= $state['status'] === 'running' ? 'animated' : '' ?>" id="filesProgress" style="width: <?= $filesProgress ?>%">
                    <span id="filesProgressText"><?= $state['files']['processed'] ?> / <?= $state['files']['total'] ?> files</span>
                </div>
            </div>
            <div class="chunks">
                <strong>Chunks created:</strong> <span id="filesChunkCount"><?= count($state['files']['chunks']) ?></span>
                <div class="chunk-list" id="filesChunkList" style="<?= empty($state['files']['chunks']) ? 'display:none;' : '' ?>">
                    <?php foreach ($state['files']['chunks'] as $chunk): ?>
                        <?= htmlspecialchars($chunk) ?><br>
                    <?php endforeach; ?>
                </div>
            </div>
            
            <div id="verificationBox" style="<?= $verification === null ? 'display:none;' : '' ?>">
                <?php if ($verification !== null): ?>
                    <div class="verification">
                        <strong>✓ Verification Sample:</strong><br>
                        Checked: <?= $verification['total_checked'] ?> files<br>
                        Found in backup: <?= $verification['found_in_backup'] ?> files<br>
                        <?php if (!empty($verification['missing_files'])): ?>
                            <div class="status warning" style="margin-top: 10px;">
                                <strong>⚠ Missing from backup:</strong><br>
                                <?php foreach ($verification['missing_files'] as $missing): ?>
                                    - <?= htmlspecialchars($missing) ?><br>
                                <?php endforeach; ?>
                            </div>
                        <?php else: ?>
                            <span style="color: green;">✓ All sampled files verified</span>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        
        <div class="details">
            <h4>Database Backup</h4>
            <div class="progress-container">
                <div class="progress-bar <?= $state['status'] === 'running' ? 'animated' : '' ?>" id="dbProgress" style="width: <?= $dbProgress ?>%">
                    <span id="dbProgressText"><?= $state['database']['processed_rows'] ?> / <?= $state['database']['total_rows'] ?> rows</span>
                </div>
            </div>
            <div class="chunks">
                <strong>Current table:</strong> <span id="currentTable"><?= $state['database']['current_table'] ?: 'N/A' ?></span><br>
                <strong>Chunks created:</strong> <span id="dbChunkCount"><?= count($state['database']['chunks']) ?></span>
                <div class="chunk-list" id="dbChunkList" style="<?= empty($state['database']['chunks']) ? 'display:none;' : '' ?>">
                    <?php foreach ($state['database']['chunks'] as $chunk): ?>
                        <?= htmlspecialchars($chunk) ?><br>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
        
        <div id="errorBox" class="status error" style="<?= $state['error'] ? '' : 'display:none;' ?>">
            <strong>❌ Error:</strong> <span id="errorText"><?= htmlspecialchars($state['error'] ?: '') ?></span>
        </div>
        
        <div style="margin-top: 20px;">
            <button id="startBtn" onclick="startBackup('<?= $csrfToken ?>')" style="<?= $state['status'] === 'running' ? 'display:none;' : '' ?>">▶ Start New Backup</button>
            <button id="cancelBtn" onclick="cancelBackup('<?= $csrfToken ?>')" style="<?= $state['status'] === 'running' ? '' : 'display:none;' ?>">⏹ Cancel</button>
            <button id="diagnosticBtn" onclick="location.href='?action=diagnostic&token=<?= $csrfToken ?>'" style="<?= $state['status'] === 'completed' ? '' : 'display:none;' ?>">📊 Show Diagnostic Report</button>
        </div>
        
        <div class="details" style="margin-top: 20px;">
            <h4>📦 Backup History (Latest <?= MAX_BACKUPS ?>)</h4>
            <p style="color: #666; font-size: 0.9em;">Older backups are automatically deleted when limit is reached</p>
            
            <div id="backupList">
                <?php if (empty($backupList)): ?>
                    <p style="color: #999;">No backups found</p>
                <?php else: ?>
                    <?php foreach ($backupList as $backup): ?>
                        <div class="backup-item <?= $backup['timestamp'] === $state['timestamp'] ? 'current' : '' ?>">
                            <table>
                                <tr>
                                    <td><strong><?= $backup['date'] ?></strong> <?= $backup['timestamp'] === $state['timestamp'] ? '<span style="color:#4CAF50;">✓ Current</span>' : '' ?></td>
                                    <td style="text-align:right;">
                                        <button class="restore" onclick="if(confirm('⚠ Restore from this backup?\n\nThis will OVERWRITE existing files and database!\n\nAre you sure?')) location.href='?action=start_restore&timestamp=<?= $backup['timestamp'] ?>&token=<?= $csrfToken ?>'">↻ Restore</button>
                                        <button class="delete" onclick="if(confirm('Delete this backup?')) location.href='?action=delete&timestamp=<?= $backup['timestamp'] ?>&token=<?= $csrfToken ?>'">🗑 Delete</button>
                                    </td>
                                </tr>
                                <tr>
                                    <td colspan="2" style="font-size:0.9em;color:#666;">
                                        📁 Files: <?= count($backup['files']) ?> chunks | 💾 Total size: <?= formatFileSize($backup['total_size']) ?>
                                    </td>
                                </tr>
                            </table>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>
        
        <div class="details" style="margin-top: 20px;">
            <h4>🔧 Debug Information</h4>
            <strong>System:</strong> <?= PHP_OS ?> <?= isWindows() ? '(Windows)' : '(Unix/Linux)' ?><br>
            <strong>PHP Version:</strong> <?= PHP_VERSION ?><br>
            <strong>Timestamp:</strong> <span id="timestamp"><?= $state['timestamp'] ?></span><br>
            <strong>Directory writable:</strong> <?= is_writable(BACKUP_DIR) ? '✓ Yes' : '❌ No' ?><br>
            <strong>File list built:</strong> <span id="fileListBuilt"><?= $state['files']['list_built'] ? '✓ Yes' : 'No' ?></span><br>
            <strong>Files in list:</strong> <span id="fileCount"><?= count($state['files']['file_list']) ?></span><br>
            <strong>Max backups to keep:</strong> <?= MAX_BACKUPS ?><br>
            <strong>Current backup count:</strong> <?= count($backupList) ?><br>
            
            <!-- Session Information -->
            <hr style="margin: 15px 0; border: none; border-top: 1px solid #ddd;">
            <strong>Session info:</strong><br>
            <span style="font-size: 0.9em; color: #666;">
                Session age: <?= gmdate("H:i:s", $sessionAge) ?><br>
                Last activity: <?= $lastActivity ?> seconds ago<br>
                <?php if ($state['status'] === 'running'): ?>
                    <span style="color: #4CAF50;">✓ Session timeout disabled (backup running)</span>
                <?php else: ?>
                    <?php if ($sessionRemaining > 0): ?>
                        Session expires in: <?= gmdate("i:s", $sessionRemaining) ?>
                    <?php else: ?>
                        <span style="color: #f44336;">Session expired</span>
                    <?php endif; ?>
                <?php endif; ?>
            </span>
        </div>

        <script>
        let isProcessing = false;
        let statusInterval = null;
        let processInterval = null;
        
        window.addEventListener('load', function() {
            const initialStatus = '<?= $state['status'] ?>';
            if (initialStatus === 'running') {
                startPolling();
                showSessionProtection();
            }
        });
        
        function startBackup(token) {
            if (confirm('Start a new backup?\n\nThis will create a complete backup of your files and database.')) {
                location.href = '?action=start&token=' + token;
            }
        }
        
        function cancelBackup(token) {
            if (confirm('Cancel the current backup?')) {
                location.href = '?action=cancel&token=' + token;
            }
        }
        
        function startPolling() {
            statusInterval = setInterval(updateStatus, 6000);
            processInterval = setInterval(triggerProcess, 3000);
            updateStatus();
            triggerProcess();
        }
        
        function stopPolling() {
            if (statusInterval) clearInterval(statusInterval);
            if (processInterval) clearInterval(processInterval);
        }
        
        function showSessionProtection() {
            document.getElementById('sessionProtectedMsg').style.display = '';
        }
        
        function hideSessionProtection() {
            document.getElementById('sessionProtectedMsg').style.display = 'none';
        }
        
        function updateStatus() {
            fetch('?ajax=status')
                .then(response => response.json())
                .then(data => {
                    updateUI(data);
                    if (data.status !== 'running') {
                        stopPolling();
                        hideSessionProtection();
                    }
                })
                .catch(error => {
                    console.error('Status update error:', error);
                });
        }
        
        function triggerProcess() {
            if (isProcessing) return;
            
            isProcessing = true;
            fetch('?ajax=process')
                .then(response => response.json())
                .then(data => {
                    if (data.state) {
                        updateUI(data.state);
                    }
                    isProcessing = false;
                })
                .catch(error => {
                    console.error('Process error:', error);
                    isProcessing = false;
                });
        }
        
        function updateUI(state) {
            const filesProgress = state.files.total > 0 
                ? (state.files.processed / state.files.total) * 100 
                : 0;
            
            const dbProgress = state.database.total_rows > 0 
                ? (state.database.processed_rows / state.database.total_rows) * 100 
                : 0;
            
            const overallProgress = (filesProgress + dbProgress) / 2;
            
            document.getElementById('statusText').textContent = state.status.charAt(0).toUpperCase() + state.status.slice(1);
            document.getElementById('statusBox').className = 'status ' + state.status;
            
            if (state.status === 'running') {
                document.getElementById('currentStage').style.display = '';
                document.getElementById('stageText').textContent = state.stage.charAt(0).toUpperCase() + state.stage.slice(1);
                showSessionProtection();
            } else {
                document.getElementById('currentStage').style.display = 'none';
                hideSessionProtection();
            }
            
            updateProgressBar('overallProgress', 'overallProgressText', overallProgress, overallProgress.toFixed(1) + '%');
            updateProgressBar('filesProgress', 'filesProgressText', filesProgress, state.files.processed + ' / ' + state.files.total + ' files');
            updateProgressBar('dbProgress', 'dbProgressText', dbProgress, state.database.processed_rows + ' / ' + state.database.total_rows + ' rows');
            
            document.getElementById('filesChunkCount').textContent = state.files.chunks.length;
            document.getElementById('dbChunkCount').textContent = state.database.chunks.length;
            document.getElementById('currentTable').textContent = state.database.current_table || 'N/A';
            
            updateChunkList('filesChunkList', state.files.chunks);
            updateChunkList('dbChunkList', state.database.chunks);
            
            if (state.error) {
                document.getElementById('errorText').textContent = state.error;
                document.getElementById('errorBox').style.display = '';
            } else {
                document.getElementById('errorBox').style.display = 'none';
            }
            
            document.getElementById('startBtn').style.display = (state.status === 'idle' || state.status === 'completed' || state.status === 'error') ? '' : 'none';
            document.getElementById('cancelBtn').style.display = state.status === 'running' ? '' : 'none';
            document.getElementById('diagnosticBtn').style.display = state.status === 'completed' ? '' : 'none';
            
            document.getElementById('timestamp').textContent = state.timestamp;
            document.getElementById('fileListBuilt').textContent = state.files.list_built ? '✓ Yes' : 'No';
            document.getElementById('fileCount').textContent = state.files.file_list.length;
            
            if (state.status === 'completed' && state.verification) {
                document.getElementById('verificationBox').style.display = '';
            }
        }
        
        function updateProgressBar(barId, textId, percentage, text) {
            const bar = document.getElementById(barId);
            const textEl = document.getElementById(textId);
            bar.style.width = percentage + '%';
            textEl.textContent = text;
        }
        
        function updateChunkList(listId, chunks) {
            const list = document.getElementById(listId);
            if (chunks.length > 0) {
                list.style.display = '';
                list.innerHTML = chunks.map(chunk => htmlspecialchars(chunk) + '<br>').join('');
            } else {
                list.style.display = 'none';
            }
        }
        
        function htmlspecialchars(str) {
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }
        </script>
    </body>
    </html>
    <?php
}

/**
 * Display restore UI with dynamic AJAX progress bar  
 */
function displayRestoreUI($state) {
    $filesProgress = $state['files']['total'] > 0 
        ? ($state['files']['processed'] / $state['files']['total']) * 100 
        : 0;
    
    $dbProgress = $state['database']['total_statements'] > 0 
        ? ($state['database']['processed_statements'] / $state['database']['total_statements']) * 100 
        : 0;
    
    $overallProgress = ($filesProgress + $dbProgress) / 2;
    $csrfToken = generateCsrfToken();
    
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Restore Progress</title>
        <meta name="robots" content="noindex, nofollow">
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
            .header { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }
            .header h1 { margin: 0; color: #FF9800; font-size: 24px; }
            .logout-btn { padding: 8px 16px; background: #f44336; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 14px; }
            .progress-container { width: 100%; background: #f0f0f0; border-radius: 5px; margin: 20px 0; }
            .progress-bar { height: 30px; background: #FF9800; border-radius: 5px; text-align: center; line-height: 30px; color: white; transition: width 0.5s ease-in-out; }
            .progress-bar.animated { animation: shimmer 2s infinite; background: linear-gradient(90deg, #FF9800, #F57C00, #FF9800); background-size: 200% 100%; }
            @keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
            .status { padding: 15px; margin: 10px 0; border-radius: 5px; background: white; }
            .status.running { border-left: 4px solid #FF9800; }
            .status.completed { border-left: 4px solid #4CAF50; }
            .status.error { border-left: 4px solid #f44336; background: #ffebee; }
            .details { background: white; padding: 15px; border-radius: 5px; margin: 10px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            button { padding: 10px 20px; margin: 5px; cursor: pointer; border: none; border-radius: 5px; background: #2196F3; color: white; }
            button:hover { background: #1976D2; }
            .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid #f3f3f3; border-top: 2px solid #FF9800; border-radius: 50%; animation: spin 1s linear infinite; margin-left: 10px; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            .warning-box { background: #FFF3E0; padding: 15px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #FF9800; }
            .user-info { font-size: 14px; color: #666; }
            .session-protected { margin-top: 10px; padding: 8px; background: #E8F5E9; border-radius: 3px; font-size: 0.9em; color: #2E7D32; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>↻ Restore Progress</h1>
            <div>
                <span class="user-info">👤 <?= htmlspecialchars($_SESSION['username'] ?? 'User') ?></span>
                <button class="logout-btn" onclick="location.href='?logout'">Logout</button>
            </div>
        </div>
        
        <div class="status <?= $state['status'] ?>" id="statusBox">
            <strong>Status:</strong> <span id="statusText"><?= ucfirst($state['status']) ?></span>
            <span id="currentStage" style="<?= $state['status'] !== 'running' ? 'display:none;' : '' ?>">
                - Current Stage: <span id="stageText"><?= ucfirst($state['stage']) ?></span>
                <span class="spinner"></span>
            </span>
            <div id="sessionProtectedMsg" style="display:none;" class="session-protected">
                🔒 <strong>Session protected:</strong> You will stay logged in while restore is running
            </div>
        </div>
        
        <div class="warning-box">
            <strong>⚠ Warning:</strong> Restoring from backup: <strong><?= $state['timestamp'] ?></strong>
        </div>
        
        <h3>Overall Progress</h3>
        <div class="progress-container">
            <div class="progress-bar <?= $state['status'] === 'running' ? 'animated' : '' ?>" id="overallProgress" style="width: <?= $overallProgress ?>%">
                <span id="overallProgressText"><?= number_format($overallProgress, 1) ?>%</span>
            </div>
        </div>
        
        <div class="details">
            <h4>Files Restore</h4>
            <div class="progress-container">
                <div class="progress-bar <?= $state['status'] === 'running' ? 'animated' : '' ?>" id="filesProgress" style="width: <?= $filesProgress ?>%">
                    <span id="filesProgressText"><?= $state['files']['processed'] ?> / <?= $state['files']['total'] ?> files</span>
                </div>
            </div>
            <p style="font-size: 0.9em; color: #666;">
                Processing chunk <span id="currentFileChunk"><?= $state['files']['current_chunk_index'] + 1 ?></span> of <span id="totalFileChunks"><?= count($state['files']['chunks']) ?></span>
            </p>
        </div>
        
        <div class="details">
            <h4>Database Restore</h4>
            <div class="progress-container">
                <div class="progress-bar <?= $state['status'] === 'running' ? 'animated' : '' ?>" id="dbProgress" style="width: <?= $dbProgress ?>%">
                    <span id="dbProgressText"><?= $state['database']['processed_statements'] ?> / <?= $state['database']['total_statements'] ?> statements</span>
                </div>
            </div>
            <p style="font-size: 0.9em; color: #666;">
                Processing chunk <span id="currentDbChunk"><?= $state['database']['current_chunk_index'] + 1 ?></span> of <span id="totalDbChunks"><?= count($state['database']['chunks']) ?></span>
            </p>
        </div>
        
        <div id="errorBox" class="status error" style="<?= $state['error'] ? '' : 'display:none;' ?>">
            <strong>❌ Error:</strong> <span id="errorText"><?= htmlspecialchars($state['error'] ?: '') ?></span>
        </div>
        
        <div style="margin-top: 20px;">
            <button id="backBtn" onclick="location.href='<?= $_SERVER['PHP_SELF'] ?>'" style="<?= $state['status'] === 'completed' ? '' : 'display:none;' ?>">← Back to Backup Dashboard</button>
            <button id="cancelBtn" onclick="cancelRestore('<?= $csrfToken ?>')" style="<?= $state['status'] === 'running' ? '' : 'display:none;' ?>">⏹ Cancel Restore</button>
        </div>
        
        <div id="successBox" style="<?= $state['status'] === 'completed' ? '' : 'display:none;' ?>; background: #C8E6C9; padding: 15px; border-radius: 5px; margin-top: 20px; border-left: 4px solid #4CAF50;">
            <strong>✓ Restore completed successfully!</strong><br>
            Your website has been restored from backup <strong><?= $state['timestamp'] ?></strong>
        </div>

        <script>
        let isProcessing = false;
        let statusInterval = null;
        let processInterval = null;
        
        window.addEventListener('load', function() {
            const initialStatus = '<?= $state['status'] ?>';
            if (initialStatus === 'running') {
                startPolling();
                showSessionProtection();
            }
        });
        
        function cancelRestore(token) {
            if (confirm('⚠ Cancel restore?\n\nThis may leave your site in an inconsistent state!\n\nAre you sure?')) {
                location.href = '?mode=restore&action=cancel&token=' + token;
            }
        }
        
        function startPolling() {
            statusInterval = setInterval(updateStatus, 1000);
            processInterval = setInterval(triggerProcess, 2000);
            updateStatus();
            triggerProcess();
        }
        
        function stopPolling() {
            if (statusInterval) clearInterval(statusInterval);
            if (processInterval) clearInterval(processInterval);
        }
        
        function showSessionProtection() {
            document.getElementById('sessionProtectedMsg').style.display = '';
        }
        
        function hideSessionProtection() {
            document.getElementById('sessionProtectedMsg').style.display = 'none';
        }
        
        function updateStatus() {
            fetch('?ajax=status&mode=restore')
                .then(response => response.json())
                .then(data => {
                    updateUI(data);
                    if (data.status !== 'running') {
                        stopPolling();
                        hideSessionProtection();
                    }
                })
                .catch(error => console.error('Status update error:', error));
        }
        
        function triggerProcess() {
            if (isProcessing) return;
            isProcessing = true;
            fetch('?ajax=process&mode=restore')
                .then(response => response.json())
                .then(data => {
                    if (data.state) updateUI(data.state);
                    isProcessing = false;
                })
                .catch(error => {
                    console.error('Process error:', error);
                    isProcessing = false;
                });
        }
        
        function updateUI(state) {
            const filesProgress = state.files.total > 0 ? (state.files.processed / state.files.total) * 100 : 0;
            const dbProgress = state.database.total_statements > 0 ? (state.database.processed_statements / state.database.total_statements) * 100 : 0;
            const overallProgress = (filesProgress + dbProgress) / 2;
            
            document.getElementById('statusText').textContent = state.status.charAt(0).toUpperCase() + state.status.slice(1);
            document.getElementById('statusBox').className = 'status ' + state.status;
            
            if (state.status === 'running') {
                document.getElementById('currentStage').style.display = '';
                document.getElementById('stageText').textContent = state.stage.charAt(0).toUpperCase() + state.stage.slice(1);
                showSessionProtection();
            } else {
                document.getElementById('currentStage').style.display = 'none';
                hideSessionProtection();
            }
            
            updateProgressBar('overallProgress', 'overallProgressText', overallProgress, overallProgress.toFixed(1) + '%');
            updateProgressBar('filesProgress', 'filesProgressText', filesProgress, state.files.processed + ' / ' + state.files.total + ' files');
            updateProgressBar('dbProgress', 'dbProgressText', dbProgress, state.database.processed_statements + ' / ' + state.database.total_statements + ' statements');
            
            document.getElementById('currentFileChunk').textContent = state.files.current_chunk_index + 1;
            document.getElementById('totalFileChunks').textContent = state.files.chunks.length;
            document.getElementById('currentDbChunk').textContent = state.database.current_chunk_index + 1;
            document.getElementById('totalDbChunks').textContent = state.database.chunks.length;
            
            if (state.error) {
                document.getElementById('errorText').textContent = state.error;
                document.getElementById('errorBox').style.display = '';
            } else {
                document.getElementById('errorBox').style.display = 'none';
            }
            
            document.getElementById('backBtn').style.display = state.status === 'completed' ? '' : 'none';
            document.getElementById('cancelBtn').style.display = state.status === 'running' ? '' : 'none';
            document.getElementById('successBox').style.display = state.status === 'completed' ? '' : 'none';
        }
        
        function updateProgressBar(barId, textId, percentage, text) {
            const bar = document.getElementById(barId);
            const textEl = document.getElementById(textId);
            bar.style.width = percentage + '%';
            textEl.textContent = text;
        }
        </script>
    </body>
    </html>
    <?php
}
?>

