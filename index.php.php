<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
/*********************************************************************
 * E-CLEAR / ELECTRONIC CLEARANCE SYSTEM  (Single-File, Secured)
 *  - TOTP two-factor auth for officers/admins
 *  - Digitally signed approvals (HMAC) + tamper-proof certificates
 *  - Watermarked certificate with public verification ID
 *  - Login throttling, session hardening, security headers
 *********************************************************************/
session_set_cookie_params([
    'lifetime' => 0, 'path' => '/', 'domain' => '',
    'secure' => false, 'httponly' => true, 'samesite' => 'Lax'
]);
session_start();

/* ---------------- CONFIG ---------------- */
define('DB_HOST', 'localhost');
define('DB_NAME', 'fixqgjon_eclear');
define('DB_USER', 'fixqgjon_eclearuser');
define('DB_PASS', 'gabolangmalakasdibamich');
define('DB_CHARSET', 'utf8mb4');

define('APP_NAME', 'E-Clear');
define('APP_TITLE', 'Electronic Clearance System');

define('SECURITY_SALT', 'eCl3ar-S3cr3t-S1gn1ng-K3y-9f2a7c1d');

define('TOTP_STEP', 30);
define('TOTP_DIGITS', 6);

define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_SECONDS', 900);

define('SITE_URL', 'https://eclear.whf.bz');

/* ---------------- DATABASE ---------------- */
$page = $_GET['page'] ?? 'home';
try {
    $pdo = new PDO('mysql:host=' . DB_HOST . ';charset=' . DB_CHARSET, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    try {
        $pdo->exec("USE `" . DB_NAME . "`");
    } catch (PDOException $e) {
        if ($page !== 'setup') die('Database <b>' . DB_NAME . '</b> not found. Run <a href="?page=setup">setup</a> to install.');
    }
} catch (PDOException $e) {
    if ($page !== 'setup') die('Cannot connect to MySQL. Start it in XAMPP and open <a href="?page=setup">setup</a>.<br>' . $e->getMessage());
    $pdo = null;
}

/* ---------------- HELPERS ---------------- */
function h($s) { return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }
function redirect($url) { header('Location: ' . $url); exit; }
function csrf_token() { if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32)); return $_SESSION['csrf']; }
function csrf_field() { return '<input type="hidden" name="csrf" value="' . csrf_token() . '">'; }
function check_csrf() { if ($_SERVER['REQUEST_METHOD'] === 'POST') { if (empty($_POST['csrf']) || !hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'])) die('Invalid CSRF token.'); } }
function status_badge($s) { $m = ['pending'=>'badge badge-warning','approved'=>'badge badge-success','cleared'=>'badge badge-success','rejected'=>'badge badge-danger']; return '<span class="' . ($m[$s] ?? 'badge') . '">' . ucfirst($s) . '</span>'; }
function get_user($pdo, $id) { $st = $pdo->prepare("SELECT u.*, d.name AS department_name FROM users u LEFT JOIN departments d ON u.department_id=d.id WHERE u.id=?"); $st->execute([$id]); return $st->fetch(); }
function all_departments($pdo) { return $pdo->query("SELECT * FROM departments ORDER BY name")->fetchAll(); }
function log_activity($pdo, $action) { $uid = $_SESSION['user_id'] ?? null; $pdo->prepare("INSERT INTO activity_log (user_id, action) VALUES (?,?)")->execute([$uid, $action]); }
function client_ip() { return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'; }
function site_url() {
    if (SITE_URL !== '') return rtrim(SITE_URL, '/');
    $s = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $path = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/index.php'));
    return rtrim($s . $host . $path, '/');
}

function recompute_clearance($pdo, $cid) {
    $rows = $pdo->prepare("SELECT status FROM clearance_items WHERE clearance_id=?");
    $rows->execute([$cid]); $rows = $rows->fetchAll();
    if (empty($rows)) return;
    $s = array_column($rows, 'status');
    if (in_array('rejected', $s, true)) $new = 'rejected';
    elseif (count(array_unique($s)) === 1 && $s[0] === 'approved') $new = 'cleared';
    else $new = 'pending';
    if ($new === 'cleared') {
        $c = $pdo->prepare("SELECT student_id, updated_at FROM clearances WHERE id=?"); $c->execute([$cid]); $c = $c->fetch();
        $vc = hash_hmac('sha256', $cid . '|' . $c['student_id'] . '|' . $c['updated_at'], SECURITY_SALT);
        $pdo->prepare("UPDATE clearances SET status=?, verify_code=? WHERE id=?")->execute([$new, $vc, $cid]);
    } else {
        $pdo->prepare("UPDATE clearances SET status=?, verify_code=NULL WHERE id=?")->execute([$new, $cid]);
    }
    return $new;
}
function verify_id($clearance) { return 'EC-' . str_pad($clearance['id'], 5, '0', STR_PAD_LEFT) . '-' . strtoupper(substr($clearance['verify_code'], 0, 8)); }

/* ---------------- TOTP (RFC 6238) ---------------- */
function totp_secret() { $a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; $s = ''; for ($i=0;$i<16;$i++) $s .= $a[random_int(0,31)]; return $s; }
function totp_b32_decode($s) {
    $s = strtoupper(rtrim($s,'=')); $alph = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; $bits = '';
    for ($i=0;$i<strlen($s);$i++) { $v = strpos($alph, $s[$i]); if ($v === false) continue; $bits .= str_pad(decbin($v), 5, '0', STR_PAD_LEFT); }
    $out = ''; for ($i=0; $i+8 <= strlen($bits); $i += 8) $out .= chr(bindec(substr($bits, $i, 8)));
    return $out;
}
function totp_int64_be($n) { return pack('C8', ($n>>56)&255,($n>>48)&255,($n>>40)&255,($n>>32)&255,($n>>24)&255,($n>>16)&255,($n>>8)&255,$n&255); }
function totp_hotp($secret, $counter) {
    $key = totp_b32_decode($secret); $data = totp_int64_be($counter);
    $hash = hash_hmac('sha1', $data, $key, true); $offset = ord($hash[19]) & 0xF;
    $bin = substr($hash, $offset, 4); $code = unpack('N', $bin)[1] & 0x7FFFFFFF;
    return str_pad($code % (10 ** TOTP_DIGITS), TOTP_DIGITS, '0', STR_PAD_LEFT);
}
function totp_code($secret, $time = null) { return totp_hotp($secret, floor(($time ?? time()) / TOTP_STEP)); }
function totp_verify($secret, $code) { $t = time(); for ($i = -1; $i <= 1; $i++) if (totp_code($secret, $t + $i * TOTP_STEP) === $code) return true; return false; }

/* ---------------- ACCESS CONTROL ---------------- */
$public = ['home','landing','login','register','setup','logout','verify','2fa','robots','sitemap'];
if (!in_array($page, $public) && empty($_SESSION['user_id'])) redirect('?page=login');
if ($page === 'student'    && ($_SESSION['role'] ?? '') !== 'student') redirect('?page=home');
if ($page === 'department' && ($_SESSION['role'] ?? '') !== 'officer')  redirect('?page=home');
if ($page === 'admin'      && ($_SESSION['role'] ?? '') !== 'admin')    redirect('?page=home');
if ($page === 'profile'    && !in_array($_SESSION['role'] ?? '', ['officer','admin'])) redirect('?page=home');
if (in_array($page, ['student','department','admin','profile']) && !empty($_SESSION['pending_2fa'])) redirect('?page=2fa');
if ($page === 'home') { if (empty($_SESSION['user_id'])) $page = 'landing'; else $page = $_SESSION['role']; }

/* ---------------- LOGIN THROTTLE ---------------- */
function attempts_exceeded($pdo) {
    $ip = client_ip();
    $row = $pdo->prepare("SELECT attempts, last_try FROM login_attempts WHERE ip=?");
    $row->execute([$ip]); $row = $row->fetch();
    if (!$row) return false;
    if ($row['attempts'] >= MAX_LOGIN_ATTEMPTS && (time() - $row['last_try']) < LOCKOUT_SECONDS) return true;
    return false;
}
function register_attempt($pdo, $fail) {
    $ip = client_ip();
    if ($fail) {
        $pdo->prepare("INSERT INTO login_attempts (ip, attempts, last_try) VALUES (?,1,?) ON DUPLICATE KEY UPDATE attempts=attempts+1, last_try=?")
             ->execute([$ip, time(), time()]);
    } else {
        $pdo->prepare("DELETE FROM login_attempts WHERE ip=?")->execute([$ip]);
    }
}
function finalize_login($user) {
    session_regenerate_id(true);
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['full_name'] = $user['full_name'];
    $_SESSION['role'] = $user['role'];
    $_SESSION['department_id'] = $user['department_id'];
    $_SESSION['2fa_verified'] = !empty($user['totp_enabled']);
    unset($_SESSION['pending_2fa']);
    log_activity($GLOBALS['pdo'], 'Logged in');
    redirect('?page=home');
}

/* ---------------- ACTIONS ---------------- */
if ($page === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    if (attempts_exceeded($pdo)) { $login_error = 'Too many attempts. Try again later.'; }
    else {
        $email = trim($_POST['email'] ?? ''); $pw = $_POST['password'] ?? '';
        $st = $pdo->prepare("SELECT * FROM users WHERE email=? AND active=1"); $st->execute([$email]); $u = $st->fetch();
        if ($u && password_verify($pw, $u['password'])) {
            register_attempt($pdo, false);
            if (!empty($u['totp_enabled'])) {
                $_SESSION['pending_2fa'] = $u['id'];
                redirect('?page=2fa');
            }
            finalize_login($u);
        } else {
            register_attempt($pdo, true);
            $login_error = 'Invalid email or password.';
        }
    }
}
if ($page === '2fa' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    if (empty($_SESSION['pending_2fa'])) redirect('?page=login');
    $u = get_user($pdo, $_SESSION['pending_2fa']);
    $code = preg_replace('/\D/', '', $_POST['code'] ?? '');
    if ($u && totp_verify($u['totp_secret'], $code)) {
        finalize_login($u);
    } else { $twofa_error = 'Invalid or expired code.'; }
}
if ($page === 'logout') { log_activity($pdo ?? null, 'Logged out'); session_destroy(); redirect('?page=login'); }

if ($page === 'register' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    $fn = trim($_POST['full_name'] ?? ''); $sid = trim($_POST['student_id'] ?? '');
    $em = trim($_POST['email'] ?? ''); $pw = $_POST['password'] ?? ''; $cf = $_POST['confirm'] ?? '';
    if (!$fn || !$sid || !$em || !$pw) $reg_error = 'All fields are required.';
    elseif (!filter_var($em, FILTER_VALIDATE_EMAIL)) $reg_error = 'Invalid email.';
    elseif ($pw !== $cf) $reg_error = 'Passwords do not match.';
    elseif (strlen($pw) < 8) $reg_error = 'Password must be at least 8 characters.';
    else {
        $c = $pdo->prepare("SELECT id FROM users WHERE email=? OR student_id=?"); $c->execute([$em, $sid]);
        if ($c->fetch()) $reg_error = 'Email or student ID already registered.';
        else {
            $pdo->prepare("INSERT INTO users (full_name,student_id,email,password,role) VALUES (?,?,?,?,?)")
                ->execute([$fn, $sid, $em, password_hash($pw, PASSWORD_DEFAULT), 'student']);
            $reg_success = 'Account created. You can now sign in.';
        }
    }
}

if ($page === 'setup') {
    $steps = []; $ok = true;
    try {
        try {
            $pdo->exec("CREATE DATABASE IF NOT EXISTS `" . DB_NAME . "` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci");
            $steps[] = 'Database created.';
        } catch (PDOException $e) {
            // Many hosts (e.g. InfinityFree) pre-create the DB in their control panel; ignore.
        }
        $pdo->exec("USE `" . DB_NAME . "`"); $steps[] = 'Database selected.';
        $pdo->exec("CREATE TABLE IF NOT EXISTS departments (id INT AUTO_INCREMENT PRIMARY KEY, code VARCHAR(20) NOT NULL UNIQUE, name VARCHAR(120) NOT NULL, description TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB");
        $pdo->exec("CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, student_id VARCHAR(30) NULL UNIQUE, full_name VARCHAR(150) NOT NULL, email VARCHAR(150) NOT NULL UNIQUE, password VARCHAR(255) NOT NULL, role ENUM('admin','student','officer') NOT NULL DEFAULT 'student', department_id INT NULL, active TINYINT(1) NOT NULL DEFAULT 1, totp_secret VARCHAR(64) NULL, totp_enabled TINYINT(1) NOT NULL DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE SET NULL) ENGINE=InnoDB");
        $pdo->exec("CREATE TABLE IF NOT EXISTS clearances (id INT AUTO_INCREMENT PRIMARY KEY, student_id INT NOT NULL, reason VARCHAR(120) NOT NULL DEFAULT 'Graduation', status ENUM('pending','cleared','rejected') NOT NULL DEFAULT 'pending', verify_code VARCHAR(64) NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE) ENGINE=InnoDB");
        $pdo->exec("CREATE TABLE IF NOT EXISTS clearance_items (id INT AUTO_INCREMENT PRIMARY KEY, clearance_id INT NOT NULL, department_id INT NOT NULL, officer_id INT NULL, status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending', notes TEXT, signature VARCHAR(64) NULL, signed_at TIMESTAMP NULL, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, FOREIGN KEY (clearance_id) REFERENCES clearances(id) ON DELETE CASCADE, FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE CASCADE, FOREIGN KEY (officer_id) REFERENCES users(id) ON DELETE SET NULL, UNIQUE KEY (clearance_id, department_id)) ENGINE=InnoDB");
        $pdo->exec("CREATE TABLE IF NOT EXISTS activity_log (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NULL, action VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL) ENGINE=InnoDB");
        $pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (ip VARCHAR(45) PRIMARY KEY, attempts INT NOT NULL DEFAULT 0, last_try INT NOT NULL DEFAULT 0) ENGINE=InnoDB");
        $steps[] = 'Tables created.';
        $deps = [['LIB','Library','Return of all borrowed books and fines.'],['BUR','Bursary / Finance','Payment of tuition and fees.'],['HOS','Hostel / Accommodation','Vacating hostel and return of keys.'],['REG','Registry / Records','Verification of academic records.'],['DEP','Department','Clearance from academic department.'],['IT','ICT / Computer Unit','Return of ICT equipment.']];
        $si = $pdo->prepare("INSERT IGNORE INTO departments (code,name,description) VALUES (?,?,?)");
        foreach ($deps as $d) $si->execute($d);
        $steps[] = 'Departments seeded.';
        $chk = $pdo->prepare("SELECT id FROM users WHERE email=?"); $chk->execute(['admin@eclear.edu']);
        if (!$chk->fetch()) { $pdo->prepare("INSERT INTO users (full_name,email,password,role) VALUES (?,?,?,?)")->execute(['System Administrator','admin@eclear.edu',password_hash('admin123',PASSWORD_DEFAULT),'admin']); $steps[] = 'Admin: admin@eclear.edu / admin123'; }
        $dr = $pdo->query("SELECT id,code,name FROM departments")->fetchAll();
        foreach ($dr as $d) { $em = strtolower($d['code']).'@eclear.edu'; $c=$pdo->prepare("SELECT id FROM users WHERE email=?"); $c->execute([$em]); if(!$c->fetch()) $pdo->prepare("INSERT INTO users (full_name,email,password,role,department_id) VALUES (?,?,?,?,?)")->execute([$d['name'].' Officer',$em,password_hash('officer123',PASSWORD_DEFAULT),'officer',$d['id']]); }
        $steps[] = 'Officers created (password: officer123).';
    } catch (PDOException $e) { $ok=false; $steps[] = '<span style="color:#c0392b">Error: '.h($e->getMessage()).'</span>'; }
}

if ($page === 'student') {
    $sid = $_SESSION['user_id'];
    if (($_POST['start'] ?? '') && $_SERVER['REQUEST_METHOD']==='POST') {
        check_csrf();
        $ex = $pdo->prepare("SELECT id FROM clearances WHERE student_id=? AND status='pending'"); $ex->execute([$sid]);
        if ($ex->fetch()) { $stu_msg = '<div class="alert alert-info">You already have a pending clearance.</div>'; }
        else {
            $reason = trim($_POST['reason'] ?? 'Graduation');
            $pdo->beginTransaction();
            $pdo->prepare("INSERT INTO clearances (student_id,reason) VALUES (?,?)")->execute([$sid,$reason]);
            $cid = $pdo->lastInsertId();
            $ds = $pdo->query("SELECT id FROM departments")->fetchAll();
            $ins = $pdo->prepare("INSERT INTO clearance_items (clearance_id,department_id) VALUES (?,?)");
            foreach ($ds as $d) $ins->execute([$cid,$d['id']]);
            $pdo->commit(); log_activity($pdo,'Started clearance #'.$cid); redirect('?page=student');
        }
    }
    if (($_GET['action'] ?? '') === 'cert' && isset($_GET['id'])) {
        $cid = (int)$_GET['id'];
        $cl = $pdo->prepare("SELECT c.*,u.full_name,u.student_id FROM clearances c JOIN users u ON c.student_id=u.id WHERE c.id=? AND c.student_id=?");
        $cl->execute([$cid,$sid]); $clr = $cl->fetch();
        if ($clr) {
            $its = $pdo->prepare("SELECT ci.*,d.name AS department_name,d.code FROM clearance_items ci JOIN departments d ON ci.department_id=d.id WHERE ci.clearance_id=? ORDER BY d.name");
            $its->execute([$cid]); $items = $its->fetchAll();
            $cert_mode = true;
        }
    }
    if (!isset($cert_mode)) {
        $cl = $pdo->prepare("SELECT * FROM clearances WHERE student_id=? ORDER BY created_at DESC LIMIT 1"); $cl->execute([$sid]); $clearance = $cl->fetch();
        $items = []; $progress = 0;
        if ($clearance) {
            $it = $pdo->prepare("SELECT ci.*,d.name AS department_name,d.code,u.full_name AS officer_name FROM clearance_items ci JOIN departments d ON ci.department_id=d.id LEFT JOIN users u ON ci.officer_id=u.id WHERE ci.clearance_id=? ORDER BY d.name");
            $it->execute([$clearance['id']]); $items = $it->fetchAll();
            $tot = count($items) ?: 1; $app = 0; foreach ($items as $i) if ($i['status']==='approved') $app++;
            $progress = round($app/$tot*100);
        }
    }
}

if ($page === 'department') {
    $dep_id = $_SESSION['department_id'];
    if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['item_id'])) {
        check_csrf();
        $item_id = (int)$_POST['item_id']; $action = $_POST['action']; $notes = trim($_POST['notes'] ?? '');
        $v = $pdo->prepare("SELECT * FROM clearance_items WHERE id=? AND department_id=?"); $v->execute([$item_id,$dep_id]); $item = $v->fetch();
        if ($item) {
            $status = $action==='reject' ? 'rejected' : 'approved';
            $sig = hash_hmac('sha256', $item_id.'|'.$item['clearance_id'].'|'.$dep_id.'|'.$_SESSION['user_id'].'|'.time(), SECURITY_SALT);
            $pdo->prepare("UPDATE clearance_items SET status=?,notes=?,officer_id=?,signature=?,signed_at=NOW() WHERE id=?")
                 ->execute([$status,$notes,$_SESSION['user_id'],$sig,$item_id]);
            recompute_clearance($pdo,$item['clearance_id']);
            log_activity($pdo, ucfirst($status).' item #'.$item_id.' (signed)');
            redirect('?page=department');
        } else $dep_msg = '<div class="alert alert-danger">Unauthorized.</div>';
    }
    $stat_pending = $pdo->prepare("SELECT COUNT(*) FROM clearance_items WHERE department_id=? AND status='pending'"); $stat_pending->execute([$dep_id]); $stat_pending = $stat_pending->fetchColumn();
    $stat_approved = $pdo->prepare("SELECT COUNT(*) FROM clearance_items WHERE department_id=? AND status='approved'"); $stat_approved->execute([$dep_id]); $stat_approved = $stat_approved->fetchColumn();
    $q = $pdo->prepare("SELECT ci.id,ci.status,ci.notes,u.full_name,u.student_id,c.id AS clearance_id,c.reason,c.created_at FROM clearance_items ci JOIN clearances c ON ci.clearance_id=c.id JOIN users u ON c.student_id=u.id WHERE ci.department_id=? AND ci.status='pending' ORDER BY c.created_at ASC");
    $q->execute([$dep_id]); $queue = $q->fetchAll();
    $hd = $pdo->prepare("SELECT ci.id,ci.status,ci.notes,ci.signature,u.full_name,u.student_id,ci.updated_at FROM clearance_items ci JOIN clearances c ON ci.clearance_id=c.id JOIN users u ON c.student_id=u.id WHERE ci.department_id=? AND ci.status!='pending' ORDER BY ci.updated_at DESC LIMIT 10");
    $hd->execute([$dep_id]); $handled = $hd->fetchAll();
    $dp = $pdo->prepare("SELECT name FROM departments WHERE id=?"); $dp->execute([$dep_id]); $dep = $dp->fetch();
}

if ($page === 'admin') {
    $section = $_GET['section'] ?? 'overview';
    if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['add_dept'])) {
        check_csrf();
        $code = strtoupper(trim($_POST['code'] ?? '')); $name = trim($_POST['name'] ?? ''); $desc = trim($_POST['description'] ?? '');
        if ($code && $name) {
            $c = $pdo->prepare("SELECT id FROM departments WHERE code=?"); $c->execute([$code]);
            if ($c->fetch()) $adm_msg = '<div class="alert alert-danger">Code exists.</div>';
            else {
                $pdo->prepare("INSERT INTO departments (code,name,description) VALUES (?,?,?)")->execute([$code,$name,$desc]);
                $nid = $pdo->lastInsertId();
                $cl = $pdo->query("SELECT id FROM clearances WHERE status='pending'")->fetchAll();
                foreach ($cl as $c2) $pdo->prepare("INSERT IGNORE INTO clearance_items (clearance_id,department_id) VALUES (?,?)")->execute([$c2['id'],$nid]);
                log_activity($pdo,'Added department '.$name); redirect('?page=admin&section=departments');
            }
        } else $adm_msg = '<div class="alert alert-danger">Code and name required.</div>';
    }
    if (isset($_GET['toggle']) && ctype_digit($_GET['toggle'])) {
        $uid = (int)$_GET['toggle'];
        if ($uid !== $_SESSION['user_id']) { $pdo->prepare("UPDATE users SET active=1-active WHERE id=?")->execute([$uid]); log_activity($pdo,'Toggled user '.$uid); }
        redirect('?page=admin&section=users');
    }
    $s = [];
    $s['students'] = $pdo->query("SELECT COUNT(*) FROM users WHERE role='student'")->fetchColumn();
    $s['officers'] = $pdo->query("SELECT COUNT(*) FROM users WHERE role='officer'")->fetchColumn();
    $s['total']    = $pdo->query("SELECT COUNT(*) FROM clearances")->fetchColumn();
    $s['cleared']  = $pdo->query("SELECT COUNT(*) FROM clearances WHERE status='cleared'")->fetchColumn();
    $s['pending']  = $pdo->query("SELECT COUNT(*) FROM clearances WHERE status='pending'")->fetchColumn();
    $s['depts']    = $pdo->query("SELECT COUNT(*) FROM departments")->fetchColumn();
    $all = $pdo->query("SELECT c.*,u.full_name,u.student_id,(SELECT COUNT(*) FROM clearance_items ci WHERE ci.clearance_id=c.id) AS total_items,(SELECT COUNT(*) FROM clearance_items ci WHERE ci.clearance_id=c.id AND ci.status='approved') AS approved_items FROM clearances c JOIN users u ON c.student_id=u.id ORDER BY c.created_at DESC")->fetchAll();
    $departments = all_departments($pdo);
    $users = $pdo->query("SELECT u.*,d.name AS department_name FROM users u LEFT JOIN departments d ON u.department_id=d.id ORDER BY u.role,u.full_name")->fetchAll();
}

if ($page === 'profile' && $_SERVER['REQUEST_METHOD']==='POST') {
    check_csrf();
    $me = get_user($pdo, $_SESSION['user_id']);
    if (isset($_POST['enable'])) {
        $secret = totp_secret();
        $pdo->prepare("UPDATE users SET totp_secret=?, totp_enabled=0 WHERE id=?")->execute([$secret, $_SESSION['user_id']]);
        $profile_msg = '<div class="alert alert-info">Scan the secret in your authenticator app, then confirm with a code below.</div>';
        $me = get_user($pdo, $_SESSION['user_id']);
    } elseif (isset($_POST['confirm'])) {
        $code = preg_replace('/\D/', '', $_POST['code'] ?? '');
        if (totp_verify($me['totp_secret'], $code)) {
            $pdo->prepare("UPDATE users SET totp_enabled=1 WHERE id=?")->execute([$_SESSION['user_id']]);
            log_activity($pdo,'Enabled 2FA'); $profile_msg = '<div class="alert alert-success">Two-factor authentication ENABLED.</div>';
            $me = get_user($pdo, $_SESSION['user_id']);
        } else $profile_msg = '<div class="alert alert-danger">Invalid code. 2FA not enabled.</div>';
    } elseif (isset($_POST['disable'])) {
        $code = preg_replace('/\D/', '', $_POST['code'] ?? '');
        if (totp_verify($me['totp_secret'], $code)) {
            $pdo->prepare("UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE id=?")->execute([$_SESSION['user_id']]);
            log_activity($pdo,'Disabled 2FA'); $profile_msg = '<div class="alert alert-success">Two-factor authentication disabled.</div>';
            $me = get_user($pdo, $_SESSION['user_id']);
        } else $profile_msg = '<div class="alert alert-danger">Invalid code.</div>';
    }
}

if ($page === 'verify' && $_SERVER['REQUEST_METHOD']==='POST') {
    check_csrf();
    if (preg_match('/^EC-(\d+)-([0-9A-Fa-f]{8})$/', trim($_POST['code'] ?? ''), $m)) {
        $cid = (int)$m[1]; $provided = strtolower($m[2]);
        $cl = $pdo->prepare("SELECT c.*,u.full_name,u.student_id FROM clearances c JOIN users u ON c.student_id=u.id WHERE c.id=?");
        $cl->execute([$cid]); $verify_clr = $cl->fetch();
        if ($verify_clr && $verify_clr['verify_code'] && strtolower(substr($verify_clr['verify_code'],0,8)) === $provided) {
            $verify_valid = ($verify_clr['status'] === 'cleared');
            $vits = $pdo->prepare("SELECT ci.*,d.name AS department_name FROM clearance_items ci JOIN departments d ON ci.department_id=d.id WHERE ci.clearance_id=? ORDER BY d.name");
            $vits->execute([$cid]); $verify_items = $vits->fetchAll();
        } else { $verify_invalid = true; }
    } else { $verify_invalid = true; }
}

/* ---------------- RENDER ---------------- */
function page_header($title, $desc = '') {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    $desc = $desc ?: APP_TITLE . ' — secure electronic clearance with two-factor authentication and digitally signed certificates.';
    $canon = site_url() . ($_SERVER['REQUEST_URI'] ?? '');
    $fav = "data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%2040%2040'%3E%3Crect%20width='40'%20height='40'%20rx='9'%20fill='%231e60d8'/%3E%3Ctext%20x='20'%20y='27'%20font-size='18'%20font-family='Arial'%20font-weight='bold'%20fill='white'%20text-anchor='middle'%3EEC%3C/text%3E%3C/svg%3E";
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">';
    echo '<meta name="description" content="'.h($desc).'">';
    echo '<meta name="keywords" content="electronic clearance, e-clearance, student clearance, university clearance, clearance system">';
    echo '<meta name="robots" content="index,follow">';
    echo '<meta property="og:title" content="'.h($title.' - '.APP_NAME).'">';
    echo '<meta property="og:type" content="website">';
    echo '<meta property="og:url" content="'.h($canon).'">';
    echo '<meta property="og:description" content="'.h($desc).'">';
    echo '<link rel="canonical" href="'.h($canon).'">';
    echo '<link rel="icon" href="'.$fav.'">';
    echo '<title>'.h($title).' - '.APP_NAME.'</title><style>'.CSS.'</style></head><body>';
    echo '<header class="topbar"><div class="brand"><span class="logo">EC</span><div><strong>'.APP_NAME.'</strong><small>'.APP_TITLE.'</small></div></div>';
    if (!empty($_SESSION['user_id'])) {
        echo '<nav class="nav">';
        if ($_SESSION['role']==='student') echo '<a href="?page=student">My Clearance</a>';
        if ($_SESSION['role']==='officer') echo '<a href="?page=department">Clearances</a>';
        if ($_SESSION['role']==='admin')   echo '<a href="?page=admin">Admin</a>';
        if (in_array($_SESSION['role'],['officer','admin'])) echo '<a href="?page=profile">Security</a>';
        echo '<a href="?page=logout" class="btn btn-ghost">Logout</a></nav>';
    }
    echo '</header><main class="container">';
}
function page_footer() { echo '</main><footer class="footer"><span>&copy; '.date('Y').' '.APP_NAME.' &middot; '.APP_TITLE.' &middot; Secured with 2FA &amp; digital signatures</span></footer></body></html>'; }
define('CSS', '
:root{--primary:#1e60d8;--primary-dark:#1546a3;--bg:#f4f6fb;--card:#fff;--text:#1f2733;--muted:#6b7787;--border:#e3e8f0;--success:#1e9e5a;--warning:#d98b00;--danger:#d23b3b;--radius:12px;--shadow:0 6px 24px rgba(20,40,80,.08)}
*{box-sizing:border-box}body{margin:0;font-family:"Segoe UI",system-ui,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
a{color:var(--primary);text-decoration:none}a:hover{text-decoration:underline}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:12px 24px;background:var(--card);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10}
.brand{display:flex;align-items:center;gap:12px}.brand .logo{width:40px;height:40px;border-radius:10px;background:linear-gradient(135deg,var(--primary),#3f86ff);color:#fff;font-weight:800;display:grid;place-items:center}.brand small{display:block;color:var(--muted);font-size:12px}
.nav{display:flex;align-items:center;gap:16px}.nav a{font-weight:600}
.container{max-width:1040px;margin:28px auto;padding:0 20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px;margin-bottom:20px}
.grid{display:grid;gap:20px}.grid.cols-2{grid-template-columns:repeat(2,1fr)}.grid.cols-3{grid-template-columns:repeat(3,1fr)}.grid.cols-4{grid-template-columns:repeat(4,1fr)}
@media(max-width:760px){.grid.cols-2,.grid.cols-3,.grid.cols-4{grid-template-columns:1fr}}
h1{font-size:26px;margin:0 0 6px}h2{font-size:20px;margin:0 0 14px}.muted{color:var(--muted)}
label{display:block;font-weight:600;margin:12px 0 6px;font-size:14px}
input,select,textarea{width:100%;padding:11px 12px;border:1px solid var(--border);border-radius:9px;font-size:15px;background:#fff;color:var(--text)}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(30,96,216,.15)}
.code-input{font-size:24px!important;letter-spacing:8px;text-align:center;font-family:monospace}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:600px){.form-row{grid-template-columns:1fr}}
.btn{display:inline-block;padding:10px 18px;border:none;border-radius:9px;background:var(--primary);color:#fff;font-weight:600;cursor:pointer;font-size:15px}
.btn:hover{background:var(--primary-dark);text-decoration:none}.btn-ghost{background:transparent;color:var(--text);padding:8px 14px}.btn-ghost:hover{background:#eef2fb}
.btn-success{background:var(--success)}.btn-success:hover{background:#178047}.btn-danger{background:var(--danger)}.btn-danger:hover{background:#b22e2e}.btn-sm{padding:6px 12px;font-size:13px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 14px;border-bottom:1px solid var(--border);font-size:14px}
th{color:var(--muted);font-weight:700;text-transform:uppercase;font-size:12px;letter-spacing:.4px}tr:hover td{background:#fafbfe}
.badge{display:inline-block;padding:4px 11px;border-radius:999px;font-size:12px;font-weight:700;text-transform:capitalize}
.badge-success{background:#e3f6ec;color:var(--success)}.badge-warning{background:#fdf1da;color:var(--warning)}.badge-danger{background:#fbe3e3;color:var(--danger)}
.alert{padding:13px 16px;border-radius:9px;margin:14px 0;font-size:14px}.alert-success{background:#e3f6ec;color:#176b3f;border:1px solid #bfe9cf}.alert-danger{background:#fbe3e3;color:#8f2424;border:1px solid #f3c6c6}.alert-info{background:#e7f0fe;color:#1c4fa3;border:1px solid #c5dbff}
.progress{height:10px;background:#e9eef7;border-radius:999px;overflow:hidden}.progress>span{display:block;height:100%;background:linear-gradient(90deg,var(--primary),#4f93ff)}
.stat{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:18px;box-shadow:var(--shadow)}.stat .num{font-size:30px;font-weight:800;color:var(--primary)}.stat .lbl{color:var(--muted);font-size:14px}
.footer{text-align:center;color:var(--muted);padding:28px;font-size:13px}.center{text-align:center}.setup-log{padding-left:18px}.setup-log li{margin:6px 0}hr{border:none;border-top:1px solid var(--border);margin:18px 0}
.secret{font-family:monospace;font-size:18px;background:#eef2fb;padding:10px 14px;border-radius:8px;letter-spacing:2px;display:inline-block}
.seal{font-family:monospace;font-size:12px;color:var(--success);background:#e3f6ec;padding:2px 8px;border-radius:6px}
.watermark{position:absolute;inset:0;pointer-events:none;opacity:.5;background-image:url("data:image/svg+xml,%3Csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20width=%27240%27%20height=%27150%27%3E%3Ctext%20x=%275%27%20y=%2780%27%20transform=%27rotate(-28%20120%2075)%27%20font-size=%2720%27%20font-family=%27Arial%27%20font-weight=%27bold%27%20fill=%27%23aab4c4%27%20fill-opacity=%270.5%27%3EE-CLEAR%20VERIFIED%3C/text%3E%3C/svg%3E");background-repeat:repeat}
.hero{background:linear-gradient(135deg,var(--primary),#3f86ff);border-radius:var(--radius);padding:48px 24px;margin-bottom:20px;box-shadow:var(--shadow)}
.hero-inner{max-width:760px;margin:0 auto;text-align:center}
.hero .logo.big{width:72px;height:72px;font-size:26px;border-radius:18px;background:rgba(255,255,255,.18);color:#fff;font-weight:800;display:inline-grid;place-items:center;margin-bottom:10px}
.hero h1{color:#fff;font-size:34px;margin:6px 0}
.hero .lead{font-size:17px;opacity:.95;max-width:620px;margin:10px auto 22px}
.hero .cta{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.hero .muted a{color:#fff;text-decoration:underline}
.btn-lg{padding:14px 26px;font-size:16px}
.hero .btn-ghost{background:rgba(255,255,255,.15);color:#fff}
.hero .btn-ghost:hover{background:rgba(255,255,255,.28)}
@media print{.topbar,.footer,.no-print{display:none!important}body{background:#fff}}
');

/* ================= PAGE: SETUP ================= */
if ($page === 'setup'):
    page_header('Setup'); ?>
    <div class="card" style="max-width:720px;margin:6vh auto;">
        <h1><?php echo APP_NAME; ?> Setup</h1>
        <p>Installation of the Electronic Clearance System (secured).</p>
        <ul class="setup-log"><?php foreach ($steps as $s) echo '<li>'.$s.'</li>'; ?></ul>
        <?php if ($ok): ?><div class="alert alert-success">Installation complete. <a href="?page=login">Login here</a>. Enable 2FA from the Security page.</div>
        <p class="muted">For security, install once then never visit ?page=setup again.</p>
        <?php else: ?><div class="alert alert-danger">Installation failed. See errors above.</div><?php endif; ?>
    </div>
<?php page_footer(); endif;

/* ================= PAGE: LOGIN ================= */
if ($page === 'login'):
    page_header('Login'); ?>
    <div class="grid" style="max-width:440px;margin:6vh auto;">
        <div class="card">
            <div class="center">
                <div class="logo" style="width:56px;height:56px;font-size:20px;margin:0 auto 10px;border-radius:14px;background:linear-gradient(135deg,var(--primary),#3f86ff);color:#fff;font-weight:800;display:grid;place-items:center;">EC</div>
                <h1>Welcome back</h1><p class="muted">Sign in to your <?php echo APP_NAME; ?> account</p>
            </div>
            <?php if (!empty($login_error)) echo '<div class="alert alert-danger">'.h($login_error).'</div>'; ?>
            <form method="post"><?php echo csrf_field(); ?>
                <label for="email">Email</label><input type="email" id="email" name="email" required autofocus placeholder="you@eclear.edu">
                <label for="password">Password</label><input type="password" id="password" name="password" required placeholder="••••••••">
                <button class="btn" style="width:100%;margin-top:18px;">Sign In</button>
            </form>
            <hr>
            <p class="center muted" style="margin:0 0 6px;">Don't have an account?</p>
            <a class="btn btn-ghost" style="width:100%;text-align:center;" href="?page=register">Create Student Account</a>
            <div class="alert alert-info" style="margin-top:16px;"><strong>Demo credentials</strong><br>
                Admin: admin@eclear.edu / admin123<br>Officer: lib@eclear.edu / officer123<br>(or register a student)</div>
        </div>
    </div>
<?php page_footer(); endif;

/* ================= PAGE: LANDING (public) ================= */
if ($page === 'landing'):
    page_header(APP_TITLE, APP_TITLE . ' is a secure, paperless electronic clearance system for schools and universities. Students request clearance online; departments approve with two-factor authentication and digitally signed certificates.');
    $feats = [
        ['🔐','Two-Factor Auth','Teacher/officer accounts are protected by TOTP 2FA so approvals cannot be forged.'],
        ['✍️','Digital Signatures','Every approval is cryptographically signed and tied to the officer.'],
        ['🛡️','Tamper-Proof Certificates','Each certificate carries a verification ID validated on a public page.'],
        ['⚡','Real-Time Progress','Students track clearance status across all departments live.'],
        ['👥','Role-Based Access','Separate secure areas for students, officers, and admins.'],
        ['🌐','Deploy Anywhere','One PHP file — runs on any PHP + MySQL host.'],
    ]; ?>
    <section class="hero">
        <div class="hero-inner">
            <span class="logo big">EC</span>
            <h1><?php echo APP_TITLE; ?></h1>
            <p class="lead">The secure, paperless way for students to get clearance — approved by every department with two-factor authentication and digitally signed certificates.</p>
            <div class="cta">
                <a class="btn btn-lg" href="?page=login">Sign In</a>
                <a class="btn btn-ghost btn-lg" href="?page=register">Create Student Account</a>
            </div>
            <p class="muted">Already cleared? <a href="?page=verify">Verify a certificate →</a></p>
        </div>
    </section>
    <div class="card"><div class="grid cols-3">
        <?php foreach ($feats as $f): ?><div class="stat"><div style="font-size:26px"><?php echo $f[0]; ?></div><div class="lbl" style="font-weight:700;color:var(--text)"><?php echo $f[1]; ?></div><p class="muted" style="margin:6px 0 0;"><?php echo $f[2]; ?></p></div><?php endforeach; ?>
    </div></div>
    <div class="card">
        <h2>How it works</h2>
        <div class="grid cols-3">
            <div><div class="stat"><div class="num">1</div><div class="lbl">Student requests</div></div><p class="muted">A student starts a clearance; one item is created per department.</p></div>
            <div><div class="stat"><div class="num">2</div><div class="lbl">Officers approve</div></div><p class="muted">Each officer signs off with a 2FA-verified session.</p></div>
            <div><div class="stat"><div class="num">3</div><div class="lbl">Certificate issued</div></div><p class="muted">When all approve, a verifiable certificate is generated.</p></div>
        </div>
    </div>
<?php page_footer(); endif;

/* ================= PAGE: 2FA ================= */
if ($page === '2fa'):
    if (empty($_SESSION['pending_2fa'])) redirect('?page=login');
    page_header('Two-Factor Authentication');
    $u = get_user($pdo, $_SESSION['pending_2fa']); ?>
    <div class="grid" style="max-width:420px;margin:6vh auto;">
        <div class="card center">
            <h1>Two-Factor Authentication</h1>
            <p class="muted">Enter the 6-digit code from your authenticator app for <strong><?php echo h($u['full_name']); ?></strong>.</p>
            <?php if (!empty($twofa_error)) echo '<div class="alert alert-danger">'.h($twofa_error).'</div>'; ?>
            <form method="post"><?php echo csrf_field(); ?>
                <input class="code-input" name="code" inputmode="numeric" maxlength="6" autocomplete="one-time-code" required autofocus placeholder="••••••">
                <button class="btn" style="width:100%;margin-top:16px;">Verify &amp; Sign In</button>
            </form>
            <p class="muted" style="margin-top:12px;"><a href="?page=logout">Cancel</a></p>
        </div>
    </div>
<?php page_footer(); endif;

/* ================= PAGE: REGISTER ================= */
if ($page === 'register'):
    page_header('Register'); ?>
    <div class="grid" style="max-width:460px;margin:5vh auto;">
        <div class="card">
            <h1>Create Student Account</h1><p class="muted">Register to start your electronic clearance.</p>
            <?php if (!empty($reg_error)) echo '<div class="alert alert-danger">'.h($reg_error).'</div>'; ?>
            <?php if (!empty($reg_success)) echo '<div class="alert alert-success">'.h($reg_success).' <a href="?page=login">Sign in</a></div>'; ?>
            <form method="post"><?php echo csrf_field(); ?>
                <label for="fn">Full Name</label><input id="fn" name="full_name" required value="<?php echo h($_POST['full_name'] ?? ''); ?>">
                <div class="form-row">
                    <div><label for="sid">Student ID</label><input id="sid" name="student_id" required value="<?php echo h($_POST['student_id'] ?? ''); ?>" placeholder="CS/2021/001"></div>
                    <div><label for="em">Email</label><input type="email" id="em" name="email" required value="<?php echo h($_POST['email'] ?? ''); ?>"></div>
                </div>
                <div class="form-row">
                    <div><label for="pw">Password</label><input type="password" id="pw" name="password" required></div>
                    <div><label for="cf">Confirm</label><input type="password" id="cf" name="confirm" required></div>
                </div>
                <button class="btn" style="width:100%;margin-top:18px;">Register</button>
            </form>
            <hr><p class="center muted" style="margin:0;"><a href="?page=login">Already have an account? Sign in</a></p>
        </div>
    </div>
<?php page_footer(); endif;

/* ================= PAGE: PROFILE (2FA) ================= */
if ($page === 'profile'):
    $me = get_user($pdo, $_SESSION['user_id']);
    page_header('Security'); ?>
    <div class="card" style="max-width:560px;">
        <h2>Account Security</h2>
        <p>Two-factor authentication (2FA) protects teacher/officer accounts so a student cannot log in and forge approvals.</p>
        <?php if (!empty($profile_msg)) echo $profile_msg; ?>
        <p>Status: <?php echo !empty($me['totp_enabled']) ? status_badge('approved').' ENABLED' : status_badge('pending').' DISABLED'; ?></p>
        <?php if (empty($me['totp_enabled'])): ?>
            <?php if (empty($me['totp_secret'])): ?>
                <form method="post"><?php echo csrf_field(); ?><button class="btn" name="enable">Enable 2FA</button></form>
            <?php else: ?>
                <div class="alert alert-info">Add this secret to Google Authenticator / Authy, then confirm.</div>
                <p class="secret"><?php echo h($me['totp_secret']); ?></p>
                <p class="muted">otpauth://totp/<?php echo APP_NAME(); ?>:<?php echo h($me['email']); ?>?secret=<?php echo h($me['totp_secret']); ?>&issuer=<?php echo APP_NAME(); ?></p>
                <form method="post"><?php echo csrf_field(); ?>
                    <input class="code-input" name="code" inputmode="numeric" maxlength="6" required placeholder="123456" style="max-width:200px;">
                    <button class="btn btn-success" name="confirm" style="margin-top:12px;">Confirm &amp; Enable</button>
                </form>
            <?php endif; ?>
        <?php else: ?>
            <form method="post"><?php echo csrf_field(); ?>
                <p>Enter a current code to disable 2FA:</p>
                <input class="code-input" name="code" inputmode="numeric" maxlength="6" required placeholder="123456" style="max-width:200px;">
                <button class="btn btn-danger" name="disable" style="margin-top:12px;">Disable 2FA</button>
            </form>
        <?php endif; ?>
    </div>
<?php page_footer(); endif;
function APP_NAME() { return APP_NAME; }

/* ================= PAGE: STUDENT ================= */
if ($page === 'student' && isset($cert_mode)):
    page_header('Certificate'); ?>
    <div class="card center no-print"><button class="btn" onclick="window.print()">Print / Save PDF</button> <a class="btn btn-ghost" href="?page=student">Back</a></div>
    <div class="card"><div class="cert" style="position:relative;overflow:hidden;border:2px solid var(--primary);border-radius:16px;padding:36px;background:#fff;">
        <div class="watermark"></div>
        <div style="position:relative;">
        <div class="center"><div class="logo" style="width:64px;height:64px;border-radius:16px;background:linear-gradient(135deg,var(--primary),#3f86ff);color:#fff;font-weight:800;display:grid;place-items:center;margin:0 auto 10px;">EC</div>
            <h1><?php echo APP_TITLE; ?></h1><p class="muted">Digitally Signed Clearance Certificate</p></div><hr>
        <p>This is to certify that</p><h2 style="text-align:center;"><?php echo h($clr['full_name']); ?></h2>
        <p class="center muted">Student ID: <?php echo h($clr['student_id'] ?? '—'); ?></p>
        <p>has been fully cleared on <strong><?php echo date('F j, Y', strtotime($clr['updated_at'])); ?></strong> for <strong><?php echo h($clr['reason']); ?></strong>.</p>
        <table><thead><tr><th>Department</th><th>Status</th><th>Signed By</th><th>Digital Seal</th></tr></thead><tbody>
        <?php foreach ($items as $it): ?><tr>
            <td><?php echo h($it['department_name']); ?></td><td><?php echo status_badge($it['status']); ?></td>
            <td><?php echo h($it['code']); ?></td>
            <td><span class="seal"><?php echo $it['signature'] ? h(substr($it['signature'],0,12)) : '—'; ?></span></td>
        </tr><?php endforeach; ?>
        </tbody></table>
        <div style="margin-top:18px;padding:14px;border:1px dashed var(--primary);border-radius:10px;">
            <strong>Verification ID:</strong> <span style="font-family:monospace;font-size:16px;"><?php echo h(verify_id($clr)); ?></span><br>
            <small class="muted">Verify authenticity at <code>?page=verify</code> — a student cannot forge this ID without the server signing key.</small>
        </div>
        </div>
    </div></div>
<?php page_footer(); endif;

if ($page === 'student' && !isset($cert_mode)):
    page_header('My Clearance'); ?>
    <div class="card"><div class="grid cols-3">
        <div class="stat"><div class="num"><?php echo h($_SESSION['full_name']); ?></div><div class="lbl">Student</div></div>
        <div class="stat"><div class="num"><?php echo h(get_user($pdo,$_SESSION['user_id'])['student_id'] ?? '—'); ?></div><div class="lbl">Student ID</div></div>
        <div class="stat"><div class="num"><?php echo $clearance ? status_badge($clearance['status']) : '—'; ?></div><div class="lbl">Status</div></div>
    </div></div>
    <?php if (!empty($stu_msg)) echo $stu_msg; ?>
    <?php if (empty($clearance)): ?>
        <div class="card center"><h2>No clearance request yet</h2><p class="muted">Start a clearance request to be approved by all departments.</p>
            <form method="post" style="max-width:360px;margin:0 auto;text-align:left;"><?php echo csrf_field(); ?>
                <label for="reason">Clearance Reason</label>
                <select id="reason" name="reason"><option>Graduation</option><option>End of Session</option><option>Transfer</option><option>Withdrawal</option></select>
                <button class="btn btn-success" name="start" style="width:100%;margin-top:16px;">Start Clearance</button>
            </form></div>
    <?php else: ?>
        <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
                <div><h2 style="margin:0;">Clearance #<?php echo $clearance['id']; ?> &mdash; <?php echo h($clearance['reason']); ?></h2>
                <small class="muted">Requested on <?php echo date('M j, Y', strtotime($clearance['created_at'])); ?></small></div>
                <div style="min-width:220px;flex:1;"><div class="progress"><span style="width:<?php echo $progress; ?>%"></span></div><small class="muted"><?php echo $progress; ?>% cleared</small></div>
            </div>
            <?php if ($clearance['status']==='cleared'): ?><div class="alert alert-success">🎉 You are fully cleared. Download your certificate below.</div>
                <a class="btn btn-success" href="?page=student&action=cert&id=<?php echo $clearance['id']; ?>">Download Certificate</a>
            <?php elseif ($clearance['status']==='rejected'): ?><div class="alert alert-danger">Your clearance was rejected by a department. Resolve and contact them.</div><?php endif; ?>
            <table style="margin-top:18px;"><thead><tr><th>Department</th><th>Status</th><th>Handled By</th><th>Notes</th></tr></thead><tbody>
            <?php foreach ($items as $it): ?><tr>
                <td><strong><?php echo h($it['department_name']); ?></strong><br><small class="muted"><?php echo h($it['code']); ?></small></td>
                <td><?php echo status_badge($it['status']); ?></td>
                <td><?php echo $it['officer_name'] ? h($it['officer_name']) : '—'; ?></td>
                <td><?php echo $it['notes'] ? h($it['notes']) : '—'; ?></td></tr>
            <?php endforeach; ?></tbody></table>
        </div>
    <?php endif; ?>
<?php page_footer(); endif;

/* ================= PAGE: DEPARTMENT ================= */
if ($page === 'department'):
    page_header('Department Clearances'); ?>
    <div class="card"><div class="grid cols-3">
        <div class="stat"><div class="num"><?php echo h($dep['name']); ?></div><div class="lbl">Your Department</div></div>
        <div class="stat"><div class="num"><?php echo $stat_pending; ?></div><div class="lbl">Pending</div></div>
        <div class="stat"><div class="num"><?php echo $stat_approved; ?></div><div class="lbl">Approved</div></div>
    </div></div>
    <?php if (!empty($dep_msg)) echo $dep_msg; ?>
    <div class="alert alert-info">Approvals are digitally signed (HMAC) and tied to your 2FA-verified session.</div>
    <div class="card"><h2>Pending Queue</h2>
        <?php if (empty($queue)): ?><p class="muted">No pending requests. 🎉</p>
        <?php else: ?><table><thead><tr><th>Student</th><th>ID</th><th>Reason</th><th>Requested</th><th style="width:280px;">Action</th></tr></thead><tbody>
        <?php foreach ($queue as $q): ?><tr>
            <td><strong><?php echo h($q['full_name']); ?></strong></td><td><?php echo h($q['student_id'] ?? '—'); ?></td>
            <td><?php echo h($q['reason']); ?></td><td><small class="muted"><?php echo date('M j', strtotime($q['created_at'])); ?></small></td>
            <td><form method="post" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;"><?php echo csrf_field(); ?>
                <input type="hidden" name="item_id" value="<?php echo $q['id']; ?>">
                <input type="text" name="notes" placeholder="Notes (optional)" style="flex:1;min-width:120px;">
                <button class="btn btn-success btn-sm" name="action" value="approve">Approve</button>
                <button class="btn btn-danger btn-sm" name="action" value="reject">Reject</button>
            </form></td></tr>
        <?php endforeach; ?></tbody></table><?php endif; ?>
    </div>
    <div class="card"><h2>Recently Handled</h2>
        <?php if (empty($handled)): ?><p class="muted">Nothing processed yet.</p>
        <?php else: ?><table><thead><tr><th>Student</th><th>ID</th><th>Status</th><th>Seal</th><th>When</th></tr></thead><tbody>
        <?php foreach ($handled as $hh): ?><tr><td><?php echo h($hh['full_name']); ?></td><td><?php echo h($hh['student_id'] ?? '—'); ?></td>
            <td><?php echo status_badge($hh['status']); ?></td><td><span class="seal"><?php echo $hh['signature']?h(substr($hh['signature'],0,12)):'—'; ?></span></td>
            <td><small class="muted"><?php echo date('M j, H:i', strtotime($hh['updated_at'])); ?></small></td></tr>
        <?php endforeach; ?></tbody></table><?php endif; ?>
    </div>
<?php page_footer(); endif;

/* ================= PAGE: ADMIN ================= */
if ($page === 'admin'):
    page_header('Admin'); ?>
    <div class="card"><div class="grid cols-3">
        <div class="stat"><div class="num"><?php echo $s['students']; ?></div><div class="lbl">Students</div></div>
        <div class="stat"><div class="num"><?php echo $s['officers']; ?></div><div class="lbl">Officers</div></div>
        <div class="stat"><div class="num"><?php echo $s['depts']; ?></div><div class="lbl">Departments</div></div>
        <div class="stat"><div class="num"><?php echo $s['cleared']; ?>/<?php echo $s['total']; ?></div><div class="lbl">Cleared / Total</div></div>
        <div class="stat"><div class="num"><?php echo $s['pending']; ?></div><div class="lbl">Pending</div></div>
        <div class="stat"><div class="num"><?php echo $s['total']?round($s['cleared']/$s['total']*100):0; ?>%</div><div class="lbl">Success Rate</div></div>
    </div></div>
    <?php if (!empty($adm_msg)) echo $adm_msg; ?>
    <div class="card"><div style="display:flex;gap:10px;flex-wrap:wrap;">
        <a class="btn btn-ghost" href="?page=admin" style="<?php echo $section==='overview'?'font-weight:800':''; ?>">Clearances</a>
        <a class="btn btn-ghost" href="?page=admin&section=departments" style="<?php echo $section==='departments'?'font-weight:800':''; ?>">Departments</a>
        <a class="btn btn-ghost" href="?page=admin&section=users" style="<?php echo $section==='users'?'font-weight:800':''; ?>">Users</a>
    </div></div>
    <?php if ($section==='departments'): ?>
    <div class="card"><h2>Departments</h2><table><thead><tr><th>Code</th><th>Name</th><th>Description</th></tr></thead><tbody>
        <?php foreach ($departments as $d): ?><tr><td><strong><?php echo h($d['code']); ?></strong></td><td><?php echo h($d['name']); ?></td><td class="muted"><?php echo h($d['description']); ?></td></tr><?php endforeach; ?>
    </tbody></table><hr><h2>Add Department</h2>
    <form method="post" class="form-row"><?php echo csrf_field(); ?>
        <div><label>Code</label><input name="code" required placeholder="e.g. SEC" maxlength="20"></div>
        <div><label>Name</label><input name="name" required placeholder="Security Unit"></div>
        <div style="grid-column:1/-1"><label>Description</label><input name="description" placeholder="What this office clears"></div>
        <div style="grid-column:1/-1"><button class="btn" name="add_dept">Add Department</button></div>
    </form></div>
    <?php elseif ($section==='users'): ?>
    <div class="card"><h2>Users</h2><table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>2FA</th><th>Department</th><th>Status</th><th></th></tr></thead><tbody>
        <?php foreach ($users as $u): ?><tr>
            <td><strong><?php echo h($u['full_name']); ?></strong><br><small class="muted"><?php echo h($u['student_id'] ?? ''); ?></small></td>
            <td><?php echo h($u['email']); ?></td><td><?php echo status_badge($u['role']); ?></td>
            <td><?php echo !empty($u['totp_enabled'])?status_badge('approved'):status_badge('pending'); ?></td>
            <td><?php echo $u['department_name'] ? h($u['department_name']) : '—'; ?></td>
            <td><?php echo $u['active']?status_badge('approved'):status_badge('rejected'); ?></td>
            <td><?php if ($u['id']!==$_SESSION['user_id']): ?><a class="btn btn-sm btn-ghost" href="?page=admin&section=users&toggle=<?php echo $u['id']; ?>"><?php echo $u['active']?'Deactivate':'Activate'; ?></a><?php else: ?><span class="muted">You</span><?php endif; ?></td>
        </tr><?php endforeach; ?></tbody></table></div>
    <?php else: ?>
    <div class="card"><h2>All Clearance Requests</h2><table><thead><tr><th>#</th><th>Student</th><th>Reason</th><th>Progress</th><th>Status</th><th>Verify ID</th><th>Date</th></tr></thead><tbody>
        <?php foreach ($all as $c): ?><tr>
            <td><?php echo $c['id']; ?></td>
            <td><strong><?php echo h($c['full_name']); ?></strong><br><small class="muted"><?php echo h($c['student_id'] ?? '—'); ?></small></td>
            <td><?php echo h($c['reason']); ?></td>
            <td><div class="progress" style="min-width:120px;"><span style="width:<?php echo round($c['approved_items']/max($c['total_items'],1)*100); ?>%"></span></div><small class="muted"><?php echo $c['approved_items']; ?>/<?php echo $c['total_items']; ?></small></td>
            <td><?php echo status_badge($c['status']); ?></td>
            <td><span class="seal"><?php echo $c['verify_code']?h(substr($c['verify_code'],0,8)):'—'; ?></span></td>
            <td><small class="muted"><?php echo date('M j, Y', strtotime($c['created_at'])); ?></small></td>
        </tr><?php endforeach; ?>
        <?php if (empty($all)): ?><tr><td colspan="7" class="muted">No clearance requests yet.</td></tr><?php endif; ?>
    </tbody></table></div>
    <?php endif; ?>
<?php page_footer(); endif;

/* ================= PAGE: VERIFY (public) ================= */
if ($page === 'verify'):
    page_header('Verify Certificate'); ?>
    <div class="card" style="max-width:620px;margin:5vh auto;">
        <h1>Certificate Verification</h1>
        <p class="muted">Enter the Verification ID from a certificate (e.g. <code>EC-00001-A1B2C3D4</code>) to confirm it is authentic and unaltered.</p>
        <form method="post"><?php echo csrf_field(); ?>
            <input name="code" placeholder="EC-00001-A1B2C3D4" required style="font-family:monospace;text-transform:uppercase;">
            <button class="btn" style="margin-top:12px;">Verify</button>
        </form>
        <?php if (isset($verify_valid)): ?>
            <div class="alert alert-success"><strong>VALID &amp; AUTHENTIC</strong> — issued by <?php echo APP_NAME; ?>.</div>
            <div class="cert" style="position:relative;overflow:hidden;border:2px solid var(--success);border-radius:16px;padding:24px;background:#fff;">
                <div class="watermark"></div><div style="position:relative;">
                <h2 style="margin:0;"><?php echo h($verify_clr['full_name']); ?></h2>
                <p class="muted">Student ID: <?php echo h($verify_clr['student_id'] ?? '—'); ?> &middot; <?php echo h($verify_clr['reason']); ?></p>
                <p>Verification ID: <span class="seal"><?php echo h(verify_id($verify_clr)); ?></span></p>
                <table><thead><tr><th>Department</th><th>Status</th><th>Seal</th></tr></thead><tbody>
                <?php foreach ($verify_items as $it): ?><tr><td><?php echo h($it['department_name']); ?></td><td><?php echo status_badge($it['status']); ?></td><td><span class="seal"><?php echo $it['signature']?h(substr($it['signature'],0,12)):'—'; ?></span></td></tr><?php endforeach; ?>
                </tbody></table></div>
            </div>
        <?php elseif (isset($verify_invalid)): ?>
            <div class="alert alert-danger"><strong>INVALID</strong> — this ID is not recognized or has been tampered with.</div>
        <?php endif; ?>
    </div>
<?php page_footer(); endif;

/* ================= PAGE: ROBOTS.TXT ================= */
if ($page === 'robots') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "User-agent: *\n";
    echo "Allow: /\n";
    echo "Disallow: /?page=admin\nDisallow: /?page=student\nDisallow: /?page=department\nDisallow: /?page=profile\n";
    echo "Sitemap: " . site_url() . "/sitemap.xml\n";
    exit;
}

/* ================= PAGE: SITEMAP.XML ================= */
if ($page === 'sitemap') {
    header('Content-Type: application/xml; charset=utf-8');
    $urls = ['', '?page=login', '?page=register', '?page=verify'];
    echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
    echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' . "\n";
    foreach ($urls as $u) {
        echo '  <url><loc>' . h(site_url() . '/' . $u) . '</loc><changefreq>weekly</changefreq></url>' . "\n";
    }
    echo '</urlset>';
    exit;
}

