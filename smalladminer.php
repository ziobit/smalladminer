<?php
/**
 * Mini Adminer-like single-file DB tool (MariaDB/MySQL)
 * Requirements:
 * - PHP 7.2+
 * - mysqli
 *
 * Security hardening highlights:
 * - CSRF protection on all state-changing actions (POST-only for mutations)
 * - No destructive actions via GET
 * - Session fixation defense (regenerate ID on login)
 * - Security headers (CSP-lite, XFO, etc.)
 * - Whitelisting tables/columns by reading schema (prevents identifier tampering)
 * - Safe JS embedding via json_encode (fixes ENUM/SET quotes breaking onclick handlers)
 */

declare(strict_types=1);

// -----------------------------
// Security headers (best-effort)
// -----------------------------
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header("Cross-Origin-Opener-Policy: same-origin");
header("Cross-Origin-Resource-Policy: same-origin");
// CSP kept permissive because you load Bootstrap/FA from CDN. Tighten if you self-host.
header("Content-Security-Policy: default-src 'self' https: data:; script-src 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; img-src 'self' https: data:;");

// -----------------------------
// Session hardening (PHP 7.2 safe)
// -----------------------------
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
  ini_set('session.cookie_secure', '1');
}
// session.cookie_samesite may not be supported everywhere on PHP 7.2 builds; set if possible
@ini_set('session.cookie_samesite', 'Strict');

session_start();

// error_reporting(E_ALL);
// ini_set('display_errors', 1);

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------
function h($s): string {
  return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function b64e($s): string {
  return base64_encode((string)$s);
}

function redirect(array $params = []): void {
  $base = $_SERVER['PHP_SELF'];
  if (!empty($params)) $base .= '?' . http_build_query($params);
  header("Location: " . $base);
  exit;
}

function set_flash(string $msg, bool $is_error = false): void {
  $_SESSION['flash_message'] = $msg;
  $_SESSION['flash_error']   = $is_error ? 1 : 0;
}

function flash_get(): array {
  $msg = $_SESSION['flash_message'] ?? '';
  $err = !empty($_SESSION['flash_error']);
  unset($_SESSION['flash_message'], $_SESSION['flash_error']);
  return [$msg, $err];
}

function is_logged_in(): bool {
  return isset($_SESSION['db_host'], $_SESSION['db_user'], $_SESSION['db_name']);
}

function csrf_token(): string {
  if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
  }
  return $_SESSION['csrf_token'];
}

function csrf_field(): string {
  return '<input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '">';
}

function csrf_check(): void {
  if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    set_flash("Invalid request method.", true);
    redirect();
  }
  $t = $_POST['csrf_token'] ?? '';
  if (!is_string($t) || $t === '' || !hash_equals((string)($_SESSION['csrf_token'] ?? ''), $t)) {
    set_flash("CSRF validation failed.", true);
    redirect();
  }
}

// Parse ENUM/SET definition robustly (supports commas, escaped quotes)
function parse_enum_set_values(string $typeDef): array {
  $values = [];
  if (!preg_match("/^(enum|set)\((.+)\)$/i", trim($typeDef), $m)) return $values;
  $inner = $m[2];

  // Match quoted items: '...'(with \' allowed) OR "..."(with \" allowed)
  if (preg_match_all("/'((?:\\\\'|[^'])*)'|\"((?:\\\\\"|[^\"])*)\"/u", $inner, $mm, PREG_SET_ORDER)) {
    foreach ($mm as $hit) {
      $v = $hit[1] !== '' ? $hit[1] : $hit[2];
      $v = str_replace(["\\'", '\\"', "\\\\"], ["'", '"', "\\"], $v);
      $values[] = $v;
    }
  } else {
    // Fallback: naive split
    $parts = explode(",", $inner);
    foreach ($parts as $p) {
      $p = trim($p);
      if ($p === "''") { $values[] = ''; continue; }
      if (strlen($p) >= 2 && ($p[0] === "'" || $p[0] === '"')) $p = substr($p, 1, -1);
      $p = str_replace(["\\'", '\\"', "\\\\"], ["'", '"', "\\"], $p);
      $values[] = $p;
    }
  }
  return $values;
}

function normalize_sql(string $sql): string {
  $sql = trim($sql);
  $sql = preg_replace('/^\xEF\xBB\xBF/', '', $sql);
  $sql = preg_replace('/;+\s*$/', '', $sql);
  return trim((string)$sql);
}

function is_resultset_sql(string $sql): bool {
  $s = ltrim($sql);
  $s = preg_replace('/^\/\*.*?\*\//s', '', $s);
  $s = ltrim((string)$s);
  $kw = strtoupper((string)strtok($s, " \t\r\n("));
  return in_array($kw, ['SELECT','SHOW','DESCRIBE','DESC','EXPLAIN'], true);
}

function sql_add_limit(string $sql, int $limitPlusOne): string {
  if (preg_match('/\blimit\b/i', $sql)) return $sql;
  return rtrim($sql) . " LIMIT " . (int)$limitPlusOne;
}

function get_mysqli(): ?mysqli {
  if (!is_logged_in()) return null;

  $host = (string)$_SESSION['db_host'];
  $user = (string)$_SESSION['db_user'];
  $pass = (string)($_SESSION['db_pass'] ?? '');
  $db   = (string)$_SESSION['db_name'];

  mysqli_report(MYSQLI_REPORT_OFF);

  $conn = new mysqli($host, $user, $pass, $db);
  if ($conn->connect_errno) return null;

  $conn->set_charset('utf8mb4');

  // Reduce risk of multi-statement abuse (still depends on server settings)
  // Note: mysqli->options must be set before real_connect; leaving as-is for simplicity.

  return $conn;
}

function list_tables(mysqli $conn): array {
  $tables = [];
  $res = $conn->query("SHOW TABLES");
  if ($res) {
    while ($row = $res->fetch_array(MYSQLI_NUM)) $tables[] = (string)$row[0];
    $res->free();
  }
  return $tables;
}

function table_exists(mysqli $conn, string $table): bool {
  $tables = list_tables($conn);
  return in_array($table, $tables, true);
}

function describe_table(mysqli $conn, string $table): array {
  $cols = [];
  $sql = "DESCRIBE `" . str_replace('`', '``', $table) . "`";
  $res = $conn->query($sql);
  if ($res) {
    while ($c = $res->fetch_assoc()) $cols[] = $c;
    $res->free();
  }
  return $cols;
}

function get_primary_key(mysqli $conn, string $table): ?string {
  $pk = null;
  $sql = "SHOW KEYS FROM `" . str_replace('`', '``', $table) . "` WHERE Key_name='PRIMARY'";
  $pkRes = $conn->query($sql);
  if ($pkRes) {
    while ($r = $pkRes->fetch_assoc()) {
      if ((string)$r['Seq_in_index'] === '1') { $pk = (string)$r['Column_name']; break; }
    }
    $pkRes->free();
  }
  return $pk;
}

function build_search_where(mysqli $conn, string $field, string $mode, string $term, bool $caseSensitive, array &$paramsOut): string {
  // Field is already whitelisted before calling this.
  $fieldEsc = "`" . str_replace('`', '``', $field) . "`";
  $expr = "CAST($fieldEsc AS CHAR)";
  $coll = $caseSensitive ? "utf8mb4_bin" : "utf8mb4_general_ci";

  $paramsOut = [];
  $term = (string)$term;

  switch ($mode) {
    case 'exact':
      $paramsOut[] = $term;
      return "$expr COLLATE $coll = ?";
    case 'like':
      $paramsOut[] = "%" . $term . "%";
      return "$expr COLLATE $coll LIKE ?";
    case 'starts':
      $paramsOut[] = $term . "%";
      return "$expr COLLATE $coll LIKE ?";
    case 'ends':
      $paramsOut[] = "%" . $term;
      return "$expr COLLATE $coll LIKE ?";
    case 'regexp':
      $paramsOut[] = $term;
      if ($caseSensitive) return "$expr REGEXP BINARY ?";
      return "$expr COLLATE $coll REGEXP ?";
    default:
      $paramsOut[] = "%" . $term . "%";
      return "$expr COLLATE $coll LIKE ?";
  }
}

function stmt_bind_all_strings(mysqli_stmt $stmt, array &$params): void {
  $types = str_repeat('s', count($params));
  $bind = [];
  $bind[] = & $types;
  foreach ($params as $k => $v) $bind[] = & $params[$k];
  call_user_func_array([$stmt, 'bind_param'], $bind);
}

function stmt_fetch_all_assoc(mysqli_stmt $stmt, array $fieldNames, int $maxRows = 0): array {
  $row = [];
  $bindOut = [];
  foreach ($fieldNames as $name) {
    $row[$name] = null;
    $bindOut[] = & $row[$name];
  }
  call_user_func_array([$stmt, 'bind_result'], $bindOut);

  $rows = [];
  $i = 0;
  while ($stmt->fetch()) {
    $r = [];
    foreach ($fieldNames as $name) $r[$name] = $row[$name];
    $rows[] = $r;
    $i++;
    if ($maxRows > 0 && $i >= $maxRows) break;
  }
  return $rows;
}

// ---------------------------------------------------------------------
// Handle actions (login/logout)
// ---------------------------------------------------------------------
$action = $_GET['action'] ?? '';

if ($action === 'logout') {
  // POST-only logout for CSRF safety
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $_SESSION = [];
    session_destroy();
    redirect();
  }
  redirect();
}

$login_error = '';
if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();

  $host = trim((string)($_POST['host'] ?? 'localhost'));
  $user = trim((string)($_POST['user'] ?? ''));
  $pass = (string)($_POST['pass'] ?? '');
  $db   = trim((string)($_POST['db'] ?? ''));

  $test = new mysqli($host, $user, $pass, $db);
  if ($test->connect_errno) {
    $login_error = 'Connection failed: ' . $test->connect_error;
  } else {
    $test->close();

    session_regenerate_id(true); // session fixation defense
    $_SESSION['db_host'] = $host;
    $_SESSION['db_user'] = $user;
    $_SESSION['db_pass'] = $pass;
    $_SESSION['db_name'] = $db;

    redirect();
  }
}

// ---------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------
$conn = null;
if (is_logged_in()) {
  $conn = get_mysqli();
  if (!$conn) {
    $login_error = 'Stored connection failed. Please login again.';
    $_SESSION = [];
    session_destroy();
  }
}

// Flash messages
[$flash_message, $flash_error] = flash_get();

// ---------------------------------------------------------------------
// DB actions (mutations + export + SQL console runner)
// ---------------------------------------------------------------------
$sql_console_result = null;

if ($conn) {
  // Add column
  if ($action === 'add_column' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();

    $table = (string)($_POST['table'] ?? '');
    $name  = trim((string)($_POST['col_name'] ?? ''));
    $type  = trim((string)($_POST['col_type'] ?? ''));

    if ($table === '' || !table_exists($conn, $table)) {
      set_flash("Invalid table.", true);
      redirect();
    }

    // Basic name sanity (still allow underscores). Hard reject weird names.
    if ($name === '' || !preg_match('/^[A-Za-z0-9_]+$/', $name)) {
      set_flash("Invalid column name.", true);
      redirect(['action' => 'structure', 'table' => $table]);
    }

    if ($type === '') {
      set_flash("Column type is required.", true);
      redirect(['action' => 'structure', 'table' => $table]);
    }

    $sql = "ALTER TABLE `" . str_replace('`', '``', $table) . "` ADD `" . str_replace('`', '``', $name) . "` " . $type;
    if ($conn->query($sql)) set_flash("Column '$name' added.");
    else set_flash("Error adding column: " . $conn->error, true);

    redirect(['action' => 'structure', 'table' => $table]);
  }

  // Drop column (POST-only)
  if ($action === 'drop_column' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();

    $table  = (string)($_POST['table'] ?? '');
    $column = (string)($_POST['column'] ?? '');

    if ($table === '' || !table_exists($conn, $table)) {
      set_flash("Invalid table.", true);
      redirect();
    }

    $cols = describe_table($conn, $table);
    $fields = array_map(fn($c) => (string)$c['Field'], $cols);
    if (!in_array($column, $fields, true)) {
      set_flash("Invalid column.", true);
      redirect(['action' => 'structure', 'table' => $table]);
    }

    $sql = "ALTER TABLE `" . str_replace('`', '``', $table) . "` DROP `" . str_replace('`', '``', $column) . "`";
    if ($conn->query($sql)) set_flash("Column '$column' dropped.");
    else set_flash("Error dropping column: " . $conn->error, true);

    redirect(['action' => 'structure', 'table' => $table]);
  }

  // Rename column (raw) - POST only
  if ($action === 'rename_column' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();

    $table   = (string)($_POST['table'] ?? '');
    $oldName = (string)($_POST['old_name'] ?? '');
    $newName = trim((string)($_POST['new_name'] ?? ''));
    $colType = trim((string)($_POST['col_type'] ?? ''));

    if ($table === '' || !table_exists($conn, $table)) {
      set_flash("Invalid table.", true);
      redirect();
    }

    $cols = describe_table($conn, $table);
    $fields = array_map(fn($c) => (string)$c['Field'], $cols);
    if (!in_array($oldName, $fields, true)) {
      set_flash("Invalid original column.", true);
      redirect(['action' => 'structure', 'table' => $table]);
    }

    if ($newName === '' || !preg_match('/^[A-Za-z0-9_]+$/', $newName) || $colType === '') {
      set_flash("New name must be [A-Za-z0-9_] and type is required.", true);
      redirect(['action' => 'structure', 'table' => $table]);
    }

    $sql = "ALTER TABLE `" . str_replace('`', '``', $table) . "` CHANGE `" .
           str_replace('`', '``', $oldName) . "` `" .
           str_replace('`', '``', $newName) . "` " . $colType;

    if ($conn->query($sql)) set_flash("Column '$oldName' altered/renamed.");
    else set_flash("Error: " . $conn->error, true);

    redirect(['action' => 'structure', 'table' => $table]);
  }

  // Change type only - POST only
  if ($action === 'change_type' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();

    $table   = (string)($_POST['table'] ?? '');
    $colName = (string)($_POST['col_name'] ?? '');
    $colType = trim((string)($_POST['col_type'] ?? ''));

    if ($table === '' || !table_exists($conn, $table)) {
      set_flash("Invalid table.", true);
      redirect();
    }

    $cols = describe_table($conn, $table);
    $fields = array_map(fn($c) => (string)$c['Field'], $cols);
    if (!in_array($colName, $fields, true)) {
      set_flash("Invalid column.", true);
      redirect(['action' => 'structure', 'table' => $table]);
    }

    if ($colType === '') {
      set_flash("New type is required.", true);
      redirect(['action' => 'structure', 'table' => $table]);
    }

    $sql = "ALTER TABLE `" . str_replace('`', '``', $table) . "` MODIFY `" .
           str_replace('`', '``', $colName) . "` " . $colType;

    if ($conn->query($sql)) set_flash("Column '$colName' changed.");
    else set_flash("Error changing type: " . $conn->error, true);

    redirect(['action' => 'structure', 'table' => $table]);
  }

  // Save row (insert/update) - POST only
  if ($action === 'save_row' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();

    $table = (string)($_POST['table'] ?? '');
    if ($table === '' || !table_exists($conn, $table)) {
      set_flash("Invalid table.", true);
      redirect();
    }

    $is_update = (!empty($_POST['is_update']) && $_POST['is_update'] === '1');

    $columnsInfo = describe_table($conn, $table);
    $allowedCols = array_map(fn($c) => (string)$c['Field'], $columnsInfo);

    $cols = $_POST['col'] ?? [];
    $vals = $_POST['val'] ?? [];

    // Keep arrays aligned
    if (!is_array($cols) || !is_array($vals) || count($cols) !== count($vals)) {
      set_flash("Invalid form payload.", true);
      redirect(['action' => 'browse', 'table' => $table]);
    }

    // Validate columns
    foreach ($cols as $c) {
      if (!is_string($c) || !in_array($c, $allowedCols, true)) {
        set_flash("Invalid column in payload.", true);
        redirect(['action' => 'browse', 'table' => $table]);
      }
    }

    // Normalize NULL sentinel
    foreach ($vals as $k => $v) {
      if ($v === '__NULL__') $vals[$k] = null;
      elseif (!is_string($v) && $v !== null) $vals[$k] = (string)$v;
    }

    $pk = get_primary_key($conn, $table);

    if ($is_update) {
      if (!$pk || !isset($_POST['pk_value'])) {
        set_flash("Update not possible (missing PK).", true);
        redirect(['action' => 'browse', 'table' => $table]);
      }
      $pkValue = (string)$_POST['pk_value'];

      $setParts = [];
      foreach ($cols as $colName) {
        $setParts[] = "`" . str_replace('`', '``', $colName) . "` = ?";
      }

      $sql = "UPDATE `" . str_replace('`', '``', $table) . "` SET " . implode(', ', $setParts) .
             " WHERE `" . str_replace('`', '``', $pk) . "` = ?";

      $stmt = $conn->prepare($sql);
      if (!$stmt) {
        set_flash("Prepare failed: " . $conn->error, true);
        redirect(['action' => 'browse', 'table' => $table]);
      }

      $bindValues = $vals;
      $bindValues[] = $pkValue;
      stmt_bind_all_strings($stmt, $bindValues);

      if ($stmt->execute()) set_flash("Row updated.");
      else set_flash("Update failed: " . $stmt->error, true);

      $stmt->close();
      redirect(['action' => 'browse', 'table' => $table]);
    } else {
      if (empty($cols)) {
        set_flash("No columns to insert.", true);
        redirect(['action' => 'browse', 'table' => $table]);
      }

      $colParts = [];
      $place    = [];
      foreach ($cols as $colName) {
        $colParts[] = "`" . str_replace('`', '``', $colName) . "`";
        $place[]    = "?";
      }

      $sql = "INSERT INTO `" . str_replace('`', '``', $table) . "` (" . implode(', ', $colParts) . ") VALUES (" . implode(', ', $place) . ")";
      $stmt = $conn->prepare($sql);
      if (!$stmt) {
        set_flash("Prepare failed: " . $conn->error, true);
        redirect(['action' => 'browse', 'table' => $table]);
      }

      stmt_bind_all_strings($stmt, $vals);

      if ($stmt->execute()) set_flash("Row inserted. ID: " . $stmt->insert_id);
      else set_flash("Insert failed: " . $stmt->error, true);

      $stmt->close();
      redirect(['action' => 'browse', 'table' => $table]);
    }
  }

  // Delete row - POST only
  if ($action === 'delete_row' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();

    $table = (string)($_POST['table'] ?? '');
    $pk    = (string)($_POST['pk'] ?? '');
    $val   = (string)($_POST['pk_value'] ?? '');

    if ($table === '' || !table_exists($conn, $table)) {
      set_flash("Invalid table.", true);
      redirect();
    }

    $realPk = get_primary_key($conn, $table);
    if (!$realPk || $pk !== $realPk) {
      set_flash("Invalid primary key.", true);
      redirect(['action' => 'browse', 'table' => $table]);
    }

    $sql = "DELETE FROM `" . str_replace('`', '``', $table) . "` WHERE `" . str_replace('`', '``', $pk) . "` = ? LIMIT 1";
    $stmt = $conn->prepare($sql);
    if (!$stmt) {
      set_flash("Prepare failed: " . $conn->error, true);
      redirect(['action' => 'browse', 'table' => $table]);
    }
    $stmt->bind_param('s', $val);
    if ($stmt->execute()) set_flash("Row deleted.");
    else set_flash("Delete failed: " . $stmt->error, true);
    $stmt->close();

    redirect(['action' => 'browse', 'table' => $table]);
  }

  // EXPORT DOWNLOAD - POST only
  if ($action === 'do_export' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();

    $tables = (array)($_POST['tables'] ?? []);
    $format = (string)($_POST['format'] ?? 'sql');
    $withData = !empty($_POST['with_data']);

    if (empty($tables)) {
      set_flash("No tables selected for export.", true);
      redirect(['action' => 'export']);
    }

    // whitelist tables
    $all = list_tables($conn);
    $tables = array_values(array_filter($tables, fn($t) => is_string($t) && in_array($t, $all, true)));
    if (empty($tables)) {
      set_flash("No valid tables selected.", true);
      redirect(['action' => 'export']);
    }

    $dbName = (string)$_SESSION['db_name'];
    $timestamp = date('Ymd_His');

    if ($format === 'csv') { $ext='csv'; $contentType='text/csv; charset=utf-8'; }
    elseif ($format === 'tsv') { $ext='tsv'; $contentType='text/tab-separated-values; charset=utf-8'; }
    else { $ext='sql'; $contentType='text/sql; charset=utf-8'; $format='sql'; }

    $filename = "export_{$dbName}_{$timestamp}.{$ext}";
    header("Content-Type: {$contentType}");
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');
    header('Expires: 0');

    if ($format === 'sql') {
      echo "-- Mini Adminer export\n";
      echo "-- Database: `" . $dbName . "`\n";
      echo "-- Generated: " . date('Y-m-d H:i:s') . "\n\n";
      echo "SET NAMES utf8mb4;\n\n";

      foreach ($tables as $table) {
        $escTable = str_replace('`', '``', $table);
        echo "-- -------------------------------------------\n";
        echo "-- Table structure for table `" . $table . "`\n";
        echo "-- -------------------------------------------\n\n";

        $res = $conn->query("SHOW CREATE TABLE `{$escTable}`");
        if ($res) {
          $row = $res->fetch_assoc();
          $create = $row['Create Table'] ?? '';
          $res->free();
          echo "DROP TABLE IF EXISTS `" . $table . "`;\n";
          echo $create . ";\n\n";
        }

        if ($withData) {
          echo "-- Dumping data for table `" . $table . "`\n\n";
          $res = $conn->query("SELECT * FROM `{$escTable}`");
          if ($res) {
            $cols = [];
            $first = true;
            while ($r = $res->fetch_assoc()) {
              if ($first) { $cols = array_keys($r); $first = false; }
              $valuesSql = [];
              foreach ($cols as $c) {
                if (!array_key_exists($c, $r) || $r[$c] === null) $valuesSql[] = "NULL";
                else $valuesSql[] = "'" . $conn->real_escape_string((string)$r[$c]) . "'";
              }
              echo "INSERT INTO `" . $table . "` (`" . implode("`,`", $cols) . "`) VALUES (" . implode(",", $valuesSql) . ");\n";
            }
            $res->free();
            echo "\n";
          }
        }
      }
    } else {
      $delimiter = ($format === 'tsv') ? "\t" : ",";
      $out = fopen('php://output', 'w');

      fwrite($out, "# Mini Adminer export\n");
      fwrite($out, "# Database: {$dbName}\n");
      fwrite($out, "# Generated: " . date('Y-m-d H:i:s') . "\n\n");

      foreach ($tables as $table) {
        $escTable = str_replace('`', '``', $table);
        fwrite($out, "# TABLE: {$table}\n");

        $res = $conn->query("SELECT * FROM `{$escTable}`");
        if ($res) {
          $cols = [];
          $first = true;
          while ($r = $res->fetch_assoc()) {
            if ($first) {
              $cols = array_keys($r);
              fputcsv($out, $cols, $delimiter);
              $first = false;
            }
            if ($withData) {
              $rowOut = [];
              foreach ($cols as $c) $rowOut[] = ($r[$c] === null ? '' : (string)$r[$c]);
              fputcsv($out, $rowOut, $delimiter);
            }
          }
          if ($first && !$withData) {
            $resCols = $conn->query("DESCRIBE `{$escTable}`");
            $colNames = [];
            if ($resCols) {
              while ($c = $resCols->fetch_assoc()) $colNames[] = $c['Field'];
              $resCols->free();
            }
            if (!empty($colNames)) fputcsv($out, $colNames, $delimiter);
          }
          $res->free();
        }
        fwrite($out, "\n");
      }
      fclose($out);
    }
    exit;
  }

  // SQL console runner (single statement) - POST only
  if ($action === 'run_sql' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();

    $sqlIn = (string)($_POST['sql'] ?? '');
    $showAll = !empty($_POST['show_all']);

    $sql = normalize_sql($sqlIn);
    if ($sql === '') {
      set_flash("SQL is empty.", true);
      redirect(['action' => 'sql']);
    }

    // Very important: this is an admin tool; do NOT pretend we can fully sanitize SQL.
    // We do enforce "single statement" by rejecting obvious multi-statement separators.
    if (preg_match('/;\s*\S/', $sql)) {
      $sql_console_result = [
        'sql' => $sql,
        'error' => 'Multiple statements detected. Only one statement is allowed.',
        'is_resultset' => false
      ];
      $action = 'sql';
    } else {
      $isRS = is_resultset_sql($sql);
      $limit = 50;

      $sqlToRun = $sql;
      if ($isRS && !$showAll) $sqlToRun = sql_add_limit($sql, $limit + 1);

      $res = @$conn->query($sqlToRun);
      if (!$res) {
        $sql_console_result = [
          'sql' => $sql,
          'error' => $conn->error,
          'is_resultset' => $isRS
        ];
      } else {
        if ($res instanceof mysqli_result) {
          $fields = $res->fetch_fields();
          $rows = [];
          $rowCountFetched = 0;
          while ($r = $res->fetch_assoc()) {
            $rows[] = $r;
            $rowCountFetched++;
            if (!$showAll && $rowCountFetched >= ($limit + 1)) break;
          }
          $res->free();

          $hasMore = (!$showAll && $rowCountFetched > $limit);
          if ($hasMore) array_pop($rows);

          $sql_console_result = [
            'sql' => $sql,
            'error' => null,
            'is_resultset' => true,
            'fields' => $fields,
            'rows' => $rows,
            'has_more' => $hasMore,
            'limit' => $limit
          ];
        } else {
          $sql_console_result = [
            'sql' => $sql,
            'error' => null,
            'is_resultset' => false,
            'affected' => $conn->affected_rows
          ];
        }
      }
      $action = 'sql';
    }
  }
}

// ---------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------
?><!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mini Adminer</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" rel="stylesheet">

  <style>
    body { background-color: #f8f9fa; }
    .navbar-brand i { margin-right: .5rem; }
    .table-fixed { table-layout: fixed; word-wrap: break-word; }
    textarea.form-control-sm { min-height: 110px; }
    .type-builder-group { border: 1px solid #dee2e6; border-radius: .25rem; padding: .5rem .75rem; background-color: #fff; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
  </style>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-3">
  <div class="container-fluid">
    <a class="navbar-brand" href="<?php echo h($_SERVER['PHP_SELF']); ?>">
      <i class="fa-solid fa-database"></i> Mini Adminer
    </a>
    <div class="d-flex gap-2">
      <?php if (is_logged_in()): ?>
        <span class="navbar-text me-2">DB: <?php echo h($_SESSION['db_name']); ?></span>
        <a href="<?php echo h($_SERVER['PHP_SELF']); ?>?action=sql" class="btn btn-outline-warning btn-sm">
          <i class="fa-solid fa-terminal"></i> SQL
        </a>
        <a href="<?php echo h($_SERVER['PHP_SELF']); ?>?action=export" class="btn btn-outline-info btn-sm">
          <i class="fa-solid fa-file-export"></i> Export
        </a>
        <form method="post" action="<?php echo h($_SERVER['PHP_SELF']); ?>?action=logout" class="d-inline">
          <?php echo csrf_field(); ?>
          <button class="btn btn-outline-light btn-sm" type="submit">
            <i class="fa-solid fa-right-from-bracket"></i> Logout
          </button>
        </form>
      <?php endif; ?>
    </div>
  </div>
</nav>

<div class="container mb-5">
  <?php if ($flash_message): ?>
    <div class="alert alert-<?php echo $flash_error ? 'danger' : 'success'; ?>">
      <?php echo h($flash_message); ?>
    </div>
  <?php endif; ?>

<?php if (!is_logged_in() || !$conn): ?>

  <div class="row justify-content-center">
    <div class="col-md-6">
      <div class="card shadow-sm">
        <div class="card-header">
          <strong><i class="fa-solid fa-right-to-bracket"></i> Database Login</strong>
        </div>
        <div class="card-body">
          <?php if ($login_error): ?>
            <div class="alert alert-danger"><?php echo h($login_error); ?></div>
          <?php endif; ?>
          <form method="post" action="<?php echo h($_SERVER['PHP_SELF']); ?>?action=login">
            <?php echo csrf_field(); ?>
            <div class="mb-3">
              <label class="form-label">Host</label>
              <input type="text" name="host" class="form-control" value="localhost">
            </div>
            <div class="mb-3">
              <label class="form-label">User</label>
              <input type="text" name="user" class="form-control" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Password</label>
              <input type="password" name="pass" class="form-control">
            </div>
            <div class="mb-3">
              <label class="form-label">Database</label>
              <input type="text" name="db" class="form-control" required>
            </div>
            <button type="submit" class="btn btn-primary">
              <i class="fa-solid fa-circle-arrow-right"></i> Connect
            </button>
          </form>
        </div>
      </div>
    </div>
  </div>

<?php else:

  $action = $action ?: 'tables';
  $currentTable = (string)($_GET['table'] ?? '');

  // -------------------------
  // SQL Console page
  // -------------------------
  if ($action === 'sql') {
    $sqlPrefill = (string)($_POST['sql'] ?? ($_GET['sql'] ?? ''));
    ?>
    <div class="mb-3">
      <a href="<?php echo h($_SERVER['PHP_SELF']); ?>" class="btn btn-secondary btn-sm">
        <i class="fa-solid fa-arrow-left"></i> Tables
      </a>
    </div>

    <div class="card shadow-sm mb-3">
      <div class="card-header">
        <strong><i class="fa-solid fa-terminal"></i> SQL Console</strong>
      </div>
      <div class="card-body">
        <form method="post" action="<?php echo h($_SERVER['PHP_SELF']); ?>?action=run_sql" id="sqlConsoleForm">
          <?php echo csrf_field(); ?>
          <div class="mb-2">
            <textarea name="sql" class="form-control form-control-sm mono" placeholder="Write a single SQL statement here..."><?php echo h($sqlPrefill); ?></textarea>
          </div>
          <input type="hidden" name="show_all" id="sql_show_all" value="0">
          <button type="submit" class="btn btn-warning btn-sm">
            <i class="fa-solid fa-play"></i> Run
          </button>
          <button type="button" class="btn btn-outline-secondary btn-sm" onclick="document.querySelector('textarea[name=sql]').value='';">
            Clear
          </button>
        </form>
      </div>
    </div>

    <?php if ($sql_console_result !== null): ?>
      <div class="card shadow-sm">
        <div class="card-header">
          <strong>Result</strong>
        </div>
        <div class="card-body">
          <div class="mb-2">
            <div class="small text-muted">SQL:</div>
            <div class="mono small"><?php echo h($sql_console_result['sql']); ?></div>
          </div>

          <?php if (!empty($sql_console_result['error'])): ?>
            <div class="alert alert-danger mb-0">
              <strong>Error:</strong> <?php echo h($sql_console_result['error']); ?>
            </div>
          <?php else: ?>

            <?php if (!$sql_console_result['is_resultset']): ?>
              <div class="alert alert-success mb-0">
                Statement executed successfully. Affected rows: <?php echo (int)$sql_console_result['affected']; ?>
              </div>
            <?php else: ?>

              <?php
                $limit = (int)$sql_console_result['limit'];
                $rows = $sql_console_result['rows'];
                $hasMore = !empty($sql_console_result['has_more']);
              ?>

              <?php if ($hasMore): ?>
                <div class="alert alert-warning d-flex justify-content-between align-items-center">
                  <div>
                    Displaying the first <?php echo (int)$limit; ?> rows.
                    Loading the entire result set may be slow and could use significant memory.
                  </div>
                  <button class="btn btn-sm btn-outline-dark"
                          onclick="runSqlShowAll(); return false;">
                    Show all rows
                  </button>
                </div>
              <?php else: ?>
                <div class="alert alert-success">
                  Query returned <?php echo count($rows); ?> row(s).
                </div>
              <?php endif; ?>

              <div class="table-responsive">
                <table class="table table-sm table-bordered table-striped table-fixed">
                  <thead class="table-light">
                    <tr>
                      <?php foreach ($sql_console_result['fields'] as $f): ?>
                        <th><?php echo h($f->name); ?></th>
                      <?php endforeach; ?>
                    </tr>
                  </thead>
                  <tbody>
                    <?php foreach ($rows as $r): ?>
                      <tr>
                        <?php foreach ($sql_console_result['fields'] as $f): ?>
                          <td><?php echo h((string)($r[$f->name] ?? '')); ?></td>
                        <?php endforeach; ?>
                      </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>

            <?php endif; ?>

          <?php endif; ?>
        </div>
      </div>
    <?php endif; ?>

    <?php
  }

  // -------------------------
  // Export page
  // -------------------------
  if ($action === 'export') {
    $tables = list_tables($conn);
    ?>
    <div class="card shadow-sm">
      <div class="card-header">
        <strong><i class="fa-solid fa-file-export"></i> Export Tables</strong>
      </div>
      <div class="card-body">
        <form method="post" action="<?php echo h($_SERVER['PHP_SELF']); ?>?action=do_export">
          <?php echo csrf_field(); ?>

          <div class="mb-3">
            <label class="form-label">Select tables</label>
            <div class="mb-2">
              <button type="button" class="btn btn-sm btn-outline-secondary" onclick="toggleAllTables(true)">Select all</button>
              <button type="button" class="btn btn-sm btn-outline-secondary" onclick="toggleAllTables(false)">Unselect all</button>
            </div>
            <div class="row row-cols-2 row-cols-md-3">
              <?php foreach ($tables as $tbl): ?>
                <div class="col">
                  <div class="form-check">
                    <input class="form-check-input export-table-checkbox" type="checkbox" name="tables[]" value="<?php echo h($tbl); ?>" id="tbl_<?php echo h($tbl); ?>" checked>
                    <label class="form-check-label" for="tbl_<?php echo h($tbl); ?>"><?php echo h($tbl); ?></label>
                  </div>
                </div>
              <?php endforeach; ?>
            </div>
          </div>

          <div class="mb-3">
            <label class="form-label">Format</label>
            <div class="form-check">
              <input class="form-check-input" type="radio" name="format" id="fmt_sql" value="sql" checked>
              <label class="form-check-label" for="fmt_sql">MySQL SQL (DDL + optional INSERTs)</label>
            </div>
            <div class="form-check">
              <input class="form-check-input" type="radio" name="format" id="fmt_csv" value="csv">
              <label class="form-check-label" for="fmt_csv">CSV</label>
            </div>
            <div class="form-check">
              <input class="form-check-input" type="radio" name="format" id="fmt_tsv" value="tsv">
              <label class="form-check-label" for="fmt_tsv">TSV</label>
            </div>
          </div>

          <div class="mb-3">
            <div class="form-check">
              <input class="form-check-input" type="checkbox" name="with_data" id="with_data" value="1" checked>
              <label class="form-check-label" for="with_data">Include data</label>
            </div>
          </div>

          <button type="submit" class="btn btn-primary">
            <i class="fa-solid fa-download"></i> Download export
          </button>
          <a href="<?php echo h($_SERVER['PHP_SELF']); ?>" class="btn btn-secondary">Cancel</a>
        </form>
      </div>
    </div>
    <?php
  }

  // -------------------------
  // Tables page
  // -------------------------
  if ($action === 'tables') {
    $tables = list_tables($conn);
    ?>
    <div class="card shadow-sm">
      <div class="card-header d-flex justify-content-between align-items-center">
        <strong><i class="fa-solid fa-table"></i> Tables in <?php echo h($_SESSION['db_name']); ?></strong>
        <div class="d-flex gap-2">
          <a href="<?php echo h($_SERVER['PHP_SELF']); ?>?action=sql" class="btn btn-sm btn-outline-warning">
            <i class="fa-solid fa-terminal"></i> SQL
          </a>
          <a href="<?php echo h($_SERVER['PHP_SELF']); ?>?action=export" class="btn btn-sm btn-outline-info">
            <i class="fa-solid fa-file-export"></i> Export
          </a>
        </div>
      </div>
      <div class="card-body">
        <div class="list-group">
          <?php foreach ($tables as $tbl): ?>
            <a href="<?php echo h($_SERVER['PHP_SELF']); ?>?action=browse&amp;table=<?php echo h(urlencode($tbl)); ?>"
               class="list-group-item list-group-item-action d-flex justify-content-between align-items-center">
              <span><i class="fa-regular fa-square"></i> <?php echo h($tbl); ?></span>
              <span class="badge bg-secondary rounded-pill">Browse</span>
            </a>
          <?php endforeach; ?>
        </div>
      </div>
    </div>
    <?php
  }

  // -------------------------
  // Browse table with SEARCH (prepared statements, no get_result dependency)
  // -------------------------
  if ($action === 'browse' && $currentTable !== '') {
    $table = $currentTable;
    if (!table_exists($conn, $table)) {
      echo '<div class="alert alert-danger">Invalid table.</div>';
    } else {
      $columns = describe_table($conn, $table);
      $fieldsList = array_map(fn($c) => (string)$c['Field'], $columns);
      $defaultField = $fieldsList[0] ?? '';

      $s_enabled = !empty($_GET['s_enabled']);
      $s_field = (string)($_GET['s_field'] ?? $defaultField);
      $s_mode  = (string)($_GET['s_mode'] ?? 'like');
      $s_term  = (string)($_GET['s_term'] ?? '');
      $s_cs    = !empty($_GET['s_cs']);
      $show_all = !empty($_GET['show_all']);

      $hasWhere = false;
      $whereSql = '';
      $params = [];

      if ($s_enabled && $s_field !== '' && in_array($s_field, $fieldsList, true) && $s_term !== '') {
        $whereSql = build_search_where($conn, $s_field, $s_mode, $s_term, $s_cs, $params);
        $hasWhere = true;
      }

      // COUNT
      $count = 0;
      if ($hasWhere) {
        $sqlCount = "SELECT COUNT(*) AS c FROM `" . str_replace('`', '``', $table) . "` WHERE $whereSql";
        $stmt = $conn->prepare($sqlCount);
        if ($stmt) {
          stmt_bind_all_strings($stmt, $params);
          $stmt->execute();
          $stmt->bind_result($c);
          if ($stmt->fetch()) $count = (int)$c;
          $stmt->close();
        }
      } else {
        $resC = $conn->query("SELECT COUNT(*) AS c FROM `" . str_replace('`', '``', $table) . "`");
        if ($resC) {
          $rowC = $resC->fetch_assoc();
          $count = (int)($rowC['c'] ?? 0);
          $resC->free();
        }
      }

      $limit = 50;
      $rows = [];
      $hasMore = false;

      // DATA
      $sql = "SELECT * FROM `" . str_replace('`', '``', $table) . "`";
      if ($hasWhere) $sql .= " WHERE $whereSql";
      if (!$show_all) $sql .= " LIMIT " . (int)($limit + 1);

      if ($hasWhere) {
        $stmt = $conn->prepare($sql);
        if ($stmt) {
          $params2 = $params;
          stmt_bind_all_strings($stmt, $params2);
          $stmt->execute();

          $meta = $stmt->result_metadata();
          $fields = [];
          $fieldNames = [];
          if ($meta) {
            while ($f = $meta->fetch_field()) {
              $fields[] = $f;
              $fieldNames[] = $f->name;
            }
            $meta->free();
          }

          $rows = stmt_fetch_all_assoc($stmt, $fieldNames, $show_all ? 0 : ($limit + 1));
          $stmt->close();

          if (!$show_all && count($rows) > $limit) {
            $hasMore = true;
            array_pop($rows);
          }
        }
      } else {
        $res = $conn->query($sql);
        $fields = [];
        if ($res) {
          $fields = $res->fetch_fields();
          while ($r = $res->fetch_assoc()) $rows[] = $r;
          $res->free();
          if (!$show_all && count($rows) > $limit) {
            $hasMore = true;
            array_pop($rows);
          }
        }
      }

      $pk = get_primary_key($conn, $table);

      $paramsUrl = ['action' => 'browse', 'table' => $table];
      if ($s_enabled) {
        $paramsUrl['s_enabled'] = 1;
        $paramsUrl['s_field'] = $s_field;
        $paramsUrl['s_mode'] = $s_mode;
        $paramsUrl['s_term'] = $s_term;
        if ($s_cs) $paramsUrl['s_cs'] = 1;
      }
      $paramsUrl['show_all'] = 1;
      $showAllUrl = $_SERVER['PHP_SELF'] . '?' . http_build_query($paramsUrl);
      ?>
      <div class="mb-3 d-flex gap-2">
        <a href="<?php echo h($_SERVER['PHP_SELF']); ?>" class="btn btn-secondary btn-sm">
          <i class="fa-solid fa-arrow-left"></i> Tables
        </a>
        <a href="<?php echo h($_SERVER['PHP_SELF']); ?>?action=structure&amp;table=<?php echo h(urlencode($table)); ?>"
           class="btn btn-outline-primary btn-sm">
          <i class="fa-solid fa-sitemap"></i> Structure
        </a>
        <a href="<?php echo h($_SERVER['PHP_SELF']); ?>?action=sql" class="btn btn-outline-warning btn-sm">
          <i class="fa-solid fa-terminal"></i> SQL
        </a>
        <button class="btn btn-success btn-sm" onclick="document.getElementById('insertForm').scrollIntoView();">
          <i class="fa-solid fa-plus"></i> Insert row
        </button>
      </div>

      <div class="card shadow-sm mb-3">
        <div class="card-header">
          <strong><i class="fa-solid fa-table"></i> Browse: <?php echo h($table); ?></strong>
        </div>
        <div class="card-body">

          <form method="get" class="row g-2 align-items-end mb-3">
            <input type="hidden" name="action" value="browse">
            <input type="hidden" name="table" value="<?php echo h($table); ?>">
            <input type="hidden" name="s_enabled" value="1">
            <div class="col-md-3">
              <label class="form-label small">Field</label>
              <select name="s_field" class="form-select form-select-sm">
                <?php foreach ($fieldsList as $f): ?>
                  <option value="<?php echo h($f); ?>" <?php echo ($f === $s_field ? 'selected' : ''); ?>>
                    <?php echo h($f); ?>
                  </option>
                <?php endforeach; ?>
              </select>
            </div>
            <div class="col-md-2">
              <label class="form-label small">Match</label>
              <select name="s_mode" class="form-select form-select-sm">
                <option value="exact"  <?php echo $s_mode==='exact'?'selected':''; ?>>Exact</option>
                <option value="like"   <?php echo $s_mode==='like'?'selected':''; ?>>Contains (LIKE %...%)</option>
                <option value="starts" <?php echo $s_mode==='starts'?'selected':''; ?>>Starts with</option>
                <option value="ends"   <?php echo $s_mode==='ends'?'selected':''; ?>>Ends with</option>
                <option value="regexp" <?php echo $s_mode==='regexp'?'selected':''; ?>>REGEXP</option>
              </select>
            </div>
            <div class="col-md-4">
              <label class="form-label small">Value</label>
              <input type="text" name="s_term" class="form-control form-control-sm" value="<?php echo h($s_term); ?>" placeholder="Search term">
            </div>
            <div class="col-md-2">
              <div class="form-check mt-4">
                <input class="form-check-input" type="checkbox" name="s_cs" value="1" id="s_cs" <?php echo $s_cs ? 'checked' : ''; ?>>
                <label class="form-check-label small" for="s_cs">Case sensitive</label>
              </div>
            </div>
            <div class="col-md-1">
              <button type="submit" class="btn btn-primary btn-sm w-100">
                <i class="fa-solid fa-magnifying-glass"></i>
              </button>
            </div>
            <div class="col-12">
              <a class="btn btn-outline-secondary btn-sm"
                 href="<?php echo h($_SERVER['PHP_SELF']); ?>?action=browse&amp;table=<?php echo h(urlencode($table)); ?>">
                Clear search
              </a>
            </div>
          </form>

          <?php if ($hasMore): ?>
            <div class="alert alert-warning d-flex justify-content-between align-items-center">
              <div>
                Displaying the first <?php echo (int)$limit; ?> rows out of <?php echo (int)$count; ?> matching row(s).
                Loading all results may be slow and could consume substantial memory.
              </div>
              <a class="btn btn-sm btn-outline-dark"
                 href="<?php echo h($showAllUrl); ?>"
                 onclick="return confirm('This may take a long time and could stress the server. Continue?');">
                Show all
              </a>
            </div>
          <?php else: ?>
            <div class="alert alert-success">
              <?php if ($hasWhere): ?>
                Matching rows: <?php echo (int)$count; ?>. Displayed: <?php echo count($rows); ?>.
              <?php else: ?>
                Total rows: <?php echo (int)$count; ?>. Displayed: <?php echo count($rows); ?>.
              <?php endif; ?>
            </div>
          <?php endif; ?>

          <?php if (empty($rows)): ?>
            <p class="mb-0">No rows found.</p>
          <?php else: ?>
            <div class="table-responsive">
              <table class="table table-sm table-bordered table-striped table-fixed">
                <thead class="table-light">
                  <tr>
                    <?php foreach ($fields as $f): ?>
                      <th><?php echo h($f->name); ?></th>
                    <?php endforeach; ?>
                    <th style="width:130px;">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($rows as $row): ?>
                    <tr>
                      <?php foreach ($fields as $f): ?>
                        <td><?php echo h((string)($row[$f->name] ?? '')); ?></td>
                      <?php endforeach; ?>
                      <td class="d-flex gap-1">
                        <?php if ($pk !== null && isset($row[$pk])): ?>
                          <a class="btn btn-sm btn-primary"
                             href="<?php echo h($_SERVER['PHP_SELF']); ?>?action=edit_row&amp;table=<?php echo h(urlencode($table)); ?>&amp;pk_value=<?php echo h(urlencode((string)$row[$pk])); ?>">
                            <i class="fa-solid fa-pen"></i>
                          </a>

                          <form method="post" action="<?php echo h($_SERVER['PHP_SELF']); ?>?action=delete_row" class="d-inline"
                                onsubmit="return confirm('Delete this row?');">
                            <?php echo csrf_field(); ?>
                            <input type="hidden" name="table" value="<?php echo h($table); ?>">
                            <input type="hidden" name="pk" value="<?php echo h($pk); ?>">
                            <input type="hidden" name="pk_value" value="<?php echo h((string)$row[$pk]); ?>">
                            <button class="btn btn-sm btn-danger" type="submit">
                              <i class="fa-solid fa-trash"></i>
                            </button>
                          </form>
                        <?php else: ?>
                          <span class="text-muted small">no PK</span>
                        <?php endif; ?>
                      </td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          <?php endif; ?>

        </div>
      </div>

      <!-- Insert form -->
      <div class="card shadow-sm" id="insertForm">
        <div class="card-header">
          <strong><i class="fa-solid fa-plus"></i> Insert new row in <?php echo h($table); ?></strong>
        </div>
        <div class="card-body">
          <form method="post" action="<?php echo h($_SERVER['PHP_SELF']); ?>?action=save_row">
            <?php echo csrf_field(); ?>
            <input type="hidden" name="table" value="<?php echo h($table); ?>">
            <input type="hidden" name="is_update" value="0">
            <div class="row g-2">
              <?php foreach ($columns as $c):
                $field    = (string)$c['Field'];
                $typeDef  = (string)$c['Type'];
                $typeLow  = strtolower($typeDef);
                $nullable = ((string)$c['Null'] === 'YES');
              ?>
                <div class="col-md-4">
                  <label class="form-label small">
                    <?php echo h($field); ?>
                    <span class="text-muted">(<?php echo h($typeDef); ?>)</span>
                    <?php if ($nullable): ?><span class="badge bg-light text-muted border">NULL</span><?php endif; ?>
                  </label>
                  <input type="hidden" name="col[]" value="<?php echo h($field); ?>">
                  <?php
                  if (strpos($typeLow, 'enum(') === 0 || strpos($typeLow, 'set(') === 0) {
                    $enumVals = parse_enum_set_values($typeDef);
                    echo '<select name="val[]" class="form-select form-select-sm">';
                    if ($nullable) echo '<option value="__NULL__">(NULL)</option>';
                    foreach ($enumVals as $v) {
                      $hv = h($v);
                      echo '<option value="' . $hv . '">' . $hv . '</option>';
                    }
                    echo '</select>';
                  } elseif (preg_match('/^(tinyint|smallint|mediumint|int|bigint)\b/i', $typeLow)) {
                    echo '<input type="number" name="val[]" class="form-control form-control-sm" value="">';
                  } elseif (preg_match('/^(decimal|float|double|real)\b/i', $typeLow)) {
                    echo '<input type="number" step="any" name="val[]" class="form-control form-control-sm" value="">';
                  } elseif (strpos($typeLow, 'date') === 0 && strpos($typeLow, 'datetime') === false) {
                    echo '<input type="date" name="val[]" class="form-control form-control-sm" value="">';
                  } elseif (strpos($typeLow, 'datetime') === 0 || strpos($typeLow, 'timestamp') === 0) {
                    echo '<input type="datetime-local" name="val[]" class="form-control form-control-sm" value="">';
                  } elseif (strpos($typeLow, 'time') === 0) {
                    echo '<input type="time" name="val[]" class="form-control form-control-sm" value="">';
                  } elseif (strpos($typeLow, 'text') !== false || strpos($typeLow, 'blob') !== false) {
                    echo '<textarea name="val[]" class="form-control form-control-sm"></textarea>';
                  } else {
                    echo '<input type="text" name="val[]" class="form-control form-control-sm" value="">';
                  }
                  ?>
                </div>
              <?php endforeach; ?>
            </div>
            <div class="mt-3">
              <button type="submit" class="btn btn-success btn-sm">
                <i class="fa-solid fa-floppy-disk"></i> Insert
              </button>
            </div>
          </form>
        </div>
      </div>
      <?php
    }
  }

  // -------------------------
  // Edit row
  // -------------------------
  if ($action === 'edit_row' && $currentTable !== '' && isset($_GET['pk_value'])) {
    $table   = $currentTable;
    if (!table_exists($conn, $table)) {
      echo '<div class="alert alert-danger">Invalid table.</div>';
    } else {
      $pkValue = (string)$_GET['pk_value'];
      $pk = get_primary_key($conn, $table);

      if ($pk === null) {
        echo '<div class="alert alert-danger">Cannot edit: table has no single-column primary key.</div>';
      } else {
        $sql = "SELECT * FROM `" . str_replace('`','``',$table) . "` WHERE `" . str_replace('`','``',$pk) . "` = ? LIMIT 1";
        $stmt = $conn->prepare($sql);
        $row = null;
        if ($stmt) {
          $stmt->bind_param('s', $pkValue);
          $stmt->execute();

          $meta = $stmt->result_metadata();
          $fieldNames = [];
          if ($meta) {
            while ($f = $meta->fetch_field()) $fieldNames[] = $f->name;
            $meta->free();
          }

          $rows = stmt_fetch_all_assoc($stmt, $fieldNames, 1);
          $stmt->close();
          $row = $rows[0] ?? null;
        }

        if (!$row) {
          echo '<div class="alert alert-warning">Row not found.</div>';
        } else {
          $colInfo = [];
          $infoRes = $conn->query("DESCRIBE `" . str_replace('`','``',$table) . "`");
          if ($infoRes) {
            while ($ci = $infoRes->fetch_assoc()) $colInfo[(string)$ci['Field']] = $ci;
            $infoRes->free();
          }
          ?>
          <div class="mb-3">
            <a href="<?php echo h($_SERVER['PHP_SELF']); ?>?action=browse&amp;table=<?php echo h(urlencode($table)); ?>"
               class="btn btn-secondary btn-sm">
              <i class="fa-solid fa-arrow-left"></i> Back to browse
            </a>
          </div>
          <div class="card shadow-sm">
            <div class="card-header">
              <strong><i class="fa-solid fa-pen"></i> Edit row in <?php echo h($table); ?></strong>
            </div>
            <div class="card-body">
              <form method="post" action="<?php echo h($_SERVER['PHP_SELF']); ?>?action=save_row">
                <?php echo csrf_field(); ?>
                <input type="hidden" name="table" value="<?php echo h($table); ?>">
                <input type="hidden" name="is_update" value="1">
                <input type="hidden" name="pk_value" value="<?php echo h($pkValue); ?>">

                <div class="row g-2">
                  <?php foreach (array_keys($row) as $col):
                    $val      = $row[$col];
                    $typeDef  = (string)($colInfo[$col]['Type'] ?? 'text');
                    $typeLow  = strtolower($typeDef);
                    $nullable = !empty($colInfo[$col]) && (string)$colInfo[$col]['Null'] === 'YES';
                    $displayVal = ($val === null ? '' : (string)$val);
                  ?>
                    <div class="col-md-4">
                      <label class="form-label small">
                        <?php echo h($col); ?>
                        <span class="text-muted">(<?php echo h($typeDef); ?>)</span>
                        <?php if ($nullable): ?><span class="badge bg-light text-muted border">NULL</span><?php endif; ?>
                      </label>
                      <input type="hidden" name="col[]" value="<?php echo h($col); ?>">
                      <?php
                      if (strpos($typeLow, 'enum(') === 0 || strpos($typeLow, 'set(') === 0) {
                        $enumVals = parse_enum_set_values($typeDef);
                        echo '<select name="val[]" class="form-select form-select-sm">';
                        if ($nullable) {
                          $sel = ($val === null) ? ' selected' : '';
                          echo '<option value="__NULL__"' . $sel . '>(NULL)</option>';
                        }
                        foreach ($enumVals as $v) {
                          $sel = ($val !== null && (string)$val === $v) ? ' selected' : '';
                          echo '<option value="' . h($v) . '"' . $sel . '>' . h($v) . '</option>';
                        }
                        echo '</select>';
                      } elseif (preg_match('/^(tinyint|smallint|mediumint|int|bigint)\b/i', $typeLow)) {
                        echo '<input type="number" name="val[]" class="form-control form-control-sm" value="' . h($displayVal) . '">';
                      } elseif (preg_match('/^(decimal|float|double|real)\b/i', $typeLow)) {
                        echo '<input type="number" step="any" name="val[]" class="form-control form-control-sm" value="' . h($displayVal) . '">';
                      } elseif (strpos($typeLow, 'date') === 0 && strpos($typeLow, 'datetime') === false) {
                        echo '<input type="date" name="val[]" class="form-control form-control-sm" value="' . h($displayVal) . '">';
                      } elseif (strpos($typeLow, 'datetime') === 0 || strpos($typeLow, 'timestamp') === 0) {
                        $valDT = $displayVal;
                        if (strlen($valDT) >= 19 && strpos($valDT, ' ') !== false) {
                          $valDT = str_replace(' ', 'T', substr($valDT, 0, 19));
                        }
                        echo '<input type="datetime-local" name="val[]" class="form-control form-control-sm" value="' . h($valDT) . '">';
                      } elseif (strpos($typeLow, 'time') === 0) {
                        echo '<input type="time" name="val[]" class="form-control form-control-sm" value="' . h($displayVal) . '">';
                      } elseif (strpos($typeLow, 'text') !== false || strpos($typeLow, 'blob') !== false) {
                        echo '<textarea name="val[]" class="form-control form-control-sm">' . h($displayVal) . '</textarea>';
                      } else {
                        echo '<input type="text" name="val[]" class="form-control form-control-sm" value="' . h($displayVal) . '">';
                      }
                      ?>
                    </div>
                  <?php endforeach; ?>
                </div>

                <div class="mt-3">
                  <button type="submit" class="btn btn-primary btn-sm">
                    <i class="fa-solid fa-floppy-disk"></i> Save changes
                  </button>
                </div>
              </form>
            </div>
          </div>
          <?php
        }
      }
    }
  }

  // -------------------------
  // Structure page (FIX: safe JS embedding for ENUM types)
  // -------------------------
  if ($action === 'structure' && $currentTable !== '') {
    $table = $currentTable;
    if (!table_exists($conn, $table)) {
      echo '<div class="alert alert-danger">Invalid table.</div>';
    } else {
      $cols = describe_table($conn, $table);
      ?>
      <div class="mb-3">
        <a href="<?php echo h($_SERVER['PHP_SELF']); ?>?action=browse&amp;table=<?php echo h(urlencode($table)); ?>"
           class="btn btn-secondary btn-sm">
          <i class="fa-solid fa-arrow-left"></i> Back to browse
        </a>
      </div>

      <div class="card shadow-sm mb-3">
        <div class="card-header">
          <strong><i class="fa-solid fa-sitemap"></i> Structure: <?php echo h($table); ?></strong>
        </div>
        <div class="card-body">
          <div class="table-responsive">
            <table class="table table-sm table-bordered table-striped">
              <thead class="table-light">
                <tr>
                  <th>Field</th><th>Type</th><th>Null</th><th>Key</th><th>Default</th><th>Extra</th><th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($cols as $c): ?>
                  <?php
                    $field = (string)$c['Field'];
                    $type  = (string)$c['Type'];
                    $null  = (string)$c['Null'];
                    $def   = (string)($c['Default'] ?? '');
                  ?>
                  <tr>
                    <td><?php echo h($field); ?></td>
                    <td><?php echo h($type); ?></td>
                    <td><?php echo h($null); ?></td>
                    <td><?php echo h((string)$c['Key']); ?></td>
                    <td><?php echo h($def); ?></td>
                    <td><?php echo h((string)$c['Extra']); ?></td>
                    <td class="d-flex gap-1 flex-wrap">
                      <form method="post" action="<?php echo h($_SERVER['PHP_SELF']); ?>?action=drop_column" class="d-inline"
                            onsubmit="return confirm('Drop column <?php echo h($field); ?>?');">
                        <?php echo csrf_field(); ?>
                        <input type="hidden" name="table" value="<?php echo h($table); ?>">
                        <input type="hidden" name="column" value="<?php echo h($field); ?>">
                        <button class="btn btn-sm btn-danger" type="submit">
                          <i class="fa-solid fa-trash"></i>
                        </button>
                      </form>
                      <button
                        type="button"
                        class="btn btn-sm btn-outline-secondary js-rename-col"
                        data-table="<?php echo h($table); ?>"
                        data-field="<?php echo h($field); ?>"
                        data-type-b64="<?php echo h(b64e($type)); ?>"
                      >
                        <i class="fa-solid fa-i-cursor"></i> Rename / raw alter
                      </button>
                      <button
                        type="button"
                        class="btn btn-sm btn-outline-primary js-change-type"
                        data-table="<?php echo h($table); ?>"
                        data-field="<?php echo h($field); ?>"
                        data-type-b64="<?php echo h(b64e($type)); ?>"
                        data-nullable="<?php echo h($null); ?>"
                        data-default-b64="<?php echo h(b64e($def)); ?>"
                      >
                        <i class="fa-solid fa-font"></i> Change type (UI)
                      </button>
                    </td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Add Column (UI builder) -->
      <div class="card shadow-sm mb-3">
        <div class="card-header">
          <strong><i class="fa-solid fa-plus"></i> Add Column</strong>
        </div>
        <div class="card-body">
          <form method="post" action="<?php echo h($_SERVER['PHP_SELF']); ?>?action=add_column"
                class="row g-2" id="addColumnForm" onsubmit="return buildAddColumnType();">
            <?php echo csrf_field(); ?>
            <input type="hidden" name="table" value="<?php echo h($table); ?>">
            <input type="hidden" name="col_type" id="add_col_type" value="">
            <div class="col-md-4">
              <label class="form-label small">Column Name</label>
              <input type="text" name="col_name" class="form-control form-control-sm" required>
            </div>
            <div class="col-md-8">
              <label class="form-label small">Type definition</label>
              <div class="type-builder-group">
                <div class="row g-1">
                  <div class="col-md-4">
                    <select id="add_type_base" class="form-select form-select-sm" onchange="updateAddTypeUI();">
                      <option value="INT">INT</option><option value="TINYINT">TINYINT</option><option value="SMALLINT">SMALLINT</option>
                      <option value="MEDIUMINT">MEDIUMINT</option><option value="BIGINT">BIGINT</option>
                      <option value="DECIMAL">DECIMAL</option><option value="FLOAT">FLOAT</option><option value="DOUBLE">DOUBLE</option>
                      <option value="CHAR">CHAR</option><option value="VARCHAR" selected>VARCHAR</option>
                      <option value="TINYTEXT">TINYTEXT</option><option value="TEXT">TEXT</option><option value="MEDIUMTEXT">MEDIUMTEXT</option><option value="LONGTEXT">LONGTEXT</option>
                      <option value="TINYBLOB">TINYBLOB</option><option value="BLOB">BLOB</option><option value="MEDIUMBLOB">MEDIUMBLOB</option><option value="LONGBLOB">LONGBLOB</option>
                      <option value="DATE">DATE</option><option value="DATETIME">DATETIME</option><option value="TIMESTAMP">TIMESTAMP</option>
                      <option value="TIME">TIME</option><option value="YEAR">YEAR</option>
                      <option value="ENUM">ENUM</option><option value="SET">SET</option>
                      <option value="CUSTOM">Custom / raw</option>
                    </select>
                  </div>
                  <div class="col-md-4" id="add_length_group">
                    <input type="text" id="add_length" class="form-control form-control-sm" placeholder="Length / M,D (e.g. 255 or 10,2)">
                  </div>
                  <div class="col-md-4" id="add_enum_group" style="display:none;">
                    <input type="text" id="add_enum" class="form-control form-control-sm" placeholder="Enum values: one,two,three">
                  </div>
                  <div class="col-12 mt-1" id="add_custom_group" style="display:none;">
                    <input type="text" id="add_custom_type" class="form-control form-control-sm" placeholder="Full MySQL type definition" />
                  </div>
                </div>
                <div class="row g-1 mt-1">
                  <div class="col-md-3">
                    <div class="form-check">
                      <input class="form-check-input" type="checkbox" id="add_nullable" checked>
                      <label class="form-check-label small" for="add_nullable">Allow NULL</label>
                    </div>
                  </div>
                  <div class="col-md-9">
                    <div class="row g-1">
                      <div class="col-md-5">
                        <select id="add_default_mode" class="form-select form-select-sm" onchange="updateAddDefaultUI();">
                          <option value="none" selected>No default</option>
                          <option value="null">DEFAULT NULL</option>
                          <option value="current_timestamp">DEFAULT CURRENT_TIMESTAMP</option>
                          <option value="value">DEFAULT literal value</option>
                        </select>
                      </div>
                      <div class="col-md-7" id="add_default_value_group" style="display:none;">
                        <input type="text" id="add_default_value" class="form-control form-control-sm" placeholder="Default value (literal)">
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="col-12 mt-2">
              <button type="submit" class="btn btn-success btn-sm">
                <i class="fa-solid fa-floppy-disk"></i> Add
              </button>
            </div>
          </form>
        </div>
      </div>

      <!-- Change type (UI builder) -->
      <div class="card shadow-sm mb-3" id="changeTypeCard" style="display:none;">
        <div class="card-header">
          <strong><i class="fa-solid fa-font"></i> Change Column Type</strong>
        </div>
        <div class="card-body">
          <form method="post" action="<?php echo h($_SERVER['PHP_SELF']); ?>?action=change_type"
                class="row g-2" id="changeTypeForm" onsubmit="return buildChangeTypeColumnType();">
            <?php echo csrf_field(); ?>
            <input type="hidden" name="table" id="changeTypeTable" value="<?php echo h($table); ?>">
            <input type="hidden" name="col_name" id="changeTypeName" value="">
            <input type="hidden" name="col_type" id="changeTypeColType" value="">
            <div class="col-md-4">
              <label class="form-label small">Column</label>
              <input type="text" id="changeTypeNameDisplay" class="form-control form-control-sm" disabled>
            </div>
            <div class="col-md-8">
              <label class="form-label small">New type definition</label>
              <div class="type-builder-group">
                <div class="row g-1">
                  <div class="col-md-4">
                    <select id="ct_type_base" class="form-select form-select-sm" onchange="updateChangeTypeUI();">
                      <option value="INT">INT</option><option value="TINYINT">TINYINT</option><option value="SMALLINT">SMALLINT</option>
                      <option value="MEDIUMINT">MEDIUMINT</option><option value="BIGINT">BIGINT</option>
                      <option value="DECIMAL">DECIMAL</option><option value="FLOAT">FLOAT</option><option value="DOUBLE">DOUBLE</option>
                      <option value="CHAR">CHAR</option><option value="VARCHAR">VARCHAR</option>
                      <option value="TINYTEXT">TINYTEXT</option><option value="TEXT">TEXT</option><option value="MEDIUMTEXT">MEDIUMTEXT</option><option value="LONGTEXT">LONGTEXT</option>
                      <option value="TINYBLOB">TINYBLOB</option><option value="BLOB">BLOB</option><option value="MEDIUMBLOB">MEDIUMBLOB</option><option value="LONGBLOB">LONGBLOB</option>
                      <option value="DATE">DATE</option><option value="DATETIME">DATETIME</option><option value="TIMESTAMP">TIMESTAMP</option>
                      <option value="TIME">TIME</option><option value="YEAR">YEAR</option>
                      <option value="ENUM">ENUM</option><option value="SET">SET</option>
                      <option value="CUSTOM">Custom / raw</option>
                    </select>
                  </div>
                  <div class="col-md-4" id="ct_length_group">
                    <input type="text" id="ct_length" class="form-control form-control-sm" placeholder="Length / M,D (e.g. 255 or 10,2)">
                  </div>
                  <div class="col-md-4" id="ct_enum_group" style="display:none;">
                    <input type="text" id="ct_enum" class="form-control form-control-sm" placeholder="Enum values: one,two,three">
                  </div>
                  <div class="col-12 mt-1" id="ct_custom_group" style="display:none;">
                    <input type="text" id="ct_custom_type" class="form-control form-control-sm" placeholder="Full MySQL type definition" />
                  </div>
                </div>
                <div class="row g-1 mt-1">
                  <div class="col-md-3">
                    <div class="form-check">
                      <input class="form-check-input" type="checkbox" id="ct_nullable">
                      <label class="form-check-label small" for="ct_nullable">Allow NULL</label>
                    </div>
                  </div>
                  <div class="col-md-9">
                    <div class="row g-1">
                      <div class="col-md-5">
                        <select id="ct_default_mode" class="form-select form-select-sm" onchange="updateChangeTypeDefaultUI();">
                          <option value="none" selected>No default</option>
                          <option value="null">DEFAULT NULL</option>
                          <option value="current_timestamp">DEFAULT CURRENT_TIMESTAMP</option>
                          <option value="value">DEFAULT literal value</option>
                        </select>
                      </div>
                      <div class="col-md-7" id="ct_default_value_group" style="display:none;">
                        <input type="text" id="ct_default_value" class="form-control form-control-sm" placeholder="Default value (literal)">
                      </div>
                    </div>
                  </div>
                </div>
                <div class="mt-1">
                  <small class="text-muted">Tip: for complex definitions (UNSIGNED, ZEROFILL, etc.) use “Custom / raw”.</small>
                </div>
              </div>
            </div>

            <div class="col-12 mt-2">
              <button type="submit" class="btn btn-primary btn-sm">
                <i class="fa-solid fa-floppy-disk"></i> Change type
              </button>
              <button type="button" class="btn btn-secondary btn-sm" onclick="document.getElementById('changeTypeCard').style.display='none';">Cancel</button>
            </div>
          </form>
        </div>
      </div>

      <!-- Rename raw -->
      <div class="card shadow-sm" id="renameCard" style="display:none;">
        <div class="card-header">
          <strong><i class="fa-solid fa-i-cursor"></i> Rename / Raw Alter Column</strong>
        </div>
        <div class="card-body">
          <form method="post" action="<?php echo h($_SERVER['PHP_SELF']); ?>?action=rename_column" class="row g-2">
            <?php echo csrf_field(); ?>
            <input type="hidden" name="table" id="renameTable" value="<?php echo h($table); ?>">
            <input type="hidden" name="old_name" id="renameOldName" value="">
            <div class="col-md-4">
              <label class="form-label small">Old Name</label>
              <input type="text" id="renameOldNameDisplay" class="form-control form-control-sm" disabled>
            </div>
            <div class="col-md-4">
              <label class="form-label small">New Name</label>
              <input type="text" name="new_name" id="renameNewName" class="form-control form-control-sm" required>
            </div>
            <div class="col-md-4">
              <label class="form-label small">Full Type (raw)</label>
              <input type="text" name="col_type" id="renameColType" class="form-control form-control-sm" required>
            </div>
            <div class="col-12 mt-2">
              <button type="submit" class="btn btn-primary btn-sm">
                <i class="fa-solid fa-floppy-disk"></i> Apply
              </button>
              <button type="button" class="btn btn-secondary btn-sm" onclick="document.getElementById('renameCard').style.display='none';">Cancel</button>
            </div>
          </form>
        </div>
      </div>
      <?php
    }
  }

endif; ?>
</div>

<script>
function toggleAllTables(flag) {
  var boxes = document.querySelectorAll('.export-table-checkbox');
  boxes.forEach(function(b) { b.checked = !!flag; });
}

// SQL console: show all
function runSqlShowAll() {
  document.getElementById('sql_show_all').value = '1';
  document.getElementById('sqlConsoleForm').submit();
}

function toggleRename(table, field, type) {
  var card = document.getElementById('renameCard');
  document.getElementById('renameOldName').value = field;
  document.getElementById('renameOldNameDisplay').value = field;
  document.getElementById('renameNewName').value = field;
  document.getElementById('renameColType').value = type;
  card.style.display = 'block';
  card.scrollIntoView({behavior:'smooth'});
}

// -------------------------
// Type builder (Add Column)
// -------------------------
function updateAddTypeUI() {
  var base = document.getElementById('add_type_base').value;
  var lenGroup = document.getElementById('add_length_group');
  var enumGroup = document.getElementById('add_enum_group');
  var customGroup = document.getElementById('add_custom_group');

  lenGroup.style.display = 'none';
  enumGroup.style.display = 'none';
  customGroup.style.display = 'none';

  if (base === 'ENUM' || base === 'SET') enumGroup.style.display = 'block';
  if (['CHAR','VARCHAR','DECIMAL','FLOAT','DOUBLE','INT','TINYINT','SMALLINT','MEDIUMINT','BIGINT'].indexOf(base) !== -1) {
    lenGroup.style.display = 'block';
  }
  if (base === 'CUSTOM') customGroup.style.display = 'block';
}

function updateAddDefaultUI() {
  var mode = document.getElementById('add_default_mode').value;
  document.getElementById('add_default_value_group').style.display = (mode === 'value') ? 'block' : 'none';
}

function buildAddColumnType() {
  var base = document.getElementById('add_type_base').value;
  var colTypeInput = document.getElementById('add_col_type');

  if (base === 'CUSTOM') {
    var raw = document.getElementById('add_custom_type').value.trim();
    if (!raw) { alert('Please enter a custom/raw MySQL type definition.'); return false; }
    colTypeInput.value = raw;
    return true;
  }

  var allowLenTypes = {
    'CHAR': true, 'VARCHAR': true,
    'DECIMAL': true, 'FLOAT': true, 'DOUBLE': true,
    'INT': true, 'TINYINT': true, 'SMALLINT': true, 'MEDIUMINT': true, 'BIGINT': true
  };

  var typeDef = base;
  var len = document.getElementById('add_length').value.trim();
  var enumStr = document.getElementById('add_enum').value.trim();
  var nullable = document.getElementById('add_nullable').checked;
  var defMode = document.getElementById('add_default_mode').value;
  var defVal = document.getElementById('add_default_value').value;

  if (base === 'ENUM' || base === 'SET') {
    if (!enumStr) { alert('Please provide values for ' + base + ' (comma separated).'); return false; }
    var parts = enumStr.split(',');
    var vals = [];
    parts.forEach(function(p) {
      var v = p.trim();
      if (!v.length) return;
      v = v.replace(/\\/g, "\\\\").replace(/'/g, "''");
      vals.push("'" + v + "'");
    });
    if (!vals.length) { alert('Please provide at least one non-empty value for ' + base + '.'); return false; }
    typeDef = base + '(' + vals.join(',') + ')';
  } else if (len && allowLenTypes[base]) {
    typeDef = base + '(' + len + ')';
  }

  typeDef += nullable ? ' NULL' : ' NOT NULL';

  if (defMode === 'null') typeDef += ' DEFAULT NULL';
  else if (defMode === 'current_timestamp') typeDef += ' DEFAULT CURRENT_TIMESTAMP';
  else if (defMode === 'value') {
    var v = defVal.replace(/\\/g, "\\\\").replace(/'/g, "''");
    typeDef += " DEFAULT '" + v + "'";
  }

  colTypeInput.value = typeDef;
  return true;
}

// -------------------------
// Type builder (Change Type)
// -------------------------
function updateChangeTypeUI() {
  var base = document.getElementById('ct_type_base').value;
  var lenGroup = document.getElementById('ct_length_group');
  var enumGroup = document.getElementById('ct_enum_group');
  var customGroup = document.getElementById('ct_custom_group');

  lenGroup.style.display = 'none';
  enumGroup.style.display = 'none';
  customGroup.style.display = 'none';

  if (base === 'ENUM' || base === 'SET') enumGroup.style.display = 'block';
  if (['CHAR','VARCHAR','DECIMAL','FLOAT','DOUBLE','INT','TINYINT','SMALLINT','MEDIUMINT','BIGINT'].indexOf(base) !== -1) {
    lenGroup.style.display = 'block';
  }
  if (base === 'CUSTOM') customGroup.style.display = 'block';
}

function updateChangeTypeDefaultUI() {
  var mode = document.getElementById('ct_default_mode').value;
  document.getElementById('ct_default_value_group').style.display = (mode === 'value') ? 'block' : 'none';
}

function buildChangeTypeColumnType() {
  var base = document.getElementById('ct_type_base').value;
  var colTypeInput = document.getElementById('changeTypeColType');

  if (base === 'CUSTOM') {
    var raw = document.getElementById('ct_custom_type').value.trim();
    if (!raw) { alert('Please enter a custom/raw MySQL type definition.'); return false; }
    colTypeInput.value = raw;
    return true;
  }

  var allowLenTypes = {
    'CHAR': true, 'VARCHAR': true,
    'DECIMAL': true, 'FLOAT': true, 'DOUBLE': true,
    'INT': true, 'TINYINT': true, 'SMALLINT': true, 'MEDIUMINT': true, 'BIGINT': true
  };

  var typeDef = base;
  var len = document.getElementById('ct_length').value.trim();
  var enumStr = document.getElementById('ct_enum').value.trim();
  var nullable = document.getElementById('ct_nullable').checked;
  var defMode = document.getElementById('ct_default_mode').value;
  var defVal = document.getElementById('ct_default_value').value;

  if (base === 'ENUM' || base === 'SET') {
    if (!enumStr) { alert('Please provide values for ' + base + ' (comma separated).'); return false; }
    var parts = enumStr.split(',');
    var vals = [];
    parts.forEach(function(p) {
      var v = p.trim();
      if (!v.length) return;
      v = v.replace(/\\/g, "\\\\").replace(/'/g, "''");
      vals.push("'" + v + "'");
    });
    if (!vals.length) { alert('Please provide at least one non-empty value for ' + base + '.'); return false; }
    typeDef = base + '(' + vals.join(',') + ')';
  } else if (len && allowLenTypes[base]) {
    typeDef = base + '(' + len + ')';
  }

  typeDef += nullable ? ' NULL' : ' NOT NULL';

  if (defMode === 'null') typeDef += ' DEFAULT NULL';
  else if (defMode === 'current_timestamp') typeDef += ' DEFAULT CURRENT_TIMESTAMP';
  else if (defMode === 'value') {
    var v = defVal.replace(/\\/g, "\\\\").replace(/'/g, "''");
    typeDef += " DEFAULT '" + v + "'";
  }

  colTypeInput.value = typeDef;
  return true;
}

function toggleChangeType(table, field, type, nullable, defVal) {
  var card = document.getElementById('changeTypeCard');
  document.getElementById('changeTypeName').value = field;
  document.getElementById('changeTypeNameDisplay').value = field;

  document.getElementById('ct_nullable').checked = (nullable === 'YES');

  document.getElementById('ct_default_mode').value = 'none';
  document.getElementById('ct_default_value').value = (defVal || '');
  updateChangeTypeDefaultUI();

  document.getElementById('ct_custom_type').value = type;

  document.getElementById('ct_type_base').value = 'VARCHAR';
  document.getElementById('ct_length').value = '';
  document.getElementById('ct_enum').value = '';
  updateChangeTypeUI();

  card.style.display = 'block';
  card.scrollIntoView({behavior:'smooth'});
}

if (document.getElementById('add_type_base')) { updateAddTypeUI(); updateAddDefaultUI(); }

function b64ToUtf8(b64) {
  try {
    // atob gives a binary string; decode to UTF-8 properly
    return decodeURIComponent(Array.prototype.map.call(atob(b64), function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
  } catch(e) {
    // fallback: atob only
    try { return atob(b64); } catch(_) { return ''; }
  }
}

document.addEventListener('click', function(e) {
  var btn = e.target.closest('.js-change-type');
  if (!btn) return;

  var table = btn.dataset.table || '';
  var field = btn.dataset.field || '';
  var type = b64ToUtf8(btn.dataset.typeB64 || '');
  var nullable = btn.dataset.nullable || '';
  var defVal = b64ToUtf8(btn.dataset.defaultB64 || '');

  toggleChangeType(table, field, type, nullable, defVal);
});
document.addEventListener('click', function(e) {
  var btn = e.target.closest('.js-rename-col');
  if (!btn) return;

  var table = btn.dataset.table || '';
  var field = btn.dataset.field || '';
  var type  = b64ToUtf8(btn.dataset.typeB64 || '');

  toggleRename(table, field, type);
});

</script>

</body>
</html>
