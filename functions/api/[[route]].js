// ============================================================
// TIMBR - Complete Backend API
// Single file: functions/api/[[route]].js
// ============================================================

// --- Crypto Helpers ---
async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function signToken(payload) {
  const encoder = new TextEncoder();
  const secret = encoder.encode('timbr-jwt-secret-key-2024-production');
  const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const header = { alg: 'HS256', typ: 'JWT' };
  const header64 = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const payload64 = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const message = encoder.encode(`${header64}.${payload64}`);
  const signature = await crypto.subtle.sign('HMAC', key, message);
  const signature64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${header64}.${payload64}.${signature64}`;
}

async function verifyToken(token) {
  try {
    const encoder = new TextEncoder();
    const secret = encoder.encode('timbr-jwt-secret-key-2024-production');
    const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header64, payload64, signature64] = parts;
    const message = encoder.encode(`${header64}.${payload64}`);
    const sigStr = signature64.replace(/-/g, '+').replace(/_/g, '/');
    const signature = Uint8Array.from(atob(sigStr), c => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify('HMAC', key, signature, message);
    if (!isValid) return null;
    const payloadStr = payload64.replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(atob(payloadStr));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

// --- Response Helpers ---
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

async function getUser(request) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const payload = await verifyToken(token);
  return payload;
}

// --- Database Setup ---
async function ensureTables(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'student',
      approved INTEGER DEFAULT 0,
      blocked INTEGER DEFAULT 0,
      device_fingerprint TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS study_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      subject TEXT NOT NULL,
      planned_start TEXT,
      planned_end TEXT,
      study_date TEXT NOT NULL,
      actual_start TEXT,
      actual_end TEXT,
      lost_minutes INTEGER DEFAULT 0,
      lost_reason TEXT,
      note TEXT,
      status TEXT DEFAULT 'Planned',
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS study_tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      subject TEXT NOT NULL,
      completed INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      message TEXT,
      type TEXT DEFAULT 'Info',
      image_url TEXT,
      button_url TEXT,
      button_text TEXT,
      pinned INTEGER DEFAULT 0,
      active INTEGER DEFAULT 1,
      popup INTEGER DEFAULT 0,
      banner INTEGER DEFAULT 0,
      audience TEXT DEFAULT 'Everyone',
      start_date TEXT,
      end_date TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS notification_reads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      notification_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      read_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (notification_id) REFERENCES notifications(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      action TEXT NOT NULL,
      details TEXT,
      performed_by INTEGER,
      target_user INTEGER,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `).run();

  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON study_sessions(user_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_date ON study_sessions(study_date)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_status ON study_sessions(status)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_tasks_user ON study_tasks(user_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_notif_reads ON notification_reads(notification_id, user_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_audit_logs ON audit_logs(created_at)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`).run();

  const adminHash = await sha256('ADMIN123');
  await db.prepare(`
    INSERT OR IGNORE INTO users (username, name, email, password_hash, role, approved, blocked)
    VALUES ('admin', 'Admin', 'text.me.md.alamin@gmail.com', ?, 'admin', 1, 0)
  `).bind(adminHash).run();

  await db.prepare(`
    INSERT OR IGNORE INTO settings (key, value) VALUES ('master_key', 'timbr-master-2024')
  `).run();
}

async function runMigrations(db) {
  const migrations = [
    "ALTER TABLE users ADD COLUMN device_fingerprint TEXT",
    "ALTER TABLE study_sessions ADD COLUMN actual_start TEXT",
    "ALTER TABLE study_sessions ADD COLUMN actual_end TEXT",
    "ALTER TABLE notifications ADD COLUMN image_url TEXT",
    "ALTER TABLE notifications ADD COLUMN button_url TEXT",
    "ALTER TABLE notifications ADD COLUMN button_text TEXT",
    "ALTER TABLE notifications ADD COLUMN popup INTEGER DEFAULT 0",
    "ALTER TABLE notifications ADD COLUMN banner INTEGER DEFAULT 0",
    "ALTER TABLE notifications ADD COLUMN start_date TEXT",
    "ALTER TABLE notifications ADD COLUMN end_date TEXT"
  ];
  for (const sql of migrations) {
    try { await db.prepare(sql).run(); } catch {}
  }
}

// ============================================================
// ROUTE HANDLERS
// ============================================================

async function handleAuth(method, path, body, db) {
  if (method === 'POST' && path === '/auth/register') {
    const { username, name, email, password, device_fingerprint } = body;
    if (!username || !name || !email || !password) return err('All fields required', 400);
    if (device_fingerprint) {
      const existing = await db.prepare('SELECT id FROM users WHERE device_fingerprint = ?').bind(device_fingerprint).first();
      if (existing) return err('An account already exists on this device', 400);
    }
    const existingUser = await db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').bind(username, email).first();
    if (existingUser) return err('Username or email already exists', 400);
    const hash = await sha256(password);
    const result = await db.prepare(
      'INSERT INTO users (username, name, email, password_hash, device_fingerprint, approved) VALUES (?, ?, ?, ?, ?, 0)'
    ).bind(username, name, email, hash, device_fingerprint || null).run();
    await db.prepare('INSERT INTO audit_logs (action, details, target_user) VALUES (?, ?, ?)')
      .bind('User registered', `Username: ${username}`, result.meta.last_row_id).run();
    return json({ message: 'Registration successful. Awaiting approval.' }, 201);
  }

  if (method === 'POST' && path === '/auth/login') {
    const { email, password } = body;
    if (!email || !password) return err('Email and password required', 400);
    const user = await db.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
    if (!user) return err('Invalid credentials', 401);
    if (user.blocked) return err('Account is blocked. Contact admin.', 403);
    if (!user.approved) return err('Account not yet approved. Please wait.', 403);
    const hash = await sha256(password);
    if (hash !== user.password_hash) return err('Invalid credentials', 401);
    const token = await signToken({
      id: user.id, username: user.username, email: user.email, role: user.role,
      exp: Date.now() + 30 * 24 * 60 * 60 * 1000
    });
    return json({
      token,
      user: { id: user.id, username: user.username, name: user.name, email: user.email, role: user.role }
    });
  }

  if (method === 'POST' && path === '/auth/verify-master-key') {
    const { key } = body;
    const setting = await db.prepare("SELECT value FROM settings WHERE key = 'master_key'").first();
    if (!setting || key !== setting.value) return err('Invalid master key', 403);
    const token = await signToken({ master: true, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 });
    return json({ token });
  }

  if (method === 'PUT' && path === '/auth/change-master-key') {
    const payload = await verifyToken(body.master_token);
    if (!payload || !payload.master) return err('Master access required', 403);
    if (!body.new_key) return err('New key required', 400);
    await db.prepare("UPDATE settings SET value = ? WHERE key = 'master_key'").bind(body.new_key).run();
    return json({ message: 'Master key updated' });
  }

  return err('Auth route not found', 404);
}

async function handleUser(method, path, body, db, user) {
  const userId = user.id;

  if (method === 'GET' && path === '/user/profile') {
    const profile = await db.prepare('SELECT id, username, name, email, role, approved, blocked, created_at FROM users WHERE id = ?').bind(userId).first();
    if (!profile) return err('User not found', 404);
    return json(profile);
  }

  if (method === 'PUT' && path === '/user/profile') {
    const { name, username } = body;
    if (username) {
      const existing = await db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').bind(username, userId).first();
      if (existing) return err('Username already taken', 400);
    }
    await db.prepare('UPDATE users SET name = COALESCE(?, name), username = COALESCE(?, username) WHERE id = ?')
      .bind(name || null, username || null, userId).run();
    return json({ message: 'Profile updated' });
  }

  if (method === 'PUT' && path === '/user/change-password') {
    const { oldPassword, newPassword } = body;
    if (!oldPassword || !newPassword) return err('Both passwords required', 400);
    const profile = await db.prepare('SELECT password_hash FROM users WHERE id = ?').bind(userId).first();
    const oldHash = await sha256(oldPassword);
    if (oldHash !== profile.password_hash) return err('Current password incorrect', 400);
    const newHash = await sha256(newPassword);
    await db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(newHash, userId).run();
    return json({ message: 'Password changed' });
  }

  if (method === 'GET' && path === '/user/dashboard') {
    const today = new Date().toISOString().split('T')[0];
    const todaySessions = await db.prepare(
      "SELECT * FROM study_sessions WHERE user_id = ? AND study_date = ? ORDER BY created_at DESC"
    ).bind(userId, today).all();
    const recentSessions = await db.prepare(
      "SELECT * FROM study_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10"
    ).bind(userId).all();
    const notifications = await db.prepare(`
      SELECT n.*, CASE WHEN nr.id IS NOT NULL THEN 1 ELSE 0 END as is_read
      FROM notifications n
      LEFT JOIN notification_reads nr ON n.id = nr.notification_id AND nr.user_id = ?
      WHERE n.active = 1 
        AND (n.audience = 'Everyone' OR n.audience = 'Students')
        AND (n.start_date IS NULL OR n.start_date <= datetime('now'))
        AND (n.end_date IS NULL OR n.end_date >= datetime('now'))
      ORDER BY n.pinned DESC, n.created_at DESC LIMIT 5
    `).bind(userId).all();
    const weekStart = new Date();
    weekStart.setDate(weekStart.getDate() - weekStart.getDay());
    const weekStartStr = weekStart.toISOString().split('T')[0];
    const weeklyStats = await db.prepare(`
      SELECT 
        COUNT(*) as total_sessions,
        SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) as completed_sessions,
        COALESCE(SUM(CASE WHEN actual_end IS NOT NULL AND actual_start IS NOT NULL
          THEN (strftime('%s', actual_end) - strftime('%s', actual_start)) / 60.0 - COALESCE(lost_minutes, 0)
          ELSE 0 END), 0) as total_minutes
      FROM study_sessions WHERE user_id = ? AND study_date >= ?
    `).bind(userId, weekStartStr).first();
    return json({
      today_sessions: todaySessions.results,
      recent_sessions: recentSessions.results,
      notifications: notifications.results,
      weekly_stats: weeklyStats
    });
  }

  if (method === 'GET' && path === '/user/backup') {
    const sessions = await db.prepare('SELECT * FROM study_sessions WHERE user_id = ? ORDER BY created_at').bind(userId).all();
    const tasks = await db.prepare('SELECT * FROM study_tasks WHERE user_id = ? ORDER BY created_at').bind(userId).all();
    const profile = await db.prepare('SELECT username, name, email, created_at FROM users WHERE id = ?').bind(userId).first();
    let txt = `TIMBR - STUDY BACKUP\nGenerated: ${new Date().toISOString()}\n${'='.repeat(50)}\n\n`;
    txt += `PROFILE\n${'-'.repeat(30)}\nUsername: ${profile.username}\nName: ${profile.name}\nEmail: ${profile.email}\nJoined: ${profile.created_at}\n\n`;
    txt += `STUDY SESSIONS (${sessions.results.length})\n${'-'.repeat(30)}\n`;
    for (const s of sessions.results) {
      txt += `Title: ${s.title}\nSubject: ${s.subject}\nDate: ${s.study_date}\nStatus: ${s.status}\n`;
      if (s.actual_start && s.actual_end) {
        const mins = (new Date(s.actual_end) - new Date(s.actual_start)) / 60000 - (s.lost_minutes || 0);
        txt += `Actual Minutes: ${Math.round(mins)}\n`;
      }
      txt += `${'-'.repeat(20)}\n`;
    }
    txt += `\nTASKS (${tasks.results.length})\n${'-'.repeat(30)}\n`;
    for (const t of tasks.results) {
      txt += `[${t.completed ? '✓' : ' '}] ${t.title} (${t.subject})\n`;
    }
    return new Response(txt, {
      headers: { ...corsHeaders, 'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename="timbr-backup.txt"' }
    });
  }

  return err('User route not found', 404);
}

async function handleSessions(method, path, body, db, user) {
  const userId = user.id;
  const sessionMatch = path.match(/^\/sessions\/(\d+)$/);
  
  if (method === 'GET' && path === '/sessions') {
    const date = body.date || null;
    const subject = body.subject || null;
    const status = body.status || null;
    const page = parseInt(body.page) || 1;
    const limit = parseInt(body.limit) || 20;
    
    let whereClause = 'WHERE user_id = ?';
    const params = [userId];
    if (date) { whereClause += ' AND study_date = ?'; params.push(date); }
    if (subject) { whereClause += ' AND subject = ?'; params.push(subject); }
    if (status) { whereClause += ' AND status = ?'; params.push(status); }
    
    const countResult = await db.prepare(`SELECT COUNT(*) as count FROM study_sessions ${whereClause}`).bind(...params).first();
    const sql = `SELECT * FROM study_sessions ${whereClause} ORDER BY study_date DESC, created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, (page - 1) * limit);
    const sessions = await db.prepare(sql).bind(...params).all();
    
    return json({ sessions: sessions.results, total: countResult.count, page, limit });
  }

  if (method === 'POST' && path === '/sessions') {
    const { title, subject, planned_start, planned_end, study_date, note, status } = body;
    if (!title || !subject || !study_date) return err('Title, subject, and date required', 400);
    const result = await db.prepare(
      'INSERT INTO study_sessions (user_id, title, subject, planned_start, planned_end, study_date, note, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(userId, title, subject, planned_start || null, planned_end || null, study_date, note || null, status || 'Planned').run();
    return json({ id: result.meta.last_row_id, message: 'Session created' }, 201);
  }

  if (method === 'GET' && sessionMatch) {
    const session = await db.prepare('SELECT * FROM study_sessions WHERE id = ? AND user_id = ?').bind(sessionMatch[1], userId).first();
    if (!session) return err('Session not found', 404);
    return json(session);
  }

  if (method === 'PUT' && sessionMatch) {
    const id = sessionMatch[1];
    const existing = await db.prepare('SELECT id FROM study_sessions WHERE id = ? AND user_id = ?').bind(id, userId).first();
    if (!existing) return err('Session not found', 404);
    const { title, subject, planned_start, planned_end, study_date, actual_start, actual_end, lost_minutes, lost_reason, note, status } = body;
    await db.prepare(`
      UPDATE study_sessions SET 
        title = COALESCE(?, title), subject = COALESCE(?, subject),
        planned_start = COALESCE(?, planned_start), planned_end = COALESCE(?, planned_end),
        study_date = COALESCE(?, study_date), actual_start = COALESCE(?, actual_start),
        actual_end = COALESCE(?, actual_end), lost_minutes = COALESCE(?, lost_minutes),
        lost_reason = COALESCE(?, lost_reason), note = COALESCE(?, note), status = COALESCE(?, status)
      WHERE id = ? AND user_id = ?
    `).bind(title, subject, planned_start, planned_end, study_date, actual_start, actual_end, lost_minutes, lost_reason, note, status, id, userId).run();
    return json({ message: 'Session updated' });
  }

  if (method === 'DELETE' && sessionMatch) {
    await db.prepare('DELETE FROM study_sessions WHERE id = ? AND user_id = ?').bind(sessionMatch[1], userId).run();
    return json({ message: 'Session deleted' });
  }

  return err('Session route not found', 404);
}

async function handleTasks(method, path, body, db, user) {
  const userId = user.id;
  const taskMatch = path.match(/^\/tasks\/(\d+)$/);
  
  if (method === 'GET' && path === '/tasks') {
    const tasks = await db.prepare('SELECT * FROM study_tasks WHERE user_id = ? ORDER BY completed ASC, created_at DESC').bind(userId).all();
    return json(tasks.results);
  }
  if (method === 'POST' && path === '/tasks') {
    const { title, subject } = body;
    if (!title || !subject) return err('Title and subject required', 400);
    const result = await db.prepare('INSERT INTO study_tasks (user_id, title, subject) VALUES (?, ?, ?)').bind(userId, title, subject).run();
    return json({ id: result.meta.last_row_id, message: 'Task created' }, 201);
  }
  if (method === 'PUT' && taskMatch) {
    const { title, subject, completed } = body;
    await db.prepare('UPDATE study_tasks SET title = COALESCE(?, title), subject = COALESCE(?, subject), completed = COALESCE(?, completed) WHERE id = ? AND user_id = ?')
      .bind(title || null, subject || null, completed !== undefined ? completed : null, taskMatch[1], userId).run();
    return json({ message: 'Task updated' });
  }
  if (method === 'DELETE' && taskMatch) {
    await db.prepare('DELETE FROM study_tasks WHERE id = ? AND user_id = ?').bind(taskMatch[1], userId).run();
    return json({ message: 'Task deleted' });
  }
  return err('Task route not found', 404);
}

async function handleNotifications(method, path, body, db, user) {
  const userId = user.id;
  const notifMatch = path.match(/^\/notifications\/(\d+)\/read$/);
  
  if (method === 'GET' && path === '/notifications') {
    const notifications = await db.prepare(`
      SELECT n.*, CASE WHEN nr.id IS NOT NULL THEN 1 ELSE 0 END as is_read
      FROM notifications n
      LEFT JOIN notification_reads nr ON n.id = nr.notification_id AND nr.user_id = ?
      WHERE n.active = 1 
        AND (n.audience = 'Everyone' OR n.audience = 'Students' OR n.audience = 'Admins')
        AND (n.start_date IS NULL OR n.start_date <= datetime('now'))
        AND (n.end_date IS NULL OR n.end_date >= datetime('now'))
      ORDER BY n.pinned DESC, n.created_at DESC
    `).bind(userId).all();
    return json(notifications.results);
  }
  if (method === 'GET' && path === '/notifications/unread-count') {
    const result = await db.prepare(`
      SELECT COUNT(*) as count FROM notifications n
      LEFT JOIN notification_reads nr ON n.id = nr.notification_id AND nr.user_id = ?
      WHERE n.active = 1 AND nr.id IS NULL
        AND (n.audience = 'Everyone' OR n.audience = 'Students' OR n.audience = 'Admins')
        AND (n.start_date IS NULL OR n.start_date <= datetime('now'))
        AND (n.end_date IS NULL OR n.end_date >= datetime('now'))
    `).bind(userId).first();
    return json({ count: result.count });
  }
  if (method === 'POST' && notifMatch) {
    await db.prepare('INSERT OR IGNORE INTO notification_reads (notification_id, user_id) VALUES (?, ?)')
      .bind(notifMatch[1], userId).run();
    return json({ message: 'Marked as read' });
  }
  return err('Notification route not found', 404);
}

async function handleStats(method, path, body, db, user) {
  const userId = user.id;
  
  if (method === 'GET' && path === '/stats/daily') {
    const targetDate = body.date || new Date().toISOString().split('T')[0];
    const stats = await db.prepare(`
      SELECT subject, COUNT(*) as session_count,
        SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) as completed,
        SUM(CASE WHEN status = 'Partial' THEN 1 ELSE 0 END) as partial,
        SUM(CASE WHEN status = 'Missed' THEN 1 ELSE 0 END) as missed,
        COALESCE(SUM(CASE WHEN actual_end IS NOT NULL AND actual_start IS NOT NULL
          THEN (strftime('%s', actual_end) - strftime('%s', actual_start)) / 60.0 - COALESCE(lost_minutes, 0)
          ELSE 0 END), 0) as actual_minutes,
        COALESCE(SUM(lost_minutes), 0) as lost_minutes
      FROM study_sessions WHERE user_id = ? AND study_date = ? GROUP BY subject
    `).bind(userId, targetDate).all();
    return json({ date: targetDate, stats: stats.results });
  }
  if (method === 'GET' && path === '/stats/weekly') {
    const weekStart = new Date(); weekStart.setDate(weekStart.getDate() - weekStart.getDay());
    const weekStartStr = weekStart.toISOString().split('T')[0];
    const stats = await db.prepare(`
      SELECT study_date, COUNT(*) as session_count,
        SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) as completed,
        COALESCE(SUM(CASE WHEN actual_end IS NOT NULL AND actual_start IS NOT NULL
          THEN (strftime('%s', actual_end) - strftime('%s', actual_start)) / 60.0 - COALESCE(lost_minutes, 0)
          ELSE 0 END), 0) as actual_minutes,
        COALESCE(SUM(lost_minutes), 0) as lost_minutes
      FROM study_sessions WHERE user_id = ? AND study_date >= ? GROUP BY study_date ORDER BY study_date
    `).bind(userId, weekStartStr).all();
    return json({ week_start: weekStartStr, stats: stats.results });
  }
  if (method === 'GET' && path === '/stats/monthly') {
    const monthStart = new Date(); monthStart.setDate(1);
    const monthStartStr = monthStart.toISOString().split('T')[0];
    const stats = await db.prepare(`
      SELECT subject, COUNT(*) as session_count,
        SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) as completed,
        COALESCE(SUM(CASE WHEN actual_end IS NOT NULL AND actual_start IS NOT NULL
          THEN (strftime('%s', actual_end) - strftime('%s', actual_start)) / 60.0 - COALESCE(lost_minutes, 0)
          ELSE 0 END), 0) as actual_minutes
      FROM study_sessions WHERE user_id = ? AND study_date >= ? GROUP BY subject
    `).bind(userId, monthStartStr).all();
    return json({ month_start: monthStartStr, stats: stats.results });
  }
  if (method === 'GET' && path === '/stats/subject-distribution') {
    const stats = await db.prepare(`
      SELECT subject, COUNT(*) as total_sessions,
        COALESCE(SUM(CASE WHEN actual_end IS NOT NULL AND actual_start IS NOT NULL
          THEN (strftime('%s', actual_end) - strftime('%s', actual_start)) / 60.0 - COALESCE(lost_minutes, 0)
          ELSE 0 END), 0) as total_minutes
      FROM study_sessions WHERE user_id = ? GROUP BY subject ORDER BY total_minutes DESC
    `).bind(userId).all();
    return json(stats.results);
  }
  return err('Stats route not found', 404);
}

// ============================================================
// FIXED: Leaderboard - ALL approved users (admin + student)
// ============================================================
async function handleLeaderboard(method, path, body, db, user) {
  if (method === 'GET' && path === '/leaderboard') {
    const period = body.period || 'today';
    let dateFilter = '';
    
    if (period === 'today') {
      const today = new Date().toISOString().split('T')[0];
      dateFilter = `AND s.study_date = '${today}'`;
    } else if (period === 'week') {
      const ws = new Date(); ws.setDate(ws.getDate() - ws.getDay());
      dateFilter = `AND s.study_date >= '${ws.toISOString().split('T')[0]}'`;
    } else if (period === 'month') {
      const ms = new Date(); ms.setDate(1);
      dateFilter = `AND s.study_date >= '${ms.toISOString().split('T')[0]}'`;
    }
    
    // FIXED: Include ALL approved, non-blocked users regardless of role
    const leaderboard = await db.prepare(`
      SELECT 
        u.id, u.username, u.name, u.role,
        COUNT(s.id) as session_count,
        COALESCE(SUM(CASE WHEN s.actual_end IS NOT NULL AND s.actual_start IS NOT NULL
          THEN (strftime('%s', s.actual_end) - strftime('%s', s.actual_start)) / 60.0 - COALESCE(s.lost_minutes, 0)
          ELSE 0 END), 0) as total_minutes,
        ROUND(COALESCE(SUM(CASE WHEN s.actual_end IS NOT NULL AND s.actual_start IS NOT NULL
          THEN (strftime('%s', s.actual_end) - strftime('%s', s.actual_start)) / 3600.0 - COALESCE(s.lost_minutes, 0)/60.0
          ELSE 0 END), 0), 1) as total_hours
      FROM users u
      LEFT JOIN study_sessions s ON u.id = s.user_id ${dateFilter} AND s.status = 'Completed'
      WHERE u.approved = 1 AND u.blocked = 0
      GROUP BY u.id
      HAVING total_minutes > 0
      ORDER BY total_minutes DESC
      LIMIT 50
    `).all();
    
    return json({ period, leaderboard: leaderboard.results });
  }
  return err('Leaderboard route not found', 404);
}

// ============================================================
// FIXED: Admin routes
// ============================================================
async function handleAdmin(method, path, body, db, user) {
  if (user.role !== 'admin') return err('Admin access required', 403);
  
  // FIXED: Dashboard - include all users with study data
  if (method === 'GET' && path === '/admin/dashboard') {
    const totalUsers = await db.prepare('SELECT COUNT(*) as count FROM users').first();
    const approvedUsers = await db.prepare('SELECT COUNT(*) as count FROM users WHERE approved = 1 AND blocked = 0').first();
    const pendingUsers = await db.prepare('SELECT COUNT(*) as count FROM users WHERE approved = 0 AND blocked = 0').first();
    const blockedUsers = await db.prepare('SELECT COUNT(*) as count FROM users WHERE blocked = 1').first();
    const totalSessions = await db.prepare('SELECT COUNT(*) as count FROM study_sessions').first();
    const totalHours = await db.prepare(`
      SELECT COALESCE(SUM(CASE WHEN actual_end IS NOT NULL AND actual_start IS NOT NULL
        THEN (strftime('%s', actual_end) - strftime('%s', actual_start)) / 3600.0 - COALESCE(lost_minutes, 0)/60.0
        ELSE 0 END), 0) as hours
      FROM study_sessions WHERE status = 'Completed'
    `).first();
    
    // FIXED: Top users - all approved, non-blocked with study hours > 0
    const topUsers = await db.prepare(`
      SELECT u.username, u.name, u.role,
        ROUND(COALESCE(SUM(CASE WHEN s.actual_end IS NOT NULL AND s.actual_start IS NOT NULL
          THEN (strftime('%s', s.actual_end) - strftime('%s', s.actual_start)) / 3600.0 - COALESCE(s.lost_minutes, 0)/60.0
          ELSE 0 END), 0), 1) as total_hours
      FROM users u
      LEFT JOIN study_sessions s ON u.id = s.user_id AND s.status = 'Completed'
      WHERE u.approved = 1 AND u.blocked = 0
      GROUP BY u.id
      HAVING total_hours > 0
      ORDER BY total_hours DESC LIMIT 10
    `).all();
    
    return json({
      total_users: totalUsers.count,
      approved_users: approvedUsers.count,
      pending_users: pendingUsers.count,
      blocked_users: blockedUsers.count,
      total_sessions: totalSessions.count,
      total_hours: Math.round(totalHours.hours * 10) / 10,
      top_users: topUsers.results
    });
  }

  // Users list
  if (method === 'GET' && path === '/admin/users') {
    const search = body.search || null;
    const role = body.role || null;
    const status = body.status || null;
    const page = parseInt(body.page) || 1;
    const limit = parseInt(body.limit) || 15;
    
    let whereParts = [];
    const params = [];
    if (search) { whereParts.push('(username LIKE ? OR email LIKE ? OR name LIKE ?)'); params.push(`%${search}%`, `%${search}%`, `%${search}%`); }
    if (role) { whereParts.push('role = ?'); params.push(role); }
    if (status === 'pending') { whereParts.push('approved = 0 AND blocked = 0'); }
    else if (status === 'approved') { whereParts.push('approved = 1 AND blocked = 0'); }
    else if (status === 'blocked') { whereParts.push('blocked = 1'); }
    
    const whereClause = whereParts.length > 0 ? 'WHERE ' + whereParts.join(' AND ') : '';
    const countResult = await db.prepare(`SELECT COUNT(*) as count FROM users ${whereClause}`).bind(...params).first();
    const dataSql = `SELECT id, username, name, email, role, approved, blocked, created_at FROM users ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    const dataParams = [...params, limit, (page - 1) * limit];
    const users = await db.prepare(dataSql).bind(...dataParams).all();
    return json({ users: users.results, total: countResult.count, page, limit });
  }

  // Approve
  const approveMatch = path.match(/^\/admin\/users\/(\d+)\/approve$/);
  if (method === 'PUT' && approveMatch) {
    await db.prepare('UPDATE users SET approved = 1 WHERE id = ?').bind(approveMatch[1]).run();
    await db.prepare('INSERT INTO audit_logs (action, details, performed_by, target_user) VALUES (?, ?, ?, ?)')
      .bind('User approved', '', user.id, approveMatch[1]).run();
    return json({ message: 'User approved' });
  }

  // Block
  const blockMatch = path.match(/^\/admin\/users\/(\d+)\/block$/);
  if (method === 'PUT' && blockMatch) {
    await db.prepare('UPDATE users SET blocked = 1 WHERE id = ?').bind(blockMatch[1]).run();
    await db.prepare('INSERT INTO audit_logs (action, details, performed_by, target_user) VALUES (?, ?, ?, ?)')
      .bind('User blocked', '', user.id, blockMatch[1]).run();
    return json({ message: 'User blocked' });
  }

  // Unblock
  const unblockMatch = path.match(/^\/admin\/users\/(\d+)\/unblock$/);
  if (method === 'PUT' && unblockMatch) {
    await db.prepare('UPDATE users SET blocked = 0 WHERE id = ?').bind(unblockMatch[1]).run();
    await db.prepare('INSERT INTO audit_logs (action, details, performed_by, target_user) VALUES (?, ?, ?, ?)')
      .bind('User unblocked', '', user.id, unblockMatch[1]).run();
    return json({ message: 'User unblocked' });
  }

  // Reset
  const resetMatch = path.match(/^\/admin\/users\/(\d+)\/reset$/);
  if (method === 'PUT' && resetMatch) {
    await db.prepare('DELETE FROM study_sessions WHERE user_id = ?').bind(resetMatch[1]).run();
    await db.prepare('DELETE FROM study_tasks WHERE user_id = ?').bind(resetMatch[1]).run();
    await db.prepare('INSERT INTO audit_logs (action, details, performed_by, target_user) VALUES (?, ?, ?, ?)')
      .bind('Study data reset', '', user.id, resetMatch[1]).run();
    return json({ message: 'Study data reset' });
  }

  // Delete user
  const deleteUserMatch = path.match(/^\/admin\/users\/(\d+)$/);
  if (method === 'DELETE' && deleteUserMatch) {
    const targetId = deleteUserMatch[1];
    await db.prepare('DELETE FROM notification_reads WHERE user_id = ?').bind(targetId).run();
    await db.prepare('DELETE FROM study_sessions WHERE user_id = ?').bind(targetId).run();
    await db.prepare('DELETE FROM study_tasks WHERE user_id = ?').bind(targetId).run();
    await db.prepare('DELETE FROM users WHERE id = ?').bind(targetId).run();
    await db.prepare('INSERT INTO audit_logs (action, details, performed_by, target_user) VALUES (?, ?, ?, ?)')
      .bind('User deleted', '', user.id, targetId).run();
    return json({ message: 'User deleted' });
  }

  // Create user
  if (method === 'POST' && path === '/admin/users') {
    const { username, name, email, password, role } = body;
    if (!username || !name || !email || !password) return err('All fields required', 400);
    const hash = await sha256(password);
    const result = await db.prepare(
      'INSERT INTO users (username, name, email, password_hash, role, approved, blocked) VALUES (?, ?, ?, ?, ?, 1, 0)'
    ).bind(username, name, email, hash, role || 'student').run();
    await db.prepare('INSERT INTO audit_logs (action, details, performed_by, target_user) VALUES (?, ?, ?, ?)')
      .bind('Admin created user', `Username: ${username}`, user.id, result.meta.last_row_id).run();
    return json({ id: result.meta.last_row_id, message: 'User created' }, 201);
  }

  // Create notification
  if (method === 'POST' && path === '/admin/notifications') {
    const { title, message, type, image_url, button_url, button_text, pinned, active, popup, banner, audience, start_date, end_date } = body;
    if (!title) return err('Title required', 400);
    const result = await db.prepare(
      'INSERT INTO notifications (title, message, type, image_url, button_url, button_text, pinned, active, popup, banner, audience, start_date, end_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(title, message, type || 'Info', image_url, button_url, button_text, pinned ? 1 : 0, active !== undefined ? (active ? 1 : 0) : 1, popup ? 1 : 0, banner ? 1 : 0, audience || 'Everyone', start_date, end_date).run();
    await db.prepare('INSERT INTO audit_logs (action, details, performed_by) VALUES (?, ?, ?)')
      .bind('Notification created', `Title: ${title}`, user.id).run();
    return json({ id: result.meta.last_row_id }, 201);
  }

  // Update notification
  const notifEditMatch = path.match(/^\/admin\/notifications\/(\d+)$/);
  if (method === 'PUT' && notifEditMatch) {
    const { title, message, type, image_url, button_url, button_text, pinned, active, popup, banner, audience, start_date, end_date } = body;
    await db.prepare(`
      UPDATE notifications SET title=COALESCE(?,title), message=COALESCE(?,message), type=COALESCE(?,type),
      image_url=COALESCE(?,image_url), button_url=COALESCE(?,button_url), button_text=COALESCE(?,button_text),
      pinned=COALESCE(?,pinned), active=COALESCE(?,active), popup=COALESCE(?,popup), banner=COALESCE(?,banner),
      audience=COALESCE(?,audience), start_date=COALESCE(?,start_date), end_date=COALESCE(?,end_date)
      WHERE id=?
    `).bind(title, message, type, image_url, button_url, button_text, pinned, active, popup, banner, audience, start_date, end_date, notifEditMatch[1]).run();
    return json({ message: 'Notification updated' });
  }

  // Delete notification
  const notifDelMatch = path.match(/^\/admin\/notifications\/(\d+)\/delete$/);
  if (method === 'DELETE' && notifDelMatch) {
    await db.prepare('DELETE FROM notification_reads WHERE notification_id = ?').bind(notifDelMatch[1]).run();
    await db.prepare('DELETE FROM notifications WHERE id = ?').bind(notifDelMatch[1]).run();
    await db.prepare('INSERT INTO audit_logs (action, details, performed_by) VALUES (?, ?, ?)')
      .bind('Notification deleted', '', user.id).run();
    return json({ message: 'Notification deleted' });
  }

  // Audit logs
  if (method === 'GET' && path === '/admin/audit-logs') {
    const logs = await db.prepare(`
      SELECT al.*, u.username as performer_name
      FROM audit_logs al LEFT JOIN users u ON al.performed_by = u.id
      ORDER BY al.created_at DESC LIMIT 100
    `).all();
    return json(logs.results);
  }

  // Settings
  if (method === 'GET' && path === '/admin/settings') {
    const settings = await db.prepare("SELECT * FROM settings WHERE key != 'master_key'").all();
    return json(settings.results);
  }

  if (method === 'PUT' && path === '/admin/settings') {
    const { site_name, announcement } = body;
    if (site_name) await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('site_name', ?)").bind(site_name).run();
    if (announcement !== undefined) await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('announcement', ?)").bind(announcement).run();
    await db.prepare('INSERT INTO audit_logs (action, details, performed_by) VALUES (?, ?, ?)')
      .bind('Settings changed', JSON.stringify(body), user.id).run();
    return json({ message: 'Settings updated' });
  }

  return err('Admin route not found', 404);
}

// ============================================================
// MAIN ROUTER
// ============================================================
export async function onRequest(context) {
  const { request, env } = context;
  const db = env.STUDY_DB;
  const url = new URL(request.url);
  const method = request.method;
  let path = url.pathname.replace('/api', '');
  
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  
  if (!globalThis.__tablesReady) {
    await ensureTables(db);
    await runMigrations(db);
    globalThis.__tablesReady = true;
  }
  
  let body = {};
  if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
    try {
      const contentType = request.headers.get('Content-Type') || '';
      if (contentType.includes('application/json')) {
        body = await request.json();
      } else {
        const text = await request.text();
        try { body = JSON.parse(text); } catch { body = {}; }
      }
    } catch { body = {}; }
  }
  
  if (method === 'GET' || method === 'DELETE') {
    for (const [key, value] of url.searchParams) {
      body[key] = value;
    }
  }
  
  try {
    if (path.startsWith('/auth')) return handleAuth(method, path, body, db);
    
    const authUser = await getUser(request);
    if (!authUser) return err('Authentication required', 401);
    
    if (path.startsWith('/user')) return handleUser(method, path, body, db, authUser);
    if (path.startsWith('/sessions')) return handleSessions(method, path, body, db, authUser);
    if (path.startsWith('/tasks')) return handleTasks(method, path, body, db, authUser);
    if (path.startsWith('/notifications')) return handleNotifications(method, path, body, db, authUser);
    if (path.startsWith('/stats')) return handleStats(method, path, body, db, authUser);
    if (path.startsWith('/leaderboard')) return handleLeaderboard(method, path, body, db, authUser);
    if (path.startsWith('/admin')) return handleAdmin(method, path, body, db, authUser);
    
    return err('Route not found', 404);
  } catch (e) {
    return err('Internal server error', 500);
  }
}
