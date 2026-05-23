const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'congmingchang_secret_key_2026';

// ========== 中间件 ==========
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ========== PostgreSQL 连接池 ==========
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ========== 初始化表 ==========
async function initDatabase() {
    const client = await pool.connect();
    try {
        // 用户表
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                nickname TEXT,
                phone TEXT,
                role TEXT DEFAULT 'normal',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        `);

        // 题集表
        await client.query(`
            CREATE TABLE IF NOT EXISTS collections (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                source_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // 题目表
        await client.query(`
            CREATE TABLE IF NOT EXISTS questions (
                id SERIAL PRIMARY KEY,
                collection_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                options TEXT NOT NULL,
                answer TEXT NOT NULL,
                explanation TEXT,
                type TEXT NOT NULL,
                difficulty TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // 错题表
        await client.query(`
            CREATE TABLE IF NOT EXISTS mistakes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                question_id INTEGER NOT NULL,
                wrong_answer TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // 笔记表
        await client.query(`
            CREATE TABLE IF NOT EXISTS notes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                mistake_id INTEGER NOT NULL,
                content TEXT,
                image_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // 薄弱知识点表
        await client.query(`
            CREATE TABLE IF NOT EXISTS weak_topics (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // 口诀表
        await client.query(`
            CREATE TABLE IF NOT EXISTS mnemonics (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                text TEXT NOT NULL,
                meaning TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('✅ 数据库表初始化完成');

        // 创建默认管理员账号（如果不存在）
        const adminResult = await client.query('SELECT * FROM users WHERE username = $1', ['admin']);
        if (adminResult.rows.length === 0) {
            const hashedPassword = bcrypt.hashSync('admin123', 10);
            await client.query(
                'INSERT INTO users (username, password, role, nickname) VALUES ($1, $2, $3, $4)',
                ['admin', hashedPassword, 'admin', '管理员']
            );
            console.log('✅ 默认管理员账号已创建: admin / admin123');
        }
    } catch (err) {
        console.error('❌ 数据库初始化失败:', err);
    } finally {
        client.release();
    }
}

initDatabase();

// ========== 工具函数 ==========
function generateToken(userId, username, role) {
    return jwt.sign({ id: userId, username, role }, JWT_SECRET, { expiresIn: '7d' });
}

// ========== 认证中间件 ==========
async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: '未登录' });
    }
    
    try {
        const user = jwt.verify(token, JWT_SECRET);
        // 识别 liufeichang 为管理员
        const ADMIN_USERS = ['liufeichang'];
        if (ADMIN_USERS.includes(user.username)) {
            user.role = 'admin';
        }
        req.user = user;
        next();
    } catch (err) {
        return res.status(403).json({ error: '登录已过期' });
    }
}

// 管理员中间件
function adminOnly(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: '需要管理员权限' });
    }
    next();
}

// ========== API 接口 ==========

// ---- 健康检查 ----
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: '聪明肠后端运行正常' });
});

// ---- 用户注册 ----
app.post('/api/register', async (req, res) => {
    const { username, password, nickname, phone } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: '用户名和密码不能为空' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: '密码至少6位' });
    }
    
    try {
        // 检查用户名是否已存在
        const existResult = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
        if (existResult.rows.length > 0) {
            return res.status(400).json({ error: '用户名已存在' });
        }
        
        const hashedPassword = bcrypt.hashSync(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, password, nickname, phone, role) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [username, hashedPassword, nickname || username, phone || null, 'normal']
        );
        const userId = result.rows[0].id;
        const token = generateToken(userId, username, 'normal');
        res.json({
            token,
            user: { id: userId, username, nickname: nickname || username, role: 'normal' }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: '注册失败' });
    }
});

// ---- 用户登录 ----
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: '用户名和密码不能为空' });
    }
    
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user) {
            return res.status(400).json({ error: '用户名或密码错误' });
        }
        
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(400).json({ error: '用户名或密码错误' });
        }
        
        // 更新最后登录时间
        await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
        
        const token = generateToken(user.id, user.username, user.role);
        res.json({
            token,
            user: { id: user.id, username: user.username, nickname: user.nickname, role: user.role }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: '登录失败' });
    }
});

// ---- 验证token ----
app.get('/api/verify-token', authenticateToken, (req, res) => {
    res.json({ user: req.user });
});

// ---- 管理员：生成账号 ----
app.post('/api/admin/generate-users', authenticateToken, adminOnly, async (req, res) => {
    const { count = 1, prefix = 'user' } = req.body;
    const num = parseInt(count);
    
    if (num < 1 || num > 50) {
        return res.status(400).json({ error: '数量必须在1-50之间' });
    }
    
    const results = [];
    
    for (let i = 0; i < num; i++) {
        const username = `${prefix}${Date.now().toString().slice(-4)}${Math.floor(Math.random() * 1000)}`;
        const password = Math.random().toString(36).slice(-8);
        const hashedPassword = bcrypt.hashSync(password, 10);
        
        try {
            const result = await pool.query(
                'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id',
                [username, hashedPassword, 'normal']
            );
            results.push({ username, password, id: result.rows[0].id });
        } catch (err) {
            i--;
        }
    }
    
    res.json({ users: results });
});

// ---- 管理员：获取用户列表 ----
app.get('/api/admin/users', authenticateToken, adminOnly, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, username, nickname, phone, role, created_at, last_login FROM users ORDER BY created_at DESC'
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: '获取用户列表失败' });
    }
});

// ---- 管理员：重置用户密码 ----
app.post('/api/admin/reset-password', authenticateToken, adminOnly, async (req, res) => {
    const { userId, newPassword } = req.body;
    
    if (!userId || !newPassword || newPassword.length < 6) {
        return res.status(400).json({ error: '请提供有效的新密码' });
    }
    
    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    try {
        await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, userId]);
        res.json({ message: '密码重置成功' });
    } catch (err) {
        res.status(500).json({ error: '重置密码失败' });
    }
});

// ---- 管理员：删除用户 ----
app.delete('/api/admin/users/:id', authenticateToken, adminOnly, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM users WHERE id = $1', [id]);
        res.json({ message: '用户已删除' });
    } catch (err) {
        res.status(500).json({ error: '删除用户失败' });
    }
});

// ---- 题集管理 ----
app.post('/api/collections', authenticateToken, async (req, res) => {
    const { name, source_file } = req.body;
    const userId = req.user.id;
    try {
        const result = await pool.query(
            'INSERT INTO collections (user_id, name, source_file) VALUES ($1, $2, $3) RETURNING id',
            [userId, name, source_file || null]
        );
        res.json({ id: result.rows[0].id, name, source_file });
    } catch (err) {
        res.status(500).json({ error: '创建题集失败' });
    }
});

app.get('/api/collections', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const result = await pool.query(
            'SELECT * FROM collections WHERE user_id = $1 ORDER BY created_at DESC',
            [userId]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: '获取题集失败' });
    }
});

app.put('/api/collections/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { name } = req.body;
    const userId = req.user.id;
    try {
        const result = await pool.query(
            'UPDATE collections SET name = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND user_id = $3',
            [name, id, userId]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ error: '题集不存在' });
        }
        res.json({ message: '重命名成功' });
    } catch (err) {
        res.status(500).json({ error: '重命名失败' });
    }
});

// ---- 题目管理 ----
app.post('/api/questions', authenticateToken, async (req, res) => {
    const { collection_id, content, options, answer, explanation, type, difficulty } = req.body;
    const userId = req.user.id;
    try {
        const result = await pool.query(
            'INSERT INTO questions (collection_id, user_id, content, options, answer, explanation, type, difficulty) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id',
            [collection_id, userId, content, JSON.stringify(options), JSON.stringify(answer), explanation, type, difficulty]
        );
        res.json({ id: result.rows[0].id });
    } catch (err) {
        res.status(500).json({ error: '添加题目失败' });
    }
});

app.get('/api/questions', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { collection_id } = req.query;
    let sql = 'SELECT * FROM questions WHERE user_id = $1';
    let params = [userId];
    if (collection_id) {
        sql += ' AND collection_id = $2';
        params.push(collection_id);
    }
    sql += ' ORDER BY created_at DESC';
    try {
        const result = await pool.query(sql, params);
        res.json(result.rows.map(row => ({
            ...row,
            options: JSON.parse(row.options),
            answer: JSON.parse(row.answer)
        })));
    } catch (err) {
        res.status(500).json({ error: '获取题目失败' });
    }
});

// ---- 错题本 ----
app.post('/api/mistakes', authenticateToken, async (req, res) => {
    const { question_id, wrong_answer } = req.body;
    const userId = req.user.id;
    try {
        const existResult = await pool.query(
            'SELECT id FROM mistakes WHERE user_id = $1 AND question_id = $2',
            [userId, question_id]
        );
        if (existResult.rows.length > 0) {
            return res.json({ message: '已存在' });
        }
        const result = await pool.query(
            'INSERT INTO mistakes (user_id, question_id, wrong_answer) VALUES ($1, $2, $3) RETURNING id',
            [userId, question_id, wrong_answer || null]
        );
        res.json({ id: result.rows[0].id });
    } catch (err) {
        res.status(500).json({ error: '添加错题失败' });
    }
});

app.get('/api/mistakes', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const result = await pool.query(`
            SELECT m.*, q.content as question_content, q.options as question_options, 
                   q.answer as question_answer, q.explanation as question_explanation,
                   q.type as question_type, c.name as collection_name
            FROM mistakes m
            JOIN questions q ON m.question_id = q.id
            LEFT JOIN collections c ON q.collection_id = c.id
            WHERE m.user_id = $1
            ORDER BY m.created_at DESC
        `, [userId]);
        res.json(result.rows.map(row => ({
            ...row,
            question_options: JSON.parse(row.question_options),
            question_answer: JSON.parse(row.question_answer)
        })));
    } catch (err) {
        res.status(500).json({ error: '获取错题失败' });
    }
});

app.delete('/api/mistakes/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    try {
        await pool.query('DELETE FROM mistakes WHERE id = $1 AND user_id = $2', [id, userId]);
        res.json({ message: '删除成功' });
    } catch (err) {
        res.status(500).json({ error: '删除错题失败' });
    }
});

// ---- 笔记 ----
app.post('/api/notes', authenticateToken, async (req, res) => {
    const { mistake_id, content, image_url } = req.body;
    const userId = req.user.id;
    try {
        const result = await pool.query(
            'INSERT INTO notes (user_id, mistake_id, content, image_url) VALUES ($1, $2, $3, $4) RETURNING id',
            [userId, mistake_id, content, image_url || null]
        );
        res.json({ id: result.rows[0].id });
    } catch (err) {
        res.status(500).json({ error: '添加笔记失败' });
    }
});

app.get('/api/notes', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { mistake_id } = req.query;
    let sql = 'SELECT * FROM notes WHERE user_id = $1';
    let params = [userId];
    if (mistake_id) {
        sql += ' AND mistake_id = $2';
        params.push(mistake_id);
    }
    sql += ' ORDER BY created_at DESC';
    try {
        const result = await pool.query(sql, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: '获取笔记失败' });
    }
});

app.put('/api/notes/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { content } = req.body;
    const userId = req.user.id;
    try {
        await pool.query('UPDATE notes SET content = $1 WHERE id = $2 AND user_id = $3', [content, id, userId]);
        res.json({ message: '更新成功' });
    } catch (err) {
        res.status(500).json({ error: '更新笔记失败' });
    }
});

app.delete('/api/notes/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    try {
        await pool.query('DELETE FROM notes WHERE id = $1 AND user_id = $2', [id, userId]);
        res.json({ message: '删除成功' });
    } catch (err) {
        res.status(500).json({ error: '删除笔记失败' });
    }
});

// ---- 薄弱知识点 ----
app.post('/api/weak-topics', authenticateToken, async (req, res) => {
    const { title, description } = req.body;
    const userId = req.user.id;
    try {
        const result = await pool.query(
            'INSERT INTO weak_topics (user_id, title, description) VALUES ($1, $2, $3) RETURNING id',
            [userId, title, description]
        );
        res.json({ id: result.rows[0].id });
    } catch (err) {
        res.status(500).json({ error: '添加薄弱知识点失败' });
    }
});

app.get('/api/weak-topics', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const result = await pool.query(
            'SELECT * FROM weak_topics WHERE user_id = $1 ORDER BY created_at DESC',
            [userId]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: '获取薄弱知识点失败' });
    }
});

app.delete('/api/weak-topics/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    try {
        await pool.query('DELETE FROM weak_topics WHERE id = $1 AND user_id = $2', [id, userId]);
        res.json({ message: '删除成功' });
    } catch (err) {
        res.status(500).json({ error: '删除薄弱知识点失败' });
    }
});

// ---- 口诀 ----
app.post('/api/mnemonics', authenticateToken, async (req, res) => {
    const { text, meaning } = req.body;
    const userId = req.user.id;
    try {
        const result = await pool.query(
            'INSERT INTO mnemonics (user_id, text, meaning) VALUES ($1, $2, $3) RETURNING id',
            [userId, text, meaning]
        );
        res.json({ id: result.rows[0].id });
    } catch (err) {
        res.status(500).json({ error: '添加口诀失败' });
    }
});

app.get('/api/mnemonics', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const result = await pool.query(
            'SELECT * FROM mnemonics WHERE user_id = $1 ORDER BY created_at DESC',
            [userId]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: '获取口诀失败' });
    }
});

app.delete('/api/mnemonics/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    try {
        await pool.query('DELETE FROM mnemonics WHERE id = $1 AND user_id = $2', [id, userId]);
        res.json({ message: '删除成功' });
    } catch (err) {
        res.status(500).json({ error: '删除口诀失败' });
    }
});

// ========== 导出服务器 ==========
// ========== 启动服务器 ==========
const PORT = process.env.PORT || 8080; // 使用环境变量 PORT，默认 8080（对应你的日志）
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 聪明肠后端服务器运行在 http://0.0.0.0:${PORT}`);
});
