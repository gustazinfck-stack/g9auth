const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const path = require('path');
const moment = require('moment');

const app = express();
const port = process.env.PORT || 5000;

// Trust proxy for Render/HTTPS
app.set('trust proxy', 1);

// Database setup
const dbPath = process.env.RENDER ? '/tmp/g9_auth.db' : path.join(__dirname, 'g9_auth.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("ERRO AO ABRIR BANCO DE DADOS:", err.message);
    } else {
        console.log(`Banco de dados conectado em: ${dbPath}`);
    }
});

// --- Database Initialization ---
db.serialize(() => {
    // Users Table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        discord_id TEXT,
        hwid TEXT,
        expiry_date TEXT,
        is_banned INTEGER DEFAULT 0,
        ban_reason TEXT,
        is_admin INTEGER DEFAULT 0,
        product TEXT DEFAULT 'G9_PRIVATE',
        last_login TEXT,
        last_ip TEXT
    )`);

    // Licenses Table
    db.run(`CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_code TEXT UNIQUE,
        duration_days INTEGER,
        product TEXT,
        is_used INTEGER DEFAULT 0,
        used_by TEXT,
        created_at TEXT
    )`);

    // Logs Table
    db.run(`CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        action TEXT,
        ip TEXT,
        product TEXT,
        type TEXT DEFAULT 'user',
        timestamp TEXT
    )`);

    // Check if 'type' column exists, if not add it (for existing databases)
    db.all("PRAGMA table_info(logs)", (err, columns) => {
        if (err) {
            console.error("Erro ao verificar colunas da tabela logs:", err.message);
            return;
        }
        console.log("Colunas da tabela logs detectadas:", columns.map(c => c.name).join(', '));
        const typeExists = columns.some(col => col.name === 'type');
        if (!typeExists) {
            console.log("Adicionando coluna 'type' na tabela logs...");
            db.run("ALTER TABLE logs ADD COLUMN type TEXT DEFAULT 'user'", (err) => {
                if (err) console.error("Erro ao adicionar coluna type:", err.message);
                else console.log("Coluna 'type' adicionada com sucesso!");
            });
        }
    });

    // Product Config Table
    db.run(`CREATE TABLE IF NOT EXISTS product_config (
        product_name TEXT PRIMARY KEY,
        is_maintenance INTEGER DEFAULT 0,
        version TEXT DEFAULT '1.0.0',
        motd TEXT DEFAULT 'Bem-vindo ao G9 Auth!'
    )`);

    // Criar admin padrão se não houver NENHUM usuário ou se o admin sumiu
    const ensureAdmin = () => {
        db.get("SELECT * FROM users WHERE username = 'admin'", (err, row) => {
            if (err) {
                console.error("Erro ao verificar admin:", err.message);
                return;
            }
            
            if (!row) {
                console.log("[SISTEMA] Admin não encontrado, recriando admin padrão...");
                const hash = bcrypt.hashSync('admin123', 10);
                db.run("INSERT INTO users (username, password, is_admin, product) VALUES (?, ?, ?, ?)", 
                    ['admin', hash, 1, 'ADMIN'], (err) => {
                    if (err) console.error("Erro ao recriar admin:", err.message);
                    else console.log("[SISTEMA] Admin padrão restaurado: admin / admin123");
                });
            } else {
                if (row.is_admin !== 1) {
                    db.run("UPDATE users SET is_admin = 1 WHERE username = 'admin'");
                    console.log("[SISTEMA] Permissões de admin restauradas para 'admin'");
                }
            }
        });
    };

    ensureAdmin();
});

// --- Discord Webhook Helper ---
const DISCORD_WEBHOOK_URL = ''; // User can fill this later

function sendDiscordLog(title, message, color = 0x7289da) {
    if (!DISCORD_WEBHOOK_URL) return;
    
    const axios = require('axios');
    axios.post(DISCORD_WEBHOOK_URL, {
        embeds: [{
            title: title,
            description: message,
            color: color,
            timestamp: new Date().toISOString()
        }]
    }).catch(err => console.error("Erro ao enviar webhook:", err.message));
}

function addLog(userId, username, action, ip, product, type = 'user') {
    const now = moment().format('YYYY-MM-DD HH:mm:ss');
    const safeUserId = userId || 0;
    const safeUsername = username || 'Sistema/Desconhecido';
    const safeProduct = product || 'N/A';
    
    console.log(`[LOG DEBUG] Tentando inserir log: UserID=${safeUserId}, User=${safeUsername}, Action=${action}, Type=${type}`);
    db.run("INSERT INTO logs (user_id, username, action, ip, product, type, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [safeUserId, safeUsername, action, ip, safeProduct, type, now], (err) => {
            if (err) {
                console.error("[LOG ERROR] Erro ao salvar log no banco de dados:", err.message);
                console.error("[LOG ERROR] Query parameters:", [safeUserId, safeUsername, action, ip, safeProduct, type, now]);
            } else {
                console.log(`[LOG SUCCESS] Log salvo com sucesso: ${action} para ${safeUsername}`);
            }
        });
}

// Configuração de Views com Debug para Deploy
const viewsPath = path.resolve(__dirname, 'views');
console.log(`[SISTEMA] Caminho das views: ${viewsPath}`);

const fs = require('fs');
if (fs.existsSync(viewsPath)) {
    console.log(`[SISTEMA] Pasta 'views' encontrada. Arquivos:`, fs.readdirSync(viewsPath));
} else {
    console.error(`[SISTEMA] ERRO: Pasta 'views' NÃO ENCONTRADA em: ${viewsPath}`);
    // Tentativa de fallback para o diretório de trabalho atual
    const fallbackPath = path.join(process.cwd(), 'views');
    console.log(`[SISTEMA] Tentando fallback: ${fallbackPath}`);
    if (fs.existsSync(fallbackPath)) {
        console.log(`[SISTEMA] Fallback funcionou!`);
        app.set('views', fallbackPath);
    }
}

app.set('view engine', 'ejs');
if (!app.get('views')) {
    app.set('views', viewsPath);
}
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: 'g9_secret_key_js_123',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000 
    }
}));

// Test route to check if server is alive
app.get('/ping', (req, res) => res.send('PONG - Servidor está vivo!'));

// Global locals middleware
app.use((req, res, next) => {
    res.locals.error = null;
    res.locals.clientIp = getClientIp(req);
    next();
});

function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const ip = forwarded ? forwarded.split(',')[0] || req.socket.remoteAddress : req.socket.remoteAddress;
    if (!ip) return '0.0.0.0';
    return ip.includes('::ffff:') ? ip.split('::ffff:')[1] : ip;
}

// Auth check middleware
function isAdmin(req, res, next) {
    if (req.session && req.session.isAdmin) {
        return next();
    }
    console.log("[AUTH] Bloqueado: Sessão inválida ou não é admin");
    res.redirect('/admin/login?error=Sessao expirada');
}

// --- Admin Routes ---

app.get('/', (req, res) => {
    if (req.session && req.session.isAdmin) {
        res.redirect('/admin/dashboard');
    } else {
        res.redirect('/admin/login');
    }
});

app.get('/admin/login', (req, res) => {
    res.render('login', { error: req.query.error || null }, (err, html) => {
        if (err) {
            console.error("ERRO AO RENDERIZAR LOGIN.EJS:", err);
            // Fallback em HTML caso o arquivo EJS suma
            return res.send(`
                <body style="background:#0a0a0a; color:white; font-family:sans-serif; display:flex; align-items:center; justify-content:center; height:100vh; margin:0;">
                    <div style="background:#141414; padding:50px; border-radius:28px; border:1px solid #222; max-width:400px; width:100%; text-align:center;">
                        <h1 style="margin-bottom:20px;">G9 AUTH</h1>
                        <p style="color:red;">Erro ao carregar template (EJS)</p>
                        <form action="/admin/login" method="POST" style="display:flex; flex-direction:column; gap:15px;">
                            <input type="text" name="username" placeholder="Admin Username" style="padding:12px; border-radius:10px; border:1px solid #333; background:#111; color:white;">
                            <input type="password" name="password" placeholder="Password" style="padding:12px; border-radius:10px; border:1px solid #333; background:#111; color:white;">
                            <button type="submit" style="padding:12px; border-radius:10px; border:none; background:white; color:black; font-weight:bold; cursor:pointer;">Entrar</button>
                        </form>
                        ${req.query.error ? `<p style="color:orange; margin-top:15px;">${req.query.error}</p>` : ''}
                    </div>
                </body>
            `);
        }
        res.send(html);
    });
});

app.post('/admin/login', (req, res) => {
    let { username, password } = req.body;
    
    // Trim e Lowercase para evitar problemas comuns
    if (username) username = username.trim().toLowerCase();
    if (password) password = password.trim();

    console.log(`[LOGIN] Tentativa de login admin: ${username}`);

    if (!username || !password) {
        return res.redirect('/admin/login?error=Preencha todos os campos');
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) {
            console.error("[LOGIN ERROR] Erro no banco:", err.message);
            return res.redirect('/admin/login?error=Erro no banco de dados');
        }

        if (!user) {
            console.log(`[LOGIN FAIL] Usuário não encontrado: ${username}`);
            // Se o admin não foi encontrado, tenta recriar (caso tenha sido deletado)
            if (username === 'admin') {
                const hash = bcrypt.hashSync('admin123', 10);
                db.run("INSERT INTO users (username, password, is_admin, product) VALUES (?, ?, ?, ?)", 
                    ['admin', hash, 1, 'ADMIN'], (err) => {
                    if (!err) console.log("[LOGIN] Admin recriado durante tentativa de login.");
                });
            }
            return res.redirect('/admin/login?error=Credenciais invalidas');
        }

        if (user.is_admin !== 1) {
            console.log(`[LOGIN FAIL] Usuário ${username} não possui privilégios de admin.`);
            return res.redirect('/admin/login?error=Acesso negado');
        }

        const passwordMatch = bcrypt.compareSync(password, user.password);
        if (passwordMatch) {
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.isAdmin = true;
            
            req.session.save((err) => {
                if (err) {
                    console.error("[SESSION ERROR] Erro ao salvar sessão:", err);
                    return res.redirect('/admin/login?error=Erro de sessao');
                }
                console.log(`[LOGIN SUCCESS] Admin logado: ${username}`);
                res.redirect('/admin/dashboard');
            });
        } else {
            console.log(`[LOGIN FAIL] Senha incorreta para: ${username}`);
            return res.redirect('/admin/login?error=Senha incorreta');
        }
    });
});

app.get('/admin/dashboard', isAdmin, (req, res) => {
    const data = {
        users: [],
        allUsers: [],
        configs: [],
        moment: moment
    };

    // Consulta 1: Usuários
    db.all("SELECT * FROM users", [], (err, rows) => {
        if (!err && rows) {
            data.allUsers = rows;
            data.users = rows.filter(u => u && u.username && u.username.toLowerCase() !== 'admin');
        }

        // Consulta 2: Configs de Produto
        db.all("SELECT * FROM product_config", [], (err, rows) => {
            if (!err && rows) data.configs = rows;

            res.render('dashboard', data, (err, html) => {
                if (err) {
                    console.error("ERRO AO RENDERIZAR DASHBOARD.EJS:", err);
                    return res.status(500).send(`
                        <body style="background:#111; color:red; padding:50px; font-family:sans-serif;">
                            <h1>ERRO NO TEMPLATE (EJS)</h1>
                            <p>O servidor está funcionando, mas o arquivo <b>dashboard.ejs</b> não pôde ser carregado ou renderizado.</p>
                            <pre style="background:#222; padding:10px; color:#eee; border:1px solid red;">${err.message}</pre>
                            <p>Verifique se o arquivo <code>views/dashboard.ejs</code> existe no servidor.</p>
                            <a href="/admin/login" style="color:white;">Voltar para Login</a>
                        </body>
                    `);
                }
                res.send(html);
            });
        });
    });
});

// --- Admin Actions ---

app.post('/admin/generate_key', isAdmin, (req, res) => {
    const { duration, product, amount } = req.body;
    const crypto = require('crypto');
    const numAmount = parseInt(amount) || 1;
    const numDuration = parseInt(duration) || 30;
    const targetProduct = product || 'G9_PRIVATE';
    
    let completed = 0;
    let errors = 0;

    for (let i = 0; i < numAmount; i++) {
        const key = `G9-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
        db.run("INSERT INTO licenses (key_code, duration_days, product, created_at) VALUES (?, ?, ?, ?)",
            [key, numDuration, targetProduct, moment().format('YYYY-MM-DD HH:mm:ss')], (err) => {
                completed++;
                if (err) {
                    console.error("Erro ao gerar key:", err.message);
                    errors++;
                }
                
                if (completed === numAmount) {
                    console.log(`${numAmount - errors} keys geradas com sucesso.`);
                    addLog(req.session.userId, req.session.username, `Gerou ${numAmount - errors} keys (${targetProduct})`, getClientIp(req), targetProduct, 'admin');
                    sendDiscordLog("🔑 Keys Geradas", `Foram geradas ${numAmount - errors} keys para o produto ${targetProduct}.`, 0x00ff00);
                    res.redirect('/admin/dashboard?tab=users');
                }
            });
    }
});

app.post('/admin/reset_hwid/:id', isAdmin, (req, res) => {
    db.run("UPDATE users SET hwid = NULL WHERE id = ?", [req.params.id], (err) => {
        addLog(req.session.userId, req.session.username, `Resetou HWID do Usuário ID: ${req.params.id}`, getClientIp(req), 'ADMIN', 'admin');
        res.redirect('/admin/dashboard?tab=users');
    });
});

app.post('/admin/update_config', isAdmin, (req, res) => {
    const { product, maintenance, version, motd } = req.body;
    db.run(`INSERT INTO product_config (product_name, is_maintenance, version, motd) 
            VALUES (?, ?, ?, ?) 
            ON CONFLICT(product_name) DO UPDATE SET 
            is_maintenance=excluded.is_maintenance, 
            version=excluded.version, 
            motd=excluded.motd`,
        [product, maintenance === 'on' ? 1 : 0, version, motd], (err) => {
            addLog(req.session.userId, req.session.username, `Atualizou config do produto: ${product}`, getClientIp(req), 'ADMIN', 'admin');
            res.redirect('/admin/dashboard?tab=products');
        });
});

app.post('/admin/add_product', isAdmin, (req, res) => {
    const { product_name, version, motd } = req.body;
    if (!product_name) return res.redirect('/admin/dashboard?tab=products');

    db.run(`INSERT INTO product_config (product_name, version, motd) VALUES (?, ?, ?)`,
        [product_name, version || '1.0.0', motd || 'Bem-vindo ao novo produto!'], (err) => {
            if (err) console.error(err);
            addLog(req.session.userId, req.session.username, `Adicionou novo produto: ${product_name}`, getClientIp(req), 'ADMIN', 'admin');
            res.redirect('/admin/dashboard?tab=products');
        });
});

app.post('/admin/delete_product/:name', isAdmin, (req, res) => {
    const { name } = req.params;
    if (!name) {
        console.error("Tentativa de excluir produto sem nome");
        return res.redirect('/admin/dashboard?tab=products');
    }
    
    db.run("DELETE FROM product_config WHERE product_name = ?", [name], function(err) {
        if (err) {
            console.error("Erro ao excluir produto:", err.message);
        } else {
            console.log(`Produto excluído: ${name} (${this.changes} linhas afetadas)`);
            addLog(req.session.userId, req.session.username, `Excluiu produto: ${name}`, getClientIp(req), 'ADMIN', 'admin');
        }
        res.redirect('/admin/dashboard?tab=products');
    });
});

// Rota de fallback para exclusão sem nome para evitar "Cannot POST /admin/delete_product/"
app.post('/admin/delete_product', isAdmin, (req, res) => {
    console.warn("Recebido POST em /admin/delete_product sem parâmetro de nome");
    res.redirect('/admin/dashboard?tab=products');
});

app.post('/admin/add_user', isAdmin, (req, res) => {
    let { username, discord_id, days, product } = req.body;
    
    if (username) username = username.trim().toLowerCase();

    if (!username) {
        return res.redirect('/admin/dashboard?error=Username is required');
    }

    if (username === 'admin') {
        return res.redirect('/admin/dashboard?tab=users&error=O nome de usuário admin é reservado.');
    }

    const numDays = parseInt(days) || 0;
    const expiryDate = numDays > 0 ? moment().add(numDays, 'days').format('YYYY-MM-DD HH:mm:ss') : null;
    const defaultPass = bcrypt.hashSync('default123', 10);
    const targetProduct = product || 'G9_PRIVATE';

    db.run("INSERT INTO users (username, password, discord_id, expiry_date, product) VALUES (?, ?, ?, ?, ?)", 
        [username, defaultPass, discord_id, expiryDate, targetProduct], (err) => {
        if (err) {
            console.error("Erro ao inserir usuário:", err.message);
        } else {
            console.log(`Usuário criado com sucesso: ${username}`);
            addLog(req.session.userId, req.session.username, `Criou usuário: ${username}`, getClientIp(req), targetProduct, 'admin');
            sendDiscordLog("👤 Novo Usuário (Admin)", `O administrador criou o usuário **${username}** para o produto **${targetProduct}**.`, 0x00ff00);
        }
        res.redirect('/admin/dashboard?tab=users');
    });
});

app.post('/admin/manage/:id/:action', isAdmin, (req, res) => {
    const { id, action } = req.params;
    console.log(`Ação administrativa: ${action} no ID: ${id}`);
    
    if (action === 'ban') {
        db.get("SELECT is_banned, username FROM users WHERE id = ?", [id], (err, row) => {
            if (err || !row) return res.redirect('/admin/dashboard?tab=users');
            const newBanStatus = row.is_banned ? 0 : 1;
            const reason = newBanStatus ? "Banido pelo administrador" : null;
            db.run("UPDATE users SET is_banned = ?, ban_reason = ? WHERE id = ?", [newBanStatus, reason, id], () => {
                addLog(req.session.userId, req.session.username, `${newBanStatus ? 'Baniu' : 'Desbaniu'} usuário: ${row.username}`, getClientIp(req), 'ADMIN', 'admin');
                res.redirect('/admin/dashboard?tab=users');
            });
        });
    } else if (action === 'reset_hwid') {
        db.get("SELECT username FROM users WHERE id = ?", [id], (err, row) => {
            db.run("UPDATE users SET hwid = NULL WHERE id = ?", [id], () => {
                addLog(req.session.userId, req.session.username, `Resetou HWID de: ${row ? row.username : id}`, getClientIp(req), 'ADMIN', 'admin');
                res.redirect('/admin/dashboard?tab=users');
            });
        });
    } else if (action === 'add_days') {
        const { days } = req.body;
        const numDays = parseInt(days) || 0;
        db.get("SELECT expiry_date, username FROM users WHERE id = ?", [id], (err, row) => {
            if (err || !row) return res.redirect('/admin/dashboard?tab=users');
            let currentExpiry = row.expiry_date ? moment(row.expiry_date) : moment();
            if (currentExpiry.isBefore(moment())) currentExpiry = moment();
            const newExpiry = currentExpiry.add(numDays, 'days').format('YYYY-MM-DD HH:mm:ss');
            db.run("UPDATE users SET expiry_date = ? WHERE id = ?", [newExpiry, id], () => {
                addLog(req.session.userId, req.session.username, `Adicionou ${numDays} dias para: ${row.username}`, getClientIp(req), 'ADMIN', 'admin');
                res.redirect('/admin/dashboard?tab=users');
            });
        });
    } else if (action === 'remove_days') {
        const { days } = req.body;
        const numDays = parseInt(days) || 0;
        db.get("SELECT expiry_date, username FROM users WHERE id = ?", [id], (err, row) => {
            if (err || !row) return res.redirect('/admin/dashboard?tab=users');
            let currentExpiry = row.expiry_date ? moment(row.expiry_date) : moment();
            const newExpiry = currentExpiry.subtract(numDays, 'days').format('YYYY-MM-DD HH:mm:ss');
            db.run("UPDATE users SET expiry_date = ? WHERE id = ?", [newExpiry, id], () => {
                addLog(req.session.userId, req.session.username, `Removeu ${numDays} dias de: ${row.username}`, getClientIp(req), 'ADMIN', 'admin');
                res.redirect('/admin/dashboard?tab=users');
            });
        });
    } else if (action === 'delete') {
        db.get("SELECT username FROM users WHERE id = ?", [id], (err, row) => {
            if (row && row.username === 'admin') {
                console.warn("[SISTEMA] Tentativa de excluir o usuário admin bloqueada.");
                return res.redirect('/admin/dashboard?tab=users&error=O admin principal não pode ser excluído.');
            }
            const username = row ? row.username : id;
            db.run("DELETE FROM users WHERE id = ?", [id], function(err) {
                if (err) {
                    console.error("Erro ao excluir usuário:", err.message);
                } else {
                    console.log(`Usuário ID ${id} excluído (${this.changes} linhas afetadas)`);
                    if (this.changes > 0) {
                        addLog(req.session.userId, req.session.username, `Excluiu usuário: ${username}`, getClientIp(req), 'ADMIN', 'admin');
                        sendDiscordLog("🗑️ Usuário Excluído", `O administrador excluiu o usuário ID: **${id}**.`, 0xff0000);
                    }
                }
                res.redirect('/admin/dashboard?tab=users');
            });
        });
    } else {
        res.redirect('/admin/dashboard?tab=users');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Erro ao destruir sessão:", err);
        }
        res.clearCookie('connect.sid'); // Limpa o cookie da sessão
        res.redirect('/admin/login');
    });
});

// --- API Endpoints ---

app.post('/api/register', (req, res) => {
    let { username, password, key, hwid } = req.body;

    if (username) username = username.trim().toLowerCase();
    
    if (username === 'admin') {
        return res.status(403).json({ status: "error", message: "Nome de usuário reservado" });
    }

    db.get("SELECT * FROM licenses WHERE key_code = ? AND is_used = 0", [key], (err, license) => {
        if (!license) {
            return res.status(400).json({ status: "error", message: "Key inválida ou já utilizada" });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        const expiryDate = moment().add(license.duration_days, 'days').format('YYYY-MM-DD HH:mm:ss');

        db.run("INSERT INTO users (username, password, hwid, expiry_date, product) VALUES (?, ?, ?, ?, ?)",
            [username, hashedPassword, hwid, expiryDate, license.product], function(err) {
                if (err) return res.status(500).json({ status: "error", message: "Erro ao criar usuário" });
                
                db.run("UPDATE licenses SET is_used = 1, used_by = ? WHERE id = ?", [username, license.id]);
                
                sendDiscordLog("🆕 Novo Registro", `Usuário **${username}** registrou uma key de ${license.duration_days} dias para **${license.product}**.`, 0x00ff00);
                res.json({ status: "success", message: "Usuário registrado com sucesso" });
            });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password, hwid, product, version } = req.body;
    const targetProduct = product || 'G9_PRIVATE';
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    // Check Product Config (Maintenance & Version)
    db.get("SELECT * FROM product_config WHERE product_name = ?", [targetProduct], (err, config) => {
        if (config) {
            if (config.is_maintenance) {
                return res.status(403).json({ status: "error", message: "Produto em manutenção" });
            }
            if (version && config.version !== version) {
                return res.status(403).json({ status: "error", message: `Versão desatualizada. Baixe a v${config.version}` });
            }
        }

        db.get("SELECT * FROM users WHERE username = ? AND product = ?", [username, targetProduct], (err, user) => {
            if (!user) {
                return res.status(404).json({ status: "error", message: "Usuário não encontrado" });
            }

            if (user.is_banned) {
                return res.status(403).json({ status: "error", message: `Você está banido: ${user.ban_reason}` });
            }

            if (user.expiry_date && moment().isAfter(moment(user.expiry_date))) {
                return res.status(403).json({ status: "error", message: "Sua licença expirou" });
            }

            // HWID Check
            if (user.hwid && user.hwid !== hwid) {
                addLog(user.id, username, `Tentativa Login (HWID Errado: ${hwid})`, ip, targetProduct, 'user');
                sendDiscordLog("⚠️ Tentativa de Login (HWID)", `Usuário **${username}** tentou logar com HWID diferente!\nRegistrado: \`${user.hwid}\`\nTentativa: \`${hwid}\``, 0xffa500);
                return res.status(403).json({ status: "error", message: "HWID não confere. Peça reset no suporte." });
            }

            // Password Check (if provided)
            if (password && !bcrypt.compareSync(password, user.password)) {
                addLog(user.id, username, 'Tentativa Login (Senha Errada)', ip, targetProduct, 'user');
                return res.status(401).json({ status: "error", message: "Senha incorreta" });
            }

            // Update user info
            const now = moment().format('YYYY-MM-DD HH:mm:ss');
            db.run("UPDATE users SET hwid = ?, last_login = ?, last_ip = ? WHERE id = ?", [hwid, now, ip, user.id]);
            
            // Log action
            addLog(user.id, username, 'Login Sucesso', ip, targetProduct, 'user');

            res.json({
                status: "success",
                message: "Login realizado com sucesso",
                user: {
                    username: user.username,
                    expiry: user.expiry_date,
                    product: user.product,
                    motd: config ? config.motd : "Bem-vindo!"
                }
            });
        });
    });
});

// Middleware de tratamento de erro do Express (DEVE SER O ÚLTIMO)
app.use((err, req, res, next) => {
    console.error("ERRO EXPRESS:", err);
    res.status(500).send(`
        <body style="background:#111; color:red; padding:50px; font-family:sans-serif;">
            <h1>ERRO INTERNO DO SERVIDOR (500)</h1>
            <p>Ocorreu um erro inesperado no processamento da rota.</p>
            <pre style="background:#222; padding:10px; color:#eee; border:1px solid red;">${err.message}\n${err.stack}</pre>
            <a href="/admin/login" style="color:white;">Voltar para Login</a>
        </body>
    `);
});

app.listen(port, () => {
    console.log(`Servidor G9 Auth rodando em http://localhost:${port}`);
});

// Captura erros globais para evitar crash silencioso na Render
process.on('uncaughtException', (err) => {
    console.error('CRASH DETECTADO (uncaughtException):', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('CRASH DETECTADO (unhandledRejection):', reason);
});
