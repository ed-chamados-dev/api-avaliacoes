require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { autenticarToken, autorizarCargo } = require('./middleware/auth');

const app = express();
app.set('trust proxy', 1);

// ===============================
// CONFIGURAÇÕES
// ===============================
const SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;

if (!SECRET) {
  console.error("❌ JWT_SECRET não definido no .env");
  process.exit(1);
}

// ===============================
// SEGURANÇA E MIDDLEWARES
// ===============================
app.use(helmet({ contentSecurityPolicy: false }));

// Limite Global: 50 requisições a cada 15 min (para o site em geral)
const limiterGeral = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: "Muitas requisições. Tente novamente mais tarde." }
});

// Limite Estrito para Login: 5 tentativas por hora
const loginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, 
  max: 5, 
  message: { message: "Muitas tentativas de login. Acesso bloqueado por 1 hora." }
});

// Aplica o limite geral em todas as rotas
app.use(limiterGeral);

app.use(express.json());
app.use(cors());

// ===============================
// ARQUIVOS ESTÁTICOS (FRONT-END)
// ===============================
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'page-ava.html'));
});

// ===============================
// BANCO DE DADOS (MySQL)
// ===============================
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

pool.getConnection()
  .then(conn => {
    console.log('✅ Banco MySQL conectado');
    conn.release();
  })
  .catch(err => {
    console.error('❌ Erro ao conectar no MySQL:', err);
    process.exit(1);
  });

// ===============================
// IMPORTANDO E USANDO AS ROTAS EXTERNAS
// ===============================
const authRoutes = require('./routes/authRoutes')(pool);
const avaliacaoRoutes = require('./routes/avaliacaoRoutes')(pool);
const rankingRoutes = require('./routes/rankingRoutes')(pool);

// Aplica o limite estrito APENAS na rota de login antes de carregar as rotas de auth
app.use('/login', loginLimiter);

app.use(authRoutes);
app.use(avaliacaoRoutes);
app.use(rankingRoutes);

// ===============================
// ROTAS PÚBLICAS RESTRANTES (Lojas e Envio de Avaliação)
// ===============================
app.get('/lojas', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, nome FROM lojas ORDER BY nome ASC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao carregar lojas' });
  }
});

app.get('/lojas/token/:token', async (req, res) => {
    const { token } = req.params;
    try {
        const [rows] = await pool.query('SELECT id, nome FROM lojas WHERE token_qr = ?', [token]);
        if(rows.length === 0) return res.status(404).json({ error: "Loja não encontrada" });
        res.json(rows[0]);
    } catch(err) {
        res.status(500).json({ error: "Erro ao buscar loja" });
    }
});

app.post('/avaliacoes', async (req, res) => {
  const {
    loja_id, nota_atendimento, nota_organizacao, nota_produtos,
    encontrou_produto, produto_desejado, deseja_contato, nome_contato,
    telefone_contato, comentar_colaborador, nome_colaborador,     
    tipo_comentario, comentario
  } = req.body;

  const atendimento = Number(nota_atendimento);
  const organizacao = Number(nota_organizacao);
  const produtos = Number(nota_produtos);

  if (!loja_id) return res.status(400).json({ error: 'Loja inválida' });
  if (atendimento < 1 || atendimento > 5 || organizacao < 1 || organizacao > 5 || produtos < 1 || produtos > 5) {
    return res.status(400).json({ error: 'Notas inválidas' });
  }

  try {
    const [lojaExiste] = await pool.query("SELECT id FROM lojas WHERE id = ?", [loja_id]);
    if (lojaExiste.length === 0) return res.status(400).json({ error: "Loja inválida." });

    await pool.query(
      `INSERT INTO avaliacoes
      (loja_id, nota_atendimento, nota_organizacao, nota_produtos, encontrou_produto, produto_desejado, deseja_contato, nome_contato, telefone_contato, comentar_colaborador, nome_colaborador, tipo_comentario, comentario)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [loja_id, atendimento, organizacao, produtos, encontrou_produto, produto_desejado, deseja_contato, nome_contato, telefone_contato, comentar_colaborador, nome_colaborador, tipo_comentario, comentario]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao salvar avaliação' });
  }
});

// ===============================
// ROTAS DE USUÁRIOS ADMIN
// ===============================
app.get('/usuarios', autenticarToken, autorizarCargo('admin'), async (req, res) => {
    try {
      const [rows] = await pool.query(`SELECT u.id, u.username, u.cargo, u.loja_id, l.nome AS loja FROM usuarios u LEFT JOIN lojas l ON l.id = u.loja_id ORDER BY u.id ASC`);
      res.json(rows);
    } catch (err) { res.status(500).json({ message: 'Erro ao listar usuários' }); }
});

app.post('/usuarios', autenticarToken, autorizarCargo('admin'), async (req, res) => {
    const { username, senha, cargo, loja_id } = req.body;
    if (!username || !senha || !cargo) return res.status(400).json({ message: 'Dados obrigatórios não informados' });
    if (!['admin', 'gerente'].includes(cargo)) return res.status(400).json({ message: 'Cargo inválido' });
    if (cargo === 'gerente' && !loja_id) return res.status(400).json({ message: 'Gerente precisa possuir uma loja.' });

    try {
      const [usuarioExistente] = await pool.query('SELECT id FROM usuarios WHERE username = ?', [username]);
      if (usuarioExistente.length) return res.status(400).json({ message: 'Usuário já existe' });
      
      const senhaHash = await bcrypt.hash(senha, 10);
      await pool.query(`INSERT INTO usuarios (username, senha, cargo, loja_id) VALUES (?,?,?,?)`, [username, senhaHash, cargo, loja_id || null]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ message: 'Erro ao cadastrar usuário' }); }
});

app.put('/usuarios/:id', autenticarToken, autorizarCargo('admin'), async (req, res) => {
    const { id } = req.params;
    const { username, senha, cargo, loja_id } = req.body;
    if (!username || !cargo) return res.status(400).json({ message: 'Usuário e cargo são obrigatórios.' });
    if (!['admin', 'gerente'].includes(cargo)) return res.status(400).json({ message: 'Cargo inválido' });
    if (parseInt(id) === req.user.id) return res.status(400).json({ message: 'Você não pode alterar seu próprio usuário.' });
    if (cargo === 'gerente' && !loja_id) return res.status(400).json({ message: 'Gerente precisa possuir uma loja.' });

    try {
      await pool.query(`UPDATE usuarios SET username = ?, cargo = ?, loja_id = ? WHERE id = ?`, [username, cargo, loja_id || null, id]);
      if (senha && senha.trim() !== "") {
        const senhaHash = await bcrypt.hash(senha, 10);
        await pool.query('UPDATE usuarios SET senha = ? WHERE id = ?', [senhaHash, id]);
      }
      res.json({ success: true });
    } catch (err) { res.status(500).json({ message: 'Erro ao atualizar usuário' }); }
});

app.delete('/usuarios/:id', autenticarToken, autorizarCargo('admin'), async (req, res) => {
    const { id } = req.params;
    try {
      if (parseInt(id) === req.user.id) return res.status(400).json({ message: 'Você não pode excluir seu próprio usuário.' });
      await pool.query('DELETE FROM usuarios WHERE id = ?', [id]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ message: 'Erro ao excluir usuário' }); }
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
});
