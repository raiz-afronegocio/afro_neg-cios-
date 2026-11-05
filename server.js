// Raiz — servidor do site de classificados de pequenos produtores.
// Rode com:  npm install  e depois  npm start   (abre em http://localhost:3000)

const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'dados.json');

const CATS = ['Alimentos', 'Bebidas', 'Artesanato', 'Papelaria', 'Moda e beleza', 'Casa e decoração', 'Plantas e hortifrúti', 'Serviços', 'Outros'];
const CONDS = ['Novo', 'Feito à mão', 'Usado'];
const PAGS = ['Pix', 'Dinheiro', 'Cartão'];
const GMAIL = /^[a-z0-9._%+-]+@gmail\.com$/i;
const SESSAO_DIAS = 30;

/* ---------- banco de dados (arquivo JSON) ---------- */
let db = { users: {}, sessoes: {}, produtos: [], compras: [], avaliacoes: [], mensagens: [], dms: [], favs: {} };
try {
  db = { ...db, ...JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) };
  console.log('Dados carregados de', DATA_FILE);
} catch (e) {
  console.log('Começando com banco vazio em', DATA_FILE);
}
let saveTimer;
function salvar() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    const tmp = DATA_FILE + '.tmp';
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, DATA_FILE);
  }, 150);
}

/* ---------- utilidades ---------- */
const novoId = () => crypto.randomBytes(9).toString('base64url');
const str = (v, max) => String(v ?? '').trim().slice(0, max);
function gerarHash(senha) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: crypto.scryptSync(senha, salt, 64).toString('hex') };
}
function senhaConfere(senha, u) {
  const h = crypto.scryptSync(String(senha || ''), u.salt, 64);
  return crypto.timingSafeEqual(h, Buffer.from(u.hash, 'hex'));
}
function lerFoto(v, max = 450000) {
  v = String(v || '');
  if (!v) return '';
  if (!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(v) || v.length > max) return null;
  return v;
}
function disponivel(p) {
  if (p.estoque == null) return null;
  const usadas = db.compras.filter(c => c.item === p.id && c.t > (p.estoqueEm || 0) && !['recusado', 'cancelado'].includes(c.status)).length;
  return Math.max(0, p.estoque - usadas);
}
function vendidosDo(p) {
  return db.compras.filter(c => c.item === p.id && !['recusado', 'cancelado'].includes(c.status)).length;
}

/* ---------- avisos em tempo real ---------- */
let wss;
let avisoTimer;
function avisar() {
  clearTimeout(avisoTimer);
  avisoTimer = setTimeout(() => {
    if (!wss) return;
    for (const c of wss.clients) if (c.readyState === 1) c.send('atualizar');
  }, 80);
}
function mudou() { salvar(); avisar(); }

/* ---------- app ---------- */
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '3mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const ok = (res, extra = {}) => res.json({ ok: true, ...extra });
const erro = (res, msg, code = 400) => res.status(code).json({ erro: msg });

function auth(req, res, next) {
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const s = token && db.sessoes[token];
  if (!s || !db.users[s.uid] || Date.now() - s.t > SESSAO_DIAS * 864e5) {
    if (s) { delete db.sessoes[token]; salvar(); }
    return erro(res, 'Sua sessão expirou. Entre de novo.', 401);
  }
  req.uid = s.uid;
  req.token = token;
  next();
}
function criarSessao(uid) {
  const token = crypto.randomBytes(32).toString('hex');
  db.sessoes[token] = { uid, t: Date.now() };
  salvar();
  return token;
}

/* limite simples de tentativas de login */
const tentativas = new Map();
function limiteLogin(req, res, next) {
  const ip = req.ip;
  const agora = Date.now();
  const t = tentativas.get(ip) || { n: 0, desde: agora };
  if (agora - t.desde > 15 * 60e3) { t.n = 0; t.desde = agora; }
  t.n++;
  tentativas.set(ip, t);
  if (t.n > 15) return erro(res, 'Muitas tentativas. Espere alguns minutos e tente de novo.', 429);
  next();
}

/* ---------- contas ---------- */
app.post('/api/cadastro', limiteLogin, (req, res) => {
  const nome = str(req.body.nome, 40);
  const idade = parseInt(req.body.idade, 10);
  const gmail = str(req.body.gmail, 120).toLowerCase();
  const senha = String(req.body.senha || '');
  if (nome.length < 2) return erro(res, 'O nome da conta precisa ter pelo menos 2 letras.');
  if (!(idade >= 18 && idade <= 120)) return erro(res, 'O Raiz é só para maiores de 18 anos. Informe uma idade entre 18 e 120.');
  if (!GMAIL.test(gmail)) return erro(res, 'Use um endereço que termine em @gmail.com.');
  if (senha.length < 6) return erro(res, 'A senha precisa ter pelo menos 6 caracteres.');
  if (Object.values(db.users).some(u => u.gmail === gmail)) return erro(res, 'Já existe uma conta com esse Gmail. Use "Entrar".', 409);
  const id = 'u' + novoId();
  db.users[id] = { id, nome, idade, gmail, ...gerarHash(senha), ramo: '', sobre: '', foto: '', desde: Date.now() };
  const token = criarSessao(id);
  mudou();
  ok(res, { token });
});

app.post('/api/login', limiteLogin, (req, res) => {
  const gmail = str(req.body.gmail, 120).toLowerCase();
  const u = Object.values(db.users).find(x => x.gmail === gmail);
  if (!u || !senhaConfere(req.body.senha, u)) return erro(res, 'Gmail ou senha incorretos.', 401);
  ok(res, { token: criarSessao(u.id) });
});

app.post('/api/sair', auth, (req, res) => {
  delete db.sessoes[req.token];
  salvar();
  ok(res);
});

/* ---------- estado do site para quem está logado ---------- */
app.get('/api/estado', auth, (req, res) => {
  const me = req.uid;
  const u = db.users[me];
  const perfis = {};
  for (const x of Object.values(db.users)) perfis[x.id] = { nome: x.nome, ramo: x.ramo, sobre: x.sobre, foto: x.foto, desde: x.desde };
  const vendas = {};
  for (const c of db.compras) if (!['recusado', 'cancelado'].includes(c.status)) vendas[c.vend] = (vendas[c.vend] || 0) + 1;
  const produtos = db.produtos
    .filter(p => db.users[p.uid] && (!p.pausado || p.uid === me))
    .map(p => ({ ...p, disponivel: disponivel(p), vendidos: p.uid === me ? vendidosDo(p) : undefined }));
  res.json({
    me,
    perfis,
    vendas,
    produtos,
    avaliacoes: db.avaliacoes,
    mensagens: db.mensagens.slice(-150),
    conta: { idade: u.idade, gmail: u.gmail },
    favs: db.favs[me] || [],
    compras: db.compras.filter(c => c.comprador === me),
    pedidos: db.compras.filter(c => c.vend === me),
    dms: db.dms.filter(m => m.de === me || m.para === me),
  });
});

/* ---------- perfil e conta ---------- */
app.put('/api/perfil', auth, (req, res) => {
  const u = db.users[req.uid];
  const nome = str(req.body.nome, 40);
  if (nome.length < 2) return erro(res, 'O nome da conta precisa ter pelo menos 2 letras.');
  u.nome = nome;
  u.ramo = str(req.body.ramo, 60);
  u.sobre = str(req.body.sobre, 400);
  if (req.body.foto !== undefined) {
    const f = lerFoto(req.body.foto, 250000);
    if (f === null) return erro(res, 'Foto inválida ou grande demais.');
    u.foto = f;
  }
  mudou();
  ok(res);
});

app.put('/api/conta', auth, (req, res) => {
  const u = db.users[req.uid];
  const idade = parseInt(req.body.idade, 10);
  const gmail = str(req.body.gmail, 120).toLowerCase();
  if (!(idade >= 18 && idade <= 120)) return erro(res, 'O Raiz é só para maiores de 18 anos. Informe uma idade entre 18 e 120.');
  if (!GMAIL.test(gmail)) return erro(res, 'Use um endereço que termine em @gmail.com.');
  if (Object.values(db.users).some(x => x.gmail === gmail && x.id !== u.id)) return erro(res, 'Esse Gmail já está em outra conta.', 409);
  u.idade = idade;
  u.gmail = gmail;
  salvar();
  ok(res);
});

app.put('/api/senha', auth, (req, res) => {
  const u = db.users[req.uid];
  if (!senhaConfere(req.body.atual, u)) return erro(res, 'A senha atual está incorreta.');
  const nova = String(req.body.nova || '');
  if (nova.length < 6) return erro(res, 'A nova senha precisa ter pelo menos 6 caracteres.');
  Object.assign(u, gerarHash(nova));
  for (const [t, s] of Object.entries(db.sessoes)) if (s.uid === u.id && t !== req.token) delete db.sessoes[t];
  salvar();
  ok(res);
});

/* ---------- anúncios ---------- */
function lerProduto(b) {
  const nome = str(b.nome, 60);
  if (nome.length < 2) throw 'Dê um título ao anúncio.';
  if (!CATS.includes(b.cat)) throw 'Escolha uma categoria.';
  const preco = Number(b.preco);
  if (!(preco >= 0 && preco < 1e7)) throw 'Informe o preço só com números, por exemplo 18,90.';
  const qtd = parseInt(b.estoque, 10);
  if (!(qtd >= 0 && qtd <= 9999)) throw 'Informe a quantidade em estoque (0 a 9999).';
  const foto = lerFoto(b.foto);
  if (foto === null) throw 'Foto inválida ou grande demais.';
  const entrega = { ret: !!(b.entrega && b.entrega.ret), ent: !!(b.entrega && b.entrega.ent) };
  if (!entrega.ret && !entrega.ent) throw 'Escolha pelo menos uma forma de entrega.';
  const pag = (Array.isArray(b.pag) ? b.pag : []).filter(x => PAGS.includes(x));
  if (!pag.length) throw 'Escolha pelo menos uma forma de pagamento.';
  return {
    dados: {
      nome, cat: b.cat, preco: Math.round(preco * 100) / 100, foto,
      cond: CONDS.includes(b.cond) ? b.cond : 'Novo', entrega, pag,
      desc: str(b.desc, 400), local: str(b.local, 50),
    },
    qtd,
  };
}

app.post('/api/produtos', auth, (req, res) => {
  let r;
  try { r = lerProduto(req.body); } catch (e) { return erro(res, String(e)); }
  if (db.produtos.filter(p => p.uid === req.uid).length >= 8) return erro(res, 'Você já tem 8 anúncios. Remova um para publicar outro.');
  const agora = Date.now();
  db.produtos.push({ id: novoId(), uid: req.uid, ...r.dados, estoque: r.qtd, estoqueEm: agora, t: agora, pausado: false });
  mudou();
  ok(res);
});

app.put('/api/produtos/:id', auth, (req, res) => {
  const p = db.produtos.find(x => x.id === req.params.id && x.uid === req.uid);
  if (!p) return erro(res, 'Anúncio não encontrado.', 404);
  let r;
  try { r = lerProduto(req.body); } catch (e) { return erro(res, String(e)); }
  Object.assign(p, r.dados);
  if (disponivel(p) !== r.qtd) { p.estoque = r.qtd; p.estoqueEm = Date.now(); }
  mudou();
  ok(res);
});

app.post('/api/produtos/:id/pausar', auth, (req, res) => {
  const p = db.produtos.find(x => x.id === req.params.id && x.uid === req.uid);
  if (!p) return erro(res, 'Anúncio não encontrado.', 404);
  p.pausado = !!req.body.pausado;
  mudou();
  ok(res);
});

app.delete('/api/produtos/:id', auth, (req, res) => {
  const antes = db.produtos.length;
  db.produtos = db.produtos.filter(x => !(x.id === req.params.id && x.uid === req.uid));
  if (db.produtos.length === antes) return erro(res, 'Anúncio não encontrado.', 404);
  for (const f of Object.values(db.favs)) {
    for (let i = f.length - 1; i >= 0; i--) if (f[i].endsWith('|' + req.params.id)) f.splice(i, 1);
  }
  mudou();
  ok(res);
});

/* ---------- compras e pedidos ---------- */
app.post('/api/comprar', auth, (req, res) => {
  const p = db.produtos.find(x => x.id === req.body.produto && !x.pausado);
  if (!p || !db.users[p.uid]) return erro(res, 'Este anúncio não está mais disponível.', 404);
  if (p.uid === req.uid) return erro(res, 'Você não pode comprar o seu próprio anúncio.');
  const d = disponivel(p);
  if (d === 0) return erro(res, 'Esse produto acabou de esgotar.', 409);
  const c = { id: novoId(), comprador: req.uid, vend: p.uid, item: p.id, nome: p.nome, preco: p.preco, t: Date.now(), status: 'novo' };
  db.compras.push(c);
  mudou();
  ok(res, { compra: c });
});

app.post('/api/compras/:id/cancelar', auth, (req, res) => {
  const c = db.compras.find(x => x.id === req.params.id && x.comprador === req.uid);
  if (!c) return erro(res, 'Compra não encontrada.', 404);
  if (c.status !== 'novo') return erro(res, 'Só dá para cancelar antes de o vendedor confirmar.');
  c.status = 'cancelado';
  c.tStatus = Date.now();
  mudou();
  ok(res);
});

const TRANSICOES = { novo: ['confirmado', 'recusado'], confirmado: ['entregue', 'recusado'] };
app.post('/api/pedidos/:id/status', auth, (req, res) => {
  const c = db.compras.find(x => x.id === req.params.id && x.vend === req.uid);
  if (!c) return erro(res, 'Pedido não encontrado.', 404);
  const s = String(req.body.s || '');
  if (!(TRANSICOES[c.status] || []).includes(s)) return erro(res, 'Esse pedido não pode mudar para esse status.');
  c.status = s;
  c.tStatus = Date.now();
  mudou();
  ok(res);
});

/* ---------- avaliações ---------- */
app.put('/api/avaliacoes/:prod', auth, (req, res) => {
  const prod = req.params.prod;
  if (!db.users[prod] || prod === req.uid) return erro(res, 'Vendedor inválido.');
  const n = parseInt(req.body.n, 10);
  if (!(n >= 1 && n <= 5)) return erro(res, 'Escolha de 1 a 5 estrelas.');
  db.avaliacoes = db.avaliacoes.filter(a => !(a.autor === req.uid && a.prod === prod));
  db.avaliacoes.push({ autor: req.uid, prod, n, txt: str(req.body.txt, 500), rec: !!req.body.rec, t: Date.now() });
  mudou();
  ok(res);
});
app.delete('/api/avaliacoes/:prod', auth, (req, res) => {
  db.avaliacoes = db.avaliacoes.filter(a => !(a.autor === req.uid && a.prod === req.params.prod));
  mudou();
  ok(res);
});

/* ---------- favoritos ---------- */
app.post('/api/favs', auth, (req, res) => {
  const k = str(req.body.k, 80);
  if (!/^[\w-]+\|[\w-]+$/.test(k)) return erro(res, 'Favorito inválido.');
  const l = db.favs[req.uid] = db.favs[req.uid] || [];
  const i = l.indexOf(k);
  if (i >= 0) l.splice(i, 1); else { l.push(k); if (l.length > 200) l.shift(); }
  salvar();
  ok(res, { favs: l });
});

/* ---------- chat geral ---------- */
app.post('/api/mensagens', auth, (req, res) => {
  const txt = str(req.body.txt, 500);
  if (!txt) return erro(res, 'Escreva uma mensagem.');
  db.mensagens.push({ id: novoId(), uid: req.uid, t: Date.now(), txt });
  if (db.mensagens.length > 500) db.mensagens.splice(0, db.mensagens.length - 500);
  mudou();
  ok(res);
});
app.delete('/api/mensagens/:id', auth, (req, res) => {
  db.mensagens = db.mensagens.filter(m => !(m.id === req.params.id && m.uid === req.uid));
  mudou();
  ok(res);
});

/* ---------- conversas privadas ---------- */
app.post('/api/dm/:para', auth, (req, res) => {
  const para = req.params.para;
  if (!db.users[para] || para === req.uid) return erro(res, 'Destinatário inválido.');
  const txt = str(req.body.txt, 500);
  if (!txt) return erro(res, 'Escreva uma mensagem.');
  db.dms.push({ id: novoId(), de: req.uid, para, t: Date.now(), txt });
  if (db.dms.length > 20000) db.dms.splice(0, db.dms.length - 20000);
  mudou();
  ok(res);
});
app.delete('/api/dm/msg/:id', auth, (req, res) => {
  db.dms = db.dms.filter(m => !(m.id === req.params.id && m.de === req.uid));
  mudou();
  ok(res);
});

app.get('/api/saude', (req, res) => ok(res, { usuarios: Object.keys(db.users).length }));
app.use('/api', (req, res) => erro(res, 'Rota não encontrada.', 404));

/* ---------- iniciar ---------- */
const server = http.createServer(app);
wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', ws => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
});
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false;
    ws.ping();
  }
}, 30000);

server.listen(PORT, () => console.log(`Raiz rodando em http://localhost:${PORT}`));
