// Zero-dependency server for the VHD form. Data is kept on the local disk
// (wiped on redeploy, which is fine for a one-time form).
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const VIEW_PW = process.env.VIEW_PASSWORD || '1234';
const EDIT_PW = process.env.EDIT_PASSWORD || '4321';
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const MAX_IMG = 10 * 1024 * 1024;

fs.mkdirSync(path.join(DIR, 'img'), { recursive: true });
const STATE_FILE = path.join(DIR, 'state.json');
let state = { f: {}, img: {} };
try { state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch {}
const persist = () => fs.writeFileSync(STATE_FILE, JSON.stringify(state));

const tokens = new Map();           // token -> role
const fails = new Map();            // ip -> {n, until}

const send = (res, code, body, type = 'application/json') => {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
};
const readBody = (req, limit) => new Promise((resolve, reject) => {
  const chunks = []; let size = 0;
  req.on('data', c => { size += c.length; if (size > limit) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
  req.on('end', () => resolve(Buffer.concat(chunks)));
  req.on('error', reject);
});
const same = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;

    if (req.method === 'GET' && (p === '/' || p === '/index.html'))
      return send(res, 200, fs.readFileSync(path.join(__dirname, 'index.html')), 'text/html; charset=utf-8');

    if (p === '/api/login' && req.method === 'POST') {
      const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
      const f = fails.get(ip);
      if (f && f.n >= 8 && Date.now() < f.until) return send(res, 429, { error: 'Thử lại sau' });
      const { password = '' } = JSON.parse((await readBody(req, 1e4)).toString() || '{}');
      let role = null;
      if (same(String(password), EDIT_PW)) role = 'edit';
      else if (same(String(password), VIEW_PW)) role = 'view';
      if (!role) {
        fails.set(ip, { n: (f?.n || 0) + 1, until: Date.now() + 60000 });
        return send(res, 401, { error: 'Sai mật khẩu' });
      }
      fails.delete(ip);
      const token = crypto.randomBytes(24).toString('hex');
      tokens.set(token, role);
      return send(res, 200, { token, role });
    }

    // everything below needs a token
    const auth = (req.headers.authorization || '').replace(/^Bearer /, '') || url.searchParams.get('t') || '';
    const role = tokens.get(auth);
    if (!role) return send(res, 401, { error: 'unauthorized' });

    if (p === '/api/state' && req.method === 'GET') return send(res, 200, { role, ...state });

    if (p === '/api/fields' && req.method === 'PUT') {
      if (role !== 'edit') return send(res, 403, { error: 'read only' });
      const { f } = JSON.parse((await readBody(req, 1e6)).toString());
      if (typeof f !== 'object' || !f) return send(res, 400, { error: 'bad body' });
      state.f = f; persist();
      return send(res, 200, { ok: true });
    }

    let m;
    if ((m = p.match(/^\/api\/img\/([a-z_]+)$/)) && req.method === 'POST') {
      if (role !== 'edit') return send(res, 403, { error: 'read only' });
      const gid = m[1];
      if ((state.img[gid] || []).length >= 20) return send(res, 400, { error: 'max 20 ảnh' });
      const buf = await readBody(req, MAX_IMG);
      const id = crypto.randomBytes(8).toString('hex');
      fs.writeFileSync(path.join(DIR, 'img', id + '.jpg'), buf);
      (state.img[gid] ||= []).push(id); persist();
      return send(res, 200, { id });
    }
    if ((m = p.match(/^\/api\/img\/([a-z_]+)\/([0-9a-f]{16})$/)) && req.method === 'DELETE') {
      if (role !== 'edit') return send(res, 403, { error: 'read only' });
      const [, gid, id] = m;
      state.img[gid] = (state.img[gid] || []).filter(x => x !== id); persist();
      fs.rm(path.join(DIR, 'img', id + '.jpg'), () => {});
      return send(res, 200, { ok: true });
    }
    if ((m = p.match(/^\/api\/img\/([0-9a-f]{16})$/)) && req.method === 'GET') {
      const file = path.join(DIR, 'img', m[1] + '.jpg');
      if (!fs.existsSync(file)) return send(res, 404, { error: 'not found' });
      res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Cache-Control': 'private, max-age=3600' });
      return fs.createReadStream(file).pipe(res);
    }

    send(res, 404, { error: 'not found' });
  } catch (e) {
    send(res, 500, { error: 'server error' });
  }
}).listen(PORT, '0.0.0.0', () => console.log('VHD form on port ' + PORT));
