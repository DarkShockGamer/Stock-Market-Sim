// Zero-dependency static server (works on Railway, which provides PORT)
const http = require('http'), fs = require('fs'), path = require('path');
const PUB = path.join(__dirname, 'public');
const TYPES = { '.html':'text/html; charset=utf-8', '.js':'text/javascript', '.css':'text/css',
  '.json':'application/json', '.svg':'image/svg+xml', '.png':'image/png', '.ico':'image/x-icon' };
http.createServer((req, res) => {
  let p = decodeURIComponent(req.url.split('?')[0]);
  if (p === '/') p = '/index.html';
  const f = path.normalize(path.join(PUB, p));
  if (!f.startsWith(PUB)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(f, (e, d) => {
    if (e) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(f)] || 'application/octet-stream' });
    res.end(d);
  });
}).listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('Running on ' + (process.env.PORT || 3000)));
