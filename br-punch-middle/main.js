const express = require('express');
const crypto = require('crypto');

const app = express();
require('express-ws')(app);
const port = process.env.PORT || 3000;
const proxyOk = Boolean(process.env.PROXY);

const sha1 = str => crypto.createHash('sha1').update(str).digest('hex');

const clients = [];
let ids = 0;

app.post('/api/join', (req, res) => {
  // get proxy agnostic ip
  let ip = proxyOk && req.headers['x-forwarded-for'] || req.socket.remoteAddress
  ip = ip.split(':').slice(-1)[0];
  ip = ip === '1' ? '127.0.0.1' : ip; // ipv6 localhost madness

  const port = parseInt(req.query.port || '0'); // get port
  const target = clients.find(t => t.hash === req.query.target); // get host from hash

  // check for valid port and target
  if (target && port > 1000 && port < 65535) {
    console.log(ip, 'wants to join', target.host, 'via', req.query.port);
    // tell the server to punch
    target.ws.send(`open ${ip} ${port}`);
  } else {
    console.log(ip, 'failed to join', req.query.target, 'via', req.query.port);
  }

  res.send('ok');
});

// websocket handler for host
app.ws('/api/host', (ws, req) => {
  // get proxy agnostic ip
  let ip = proxyOk && req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  ip = ip.split(':').slice(-1)[0];
  if (ip === '127.0.0.1' && process.env.EXTERNAL_IP)
    ip = process.env.EXTERNAL_IP;

  // create client entry
  const id = ids++;
  const client = {
    ws, ip, id,
    hash: '', host: '',
  };
  clients.push(client);

  // message handler, though the only message sent is server port
  ws.on('message', msg => {
    if (client.hash) return;
    const match = msg.match(/^server_port: *(\d{2,5})$/);
    if (match) {
      const host = `${ip}:${match[1]}`;
      const hash = sha1(host);
      if (clients.find(h => h.hash === hash)) {
        return ws.close();
      }
      client.host = host;
      client.hash = hash;
      console.log(id, 'is', host, 'with hash', hash);
      ws.send('ok');
    }
  });

  // remove client on socket close
  ws.on('close', () => {
    const index = clients.indexOf(client);
    if (index > -1) {
      clients[index] = clients[clients.length - 1];
      clients.pop();
    }
    console.log(id, 'left');
  });
});

app.get('/', (req, res) => res.send('this website helps you nat punch'));
app.listen(port, () => console.log('listening on', port));
