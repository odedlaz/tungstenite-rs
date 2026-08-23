// Reference permessage-deflate echo server: Node `ws`.
//
// The control needs a peer that is known-good and is not ours, so that a memory
// runaway in `wstest` can be attributed to the tester rather than to what our
// server sends. `threshold: 0` compresses every payload; leaving ws's 1 KiB
// default would hand the tester less compressed data than tungstenite does and
// make a quiet arm uninformative.
const { WebSocketServer } = require('ws');

const wss = new WebSocketServer({
  host: '127.0.0.1',
  port: 9002,
  maxPayload: 64 * 1024 * 1024,
  perMessageDeflate: { threshold: 0 },
});

wss.on('connection', (ws) => {
  ws.on('message', (data, isBinary) => ws.send(data, { binary: isBinary }));
  // Autobahn's protocol-violation cases close hard on purpose; an unhandled
  // 'error' would take the whole process down mid-suite.
  ws.on('error', () => {});
});

wss.on('listening', () => console.log('node-ws testee listening on 9002'));
