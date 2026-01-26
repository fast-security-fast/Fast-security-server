const express = require("express");
const http = require("http");
const WebSocket = require("ws");

const app = express();
app.use(express.json());

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;

// =====================
// TOKEN
// =====================
function checkToken(req, res) {
  const token = req.header("X-SOS-TOKEN");
  if (!process.env.SOS_TOKEN) {
    res.status(500).json({ ok: false, error: "SOS_TOKEN non configurato sul server" });
    return false;
  }
  if (token !== process.env.SOS_TOKEN) {
    res.status(401).json({ ok: false, error: "Unauthorized" });
    return false;
  }
  return true;
}

app.get("/", (req, res) => {
  res.json({ ok: true, message: "Fast Security server online", ws: "/ws" });
});

// GET (compatibilità)
app.get("/sos", (req, res) => {
  if (!checkToken(req, res)) return;
  console.log("🚨 SOS GET ricevuto");
  res.json({ ok: true, message: "SOS ricevuto (GET)" });
});

// POST (V3)
app.post("/sos", (req, res) => {
  if (!checkToken(req, res)) return;

  const { lat, lon, accuracy, timestamp, mode, battery, speedKmh } = req.body || {};
  console.log("🚨 SOS POST:", { lat, lon, accuracy, timestamp, mode, battery, speedKmh });

  res.json({ ok: true, message: "SOS ricevuto (POST)" });
});

// =====================
// WebRTC Signaling via WebSocket
// ws://<host>/ws
// =====================
const rooms = new Map(); // roomId -> Set(ws)

function safeSend(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

function joinRoom(ws, roomId) {
  if (!rooms.has(roomId)) rooms.set(roomId, new Set());
  rooms.get(roomId).add(ws);
  ws._roomId = roomId;
}

function leaveRoom(ws) {
  const r = ws._roomId;
  if (!r) return;
  const set = rooms.get(r);
  if (set) {
    set.delete(ws);
    if (set.size === 0) rooms.delete(r);
  }
  ws._roomId = null;
}

function broadcastToRoom(roomId, fromWs, msg) {
  const set = rooms.get(roomId);
  if (!set) return;
  for (const client of set) {
    if (client !== fromWs && client.readyState === WebSocket.OPEN) {
      safeSend(client, msg);
    }
  }
}

wss.on("connection", (ws, req) => {
  // Esempio messaggi:
  // {type:"join", room:"abc123", role:"sender"|"viewer"}
  // {type:"offer", sdp:"..."}
  // {type:"answer", sdp:"..."}
  // {type:"ice", candidate:{...}}

  ws.on("message", (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }

    if (msg.type === "join") {
      const room = String(msg.room || "").trim();
      if (!room) return safeSend(ws, { type: "error", error: "room mancante" });
      joinRoom(ws, room);
      safeSend(ws, { type: "joined", room });
      // Notifica agli altri
      broadcastToRoom(room, ws, { type: "peer-joined" });
      return;
    }

    const roomId = ws._roomId;
    if (!roomId) {
      return safeSend(ws, { type: "error", error: "Non sei in una room. Invia join prima." });
    }

    if (msg.type === "offer") {
      broadcastToRoom(roomId, ws, { type: "offer", sdp: msg.sdp });
      return;
    }
    if (msg.type === "answer") {
      broadcastToRoom(roomId, ws, { type: "answer", sdp: msg.sdp });
      return;
    }
    if (msg.type === "ice") {
      broadcastToRoom(roomId, ws, { type: "ice", candidate: msg.candidate });
      return;
    }
    if (msg.type === "hangup") {
      broadcastToRoom(roomId, ws, { type: "hangup" });
      return;
    }
  });

  ws.on("close", () => {
    const roomId = ws._roomId;
    leaveRoom(ws);
    if (roomId) broadcastToRoom(roomId, ws, { type: "peer-left" });
  });

  ws.on("error", () => {});
});

server.listen(PORT, () => {
  console.log(`🚀 Server Fast Security attivo sulla porta ${PORT}`);
});
