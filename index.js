const express = require("express");
const cors = require("cors");
const http = require("http");
const WebSocket = require("ws");

require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

/**
 * TOKEN CHECK
 * Header: X-SOS-TOKEN
 */
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
  res.json({ ok: true, message: "Fast Security server online" });
});

/**
 * GET /sos (compatibilità)
 */
app.get("/sos", (req, res) => {
  if (!checkToken(req, res)) return;
  console.log("🚨 SOS GET ricevuto");
  res.json({ ok: true, message: "SOS ricevuto (GET)" });
});

/**
 * POST /sos (V3 Pro)
 * Body: { lat, lon, accuracy?, timestamp?, mode?, battery?, speedKmh?, incident? }
 */
app.post("/sos", (req, res) => {
  if (!checkToken(req, res)) return;

  const body = req.body || {};
  const {
    lat,
    lon,
    accuracy,
    timestamp,
    mode,
    battery,
    speedKmh,
    incident
  } = body;

  // lat/lon possono essere null in casi particolari, ma qui li gestiamo:
  if (typeof lat !== "number" || typeof lon !== "number") {
    return res.status(400).json({ ok: false, error: "Invalid lat/lon" });
  }

  console.log("🚨 SOS POST ricevuto:", {
    lat,
    lon,
    accuracy,
    timestamp,
    mode,
    battery,
    speedKmh,
    incident
  });

  res.json({
    ok: true,
    message: "SOS ricevuto (POST)",
    received: {
      lat,
      lon,
      accuracy: accuracy ?? null,
      timestamp: timestamp ?? Date.now(),
      mode: mode ?? "UNKNOWN",
      battery: battery ?? null,
      speedKmh: speedKmh ?? null,
      incident: incident ?? null
    }
  });
});

/**
 * ============ WEBSOCKET SIGNALING (WebRTC) ============
 * Endpoint: /ws
 *
 * Messaggi JSON:
 * 1) join:   { "type":"join", "room":"abc", "peerId":"p1" }
 * 2) offer:  { "type":"offer", "room":"abc", "from":"p1", "to":"p2", "sdp":{...} }
 * 3) answer: { "type":"answer","room":"abc", "from":"p2", "to":"p1", "sdp":{...} }
 * 4) ice:    { "type":"ice",   "room":"abc", "from":"p1", "to":"p2", "candidate":{...} }
 * 5) leave:  { "type":"leave", "room":"abc", "peerId":"p1" }
 */
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: "/ws" });

// rooms: Map<room, Map<peerId, ws>>
const rooms = new Map();

function safeSend(ws, obj) {
  try {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(obj));
    }
  } catch (_) {}
}

function roomPeers(room) {
  const m = rooms.get(room);
  if (!m) return [];
  return [...m.keys()];
}

function removePeer(room, peerId) {
  const m = rooms.get(room);
  if (!m) return;

  m.delete(peerId);
  if (m.size === 0) rooms.delete(room);
}

function broadcastToRoom(room, obj, exceptPeerId = null) {
  const m = rooms.get(room);
  if (!m) return;

  for (const [pid, ws] of m.entries()) {
    if (exceptPeerId && pid === exceptPeerId) continue;
    safeSend(ws, obj);
  }
}

wss.on("connection", (ws) => {
  ws._peerId = null;
  ws._room = null;

  safeSend(ws, { type: "hello", ok: true, message: "ws connected" });

  ws.on("message", (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch (e) {
      return safeSend(ws, { type: "error", error: "invalid_json" });
    }

    const type = msg.type;

    // JOIN
    if (type === "join") {
      const room = String(msg.room || "").trim();
      const peerId = String(msg.peerId || "").trim();
      if (!room || !peerId) {
        return safeSend(ws, { type: "error", error: "missing_room_or_peerId" });
      }

      // salva
      ws._room = room;
      ws._peerId = peerId;

      if (!rooms.has(room)) rooms.set(room, new Map());
      const peers = rooms.get(room);

      // se peerId già esiste, rimpiazza
      peers.set(peerId, ws);

      // invia lista peer al nuovo
      safeSend(ws, { type: "joined", room, peerId, peers: roomPeers(room).filter(p => p !== peerId) });

      // avvisa gli altri che è entrato
      broadcastToRoom(room, { type: "peer-joined", room, peerId }, peerId);
      return;
    }

    // LEAVE
    if (type === "leave") {
      const room = ws._room || msg.room;
      const peerId = ws._peerId || msg.peerId;
      if (room && peerId) {
        removePeer(room, peerId);
        broadcastToRoom(room, { type: "peer-left", room, peerId }, peerId);
      }
      ws._room = null;
      ws._peerId = null;
      return safeSend(ws, { type: "left", ok: true });
    }

    // OFFER / ANSWER / ICE -> forward al destinatario
    if (type === "offer" || type === "answer" || type === "ice") {
      const room = String(msg.room || ws._room || "").trim();
      const to = String(msg.to || "").trim();
      const from = String(msg.from || ws._peerId || "").trim();

      if (!room || !to || !from) {
        return safeSend(ws, { type: "error", error: "missing_room_to_from" });
      }

      const peers = rooms.get(room);
      const target = peers ? peers.get(to) : null;
      if (!target) {
        return safeSend(ws, { type: "error", error: "target_not_found", to });
      }

      // inoltra ESATTAMENTE il messaggio (ma garantiamo room/from/to)
      const payload = { ...msg, room, from, to };
      safeSend(target, payload);
      return;
    }

    // fallback
    safeSend(ws, { type: "error", error: "unknown_type" });
  });

  ws.on("close", () => {
    const room = ws._room;
    const peerId = ws._peerId;
    if (room && peerId) {
      removePeer(room, peerId);
      broadcastToRoom(room, { type: "peer-left", room, peerId }, peerId);
    }
  });
});

server.listen(PORT, () => {
  console.log(`🚀 Server Fast Security attivo sulla porta ${PORT}`);
  console.log(`✅ HTTP: /  /sos (GET+POST)`);
  console.log(`✅ WS: /ws`);
});
