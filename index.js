const express = require("express");
const cors = require("cors");
const http = require("http");
const WebSocket = require("ws");
require("dotenv").config();

const fs = require("fs");

// ================================
// Firebase Admin init (robusto)
// ================================
let admin = null;
let db = null;

function initFirebaseAdmin() {
  try {
    admin = require("firebase-admin");

    // già inizializzato (hot reload / reuse)
    if (admin.apps.length) {
      db = admin.firestore();
      console.log("✅ Firebase Admin già inizializzato");
      return { ok: true, source: "already_initialized" };
    }

    // 1) ENV JSON completo
    const saJson = process.env.FIREBASE_SA_JSON;
    if (saJson && saJson.trim().startsWith("{")) {
      const serviceAccount = JSON.parse(saJson);
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
      });
      db = admin.firestore();
      console.log("✅ Firebase Admin init da FIREBASE_SA_JSON");
      return { ok: true, source: "FIREBASE_SA_JSON" };
    }

    // 2) File path (Render Secret File)
    const credPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
    if (credPath) {
      if (!fs.existsSync(credPath)) {
        console.error(`❌ GOOGLE_APPLICATION_CREDENTIALS punta a file mancante: ${credPath}`);
        return { ok: false, reason: "gac_file_missing", path: credPath };
      }
      admin.initializeApp(); // usa GOOGLE_APPLICATION_CREDENTIALS
      db = admin.firestore();
      console.log("✅ Firebase Admin init da GOOGLE_APPLICATION_CREDENTIALS =", credPath);
      return { ok: true, source: `GOOGLE_APPLICATION_CREDENTIALS:${credPath}` };
    }

    console.warn("⚠️ Firebase Admin NON pronto: manca FIREBASE_SA_JSON o GOOGLE_APPLICATION_CREDENTIALS");
    return { ok: false, reason: "no_credentials" };
  } catch (e) {
    console.error("❌ Firebase Admin init error:", e?.message || e);
    return { ok: false, reason: "init_exception" };
  }
}

const fb = initFirebaseAdmin();
const firebaseReady = fb.ok;

if (firebaseReady) {
  console.log("✅ Firebase Admin inizializzato (Firestore+FCM) | source:", fb.source);
} else {
  console.warn("⚠️ Firebase Admin NON pronto:", fb);
  console.warn("⚠️ /event risponderà 503 finché non configuri le credenziali.");
}

// ================================
// Express
// ================================
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

/**
 * TOKEN CHECK (HTTP)
 * Header: X-SOS-TOKEN
 */
function checkToken(req, res) {
  const token = req.header("X-SOS-TOKEN");

  if (!process.env.SOS_TOKEN) {
    res.status(500).json({ ok: false, error: "SOS_TOKEN_not_configured" });
    return false;
  }

  if (token !== process.env.SOS_TOKEN) {
    res.status(401).json({ ok: false, error: "Unauthorized" });
    return false;
  }
  return true;
}

// ✅ debug (chiuso correttamente)
app.get("/debug/firebase", (req, res) => {
  res.json({
    ok: true,
    firebaseReady,
    hasAdmin: !!admin,
    hasDb: !!db,
    hasFIREBASE_SA_JSON: !!process.env.FIREBASE_SA_JSON,
    GOOGLE_APPLICATION_CREDENTIALS: process.env.GOOGLE_APPLICATION_CREDENTIALS || null,
    SOS_TOKEN_set: !!process.env.SOS_TOKEN,
  });
});

app.get("/health", (req, res) =>
  res.json({ ok: true, firebaseAdmin: !!admin, firestore: !!db })
);

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
 * POST /sos (compatibilità V3)
 */
app.post("/sos", (req, res) => {
  if (!checkToken(req, res)) return;

  const body = req.body || {};
  const { lat, lon, accuracy, timestamp, mode, battery, speedKmh, incident, victimUid } = body;

  if (typeof lat !== "number" || typeof lon !== "number") {
    return res.status(400).json({ ok: false, error: "Invalid lat/lon" });
  }

  console.log("🚨 SOS POST ricevuto:", {
    victimUid: victimUid || null,
    lat,
    lon,
    accuracy,
    timestamp,
    mode,
    battery,
    speedKmh,
    incident,
  });

  res.json({
    ok: true,
    message: "SOS ricevuto (POST)",
    received: {
      victimUid: victimUid ?? null,
      lat,
      lon,
      accuracy: accuracy ?? null,
      timestamp: timestamp ?? Date.now(),
      mode: mode ?? "UNKNOWN",
      battery: battery ?? null,
      speedKmh: speedKmh ?? null,
      incident: incident ?? null,
    },
  });
});

/**
 * ✅ POST /event (Dispatcher ufficiale)
 * Accetta lat/lon null (se shareLoc=false), ma se presenti devono essere number
 */
app.post("/event", async (req, res) => {
  if (!checkToken(req, res)) return;

  if (!admin || !db) {
    return res.status(503).json({
      ok: false,
      error: "firebase_admin_not_ready",
      hint:
        "Configura FIREBASE_SA_JSON (ENV) oppure GOOGLE_APPLICATION_CREDENTIALS (Render Secret File) e redeploy",
    });
  }

  try {
    const body = req.body || {};
    const type = String(body.type || "").trim().toUpperCase();
    const victimUid = String(body.victimUid || "").trim();

    const lat = body.lat;
    const lon = body.lon;

    if (!["SOS", "PROTECT", "INCIDENT"].includes(type)) {
      return res.status(400).json({ ok: false, error: "Invalid type (use SOS|PROTECT|INCIDENT)" });
    }
    if (!victimUid) {
      return res.status(400).json({ ok: false, error: "Missing victimUid" });
    }

    const latOk = lat == null || typeof lat === "number";
    const lonOk = lon == null || typeof lon === "number";
    if (!latOk || !lonOk) {
      return res.status(400).json({ ok: false, error: "Invalid lat/lon (must be number or null)" });
    }

    const eventId = `${Date.now()}_${Math.random().toString(16).slice(2)}`;
    const ts = body.timestamp != null ? Number(body.timestamp) : Date.now();

    const accuracy = body.accuracy != null ? Number(body.accuracy) : null;
    const battery = body.battery != null ? Number(body.battery) : null;
    const speedKmh = body.speedKmh != null ? Number(body.speedKmh) : null;
    const altitude = body.altitude != null ? Number(body.altitude) : null;
    const heading = body.heading != null ? Number(body.heading) : null;

    const address = typeof body.address === "string" ? body.address.trim() : "";
    const addressOk = normalizeBool(body.addressOk);

    console.log(`🚨 EVENT ricevuto: ${type}`, {
      eventId,
      victimUid,
      lat: lat ?? null,
      lon: lon ?? null,
      mode: body.mode || null,
      accuracy,
      battery,
      speedKmh,
      altitude,
      addressOk,
    });

    const trustedUids = await getTrustedUids(db, victimUid);
    const tokens = await getTrustedTokens(db, trustedUids);

    const dataPayload = toFcmData({
      type,
      eventId,
      victimUid,
      lat: lat ?? null,
      lon: lon ?? null,
      accuracy,
      battery,
      speedKmh,
      altitude,
      heading,
      address,
      addressOk,
      mode: body.mode,
      timestamp: ts,
      incident: body.incident,
    });

    const results = await sendToTokens(admin, tokens, dataPayload);

    await db.collection("events").doc(eventId).set({
      type,
      eventId,
      victimUid,
      lat: lat ?? null,
      lon: lon ?? null,
      accuracy,
      battery,
      speedKmh,
      altitude,
      heading,
      address: address || null,
      addressOk,
      mode: body.mode ?? null,
      timestamp: ts,
      incident: body.incident ?? null,
      trustedUids,
      tokensCount: tokens.length,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.json({
      ok: true,
      eventId,
      trustedUidsCount: trustedUids.length,
      tokensCount: tokens.length,
      fcm: results,
    });
  } catch (e) {
    console.error("❌ POST /event error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

/* =========================
   Helpers Firestore + FCM
   ========================= */

function normalizeBool(v) {
  if (v === true || v === false) return v;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (s === "true" || s === "1" || s === "yes") return true;
    if (s === "false" || s === "0" || s === "no") return false;
  }
  if (typeof v === "number") return v !== 0;
  return false;
}

function toFcmData(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    out[k] = String(v);
  }
  return out;
}

async function getTrustedUids(db, victimUid) {
  // Schema A: users/{victimUid}/trustedContacts/{trustedUid}
  try {
    const sub = await db.collection("users").doc(victimUid).collection("trustedContacts").get();
    if (!sub.empty) return sub.docs.map((d) => d.id);
  } catch (_) {}

  // Schema B: users/{victimUid}.trustedUids array
  try {
    const userDoc = await db.collection("users").doc(victimUid).get();
    if (userDoc.exists) {
      const data = userDoc.data() || {};
      if (Array.isArray(data.trustedUids) && data.trustedUids.length) {
        return data.trustedUids.map(String);
      }
    }
  } catch (_) {}

  return [];
}

async function getTrustedTokens(db, trustedUids) {
  const tokens = [];

  for (const uid of trustedUids) {
    // Schema A: users/{uid}/fcmTokens/*
    try {
      const snap = await db.collection("users").doc(uid).collection("fcmTokens").get();
      if (!snap.empty) {
        for (const d of snap.docs) {
          const data = d.data() || {};
          const t = data.token || d.id;
          if (t) tokens.push(String(t));
        }
        continue;
      }
    } catch (_) {}

    // Schema B: users/{uid}.fcmToken o fcmTokens[]
    try {
      const userDoc = await db.collection("users").doc(uid).get();
      if (userDoc.exists) {
        const data = userDoc.data() || {};
        if (data.fcmToken) tokens.push(String(data.fcmToken));
        if (Array.isArray(data.fcmTokens)) data.fcmTokens.forEach((t) => tokens.push(String(t)));
      }
    } catch (_) {}
  }

  return [...new Set(tokens)].filter((t) => typeof t === "string" && t.length > 20);
}

async function sendToTokens(admin, tokens, data) {
  if (!tokens.length) return { sent: 0, failures: 0, batches: 0 };

  const BATCH = 500;
  let sent = 0;
  let failures = 0;
  let batches = 0;

  for (let i = 0; i < tokens.length; i += BATCH) {
    const chunk = tokens.slice(i, i + BATCH);
    batches++;

    const resp = await admin.messaging().sendEachForMulticast({
      tokens: chunk,
      android: { priority: "high" },
      data, // data-only
    });

    sent += resp.successCount;
    failures += resp.failureCount;

    resp.responses.forEach((r, idx) => {
      if (!r.success) console.warn("⚠️ FCM fail token:", chunk[idx], r.error?.message);
    });
  }

  return { sent, failures, batches };
}

/**
 * ============ WEBSOCKET SIGNALING ============
 */
const server = http.createServer(app);

const wss = new WebSocket.Server({
  server,
  path: "/ws",
  maxPayload: 1024 * 1024,
});

const rooms = new Map();

function safeSend(ws, obj) {
  try {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
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

const WS_TOKEN = process.env.WS_TOKEN || null;

function wsAuthorized(msg) {
  if (!WS_TOKEN) return true;
  return msg && msg.token === WS_TOKEN;
}

function heartbeat() {
  this.isAlive = true;
}

wss.on("connection", (ws) => {
  ws._peerId = null;
  ws._room = null;

  ws.isAlive = true;
  ws.on("pong", heartbeat);

  safeSend(ws, { type: "hello", ok: true, message: "ws connected", path: "/ws" });

  ws.on("message", (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return safeSend(ws, { type: "error", error: "invalid_json" });
    }

    const type = msg.type;

    if (type === "join") {
      if (!wsAuthorized(msg)) {
        safeSend(ws, { type: "error", error: "unauthorized_ws" });
        try { ws.close(1008, "Unauthorized"); } catch (_) {}
        return;
      }

      const room = String(msg.room || "").trim();
      const peerId = String(msg.peerId || "").trim();
      if (!room || !peerId) {
        return safeSend(ws, { type: "error", error: "missing_room_or_peerId" });
      }

      ws._room = room;
      ws._peerId = peerId;

      if (!rooms.has(room)) rooms.set(room, new Map());
      const peers = rooms.get(room);

      const old = peers.get(peerId);
      if (old && old !== ws) {
        try { safeSend(old, { type: "bye", reason: "replaced_by_new_connection" }); } catch (_) {}
        try { old.close(1000, "Replaced"); } catch (_) {}
      }

      peers.set(peerId, ws);

      safeSend(ws, {
        type: "joined",
        room,
        peerId,
        peers: roomPeers(room).filter((p) => p !== peerId),
      });

      broadcastToRoom(room, { type: "peer-joined", room, peerId }, peerId);
      return;
    }

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

      const payload = { ...msg, room, from, to };
      safeSend(target, payload);
      return;
    }

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

// ping keep-alive
const pingInterval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      try { ws.terminate(); } catch (_) {}
      return;
    }
    ws.isAlive = false;
    try { ws.ping(); } catch (_) {}
  });
}, 30000);

wss.on("close", () => clearInterval(pingInterval));

server.listen(PORT, () => {
  console.log(`🚀 Server Fast Security attivo sulla porta ${PORT}`);
  console.log(`✅ HTTP: /  /health  /sos (GET+POST)  /event (POST)`);
  console.log(`✅ WS: /ws`);
  console.log(`✅ WS_TOKEN: ${WS_TOKEN ? "ON" : "OFF (dev)"}`);
});
