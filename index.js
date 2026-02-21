"use strict";

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

    // già inizializzato
    if (admin.apps && admin.apps.length) {
      db = admin.firestore();
      return { ok: true, source: "already_initialized" };
    }

    // 1) ENV JSON (stringa JSON completa)
    if (process.env.FIREBASE_SA_JSON && process.env.FIREBASE_SA_JSON.trim().startsWith("{")) {
      const credObj = JSON.parse(process.env.FIREBASE_SA_JSON);
      admin.initializeApp({ credential: admin.credential.cert(credObj) });
      db = admin.firestore();
      return { ok: true, source: "FIREBASE_SA_JSON" };
    }

    // 2) ENV base64 (opzionale)
    if (process.env.FIREBASE_SA_B64) {
      const raw = Buffer.from(process.env.FIREBASE_SA_B64, "base64").toString("utf8");
      const credObj = JSON.parse(raw);
      admin.initializeApp({ credential: admin.credential.cert(credObj) });
      db = admin.firestore();
      return { ok: true, source: "FIREBASE_SA_B64" };
    }

    // 3) Secret file path (Render)
    const gac = process.env.GOOGLE_APPLICATION_CREDENTIALS;
    if (gac) {
      if (!fs.existsSync(gac)) {
        return { ok: false, reason: "gac_file_missing", path: gac };
      }
      admin.initializeApp(); // usa GOOGLE_APPLICATION_CREDENTIALS
      db = admin.firestore();
      return { ok: true, source: `GOOGLE_APPLICATION_CREDENTIALS:${gac}` };
    }

    return { ok: false, reason: "no_credentials" };
  } catch (e) {
    return { ok: false, reason: "init_error", message: e?.message || String(e) };
  }
}

const fb = initFirebaseAdmin();
console.log(fb.ok
  ? `✅ Firebase Admin READY | source: ${fb.source}`
  : `⚠️ Firebase Admin NOT READY | ${JSON.stringify(fb)}`
);

// ================================
// Express
// ================================
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Token check
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

app.get("/", (req, res) => res.json({ ok: true, message: "Fast Security server online" }));

app.get("/health", (req, res) =>
  res.json({ ok: true, firebaseReady: !!db, hasAdmin: !!admin, port: PORT })
);

app.get("/debug/firebase", (req, res) => {
  res.json({
    ok: true,
    firebaseInit: fb,
    hasAdmin: !!admin,
    hasDb: !!db,
    hasFIREBASE_SA_JSON: !!process.env.FIREBASE_SA_JSON,
    hasFIREBASE_SA_B64: !!process.env.FIREBASE_SA_B64,
    GOOGLE_APPLICATION_CREDENTIALS: process.env.GOOGLE_APPLICATION_CREDENTIALS || null,
    SOS_TOKEN_set: !!process.env.SOS_TOKEN,
  });
});

// Compat GET /sos
app.get("/sos", (req, res) => {
  if (!checkToken(req, res)) return;
  console.log("🚨 SOS GET ricevuto");
  res.json({ ok: true, message: "SOS ricevuto (GET)" });
});

// Compat POST /sos
app.post("/sos", (req, res) => {
  if (!checkToken(req, res)) return;

  const body = req.body || {};
  const { lat, lon } = body;

  if (typeof lat !== "number" || typeof lon !== "number") {
    return res.status(400).json({ ok: false, error: "Invalid lat/lon" });
  }

  console.log("🚨 SOS POST ricevuto:", body);
  res.json({ ok: true, message: "SOS ricevuto (POST)", received: body });
});

// Dispatcher /event
app.post("/event", async (req, res) => {
  if (!checkToken(req, res)) return;

  if (!admin || !db) {
    return res.status(503).json({
      ok: false,
      error: "firebase_admin_not_ready",
      firebaseInit: fb,
    });
  }

  try {
    const body = req.body || {};
    const type = String(body.type || "").trim().toUpperCase();
    const victimUid = String(body.victimUid || "").trim();

    const lat = body.lat;
    const lon = body.lon;

    if (!["SOS", "PROTECT", "INCIDENT"].includes(type)) {
      return res.status(400).json({ ok: false, error: "Invalid type" });
    }
    if (!victimUid) {
      return res.status(400).json({ ok: false, error: "Missing victimUid" });
    }
    if (typeof lat !== "number" || typeof lon !== "number") {
      return res.status(400).json({ ok: false, error: "Invalid lat/lon" });
    }

    const eventId = `${Date.now()}_${Math.random().toString(16).slice(2)}`;
    const ts = body.timestamp != null ? Number(body.timestamp) : Date.now();

    const trustedUids = await getTrustedUids(db, victimUid);
    const tokens = await getTrustedTokens(db, trustedUids);

    const dataPayload = toFcmData({
      type,
      eventId,
      victimUid,
      lat,
      lon,
      accuracy: body.accuracy,
      battery: body.battery,
      speedKmh: body.speedKmh,
      altitude: body.altitude,
      heading: body.heading,
      address: body.address,
      addressOk: body.addressOk,
      mode: body.mode,
      timestamp: ts,
    });

    const fcm = await sendToTokens(admin, tokens, dataPayload);

    await db.collection("events").doc(eventId).set({
      ...body,
      type,
      victimUid,
      eventId,
      tokensCount: tokens.length,
      trustedUids,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.json({
      ok: true,
      eventId,
      trustedUidsCount: trustedUids.length,
      tokensCount: tokens.length,
      fcm,
    });
  } catch (e) {
    console.error("❌ /event error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

// Helpers
function toFcmData(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    out[k] = String(v);
  }
  return out;
}

async function getTrustedUids(db, victimUid) {
  // users/{victimUid}/trustedContacts/{trustedUid}
  try {
    const sub = await db.collection("users").doc(victimUid).collection("trustedContacts").get();
    if (!sub.empty) return sub.docs.map((d) => d.id);
  } catch (_) {}

  // users/{victimUid}.trustedUids array
  try {
    const doc = await db.collection("users").doc(victimUid).get();
    if (doc.exists) {
      const data = doc.data() || {};
      if (Array.isArray(data.trustedUids)) return data.trustedUids.map(String);
    }
  } catch (_) {}

  return [];
}

async function getTrustedTokens(db, trustedUids) {
  const tokens = [];

  for (const uid of trustedUids) {
    // users/{uid}/fcmTokens/*
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

    // users/{uid}.fcmToken
    try {
      const doc = await db.collection("users").doc(uid).get();
      if (doc.exists) {
        const data = doc.data() || {};
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
      data,
    });

    sent += resp.successCount;
    failures += resp.failureCount;
  }

  return { sent, failures, batches };
}

// ================================
// WebSocket /ws
// ================================
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
      if (!room || !peerId) return safeSend(ws, { type: "error", error: "missing_room_or_peerId" });

      ws._room = room;
      ws._peerId = peerId;

      if (!rooms.has(room)) rooms.set(room, new Map());
      const peers = rooms.get(room);

      const old = peers.get(peerId);
      if (old && old !== ws) {
        try { safeSend(old, { type: "bye", reason: "replaced" }); } catch (_) {}
        try { old.close(1000, "Replaced"); } catch (_) {}
      }

      peers.set(peerId, ws);

      safeSend(ws, { type: "joined", room, peerId, peers: roomPeers(room).filter((p) => p !== peerId) });
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
      if (!room || !to || !from) return safeSend(ws, { type: "error", error: "missing_room_to_from" });

      const peers = rooms.get(room);
      const target = peers ? peers.get(to) : null;
      if (!target) return safeSend(ws, { type: "error", error: "target_not_found", to });

      safeSend(target, { ...msg, room, from, to });
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
  console.log(`✅ HTTP: /  /health  /debug/firebase  /sos (GET+POST)  /event (POST)`);
  console.log(`✅ WS: /ws`);
  console.log(`✅ WS_TOKEN: ${WS_TOKEN ? "ON" : "OFF (dev)"}`);
});
