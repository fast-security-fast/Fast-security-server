const express = require("express");
const app = express();

app.use(express.json());

const PORT = process.env.PORT || 3000;

/**
 * 🔐 Verifica token SOS
 */
function checkToken(req, res) {
  const token = req.header("X-SOS-TOKEN");

  if (!process.env.SOS_TOKEN) {
    res.status(500).json({
      ok: false,
      error: "SOS_TOKEN non configurato sul server"
    });
    return false;
  }

  if (token !== process.env.SOS_TOKEN) {
    res.status(401).json({
      ok: false,
      error: "Non autorizzato"
    });
    return false;
  }

  return true;
}

/**
 * ✅ Root
 */
app.get("/", (req, res) => {
  res.json({
    ok: true,
    message: "Fast Security server online 🚀"
  });
});

/**
 * 🚨 SOS GET (compatibilità / test browser)
 */
app.get("/sos", (req, res) => {
  if (!checkToken(req, res)) return;

  console.log("🚨 SOS GET ricevuto");

  res.json({
    ok: true,
    message: "SOS ricevuto (GET)"
  });
});

/**
 * 🚨 SOS POST (ufficiale – APP)
 */
app.post("/sos", (req, res) => {
  if (!checkToken(req, res)) return;

  const { lat, lon, accuracy, speed, timestamp, mode } = req.body || {};

  if (typeof lat !== "number" || typeof lon !== "number") {
    return res.status(400).json({
      ok: false,
      error: "Latitudine o longitudine non valide"
    });
  }

  console.log("🚨 SOS POST ricevuto:", {
    lat,
    lon,
    accuracy,
    speed,
    timestamp,
    mode
  });

  // 🔜 QUI in futuro:
  // - invio a contatti
  // - salvataggio DB
  // - push / WebSocket
  // - attivazione streaming

  res.json({
    ok: true,
    message: "SOS ricevuto correttamente",
    received: {
      lat,
      lon,
      accuracy,
      speed,
      timestamp,
      mode
    }
  });
});

/**
 * 🎙️ LIVE AUDIO (placeholder – prossimo step)
 */
app.post("/live/audio/start", (req, res) => {
  if (!checkToken(req, res)) return;

  console.log("🎙️ Richiesta avvio audio live");

  res.json({
    ok: true,
    message: "Audio live start (placeholder)"
  });
});

/**
 * 🚀 Avvio server
 */
app.listen(PORT, () => {
  console.log(`🚀 Fast Security server attivo sulla porta ${PORT}`);
});
