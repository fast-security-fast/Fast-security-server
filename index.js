const express = require("express");
const app = express();

app.use(express.json());

const PORT = process.env.PORT || 3000;

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

// GET (compatibilità)
app.get("/sos", (req, res) => {
  if (!checkToken(req, res)) return;
  console.log("🚨 SOS GET ricevuto");
  res.json({ ok: true, message: "SOS ricevuto (GET)" });
});

// POST (nuovo)
app.post("/sos", (req, res) => {
  if (!checkToken(req, res)) return;

  const { lat, lon, timestamp } = req.body || {};
  console.log("🚨 SOS POST ricevuto:", { lat, lon, timestamp });

  res.json({
    ok: true,
    message: "SOS ricevuto (POST)",
    received: { lat, lon, timestamp }
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server Fast Security attivo sulla porta ${PORT}`);
});
