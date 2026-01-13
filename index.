const express = require("express");
const app = express();

app.use(express.json());

// Home
app.get("/", (req, res) => {
  res.status(200).send("Fast Security server OK");
});

// ✅ SOS - GET (test rapido)
app.get("/sos", (req, res) => {
  res.status(200).json({
    ok: true,
    method: "GET",
    message: "SOS ricevuto (GET)",
    at: new Date().toISOString(),
  });
});

// ✅ SOS - POST (per GPS / payload)
app.post("/sos", (req, res) => {
  res.status(200).json({
    ok: true,
    method: "POST",
    message: "SOS ricevuto (POST)",
    at: new Date().toISOString(),
    body: req.body ?? null,
  });
});

// 404 fallback (così vedi subito se sbagli endpoint)
app.use((req, res) => {
  res.status(404).json({ ok: false, error: "Not Found", path: req.path });
});

// Avvio server (0.0.0.0 = accessibile anche da altri dispositivi in LAN)
const PORT = 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Fast Security server avviato su http://127.0.0.1:${PORT}`);
});
