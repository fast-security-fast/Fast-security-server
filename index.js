const express = require("express");
const app = express();

// Render/Proxy friendly
app.set("trust proxy", 1);

// Body JSON
app.use(express.json());

// Home
app.get("/", (req, res) => {
  res.status(200).send("OK");
});

// Health
app.get("/health", (req, res) => {
  res.status(200).json({ ok: true });
});

// SOS (POST)
app.post("/sos", (req, res) => {
  const { deviceId, lat, lon, accuracy, timestamp } = req.body || {};
  console.log("SOS ricevuto:", { deviceId, lat, lon, accuracy, timestamp });

  res.status(200).json({
    ok: true,
    message: "SOS ricevuto",
    received: { deviceId, lat, lon, accuracy, timestamp },
  });
});

// Render uses process.env.PORT
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on port " + PORT);
});
