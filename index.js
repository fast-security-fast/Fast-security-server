const express = require("express");
const app = express();

// Middleware per JSON
app.use(express.json());

// Porta (Render usa process.env.PORT)
const PORT = process.env.PORT || 3000;

// Endpoint root
app.get("/", (req, res) => {
  res.status(200).send("OK");
});

// Endpoint SOS
app.get("/sos", (req, res) => {
  console.log("SOS ricevuto");
  res.status(200).send("OK");
});

// Avvio server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

