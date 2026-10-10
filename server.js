import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import { analyzeMessage } from "./securityEngine.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = parseInt(process.env.PORT || "3000", 10);
const host = "0.0.0.0";

app.use(cors());
app.use(express.json({ limit: "2mb" }));

// API health endpoint
app.get("/api/health", (_req, res) => {
  res.json({
    name: "ScamShield AI",
    status: "online",
    message: "Security analysis API is running",
  });
});

// Analyze endpoint
const handleAnalyze = (req, res) => {
  const text = (req.body && req.body.text) || "";
  if (!text.trim()) {
    return res.status(400).json({
      error: "Please provide a message or URL to analyze.",
    });
  }

  try {
    const result = analyzeMessage(text);
    return res.json(result);
  } catch (error) {
    console.error("Analysis error:", error);
    return res.status(500).json({
      error: "An error occurred during security analysis.",
    });
  }
};

app.post("/analyze", handleAnalyze);
app.post("/api/analyze", handleAnalyze);

// Static assets
app.use(express.static(__dirname));

// Fallback to index.html for SPA/root navigation
app.get("*", (req, res, next) => {
  if (req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "index.html"));
  }
  next();
});

app.listen(port, host, () => {
  console.log(`ScamShield AI server running at http://${host}:${port}`);
});
