# 🛡️ ScamShield AI

### Explainable Phishing & Scam Defense

ScamShield AI is a defensive cybersecurity tool that analyzes suspicious messages and URLs, identifies common phishing and scam indicators, explains why content may be risky, and provides practical safety recommendations.

> **Don't just detect the scam. Understand why it may be dangerous — and what to do next.**

---

## 🚨 The Problem

Phishing and online scams often rely on social engineering rather than technical exploits.

Attackers may use:

* Urgency and time pressure
* Account suspension threats
* Requests for passwords or security codes
* Fake payment requests
* Impersonation of trusted organizations
* Suspicious links
* Fake rewards and cryptocurrency offers

Many users can recognize that something "looks suspicious" but cannot easily understand **which signals make it risky**.

ScamShield AI focuses on making security analysis understandable and actionable.

---

## 💡 The Solution

ScamShield analyzes a message or URL through multiple defensive security layers:

```text
User Input
    ↓
Message Analysis
    ↓
URL Analysis
    ↓
Security Indicators
    ↓
Cross-Signal Reinforcement
    ↓
Risk Score
    ↓
Explainable Security Report
    ↓
Recommended Actions
```

Instead of returning only a label, ScamShield shows the evidence behind the assessment.

---

## ✨ Key Features

### 🔍 Message Analysis

Detects common social-engineering patterns including:

* Urgency
* Credential requests
* Financial requests
* Threats
* Reward manipulation
* Possible impersonation
* Suspicious actions

### 🔗 URL Analysis

Examines URLs for characteristics such as:

* HTTP instead of HTTPS
* IP-address destinations
* Suspicious keywords
* Unusually long domains
* Complex subdomain structures
* Excessive hyphens
* Non-standard ports
* Link-shortening services
* URL encoding
* Suspicious URL length

### 🎯 Explainable Risk Score

The final score is based on multiple components:

```text
Message Analysis       → up to 55 points
URL Analysis           → up to 25 points
Cross-Signal Reinforcement
                       → additional points

Final Risk Score       → 0–100
```

The interface exposes these contributions so users can understand how the assessment was produced.

### 🧠 Explainable Security Analysis

ScamShield provides:

* Detected indicators
* Evidence
* Risk factors
* Explanation
* Security reasoning
* Recommended actions
* Educational guidance

### 🛡️ Defensive Recommendations

Depending on the detected indicators, the system may recommend users to:

* Avoid clicking suspicious links
* Avoid entering passwords or OTP codes
* Avoid sending money
* Verify requests through independent official channels
* Avoid acting under pressure
* Treat unexpected rewards with caution

---

## 🔒 Privacy by Design

ScamShield is designed around a privacy-first security model.

The interface explicitly warns users:

* Never submit passwords
* Never submit OTP codes
* Never submit private keys
* Do not share sensitive information

The security engine performs analysis based on the submitted content and does not require users to provide credentials.

> **A security scanner should never ask the user to sacrifice the information it is trying to protect.**

---

## 🏗️ Architecture

```text
                    ┌──────────────────┐
                    │   User Input     │
                    │ Message / URL    │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │    Frontend      │
                    │ HTML / CSS / JS  │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │   FastAPI API    │
                    │    /analyze      │
                    └────────┬─────────┘
                             │
                ┌────────────┴────────────┐
                ▼                         ▼
       ┌─────────────────┐       ┌─────────────────┐
       │ Message Security│       │   URL Security  │
       │     Engine      │       │     Analysis    │
       └────────┬────────┘       └────────┬────────┘
                │                         │
                └────────────┬────────────┘
                             ▼
                    ┌──────────────────┐
                    │ Cross-Signal     │
                    │ Reinforcement    │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │   Risk Scoring   │
                    │      0–100       │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Explainable      │
                    │ Threat Report    │
                    └──────────────────┘
```

---

## 🧰 Technology Stack

### Frontend

* HTML5
* CSS3
* Vanilla JavaScript

### Backend

* Python
* FastAPI
* Pydantic
* Uvicorn

### Security Analysis

* Rule-based security engine
* Regular expressions
* URL parsing
* Pattern detection
* Explainable risk scoring
* Cross-signal reinforcement

### Optional AI Layer

ScamShield includes an optional AI analysis layer designed to provide additional defensive analysis when an AI provider is configured and available.

The core security assessment does **not depend on an external AI decision**.

This allows the application to continue providing explainable rule-based analysis even when the external AI service is unavailable.

---

## 🤖 AI Disclosure

AI-assisted development and an optional AI analysis layer were used during the project.

The project maintains a clear distinction between:

**Deterministic security analysis**

and

**Optional AI-generated analysis.**

The rule-based engine is responsible for the primary explainable security assessment.

AI output is treated as supplementary analysis rather than an authoritative security verdict.

The system does not claim that AI can determine with certainty whether content is malicious.

---

## 🧪 Testing

ScamShield was tested against multiple representative scenarios.

| Scenario                                | Result |
| --------------------------------------- | -----: |
| 🟢 Benign appointment message           |  0/100 |
| 🏦 Suspicious bank phishing message     | 93/100 |
| 📦 Delivery payment scam                | 52/100 |
| ₿ Cryptocurrency reward scam            | 88/100 |
| 🔐 Legitimate password-reset discussion |  0/100 |

These examples demonstrate that the system can distinguish between ordinary content and messages containing multiple suspicious signals.

---

## ⚠️ Limitations

ScamShield is a defensive analysis tool, not an absolute truth engine.

A low score does **not** guarantee that content is safe.

A high score does **not** mathematically prove malicious intent.

The system currently relies primarily on detectable patterns and URL characteristics. Attackers can change their language, domains, and techniques.

For this reason, ScamShield communicates results as **risk indicators** rather than certainty.

---

## 🔐 Security Philosophy

ScamShield follows three principles:

### 1. Explain, don't just classify

Users should understand why something is suspicious.

### 2. Minimize sensitive information

The scanner should never require passwords, OTP codes, or private keys.

### 3. Encourage independent verification

Users should verify important requests through trusted channels rather than relying solely on the scanner.

---

## ▶️ Running Locally

### 1. Start the backend

Open a terminal:

```bash
cd E:\ScamShield-AI\backend
python -m uvicorn main:app --reload
```

The API runs at:

```text
http://127.0.0.1:8000
```

### 2. Start the frontend

Open another terminal:

```bash
cd E:\ScamShield-AI
python -m http.server 5500
```

Open:

```text
http://127.0.0.1:5500
```

> Do not open `index.html` directly using `file://`. Use the local HTTP server.

---

## 📁 Project Structure

```text
ScamShield-AI/
│
├── index.html
├── style.css
├── app.js
│
├── README.md
│
└── backend/
    ├── main.py
    └── security_engine.py
```

---

## 🎬 Demo Scenarios

The application includes built-in examples for rapid demonstration:

### 🏦 Bank Phishing

Demonstrates:

* Urgency
* Credential requests
* Financial context
* Threats
* Possible impersonation
* Suspicious URL

### 📦 Delivery Scam

Demonstrates:

* Payment request
* Urgency
* Suspicious URL

### ₿ Crypto Reward Scam

Demonstrates:

* Reward manipulation
* Cryptocurrency context
* Credential request
* Urgency
* Suspicious URL

### 🟢 Safe Message

Demonstrates that ordinary content can receive a low-risk assessment without suspicious indicators.

---

## 🌍 Why It Matters

Online scams increasingly target people through ordinary communication channels.

The technical challenge is not only detecting suspicious content.

It is helping people answer three questions:

> **What is suspicious?**

> **Why is it suspicious?**

> **What should I do now?**

ScamShield is designed around those three questions.

---

## 🏆 Hackathon Focus

ScamShield AI was built as a defensive cybersecurity project focused on:

* Phishing detection
* Scam awareness
* Social-engineering defense
* URL security
* Explainable security analysis
* Privacy-conscious design
* Practical user protection

The project does not perform unauthorized access, credential theft, malware deployment, or destructive actions.

---

## 👤 Project

**ScamShield AI**

**Explainable Phishing & Scam Defense**

Built for the TLN Cybersecurity Challenge 2026.
