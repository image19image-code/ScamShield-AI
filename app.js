"use strict";

/* =========================
   DOM
========================= */

const inputText = document.getElementById("inputText");
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");
const loading = document.getElementById("loading");
const results = document.getElementById("results");

const scoreElement = document.getElementById("score");
const threatLevelElement = document.getElementById("threatLevel");
const categoryElement = document.getElementById("category");
const indicatorsElement = document.getElementById("indicators");
const riskFactorsElement = document.getElementById("riskFactors");
const explanationElement = document.getElementById("explanation");
const aiAnalysisElement = document.getElementById("aiAnalysis");
const evidenceElement = document.getElementById("evidence");
const scoreBreakdownElement = document.getElementById("scoreBreakdown");
const recommendationsElement = document.getElementById("recommendations");
const educationElement = document.getElementById("education");


/* =========================
   SCAM PATTERNS
========================= */

const scamPatterns = {
  urgency: [
    "urgent",
    "immediately",
    "act now",
    "right now",
    "today",
    "within 24 hours",
    "within 48 hours",
    "expires",
    "last chance",
    "limited time",
    "do it now",
    "respond now"
  ],

  credentials: [
    "password",
    "verify your account",
    "verify your identity",
    "verification",
    "verify",
    "login",
    "username",
    "security code",
    "security codes",
    "otp",
    "one time password",
    "one-time password",
    "sign in",
    "confirm your account",
    "confirm your identity",
    "account information",
    "security alert",
    "reset your password",
    "update your account",
    "enter your password",
    "provide your password",
    "type your password",
    "submit your password",
    "password to confirm",
    "password to verify",
    "login with your password",
    "authentication code",
    "verification code",
    "access code"
  ],

  suspicious_action: [
    "click here",
    "click the link",
    "click this link",
    "open the link",
    "follow the link",
    "review your account",
    "verify now",
    "click to verify",
    "click here to verify",
    "click here to claim",
    "click to claim",
    "claim now",
    "claim your prize",
    "claim your reward",
    "tap here",
    "open now",
    "confirm now",
    "download now"
  ],

  financial: [
    "credit card",
    "debit card",
    "bank account",
    "payment",
    "send money",
    "transfer money",
    "wire transfer",
    "bitcoin",
    "crypto",
    "cryptocurrency",
    "wallet",
    "refund",
    "fee",
    "invoice",
    "billing",
    "payment information",
    "banking information"
  ],

  threats: [
    "suspended",
    "suspend",
    "blocked",
    "closed",
    "legal action",
    "police",
    "penalty",
    "deactivated",
    "terminate",
    "terminated",
    "account will be closed",
    "account will be suspended",
    "lose access"
  ],

  rewards: [
    "winner",
    "you won",
    "you have won",
    "prize",
    "free money",
    "claim your reward",
    "lottery",
    "congratulations",
    "cash prize",
    "bonus",
    "gift card",
    "reward"
  ],

  impersonation: [
    "security team",
    "support team",
    "customer service",
    "your bank",
    "paypal",
    "microsoft",
    "apple",
    "amazon",
    "google",
    "netflix",
    "official support",
    "account security"
  ]
};


/* =========================
   LABELS
========================= */

function formatCategory(category) {
  const names = {
    urgency: "Urgency Manipulation",
    credentials: "Credential Request",
    financial: "Financial Risk",
    threats: "Threat / Fear Tactic",
    rewards: "Reward Scam Indicator",
    impersonation: "Possible Impersonation",
    suspicious_action: "Suspicious Action",
    url: "Suspicious URL",
    brand_mismatch: "Brand / Domain Mismatch"
  };

  return names[category] || category;
}


function getDescription(category) {
  const descriptions = {
    urgency:
      "The message pressures the recipient to act quickly without taking time to verify the request.",

    credentials:
      "The message requests or references sensitive authentication information.",

    financial:
      "The message involves money, payment, banking information, or cryptocurrency.",

    threats:
      "The message uses fear, consequences, or threats to influence the recipient.",

    rewards:
      "The message uses prizes, rewards, or unexpected benefits as a possible lure.",

    impersonation:
      "The message contains language associated with trusted organizations or support services.",

    suspicious_action:
      "The message encourages the recipient to click, open, claim, download, or interact.",

    url:
      "The detected URL contains characteristics that deserve additional verification.",

    brand_mismatch:
      "A trusted organization appears to be referenced, but the detected domain may not match the official service."
  };

  return (
    descriptions[category] ||
    "A potentially suspicious characteristic was detected."
  );
}


/* =========================
   FRONTEND FALLBACK ANALYSIS
========================= */

function analyzeText(text) {
  const lowerText = String(text || "")
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();

  const indicators = [];
  const categories = [];

  const weights = {
    credentials: 25,
    financial: 25,
    urgency: 15,
    threats: 15,
    rewards: 15,
    impersonation: 10,
    suspicious_action: 10
  };

  Object.entries(scamPatterns).forEach(
    ([category, patterns]) => {
      const matches = patterns.filter(
        (pattern) => lowerText.includes(pattern)
      );

      if (!matches.length) {
        return;
      }

      categories.push(category);

      matches.forEach((match) => {
        indicators.push({
          type: category,
          category,
          title: formatCategory(category),
          description: getDescription(category),
          evidence: match,
          matches: [match]
        });
      });
    }
  );

  const score = Math.min(
    categories.reduce(
      (total, category) =>
        total + (weights[category] || 0),
      0
    ),
    70
  );

  return {
    score,
    categories,
    indicators
  };
}


/* =========================
   THREAT LEVEL
========================= */

function getThreatLevel(score) {
  if (score >= 80) {
    return {
      level: "CRITICAL",
      category: "HIGH-RISK SCAM",
      color: "#ff5364"
    };
  }

  if (score >= 60) {
    return {
      level: "HIGH RISK",
      category: "LIKELY PHISHING / SCAM",
      color: "#ff6b4a"
    };
  }

  if (score >= 35) {
    return {
      level: "SUSPICIOUS",
      category: "SUSPICIOUS CONTENT",
      color: "#ffad42"
    };
  }

  return {
    level: "LOW RISK",
    category: "NO STRONG SCAM SIGNALS",
    color: "#42e8a0"
  };
}


/* =========================
   HTML SAFETY
========================= */

function escapeHTML(value) {
  const div = document.createElement("div");
  div.textContent = String(value ?? "");
  return div.innerHTML;
}


function escapeRegExp(value) {
  return String(value).replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&"
  );
}


function cleanAIText(value) {
  return String(value || "")
    .replace(/\\-/g, "-")
    .replace(/\r/g, "")
    .replace(/\u00a0/g, " ")
    .trim();
}


/* =========================
   EVIDENCE
========================= */

function createEvidence(text, indicators) {
  let result = escapeHTML(text);
  const matches = [];

  indicators.forEach((indicator) => {
    if (Array.isArray(indicator.matches)) {
      indicator.matches.forEach((match) => {
        if (match) {
          matches.push(String(match));
        }
      });
    }

    if (indicator.evidence) {
      matches.push(String(indicator.evidence));
    }
  });

  const uniqueMatches = [
    ...new Set(matches)
  ]
    .sort((a, b) => b.length - a.length)
    .map(escapeHTML)
    .map(escapeRegExp);

  if (!uniqueMatches.length) {
    return result;
  }

  const regex = new RegExp(
    `(${uniqueMatches.join("|")})`,
    "gi"
  );

  return result.replace(
    regex,
    "<mark>$1</mark>"
  );
}


/* =========================
   NORMALIZE BACKEND DATA
========================= */

function normalizeIndicators(indicators) {
  if (!Array.isArray(indicators)) {
    return [];
  }

  return indicators.map((indicator) => {
    const type =
      indicator?.type ||
      indicator?.category ||
      "unknown";

    const evidence =
      indicator?.evidence ??
      indicator?.description ??
      "";

    return {
      ...indicator,
      type,
      category: type,
      title:
        indicator?.title ||
        formatCategory(type),
      description:
        indicator?.description ||
        indicator?.evidence ||
        getDescription(type),
      evidence: String(evidence),
      matches: Array.isArray(indicator?.matches)
        ? indicator.matches
        : evidence
          ? [String(evidence)]
          : []
    };
  });
}


/* =========================
   REMOVE EXACT DUPLICATES
========================= */

function uniqueIndicators(indicators) {
  const result = [];
  const seen = new Set();

  indicators.forEach((indicator) => {
    const key =
      `${indicator.type}::${indicator.evidence}`;

    if (!seen.has(key)) {
      seen.add(key);
      result.push(indicator);
    }
  });

  return result;
}


/* =========================
   GROUPED DETECTED INDICATORS
========================= */

function renderIndicators(indicators) {
  indicatorsElement.innerHTML = "";

  if (!indicators || !indicators.length) {
    indicatorsElement.innerHTML = `
      <div
        class="indicator"
        style="border-left-color:#42e8a0"
      >
        <strong>
          🟢 No strong indicators detected
        </strong>

        <span>
          The scanner did not find major scam patterns
          in this content.
        </span>
      </div>
    `;

    return;
  }

  const groups = new Map();

  indicators.forEach((indicator) => {
    const type =
      indicator.type ||
      indicator.category ||
      "unknown";

    if (!groups.has(type)) {
      groups.set(type, {
        type,
        title:
          indicator.title ||
          formatCategory(type),
        evidence: []
      });
    }

    const group = groups.get(type);

    const evidenceItems = [
      ...(Array.isArray(indicator.matches)
        ? indicator.matches
        : []),
      indicator.evidence
    ]
      .filter(Boolean)
      .map(String);

    evidenceItems.forEach((item) => {
      if (!group.evidence.includes(item)) {
        group.evidence.push(item);
      }
    });
  });

  const icons = {
    urgency: "⏱️",
    credentials: "🔐",
    financial: "💳",
    threats: "⚠️",
    impersonation: "🏢",
    rewards: "🎁",
    suspicious_action: "🖱️",
    url: "🔗",
    brand_mismatch: "🏢"
  };

  groups.forEach((group) => {
    const div =
      document.createElement("div");

    div.className = "indicator";

    if (group.type === "brand_mismatch") {
      div.style.borderLeftColor = "#a855f7";
    }

    const icon =
      icons[group.type] || "⚠️";

    const evidenceHTML =
      group.evidence.length
        ? `
          <div style="
            margin-top:9px;
            display:flex;
            flex-direction:column;
            gap:6px;
          ">
            ${group.evidence
              .map(
                (item) => `
                  <div style="
                    padding:7px 9px;
                    border-radius:8px;
                    background:rgba(255,255,255,.035);
                    border:1px solid rgba(255,255,255,.05);
                    font-size:.82rem;
                    line-height:1.5;
                  ">
                    <span style="opacity:.7">
                      ↳
                    </span>
                    ${escapeHTML(item)}
                  </div>
                `
              )
              .join("")}
          </div>
        `
        : "";

    div.innerHTML = `
      <strong>
        ${icon}
        ${escapeHTML(group.title)}
      </strong>

      ${evidenceHTML}
    `;

    indicatorsElement.appendChild(div);
  });
}


/* =========================
   RISK FACTORS
========================= */

function renderRiskFactors(riskFactors) {
  riskFactorsElement.innerHTML = "";

  const uniqueRiskFactors = [
    ...new Set(
      (Array.isArray(riskFactors)
        ? riskFactors
        : []
      )
        .map((factor) => String(factor))
        .filter(Boolean)
    )
  ];

  if (!uniqueRiskFactors.length) {
    riskFactorsElement.innerHTML = `
      <div
        class="indicator"
        style="border-left-color:#42e8a0"
      >
        <strong>
          🟢 No major risk factors detected
        </strong>

        <span>
          No significant security factors
          contributed to the risk score.
        </span>
      </div>
    `;

    return;
  }

  uniqueRiskFactors.forEach(
    (factor, index) => {
      const div =
        document.createElement("div");

      div.className = "indicator";

      div.innerHTML = `
        <strong>
          ${index < 2 ? "🔴" : "🟠"}
          Risk factor
        </strong>

        <span>
          ${escapeHTML(factor)}
        </span>
      `;

      riskFactorsElement.appendChild(div);
    }
  );
}


/* =========================
   EXPLANATION FALLBACK
========================= */

function getExplanation(score) {
  if (score >= 80) {
    return (
      "Multiple high-risk indicators commonly associated with phishing, scams, or social engineering were detected. Treat this content as high risk and verify the request independently."
    );
  }

  if (score >= 60) {
    return (
      "Several suspicious characteristics were detected. The content may involve phishing or social engineering and should be independently verified."
    );
  }

  if (score >= 35) {
    return (
      "Some suspicious characteristics were detected. This does not prove malicious intent, but the content deserves additional verification."
    );
  }

  return (
    "No strong scam indicators were detected by the current security rules. This does not guarantee that the content is safe."
  );
}


/* =========================
   AI ANALYSIS
========================= */

function renderAIAnalysis(ai) {
  if (
    ai &&
    ai.status === "success" &&
    typeof ai.analysis === "string" &&
    ai.analysis.trim()
  ) {
    const cleanAnalysis =
      cleanAIText(ai.analysis);

    aiAnalysisElement.innerHTML = `
      <strong>
        🤖 AI Security Analysis
      </strong>

      <div style="
        margin-top:12px;
        padding:13px;
        border-radius:10px;
        background:rgba(255,255,255,.03);
        border:1px solid rgba(255,255,255,.05);
        white-space:pre-line;
        line-height:1.7;
        font-size:.9rem;
      ">
        ${escapeHTML(cleanAnalysis)}
      </div>

      <small style="
        display:block;
        margin-top:10px;
        opacity:.65;
        line-height:1.5;
      ">
        AI-assisted explanation.
        The final risk score is determined by
        the explainable security engine.
      </small>
    `;

    return;
  }

  aiAnalysisElement.innerHTML = `
    <strong>
      🧠 Explainable Security Analysis
    </strong>

    <p>
      The AI explanation is currently unavailable.
      The security engine completed the assessment
      using deterministic security rules,
      message indicators, URL analysis,
      and cross-signal reasoning.
    </p>

    <small>
      AI explanation is optional and does not determine
      the final risk score.
    </small>
  `;
}


/* =========================
   RECOMMENDATIONS
========================= */

function getRecommendations(score, indicators) {
  const recommendations = [];

  const types = indicators.map(
    (indicator) => indicator.type
  );

  if (types.includes("credentials")) {
    recommendations.push(
      "🔐 Do not enter your password, OTP, security code, or other credentials in response to this message."
    );
  }

  if (types.includes("url")) {
    recommendations.push(
      "🔗 Do not open the detected link. If you need to access the service, open its official website or app directly."
    );
  }

  if (types.includes("financial")) {
    recommendations.push(
      "🏦 Do not send money or provide banking information through this message. Verify the request using an official channel."
    );
  }

  if (types.includes("urgency")) {
    recommendations.push(
      "⏸️ Do not let urgency pressure you into acting immediately. Stop and verify the request independently."
    );
  }

  if (types.includes("threats")) {
    recommendations.push(
      "⚠️ Do not respond to threats or account-closure warnings until you independently verify the situation."
    );
  }

  if (types.includes("impersonation")) {
    recommendations.push(
      "🏢 Verify the sender through the organization's official website, app, or known contact information—not through the message."
    );
  }

  if (types.includes("rewards")) {
    recommendations.push(
      "🎁 Be cautious with unexpected prizes or rewards. Do not provide personal or financial information to claim them."
    );
  }

  return [...new Set(recommendations)];
}


/* =========================
   EDUCATION
========================= */

function getEducation(indicators) {
  const categories = indicators.map(
    (item) => item.type
  );

  if (categories.includes("urgency")) {
    return `
      Attackers often create urgency or fear
      to prevent victims from thinking carefully.
      Stop, verify the request independently,
      and only then take action.
    `;
  }

  if (categories.includes("credentials")) {
    return `
      Be cautious when a message asks you to
      enter credentials through a link. Use the
      organization's official website or app directly.
    `;
  }

  if (categories.includes("financial")) {
    return `
      Financial requests deserve extra caution.
      Never send money or financial information
      simply because a message creates pressure
      or urgency.
    `;
  }

  return `
    A security tool can identify warning signs,
    but important requests should always be
    verified through trusted official channels.
  `;
}


/* =========================
   SCORE UI
========================= */

function updateScoreUI(
  totalScore,
  textContribution,
  urlContribution,
  reinforcementScore
) {
  const safeScore = Math.max(
    0,
    Math.min(
      100,
      Number(totalScore) || 0
    )
  );

  scoreElement.textContent =
    safeScore;

  const threat =
    getThreatLevel(safeScore);

  threatLevelElement.textContent =
    threat.level;

  threatLevelElement.style.color =
    threat.color;

  categoryElement.textContent = "";

  const scoreBar =
    document.getElementById("scoreBar");

  const scorePercentage =
    document.getElementById(
      "scorePercentage"
    );

  const textContributionElement =
    document.getElementById(
      "textContribution"
    );

  const urlContributionElement =
    document.getElementById(
      "urlContribution"
    );

  const reinforcementScoreElement =
    document.getElementById(
      "reinforcementScore"
    );

  const finalScoreElement =
    document.getElementById(
      "finalScore"
    );

  const scoreBarContainer =
    document.querySelector(
      ".score-bar-container"
    );

  if (scoreBarContainer) {
    scoreBarContainer.style.setProperty(
      "--score",
      `${safeScore}%`
    );
  }

  if (scoreBar) {
    scoreBar.style.width =
      `${safeScore}%`;
  }

  if (scorePercentage) {
    scorePercentage.textContent =
      `${safeScore}/100`;
  }

  if (textContributionElement) {
    textContributionElement.textContent =
      `+${textContribution}`;
  }

  if (urlContributionElement) {
    urlContributionElement.textContent =
      `+${urlContribution}`;
  }

  if (reinforcementScoreElement) {
    reinforcementScoreElement.textContent =
      `+${reinforcementScore}`;
  }

  if (finalScoreElement) {
    finalScoreElement.textContent =
      `${safeScore}/100`;
  }

  return safeScore;
}


/* =========================
   SCORE BREAKDOWN
========================= */

function renderDetailedSecurityReasoning(
  finalScore,
  textContribution,
  urlContribution,
  reinforcementScore,
  indicators
) {
  const types = indicators.map(
    (item) => item.type
  );

  const messageSignals = [];

  if (types.includes("credentials")) {
    messageSignals.push(
      "🔐 Credential request"
    );
  }

  if (types.includes("financial")) {
    messageSignals.push(
      "💳 Financial risk"
    );
  }

  if (types.includes("urgency")) {
    messageSignals.push(
      "⏱️ Urgency pressure"
    );
  }

  if (types.includes("threats")) {
    messageSignals.push(
      "⚠️ Threat / fear tactic"
    );
  }

  if (types.includes("impersonation")) {
    messageSignals.push(
      "🏢 Possible impersonation"
    );
  }

  if (types.includes("rewards")) {
    messageSignals.push(
      "🎁 Unexpected reward"
    );
  }

  if (types.includes("suspicious_action")) {
    messageSignals.push(
      "🖱️ Suspicious action request"
    );
  }

  const urlSignals = [];

  indicators
    .filter(
      (item) => item.type === "url"
    )
    .forEach((indicator) => {
      const evidence = String(
        indicator.evidence ||
        indicator.description ||
        ""
      ).toLowerCase();

      if (
        evidence.includes(
          "http instead of https"
        )
      ) {
        urlSignals.push(
          "🔗 HTTP instead of HTTPS"
        );
      }

      if (
        evidence.includes(
          "suspicious url keywords"
        )
      ) {
        urlSignals.push(
          "🔎 Suspicious URL keywords"
        );
      }

      if (evidence.includes("hyphen")) {
        urlSignals.push(
          "➖ Unusually high number of hyphens"
        );
      }

      if (evidence.includes("long domain")) {
        urlSignals.push(
          "🌐 Unusually long domain"
        );
      }

      if (evidence.includes("ip address")) {
        urlSignals.push(
          "🌐 IP address used instead of a domain"
        );
      }

      if (evidence.includes("@")) {
        urlSignals.push(
          "⚠️ URL contains @ symbol"
        );
      }

      if (evidence.includes("non-standard port")) {
        urlSignals.push(
          "🔌 Non-standard port"
        );
      }

      if (evidence.includes("shortening service")) {
        urlSignals.push(
          "🔗 URL shortening service"
        );
      }

      if (evidence.includes("encoded characters")) {
        urlSignals.push(
          "🔐 Encoded URL characters"
        );
      }

      if (evidence.includes("complex subdomain")) {
        urlSignals.push(
          "🌐 Complex subdomain structure"
        );
      }

      if (
        evidence.includes(
          "suspicious security-related subdomain"
        )
      ) {
        urlSignals.push(
          "⚠️ Suspicious security-related subdomain"
        );
      }
    });

  indicators
    .filter(
      (item) =>
        item.type === "brand_mismatch"
    )
    .forEach((indicator) => {
      urlSignals.push(
        "🏢 " +
        (
          indicator.evidence ||
          indicator.description ||
          "Brand/domain mismatch detected"
        )
      );
    });

  const uniqueUrlSignals = [
    ...new Set(urlSignals)
  ];

  const reinforcementSignals = [];

  if (
    types.includes("credentials") &&
    types.includes("url")
  ) {
    reinforcementSignals.push(
      "🔐 Credentials + suspicious URL"
    );
  }

  if (
    types.includes("financial") &&
    types.includes("url")
  ) {
    reinforcementSignals.push(
      "💳 Financial risk + suspicious URL"
    );
  }

  if (
    types.includes("urgency") &&
    types.includes("credentials")
  ) {
    reinforcementSignals.push(
      "⏱️ Urgency + credentials"
    );
  }

  if (
    types.includes("threats") &&
    types.includes("urgency")
  ) {
    reinforcementSignals.push(
      "⚠️ Threat + urgency"
    );
  }

  if (
    types.includes("impersonation") &&
    types.includes("credentials")
  ) {
    reinforcementSignals.push(
      "🏢 Impersonation + credentials"
    );
  }

  if (
    types.includes("rewards") &&
    types.includes("urgency")
  ) {
    reinforcementSignals.push(
      "🎁 Reward + urgency"
    );
  }

  if (
    types.includes("rewards") &&
    types.includes("suspicious_action")
  ) {
    reinforcementSignals.push(
      "🎁 Reward + suspicious action"
    );
  }

  if (
    types.includes("urgency") &&
    types.includes("suspicious_action")
  ) {
    reinforcementSignals.push(
      "⏱️ Urgency + suspicious action"
    );
  }

  if (
    types.includes("credentials") &&
    types.includes("url") &&
    (
      types.includes("urgency") ||
      types.includes("threats") ||
      types.includes("impersonation")
    )
  ) {
    reinforcementSignals.push(
      "🎯 Strong phishing pattern"
    );
  }

  const section = (
    title,
    items,
    contribution,
    maximum
  ) => `
    <div style="
      margin-top:14px;
      padding:13px;
      border-radius:10px;
      background:rgba(255,255,255,.03);
    ">
      <div style="
        display:flex;
        justify-content:space-between;
        align-items:center;
        gap:12px;
      ">
        <strong>
          ${escapeHTML(title)}
        </strong>

        <strong>
          +${contribution}/${maximum}
        </strong>
      </div>

      <div style="margin-top:9px;">
        ${
          items.length
            ? items
                .map(
                  (item) => `
                    <div style="
                      padding:7px 0;
                      border-bottom:
                        1px solid
                        rgba(255,255,255,.06);
                      line-height:1.5;
                      opacity:.92;
                    ">
                      ${escapeHTML(item)}
                    </div>
                  `
                )
                .join("")
            : `
              <div style="
                opacity:.6;
                font-size:.85rem;
              ">
                No major signals detected.
              </div>
            `
        }
      </div>
    </div>
  `;

  const calculatedScore =
    Number(textContribution || 0) +
    Number(urlContribution || 0) +
    Number(reinforcementScore || 0);

  const normalizedScore = Math.max(
    0,
    Math.min(
      100,
      Number(finalScore || calculatedScore)
    )
  );

  return `
    <div style="
      margin-top:18px;
      padding-top:18px;
      border-top:
        1px solid
        rgba(255,255,255,.10);
    ">

      <div style="
        font-size:1.05rem;
        font-weight:700;
      ">
        🧠 WHY ${normalizedScore}/100?
      </div>

      <div style="
        font-size:.85rem;
        opacity:.7;
        margin-top:6px;
        line-height:1.6;
      ">
        The final score is calculated from message signals,
        URL and domain characteristics, and cross-signal
        reinforcement.
      </div>

      ${section(
        "MESSAGE ANALYSIS",
        messageSignals,
        textContribution,
        55
      )}

      ${section(
        "URL / DOMAIN ANALYSIS",
        uniqueUrlSignals,
        urlContribution,
        25
      )}

      ${section(
        "CROSS-SIGNAL REINFORCEMENT",
        reinforcementSignals,
        reinforcementScore,
        20
      )}

      <div style="
        margin-top:14px;
        padding:10px 12px;
        border-radius:10px;
        background:rgba(255,255,255,.025);
        font-size:.8rem;
        opacity:.65;
        line-height:1.6;
      ">
        Score calculation:
        <strong>${textContribution}</strong>
        +
        <strong>${urlContribution}</strong>
        +
        <strong>${reinforcementScore}</strong>
        =
        <strong>${calculatedScore}</strong>
      </div>

      <div style="
        display:flex;
        justify-content:space-between;
        align-items:center;
        gap:16px;
        margin-top:16px;
        padding:14px;
        border-radius:10px;
        background:rgba(255,255,255,.05);
      ">
        <strong>
          FINAL RISK SCORE
        </strong>

        <strong>
          ${normalizedScore}/100
        </strong>
      </div>

    </div>
  `;
}


function renderScoreBreakdown(
  finalScore,
  textContribution,
  urlContribution,
  reinforcementScore,
  indicators
) {
  if (!scoreBreakdownElement) {
    return;
  }

  let reasoning =
    document.getElementById(
      "detailedSecurityReasoning"
    );

  if (!reasoning) {
    reasoning =
      document.createElement("div");

    reasoning.id =
      "detailedSecurityReasoning";

    scoreBreakdownElement.appendChild(
      reasoning
    );
  }

  reasoning.innerHTML =
    renderDetailedSecurityReasoning(
      finalScore,
      textContribution,
      urlContribution,
      reinforcementScore,
      indicators
    );
}


/* =========================
   MAIN ANALYSIS
========================= */

async function analyze() {
  const text =
    inputText.value.trim();

  if (!text) {
    alert(
      "Please paste a message or URL first."
    );
    return;
  }

  results.classList.add("hidden");
  loading.classList.remove("hidden");

  const controller =
    new AbortController();

  const timeoutId = setTimeout(
    () => controller.abort(),
    45000
  );

  try {
    const response = await fetch(
      "https://scamshield-ai-api-82p6.onrender.com/analyze",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json"
        },
        body: JSON.stringify({
          text
        }),
        signal: controller.signal
      }
    );

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(
        `Backend returned HTTP ${response.status}`
      );
    }

    const data =
      await response.json();

    const fallback =
      analyzeText(text);

    const backendIndicators =
      normalizeIndicators(
        data.indicators
      );

    const allIndicators =
      uniqueIndicators(
        backendIndicators.length
          ? backendIndicators
          : fallback.indicators
      );

    const rawTextContribution =
      Number(
        data.text_contribution
      );

    const rawUrlContribution =
      Number(
        data.url_contribution
      );

    const rawReinforcementScore =
      Number(
        data.reinforcement_score
      );

    const fallbackTextContribution =
      Math.round(
        (Math.min(
          fallback.score,
          70
        ) / 70) * 55
      );

    const textContribution =
      Number.isFinite(
        rawTextContribution
      )
        ? rawTextContribution
        : fallbackTextContribution;

    const urlContribution =
      Number.isFinite(
        rawUrlContribution
      )
        ? rawUrlContribution
        : 0;

    const reinforcementScore =
      Number.isFinite(
        rawReinforcementScore
      )
        ? rawReinforcementScore
        : 0;

    const calculatedScore =
      textContribution +
      urlContribution +
      reinforcementScore;

    const backendScore =
      Number(data.score);

    const totalScore =
      Math.max(
        0,
        Math.min(
          100,
          Number.isFinite(backendScore)
            ? backendScore
            : calculatedScore
        )
      );

    const safeScore =
      updateScoreUI(
        totalScore,
        textContribution,
        urlContribution,
        reinforcementScore
      );

    const threat =
      getThreatLevel(safeScore);

    categoryElement.textContent =
      data.category ||
      threat.category;

    /* =========================
       INDICATORS
    ========================= */

    renderIndicators(
      allIndicators
    );

    /* =========================
       SECURITY REASONING
    ========================= */

    renderScoreBreakdown(
      safeScore,
      textContribution,
      urlContribution,
      reinforcementScore,
      allIndicators
    );

    /* =========================
       RISK FACTORS
    ========================= */

    renderRiskFactors(
      data.risk_factors
    );

    /* =========================
       EXPLANATION
    ========================= */

    const backendExplanation =
      typeof data.explanation === "string" &&
      data.explanation.trim()
        ? data.explanation.trim()
        : getExplanation(safeScore);

    explanationElement.textContent =
      backendExplanation;

    /* =========================
       EVIDENCE
    ========================= */

    evidenceElement.innerHTML =
      createEvidence(
        text,
        allIndicators
      );

    /* =========================
       AI ANALYSIS
    ========================= */

    renderAIAnalysis(
      data.ai_analysis ||
      data.ai ||
      null
    );

    /* =========================
       RECOMMENDATIONS
    ========================= */

    recommendationsElement.innerHTML = "";

    const finalRecommendations = [];

    const backendRecommendedAction =
      typeof data.recommended_action === "string" &&
      data.recommended_action.trim()
        ? data.recommended_action.trim()
        : "";

    if (backendRecommendedAction) {
      finalRecommendations.push(
        backendRecommendedAction
      );
    }

    getRecommendations(
      safeScore,
      allIndicators
    ).forEach(
      (recommendation) => {
        if (
          !finalRecommendations.includes(
            recommendation
          )
        ) {
          finalRecommendations.push(
            recommendation
          );
        }
      }
    );

    recommendationsElement.innerHTML =
      finalRecommendations
        .map(
          (recommendation) => `
            <p>
              ${escapeHTML(
                recommendation
              )}
            </p>
          `
        )
        .join("");

    /* =========================
       EDUCATION
    ========================= */

    educationElement.innerHTML =
      getEducation(
        allIndicators
      );

    /* =========================
       SHOW RESULTS
    ========================= */

    loading.classList.add("hidden");
    results.classList.remove("hidden");

    results.scrollIntoView({
      behavior: "smooth",
      block: "start"
    });

  } catch (error) {
    clearTimeout(timeoutId);

    console.error(
      "ScamShield analysis error:",
      error
    );

    /* =========================
       LOCAL FALLBACK
    ========================= */

    try {
      const fallback =
        analyzeText(text);

      const fallbackIndicators =
        uniqueIndicators(
          normalizeIndicators(
            fallback.indicators
          )
        );

      const fallbackScore =
        Math.max(
          0,
          Math.min(
            70,
            Number(fallback.score) || 0
          )
        );

      const fallbackTextContribution =
        Math.round(
          (fallbackScore / 70) * 55
        );

      updateScoreUI(
        fallbackScore,
        fallbackTextContribution,
        0,
        0
      );

      const threat =
        getThreatLevel(
          fallbackScore
        );

      categoryElement.textContent =
        threat.category;

      renderIndicators(
        fallbackIndicators
      );

      renderScoreBreakdown(
        fallbackScore,
        fallbackTextContribution,
        0,
        0,
        fallbackIndicators
      );

      renderRiskFactors([]);

      explanationElement.textContent =
        "The backend service was unavailable, so a local rule-based analysis was used.";

      evidenceElement.innerHTML =
        createEvidence(
          text,
          fallbackIndicators
        );

      renderAIAnalysis(null);

      recommendationsElement.innerHTML =
        getRecommendations(
          fallbackScore,
          fallbackIndicators
        )
          .map(
            (recommendation) => `
              <p>
                ${escapeHTML(
                  recommendation
                )}
              </p>
            `
          )
          .join("");

      educationElement.innerHTML =
        getEducation(
          fallbackIndicators
        );

      loading.classList.add("hidden");
      results.classList.remove("hidden");

      results.scrollIntoView({
        behavior: "smooth",
        block: "start"
      });

    } catch (fallbackError) {
      console.error(
        "ScamShield fallback error:",
        fallbackError
      );

      loading.classList.add("hidden");

      alert(
        "Analysis could not be completed."
      );
    }
  }
}


/* =========================
   ANALYZE BUTTON
========================= */

analyzeBtn.addEventListener(
  "click",
  analyze
);


/* =========================
   CLEAR BUTTON
========================= */

clearBtn.addEventListener(
  "click",
  () => {
    inputText.value = "";

    results.classList.add(
      "hidden"
    );

    loading.classList.add(
      "hidden"
    );

    const reasoning =
      document.getElementById(
        "detailedSecurityReasoning"
      );

    if (reasoning) {
      reasoning.remove();
    }

    scoreElement.textContent = "0";
    threatLevelElement.textContent = "";
    categoryElement.textContent = "";
    indicatorsElement.innerHTML = "";
    riskFactorsElement.innerHTML = "";
    explanationElement.textContent = "";
    aiAnalysisElement.innerHTML = "";
    evidenceElement.innerHTML = "";
    recommendationsElement.innerHTML = "";
    educationElement.innerHTML = "";
  }
);


/* =========================
   CTRL + ENTER
========================= */

inputText.addEventListener(
  "keydown",
  (event) => {
    if (
      event.ctrlKey &&
      event.key === "Enter"
    ) {
      event.preventDefault();
      analyze();
    }
  }
);
