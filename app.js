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
    "expires",
    "last chance"
  ],

  credentials: [
    "password",
    "verify your account",
    "verify your identity",
    "login",
    "username",
    "security code",
    "otp",
    "one time password",
    "sign in"
  ],

  financial: [
    "credit card",
    "bank account",
    "payment",
    "send money",
    "transfer money",
    "bitcoin",
    "crypto",
    "wallet",
    "refund",
    "fee"
  ],

  threats: [
    "suspended",
    "suspend",
    "blocked",
    "closed",
    "legal action",
    "police",
    "penalty",
    "deactivated"
  ],

  rewards: [
    "winner",
    "you won",
    "prize",
    "free money",
    "claim your reward",
    "lottery",
    "congratulations"
  ],

  impersonation: [
    "official",
    "security team",
    "support team",
    "customer service",
    "your bank",
    "paypal",
    "microsoft",
    "apple",
    "amazon"
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
      "The message appears to request authentication or account information.",

    financial:
      "The message involves money, payment, financial information, or cryptocurrency.",

    threats:
      "The message uses fear, consequences, or threats to influence the recipient.",

    rewards:
      "The message uses prizes, rewards, or unexpected benefits as a possible lure.",

    impersonation:
      "The message contains language associated with trusted organizations or support services.",

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
  const lowerText = text.toLowerCase();
  const indicators = [];

  let score = 0;

  const weights = {
    credentials: 25,
    financial: 25,
    urgency: 15,
    threats: 15,
    rewards: 15,
    impersonation: 10
  };

  for (const category in scamPatterns) {
    const matches = scamPatterns[category].filter((pattern) =>
      lowerText.includes(pattern)
    );

    if (!matches.length) {
      continue;
    }

    score += weights[category] || 0;

    indicators.push({
      type: category,
      category,
      matches,
      title: formatCategory(category),
      description: getDescription(category),
      evidence: matches.join(", ")
    });
  }

  return {
    score: Math.min(score, 100),
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
   ESCAPE HTML / REGEX
========================= */

function escapeHTML(value) {
  const div = document.createElement("div");
  div.textContent = String(value ?? "");
  return div.innerHTML;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/* =========================
   EVIDENCE
========================= */

function createEvidence(text, indicators) {
  let result = escapeHTML(text);

  const matches = [];

  indicators.forEach((indicator) => {
    if (!Array.isArray(indicator.matches)) {
      return;
    }

    indicator.matches.forEach((match) => {
      if (match) {
        matches.push(String(match));
      }
    });
  });

  const uniqueMatches = [...new Set(matches)]
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

  return result.replace(regex, "<mark>$1</mark>");
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

    const title =
      indicator?.title ||
      formatCategory(type);

    const description =
      indicator?.description ||
      indicator?.evidence ||
      getDescription(type);

    const matches = Array.isArray(indicator?.matches)
      ? indicator.matches
      : evidence
        ? [String(evidence)]
        : [];

    return {
      ...indicator,
      type,
      category: type,
      title,
      description,
      evidence: String(evidence),
      matches
    };
  });
}

/* =========================
   REMOVE DUPLICATES
========================= */

function uniqueByType(indicators) {
  const result = [];
  const seen = new Set();

  indicators.forEach((indicator) => {
    const key =
      indicator.type ||
      indicator.category ||
      indicator.title ||
      indicator.description;

    if (!seen.has(key)) {
      seen.add(key);
      result.push(indicator);
    }
  });

  return result;
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
  const types = indicators.map((item) => item.type);

  const messageSignals = [];

  if (types.includes("credentials")) {
    messageSignals.push("🔐 Credential request");
  }

  if (types.includes("financial")) {
    messageSignals.push("💳 Financial risk");
  }

  if (types.includes("urgency")) {
    messageSignals.push("⏱️ Urgency pressure");
  }

  if (types.includes("threats")) {
    messageSignals.push("⚠️ Threat / fear tactic");
  }

  if (types.includes("impersonation")) {
    messageSignals.push("🏢 Possible impersonation");
  }

  if (types.includes("rewards")) {
    messageSignals.push("🎁 Unexpected reward");
  }

  const urlSignals = [];

  indicators
    .filter((item) => item.type === "url")
    .forEach((indicator) => {
      const evidence = String(
        indicator.evidence ||
        indicator.description ||
        ""
      ).toLowerCase();

      if (evidence.includes("http instead of https")) {
        urlSignals.push("🔗 HTTP instead of HTTPS");
      }

      if (evidence.includes("suspicious url keywords")) {
        urlSignals.push("🔎 Suspicious URL keywords");
      }

      if (evidence.includes("hyphen")) {
        urlSignals.push("➖ Unusual hyphen usage");
      }

      if (evidence.includes("long domain")) {
        urlSignals.push("🌐 Unusually long domain");
      }

      if (evidence.includes("direct ip")) {
        urlSignals.push("🌐 Direct IP address");
      }

      if (evidence.includes("@")) {
        urlSignals.push("⚠️ URL contains @ symbol");
      }
    });

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

  const rawScore =
    textContribution +
    urlContribution +
    reinforcementScore;

  const section = (
    title,
    items,
    contribution
  ) => {
    return `
      <div style="
        margin-top:14px;
        padding:12px;
        border-radius:10px;
        background:rgba(255,255,255,.03);
      ">
        <div style="
          display:flex;
          justify-content:space-between;
          align-items:center;
          gap:12px;
        ">
          <strong>${title}</strong>
          <strong>+${contribution}</strong>
        </div>

        <div style="margin-top:8px;">
          ${
            items.length
              ? items
                  .map(
                    (item) => `
                      <div style="
                        padding:7px 0;
                        border-bottom:1px solid rgba(255,255,255,.06);
                        opacity:.9;
                      ">
                        ${escapeHTML(item)}
                      </div>
                    `
                  )
                  .join("")
              : `
                <div style="opacity:.65;">
                  No major signals detected.
                </div>
              `
          }
        </div>
      </div>
    `;
  };

  return `
    <div style="
      margin-top:18px;
      padding-top:18px;
      border-top:1px solid rgba(255,255,255,.10);
    ">

      <div style="
        font-size:1.05rem;
        font-weight:700;
      ">
        🧠 WHY ${finalScore}/100?
      </div>

      <div style="
        font-size:.85rem;
        opacity:.7;
        margin-top:5px;
        line-height:1.6;
      ">
        The score is derived from detected security signals,
        URL characteristics and cross-signal reinforcement.
      </div>

      ${section(
        "MESSAGE ANALYSIS",
        messageSignals,
        textContribution
      )}

      ${section(
        "URL ANALYSIS",
        urlSignals,
        urlContribution
      )}

      ${section(
        "CROSS-SIGNAL REINFORCEMENT",
        reinforcementSignals,
        reinforcementScore
      )}

      <div style="
        margin-top:14px;
        padding:10px 12px;
        border-radius:10px;
        background:rgba(255,255,255,.025);
        font-size:.8rem;
        opacity:.7;
      ">
        Raw calculated contribution:
        <strong>${rawScore}</strong>
        → normalized final score:
        <strong>${finalScore}/100</strong>
      </div>

      <div style="
        display:flex;
        justify-content:space-between;
        align-items:center;
        gap:16px;
        margin-top:16px;
        padding:13px;
        border-radius:10px;
        background:rgba(255,255,255,.05);
      ">
        <strong>FINAL RISK SCORE</strong>
        <strong>${finalScore}/100</strong>
      </div>

    </div>
  `;
}

/* =========================
   RENDER SCORE BREAKDOWN
========================= */

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
    reasoning = document.createElement("div");
    reasoning.id =
      "detailedSecurityReasoning";

    scoreBreakdownElement.appendChild(
      reasoning
    );
  }

  // Replace instead of append to prevent duplicate reports.
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
   INDICATORS
========================= */

function renderIndicators(indicators) {
  indicatorsElement.innerHTML = "";

  if (!indicators.length) {
    indicatorsElement.innerHTML = `
      <div
        class="indicator"
        style="border-left-color:#42e8a0"
      >
        <strong>🟢 No strong indicators detected</strong>
        <span>
          The scanner did not find major scam patterns
          in this content.
        </span>
      </div>
    `;

    return;
  }

  indicators.forEach((indicator) => {
    const div =
      document.createElement("div");

    div.className = "indicator";

    if (
      indicator.type ===
      "brand_mismatch"
    ) {
      div.style.borderLeftColor =
        "#a855f7";
    }

    const icon =
      indicator.type ===
      "brand_mismatch"
        ? "🏢"
        : "⚠️";

    div.innerHTML = `
      <strong>
        ${icon}
        ${escapeHTML(indicator.title)}
      </strong>

      <span>
        ${escapeHTML(indicator.description)}
      </span>
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
   EXPLANATION
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
    aiAnalysisElement.innerHTML = `
      <strong>🤖 AI Security Analysis</strong>

      <p>
        ${escapeHTML(ai.analysis.trim())}
      </p>

      <small>
        AI-assisted explanation.
        The final risk score is determined by the
        explainable security engine.
      </small>
    `;

    return;
  }

  // AI failure no longer breaks or degrades the main report.
  aiAnalysisElement.innerHTML = `
    <strong>🧠 Explainable Security Analysis</strong>

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

  if (score >= 80) {
    recommendations.push(
      "🛑 Recommended action: do not click, reply, download attachments, or provide sensitive information."
    );
  } else if (score >= 50) {
    recommendations.push(
      "🟠 Recommended action: treat this content as suspicious and verify it through an independent trusted source."
    );
  } else if (score >= 25) {
    recommendations.push(
      "🟡 Recommended action: review the message carefully and verify unexpected requests before taking action."
    );
  } else {
    recommendations.push(
      "🟢 No strong scam indicators were detected, but remain cautious with unexpected requests or links."
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
    Math.min(100, Number(totalScore) || 0)
  );

  scoreElement.textContent =
    safeScore;

  const threat =
    getThreatLevel(safeScore);

  threatLevelElement.textContent =
    threat.level;

  threatLevelElement.style.color =
    threat.color;

  categoryElement.textContent =
    "";

  if (
    scoreBreakdownElement
  ) {
    const scoreBar =
      document.getElementById(
        "scoreBar"
      );

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
  }

  return safeScore;
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

  try {
    const response = await fetch(
      "https://scamshield-ai-api-82p6.onrender.com/analyze",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          text
        })
      }
    );

    if (!response.ok) {
      throw new Error(
        `Backend returned HTTP ${response.status}`
      );
    }

    const data =
      await response.json();

    /* =========================
       BACKEND SCORE
    ========================= */

    const fallback =
      analyzeText(text);

    const backendIndicators =
      normalizeIndicators(
        data.indicators
      );

    const allIndicators =
      uniqueByType(
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

    const rawReinforcement =
      Number(
        data.reinforcement_score
      );

    const textContribution =
      Number.isFinite(
        rawTextContribution
      )
        ? rawTextContribution
        : fallback.score;

    const urlContribution =
      Number.isFinite(
        rawUrlContribution
      )
        ? rawUrlContribution
        : 0;

    const reinforcementScore =
      Number.isFinite(
        rawReinforcement
      )
        ? rawReinforcement
        : 0;

    const rawCalculatedScore =
      textContribution +
      urlContribution +
      reinforcementScore;

    const backendScore =
      Number(data.score);

    // Normalize the final score to prevent invalid values.
    const totalScore =
      Math.max(
        0,
        Math.min(
          100,
          Number.isFinite(backendScore)
            ? backendScore
            : rawCalculatedScore
        )
      );

    /* =========================
       SCORE
    ========================= */

    const safeScore =
      updateScoreUI(
        totalScore,
        textContribution,
        urlContribution,
        reinforcementScore
      );

    categoryElement.textContent =
      data.category ||
      getThreatLevel(
        safeScore
      ).category;

    /* =========================
       INDICATORS
    ========================= */

    renderIndicators(
      allIndicators
    );

    /* =========================
       DETAILED REASONING
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

    explanationElement.textContent =
      getExplanation(
        safeScore
      );

    /* =========================
       EVIDENCE
    ========================= */

    evidenceElement.innerHTML =
      createEvidence(
        text,
        allIndicators
      );

    /* =========================
       AI
    ========================= */

    renderAIAnalysis(
      data.ai_analysis ||
      data.ai ||
      null
    );

    /* =========================
       RECOMMENDATIONS
    ========================= */

    const recommendations =
      getRecommendations(
        safeScore,
        allIndicators
      );

    recommendationsElement.innerHTML =
      recommendations
        .map(
          (recommendation) =>
            `<p>${escapeHTML(
              recommendation
            )}</p>`
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
    console.error(
      "ScamShield analysis error:",
      error
    );

    /*
      Fallback keeps the application useful
      even when the API or AI service fails.
    */

    try {
      const fallback =
        analyzeText(text);

      const score =
        fallback.score;

      loading.classList.add(
        "hidden"
      );

      scoreElement.textContent =
        score;

      const threat =
        getThreatLevel(score);

      threatLevelElement.textContent =
        threat.level;

      threatLevelElement.style.color =
        threat.color;

      categoryElement.textContent =
        threat.category;

      const indicators =
        uniqueByType(
          normalizeIndicators(
            fallback.indicators
          )
        );

      renderIndicators(
        indicators
      );

      renderRiskFactors([]);

      explanationElement.textContent =
        getExplanation(score);

      evidenceElement.innerHTML =
        createEvidence(
          text,
          indicators
        );

      renderAIAnalysis(null);

      const recommendations =
        getRecommendations(
          score,
          indicators
        );

      recommendationsElement.innerHTML =
        recommendations
          .map(
            (recommendation) =>
              `<p>${escapeHTML(
                recommendation
              )}</p>`
          )
          .join("");

      educationElement.innerHTML =
        getEducation(
          indicators
        );

      renderScoreBreakdown(
        score,
        score,
        0,
        0,
        indicators
      );

      results.classList.remove(
        "hidden"
      );

      results.scrollIntoView({
        behavior: "smooth",
        block: "start"
      });

    } catch {
      loading.classList.add(
        "hidden"
      );

      alert(
        "Analysis could not be completed."
      );
    }
  }
}

/* =========================
   EXAMPLES
========================= */

const examples = {
  bank: `
URGENT!

Your bank account will be suspended today.

Verify your account immediately by clicking:

http://secure-bank-login-example.com/verify

Enter your password and security code to prevent
your account from being closed.
`,

  delivery: `
FINAL DELIVERY NOTICE!

Your package could not be delivered.

A $2.99 redelivery fee is required within 24 hours.

Confirm your payment information here:

http://delivery-payment-update-example.com/confirm

Failure to pay may result in your package being returned.
`,

  crypto: `
CONGRATULATIONS!

You have been selected to receive a $5,000 crypto reward.

Claim your reward immediately by connecting your
wallet and verifying your account:

http://crypto-reward-claim-example.com/wallet

This offer expires today.
`,

  safe: `
Hi Alex,

Your appointment is confirmed for Tuesday
at 10:00 AM.

Please arrive 10 minutes early.

See you then.
`
};

/* =========================
   EXAMPLE BUTTONS
========================= */

document
  .querySelectorAll("[data-example]")
  .forEach((button) => {
    button.addEventListener(
      "click",
      () => {
        const type =
          button.dataset.example;

        if (
          Object.prototype.hasOwnProperty.call(
            examples,
            type
          )
        ) {
          inputText.value =
            examples[type];

          inputText.focus();
        }
      }
    );
  });

/* =========================
   BUTTONS
========================= */

analyzeBtn.addEventListener(
  "click",
  analyze
);

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

    // Remove old dynamically generated reasoning.
    const reasoning =
      document.getElementById(
        "detailedSecurityReasoning"
      );

    if (reasoning) {
      reasoning.remove();
    }
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
