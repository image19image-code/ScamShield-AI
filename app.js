/* =========================================================
   SCAMSHIELD - MAIN JAVASCRIPT
   ========================================================= */

/* =========================================================
   DOM ELEMENTS
   ========================================================= */

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

const scoreBreakdownElement =
  document.getElementById("scoreBreakdown");

const recommendationsElement =
  document.getElementById("recommendations");

const educationElement =
  document.getElementById("education");


/* =========================================================
   CHECK REQUIRED ELEMENTS
   ========================================================= */

if (!inputText) {
  console.error("ScamShield: #inputText was not found.");
}

if (!analyzeBtn) {
  console.error("ScamShield: #analyzeBtn was not found.");
}

if (!clearBtn) {
  console.error("ScamShield: #clearBtn was not found.");
}


/* =========================================================
   SCAM PATTERNS
   ========================================================= */

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
    "verification",
    "verify",
    "login",
    "username",
    "security code",
    "otp",
    "one time password",
    "sign in",
    "confirm your account",
    "confirm your identity",
    "account information",
    "security alert",
    "reset your password",
    "update your account"
  ],

  suspicious_action: [
    "click here",
    "click the link",
    "open the link",
    "follow the link",
    "review your account",
    "verify now",
    "click to verify"
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
    "amazon",
    "google"
  ]

};


/* =========================================================
   CATEGORY FORMAT
   ========================================================= */

function formatCategory(category) {

  const names = {

    urgency: "Urgency Manipulation",

    credentials: "Credential Request",

    suspicious_action: "Suspicious Action",

    financial: "Financial Request",

    threats: "Threat / Fear Tactic",

    rewards: "Reward Scam Indicator",

    impersonation: "Possible Impersonation",

    url: "Suspicious URL",

    brand_mismatch: "Brand / Domain Mismatch"

  };

  return names[category] || category;

}


/* =========================================================
   DESCRIPTIONS
   ========================================================= */

function getDescription(category) {

  const descriptions = {

    urgency:
      "The message pressures the recipient to act quickly without taking time to verify the request.",

    credentials:
      "The message appears to request authentication or account information.",

    suspicious_action:
      "The message encourages the recipient to click or interact with a link or request.",

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
      "A trusted brand is referenced, but the detected domain does not match a recognized official domain."

  };

  return (
    descriptions[category] ||
    "A potentially suspicious characteristic was detected."
  );

}


/* =========================================================
   THREAT LEVEL
   ========================================================= */

function getThreatLevel(score) {

  if (score >= 80) {

    return {
      level: "CRITICAL",
      category: "HIGH-RISK SCAM",
      color: "#ff5364"
    };

  }

  if (score >= 50) {

    return {
      level: "HIGH RISK",
      category: "LIKELY PHISHING / SCAM",
      color: "#ff6b4a"
    };

  }

  if (score >= 25) {

    return {
      level: "MEDIUM RISK",
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


/* =========================================================
   HTML ESCAPE
   ========================================================= */

function escapeHTML(text) {

  const div = document.createElement("div");

  div.textContent = String(text ?? "");

  return div.innerHTML;

}


/* =========================================================
   REGEX ESCAPE
   ========================================================= */

function escapeRegExp(text) {

  return String(text).replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&"
  );

}


/* =========================================================
   NORMALIZE BACKEND INDICATORS
   ========================================================= */

function normalizeIndicators(indicators) {

  if (!Array.isArray(indicators)) {
    return [];
  }

  return indicators.map(indicator => {

    const type = indicator.type || "unknown";

    const evidence =
      indicator.evidence ||
      indicator.description ||
      "Suspicious indicator detected.";

    let matches = [];

    if (Array.isArray(indicator.matches)) {
      matches = indicator.matches;
    }

    /*
      URL and brand mismatch evidence can be
      generated descriptions rather than exact
      text from the original message.
    */

    if (
      matches.length === 0 &&
      type !== "url" &&
      type !== "brand_mismatch"
    ) {
      matches = [evidence];
    }

    return {

      category: type,

      type: type,

      matches: matches,

      title: formatCategory(type),

      description: evidence,

      evidence: evidence

    };

  });

}


/* =========================================================
   EVIDENCE HIGHLIGHTING
   ========================================================= */

function createEvidence(text, indicators) {

  let result = escapeHTML(text);

  const matches = [];

  indicators.forEach(indicator => {

    if (
      Array.isArray(indicator.matches)
    ) {

      indicator.matches.forEach(match => {

        if (
          typeof match === "string" &&
          match.trim()
        ) {

          matches.push(match);

        }

      });

    }

  });

  /*
    Remove duplicates and highlight longest
    phrases first.
  */

  const uniqueMatches = [
    ...new Set(matches)
  ].sort(
    (a, b) => b.length - a.length
  );

  uniqueMatches.forEach(match => {

    const escapedMatch =
      escapeRegExp(
        escapeHTML(match)
      );

    if (!escapedMatch) {
      return;
    }

    const regex =
      new RegExp(
        `(${escapedMatch})`,
        "gi"
      );

    result = result.replace(
      regex,
      "<mark>$1</mark>"
    );

  });

  return result;

}


/* =========================================================
   SCORE BREAKDOWN
   ========================================================= */

function renderScoreBreakdown(data, totalScore) {

  if (!scoreBreakdownElement) {
    return;
  }

  const scorePercentage =
    document.getElementById("scorePercentage");

  const textContributionElement =
    document.getElementById("textContribution");

  const urlContributionElement =
    document.getElementById("urlContribution");

  const reinforcementScoreElement =
    document.getElementById("reinforcementScore");

  const finalScoreElement =
    document.getElementById("finalScore");

  const brandContributionElement =
    document.getElementById("brandContribution");

  const scoreBarContainer =
    document.querySelector(".score-bar-container");


  const textContribution =
    Number(data.text_contribution) || 0;

  const urlContribution =
    Number(data.url_contribution) || 0;

  const brandContribution =
    Number(data.brand_contribution) || 0;

  const reinforcementScore =
    Number(data.reinforcement_score) || 0;


  if (scoreBarContainer) {

    scoreBarContainer.style.setProperty(
      "--score",
      `${totalScore}%`
    );

  }


  if (scorePercentage) {

    scorePercentage.textContent =
      `${totalScore}/100`;

  }


  if (textContributionElement) {

    textContributionElement.textContent =
      `+${textContribution}/55`;

  }


  if (urlContributionElement) {

    urlContributionElement.textContent =
      `+${urlContribution}/25`;

  }


  if (reinforcementScoreElement) {

    reinforcementScoreElement.textContent =
      `+${reinforcementScore}`;

  }


  if (brandContributionElement) {

    brandContributionElement.textContent =
      `+${brandContribution}/15`;

  }


  if (finalScoreElement) {

    finalScoreElement.textContent =
      `${totalScore}/100`;

  }

}


/* =========================================================
   RENDER INDICATORS
   ========================================================= */

function renderIndicators(indicators) {

  if (!indicatorsElement) {
    return;
  }

  indicatorsElement.innerHTML = "";


  if (indicators.length === 0) {

    indicatorsElement.innerHTML = `

      <div
        class="indicator"
        style="border-left-color:#42e8a0"
      >

        <strong>
          🟢 No strong indicators detected
        </strong>

        <span>
          The scanner did not find major
          scam patterns in this content.
        </span>

      </div>

    `;

    return;

  }


  const seen = new Set();

  const uniqueIndicators =
    indicators.filter(indicator => {

      const key =
        `${indicator.type}|${indicator.evidence}`;

      if (seen.has(key)) {
        return false;
      }

      seen.add(key);

      return true;

    });


  uniqueIndicators.forEach(indicator => {

    const div =
      document.createElement("div");

    div.className = "indicator";


    if (
      indicator.type === "brand_mismatch"
    ) {

      div.style.borderLeftColor =
        "#a855f7";

    }


    const title =
      indicator.type === "brand_mismatch"
        ? "Brand / Domain Mismatch"
        : indicator.title;


    const description =
      indicator.evidence ||
      indicator.description ||
      "Suspicious security characteristic detected.";


    div.innerHTML = `

      <strong>

        ${
          indicator.type === "brand_mismatch"
            ? "🏢"
            : "⚠️"
        }

        ${escapeHTML(title)}

      </strong>

      <span>

        ${escapeHTML(description)}

      </span>

    `;


    indicatorsElement.appendChild(div);

  });

}


/* =========================================================
   RENDER RISK FACTORS
   ========================================================= */

function renderRiskFactors(riskFactors) {

  if (!riskFactorsElement) {
    return;
  }

  riskFactorsElement.innerHTML = "";


  if (
    !Array.isArray(riskFactors) ||
    riskFactors.length === 0
  ) {

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


  const uniqueRiskFactors =
    [...new Set(riskFactors)];


  uniqueRiskFactors.forEach(
    (factor, index) => {

      const div =
        document.createElement("div");

      div.className = "indicator";


      div.innerHTML = `

        <strong>

          ${
            index < 2
              ? "🔴"
              : "🟠"
          }

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


/* =========================================================
   RENDER EXPLANATION
   ========================================================= */

function renderExplanation(
  data,
  totalScore,
  indicators
) {

  if (!explanationElement) {
    return;
  }


  if (data.explanation) {

    explanationElement.textContent =
      data.explanation;

    return;

  }


  const hasBrandMismatch =
    indicators.some(
      indicator =>
        indicator.type === "brand_mismatch"
    );


  if (hasBrandMismatch) {

    explanationElement.textContent =
      "The message references a trusted brand, but the detected URL domain does not match a recognized official domain. This mismatch can indicate brand impersonation or phishing. Verify the request through the organization's official website or application.";

    return;

  }


  if (totalScore >= 80) {

    explanationElement.textContent =
      "Multiple strong indicators associated with scams, phishing, or social engineering were detected. Treat this content with extreme caution and verify it independently.";

  } else if (totalScore >= 50) {

    explanationElement.textContent =
      "Several suspicious characteristics were detected. Treat this content cautiously and verify the request independently.";

  } else if (totalScore >= 25) {

    explanationElement.textContent =
      "Some suspicious characteristics were detected. This does not prove malicious intent, but the content deserves additional verification.";

  } else {

    explanationElement.textContent =
      "No strong scam indicators were detected by the current security rules. This does not guarantee that the content is safe.";

  }

}


/* =========================================================
   AI ANALYSIS
   ========================================================= */

function renderAIAnalysis(data) {

  if (!aiAnalysisElement) {
    return;
  }


  if (
    data.ai_analysis &&
    data.ai_analysis.status === "success" &&
    data.ai_analysis.analysis
  ) {

    aiAnalysisElement.textContent =
      data.ai_analysis.analysis;

    return;

  }


  aiAnalysisElement.innerHTML = `

    <strong>
      Rule-based security analysis completed
    </strong>

    <p>
      This assessment was generated using
      explainable security rules,
      message indicators, and URL analysis.
    </p>

    <p>
      The result does not rely on an
      external AI decision.
    </p>

  `;

}


/* =========================================================
   SMART SECURITY RECOMMENDATIONS
   ========================================================= */

function getRecommendations(
  score,
  indicators
) {

  const recommendations = [];


  const types =
    indicators.map(
      indicator =>
        indicator.type ||
        indicator.category
    );


  const hasType = type =>
    types.includes(type);


  if (hasType("credentials")) {

    recommendations.push(
      "🔐 Do not enter your password, OTP, security code, or other credentials in response to this message."
    );

  }


  if (
    hasType("url") ||
    hasType("brand_mismatch")
  ) {

    recommendations.push(
      "🔗 Do not open the detected link. If you need to access the service, open its official website or app directly."
    );

  }


  if (hasType("financial")) {

    recommendations.push(
      "🏦 Do not send money or provide banking information through this message. Verify the request using an official channel."
    );

  }


  if (hasType("urgency")) {

    recommendations.push(
      "⏸️ Do not let urgency pressure you into acting immediately. Stop and verify the request independently."
    );

  }


  if (hasType("threats")) {

    recommendations.push(
      "⚠️ Do not respond to threats or account-closure warnings until you independently verify the situation."
    );

  }


  if (hasType("impersonation")) {

    recommendations.push(
      "🏢 Verify the sender through the organization's official website, app, or known contact information—not through the message."
    );

  }


  if (hasType("rewards")) {

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


  return recommendations;

}


/* =========================================================
   RENDER RECOMMENDATIONS
   ========================================================= */

function renderRecommendations(
  score,
  indicators
) {

  if (!recommendationsElement) {
    return;
  }

  recommendationsElement.innerHTML = "";


  const recommendations =
    getRecommendations(
      score,
      indicators
    );


  recommendationsElement.innerHTML =
    recommendations
      .map(
        recommendation =>
          `<p>${escapeHTML(
            recommendation
          )}</p>`
      )
      .join("");

}


/* =========================================================
   EDUCATION
   ========================================================= */

function getEducation(indicators) {

  const categories =
    indicators.map(
      item =>
        item.type ||
        item.category
    );


  if (
    categories.includes("brand_mismatch")
  ) {

    return `

      <p>
        A message can imitate a trusted organization
        while using a completely different website.
        Always check the real domain and access important
        services through their official website or app.
      </p>

    `;

  }


  if (
    categories.includes("urgency")
  ) {

    return `

      <p>
        Attackers often create urgency or fear
        to prevent victims from thinking carefully.
        Stop, verify the request independently,
        and only then take action.
      </p>

    `;

  }


  if (
    categories.includes("credentials")
  ) {

    return `

      <p>
        Be cautious when a message asks you to enter
        passwords, OTP codes, or other credentials.
        Access your account through the organization's
        official website or application instead of
        following an unexpected link.
      </p>

    `;

  }


  if (
    categories.includes("financial")
  ) {

    return `

      <p>
        Financial requests deserve extra caution.
        Never send money or financial information
        simply because a message creates pressure
        or urgency.
      </p>

    `;

  }


  if (
    categories.includes("url")
  ) {

    return `

      <p>
        A suspicious URL does not automatically prove
        that a website is malicious. However, unusual
        domains, redirects, or link structures deserve
        additional verification before opening.
      </p>

    `;

  }


  return `

    <p>
      A security tool can identify warning signs,
      but users should always verify important
      requests through trusted official channels.
    </p>

  `;

}


function renderEducation(indicators) {

  if (!educationElement) {
    return;
  }

  educationElement.innerHTML =
    getEducation(indicators);

}


/* =========================================================
   MAIN ANALYSIS
   ========================================================= */

async function analyze() {

  if (!inputText) {
    return;
  }


  const text =
    inputText.value.trim();


  if (!text) {

    alert(
      "Please paste a message or URL first."
    );

    return;

  }


  if (results) {
    results.classList.add("hidden");
  }

  if (loading) {
    loading.classList.remove("hidden");
  }


  try {

    console.log(
      "Sending request to ScamShield backend..."
    );


    /*
      IMPORTANT:
      This is a normal URL.
      Do NOT put Markdown [ ] ( ) around it.
    */

    const response =
      await fetch(
        "http://127.0.0.1:8000/analyze",
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json"
          },

          body: JSON.stringify({
            text: text
          })
        }
      );


    console.log(
      "Backend response:",
      response.status
    );


    if (!response.ok) {

      throw new Error(
        `Backend returned HTTP ${response.status}`
      );

    }


    const data =
      await response.json();


    console.log(
      "Backend data:",
      data
    );


    /* =====================================================
       NORMALIZE SCORE
       ===================================================== */

    const totalScore =
      Math.max(
        0,
        Math.min(
          100,
          Number(data.score) || 0
        )
      );


    const allIndicators =
      normalizeIndicators(
        data.indicators
      );


    /* =====================================================
       SCORE BREAKDOWN
       ===================================================== */

    renderScoreBreakdown(
      data,
      totalScore
    );


    /* =====================================================
       MAIN SCORE
       ===================================================== */

    if (scoreElement) {

      scoreElement.textContent =
        totalScore;

    }


    const threat =
      getThreatLevel(
        totalScore
      );


    const backendThreatLevel =
      data.threat_level ||
      threat.level;


    if (threatLevelElement) {

      threatLevelElement.textContent =
        backendThreatLevel;

      threatLevelElement.style.color =
        threat.color;

    }


    if (categoryElement) {

      categoryElement.textContent =
        data.category ||
        threat.category;

    }


    /* =====================================================
       INDICATORS
       ===================================================== */

    renderIndicators(
      allIndicators
    );


    /* =====================================================
       RISK FACTORS
       ===================================================== */

    renderRiskFactors(
      data.risk_factors
    );


    /* =====================================================
       EXPLANATION
       ===================================================== */

    renderExplanation(
      data,
      totalScore,
      allIndicators
    );


    /* =====================================================
       EVIDENCE
       ===================================================== */

    if (evidenceElement) {

      evidenceElement.innerHTML =
        createEvidence(
          text,
          allIndicators
        );

    }


    /* =====================================================
       AI ANALYSIS
       ===================================================== */

    renderAIAnalysis(
      data
    );


    /* =====================================================
       RECOMMENDATIONS
       ===================================================== */

    renderRecommendations(
      totalScore,
      allIndicators
    );


    /* =====================================================
       EDUCATION
       ===================================================== */

    renderEducation(
      allIndicators
    );


    /* =====================================================
       SHOW RESULTS
       ===================================================== */

    if (results) {

      results.classList.remove(
        "hidden"
      );

      results.scrollIntoView({
        behavior: "smooth",
        block: "start"
      });

    }


    console.log(
      "ScamShield analysis completed successfully."
    );

  }

  catch (error) {

    console.error(
      "ScamShield analysis error:",
      error
    );


    if (results) {

      results.classList.add(
        "hidden"
      );

    }


    alert(
      "Analysis error: " +
      error.message
    );

  }

  finally {

    if (loading) {

      loading.classList.add(
        "hidden"
      );

    }

  }

}


/* =========================================================
   EXAMPLES
   ========================================================= */

const examples = {

  bank: `URGENT!

Your bank account will be suspended today.

Verify your account immediately by clicking:

http://secure-bank-login-example.com/verify

Enter your password and security code to prevent
your account from being closed.`,


  delivery: `FINAL DELIVERY NOTICE!

Your package could not be delivered.

A $2.99 redelivery fee is required within 24 hours.

Confirm your payment information here:

http://delivery-payment-update-example.com/confirm

Failure to pay may result in your package being returned.`,


  crypto: `CONGRATULATIONS!

You have been selected to receive a $5,000 crypto reward.

Claim your reward immediately by connecting your
wallet and verifying your account:

http://crypto-reward-claim-example.com/wallet

This offer expires today.`,


  safe: `Hi Alex,

Your appointment is confirmed for Tuesday
at 10:00 AM.

Please arrive 10 minutes early.

See you then.`

};


/* =========================================================
   EXAMPLE BUTTONS
   ========================================================= */

document
  .querySelectorAll("[data-example]")
  .forEach(button => {

    button.addEventListener(
      "click",
      () => {

        const type =
          button.dataset.example;


        if (
          examples[type] &&
          inputText
        ) {

          inputText.value =
            examples[type];

          inputText.focus();

        }

      }
    );

  });


/* =========================================================
   ANALYZE BUTTON
   ========================================================= */

if (analyzeBtn) {

  analyzeBtn.addEventListener(
    "click",
    analyze
  );

}


/* =========================================================
   CLEAR BUTTON
   ========================================================= */

if (clearBtn) {

  clearBtn.addEventListener(
    "click",
    () => {

      if (inputText) {
        inputText.value = "";
        inputText.focus();
      }

      if (results) {
        results.classList.add("hidden");
      }

      if (loading) {
        loading.classList.add("hidden");
      }

    }
  );

}


/* =========================================================
   CTRL + ENTER
   ========================================================= */

if (inputText) {

  inputText.addEventListener(
    "keydown",
    event => {

      if (
        event.ctrlKey &&
        event.key === "Enter"
      ) {

        event.preventDefault();

        analyze();

      }

    }
  );

}


/* =========================================================
   READY
   ========================================================= */

console.log(
  "ScamShield JavaScript loaded successfully."
);