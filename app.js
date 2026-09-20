const inputText = document.getElementById("inputText");
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");

const loading = document.getElementById("loading");
const results = document.getElementById("results");

const scoreElement = document.getElementById("score");
const threatLevelElement = document.getElementById("threatLevel");
const categoryElement = document.getElementById("category");

const indicatorsElement = document.getElementById("indicators");
const riskFactorsElement =
  document.getElementById("riskFactors");
const explanationElement = document.getElementById("explanation");
const aiAnalysisElement = document.getElementById("aiAnalysis");
const evidenceElement = document.getElementById("evidence");

const scoreBreakdownElement =
  document.getElementById("scoreBreakdown");

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
   CATEGORY FORMAT
========================= */

function formatCategory(category) {

  const names = {

    urgency: "Urgency Manipulation",

    credentials: "Credential Request",

    financial: "Financial Request",

    threats: "Threat / Fear Tactic",

    rewards: "Reward Scam Indicator",

    impersonation: "Possible Impersonation",

    url: "Suspicious URL"

  };

  return names[category] || category;

}


/* =========================
   DESCRIPTIONS
========================= */

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
      "The detected URL contains characteristics that deserve additional verification."

  };

  return descriptions[category] || "A potentially suspicious characteristic was detected.";

}


/* =========================
   OLD FRONTEND ANALYSIS
   Used only as fallback
========================= */

function analyzeText(text) {

  const lowerText = text.toLowerCase();

  const indicators = [];

  let score = 0;


  for (const category in scamPatterns) {

    const matches =
      scamPatterns[category].filter(pattern =>
        lowerText.includes(pattern)
      );


    if (matches.length > 0) {

      let categoryScore = 0;

      switch (category) {

        case "credentials":
          categoryScore = 25;
          break;

        case "financial":
          categoryScore = 25;
          break;

        case "urgency":
          categoryScore = 15;
          break;

        case "threats":
          categoryScore = 15;
          break;

        case "rewards":
          categoryScore = 15;
          break;

        case "impersonation":
          categoryScore = 10;
          break;

      }


      score += categoryScore;


      indicators.push({

        category: category,

        matches: matches,

        title: formatCategory(category),

        description: getDescription(category)

      });

    }

  }


  return {

    score: Math.min(score, 70),

    indicators: indicators

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
   RECOMMENDATIONS
========================= */

function getRecommendations(score, indicators) {

  const recommendations = [];


  if (score >= 35) {

    recommendations.push(
      "🛑 Do not click suspicious links."
    );

    recommendations.push(
      "🔐 Do not enter passwords, OTP codes, or financial information."
    );

    recommendations.push(
      "🔎 Verify the sender through an official channel."
    );

  }


  if (score >= 60) {

    recommendations.push(
      "⚠️ Consider reporting the message as phishing or spam."
    );

  }


  if (score < 35) {

    recommendations.push(
      "✅ No strong scam indicators were detected."
    );

    recommendations.push(
      "🔎 Still verify unexpected requests before taking action."
    );

  }


  return recommendations;

}


/* =========================
   EDUCATION
========================= */

function getEducation(indicators) {

  const categories =
    indicators.map(item => item.category);


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
      Legitimate organizations generally have
      established official channels for account
      management. Be cautious when a message
      asks you to enter credentials through a link.
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
    but users should always verify important
    requests through trusted official channels.
  `;

}


/* =========================
   ESCAPE HTML
========================= */

function escapeHTML(text) {

  const div = document.createElement("div");

  div.textContent = text;

  return div.innerHTML;

}


function escapeRegExp(text) {

  return text.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&"
  );

}


/* =========================
   HIGHLIGHT EVIDENCE
========================= */

function createEvidence(text, indicators) {

  let result = escapeHTML(text);


  indicators.forEach(indicator => {

    if (!indicator.matches) {
      return;
    }


    indicator.matches.forEach(match => {

      const escaped =
        escapeRegExp(
          escapeHTML(match)
        );


      const regex =
        new RegExp(
          `(${escaped})`,
          "gi"
        );


      result =
        result.replace(
          regex,
          "<mark>$1</mark>"
        );

    });

  });


  return result;

}


/* =========================
   NORMALIZE BACKEND DATA
========================= */

function normalizeIndicators(indicators) {

  return (indicators || []).map(indicator => {

    const type =
      indicator.type || "unknown";

    const evidence =
      indicator.evidence ||
      indicator.description ||
      "Suspicious indicator detected";


    let title;

    switch (type) {

      case "credentials":
        title = "Credential Request";
        break;

      case "financial":
        title = "Financial Risk";
        break;

      case "urgency":
        title = "Urgency Manipulation";
        break;

      case "threats":
        title = "Threat / Fear Tactic";
        break;

      case "impersonation":
        title = "Possible Impersonation";
        break;

      case "rewards":
        title = "Unexpected Reward";
        break;

      case "url":
        title = "Suspicious URL";
        break;

      case "brand_mismatch":
        title = "Brand / Domain Mismatch";
        break;

      default:
        title = formatCategory(type);
    }


    return {

      category: type,

      type: type,

      matches: [evidence],

      title: title,

      description: evidence,

      evidence: evidence

    };

  });

}


/* =========================
   AI OUTPUT CLEANUP
========================= */

function cleanAIAnalysis(text) {

  return String(text || "")
    .replace(/```(?:text|markdown)?/gi, "")
    .replace(/```/g, "")
    .replace(/\*\*/g, "")
    .replace(/__/g, "")
    .replace(/^\s*#{1,6}\s*/gm, "")
    .replace(/^\s*[-*•]\s+/gm, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
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

    console.log("Sending request to ScamShield backend...");


    const response =
      await fetch(
        "https://scamshield-ai-api-82p6.onrender.com/analyze",
        {

          method: "POST",

          headers: {
            "Content-Type": "application/json"
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

    console.log(
      "FULL BACKEND DATA:",
      JSON.stringify(data, null, 2)
    );


    /* =========================
       NORMALIZE DATA
    ========================= */

    const totalScore =
      Number(data.score) || 0;

    const textContribution =
      Number(data.text_contribution) || 0;

    const urlContribution =
      Number(data.url_contribution) || 0;

    const reinforcementScore =
      Number(data.reinforcement_score) || 0;


    const allIndicators =
      normalizeIndicators(
        data.indicators
      );

    if (scoreBreakdownElement) {

      const scoreBar =
        document.getElementById("scoreBar");

      console.log(
        "Score bar:",
        scoreBar
      );

      console.log(
        "Total score:",
        totalScore
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
          `${totalScore}%`
        );

      }


      if (scorePercentage) {

        scorePercentage.textContent =
          `${totalScore}/100`;

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
          `${totalScore}/100`;

      }

    }


    /* =========================
       SCORE
    ========================= */

    scoreElement.textContent =
      totalScore;


    const threat =
      getThreatLevel(totalScore);


    threatLevelElement.textContent =
      data.threat_level ||
      threat.level;


    threatLevelElement.style.color =
      threat.color;


    categoryElement.textContent =
      data.category ||
      threat.category;


    /* =========================
       INDICATORS
    ========================= */

    indicatorsElement.innerHTML =
      "";


    const indicatorTitles = {

      credentials:
        "Credential Request",

      financial:
        "Financial Risk",

      urgency:
        "Urgency Manipulation",

      threats:
        "Threat / Fear Tactic",

      impersonation:
        "Possible Impersonation",

      rewards:
        "Unexpected Reward",

      url:
        "Suspicious URL",

      brand_mismatch:
        "Brand / Domain Mismatch"

    };


    const indicatorDefaults = {

      credentials:
        "The message appears to request authentication or account information.",

      financial:
        "The message involves money, payment, financial information, or cryptocurrency.",

      urgency:
        "The message pressures the recipient to act quickly.",

      threats:
        "The message uses fear, consequences, or threats to influence the recipient.",

      impersonation:
        "The message uses language associated with a trusted organization or service.",

      rewards:
        "The message contains an unexpected prize, reward, or promotional claim.",

      url:
        "The detected URL contains suspicious characteristics.",

      brand_mismatch:
        "A trusted brand is referenced, but the detected URL domain does not match a recognized official domain."

    };


    /*
      Aggregate indicators by category so the report shows
      one clear security finding with its supporting evidence.
    */

    const groupedIndicators =
      new Map();


    allIndicators.forEach(
      indicator => {

        const type =
          indicator.type ||
          indicator.category ||
          "unknown";


        const evidence =
          indicator.evidence ||
          indicator.description ||
          "Suspicious security characteristic detected.";


        if (!groupedIndicators.has(type)) {

          groupedIndicators.set(
            type,
            {

              ...indicator,

              type,

              category: type,

              title:
                indicatorTitles[type] ||
                indicator.title ||
                formatCategory(type),

              description:
                indicatorDefaults[type] ||
                indicator.description ||
                "Suspicious security characteristic detected.",

              evidenceList: [],

              matches: []

            }
          );

        }


        const grouped =
          groupedIndicators.get(type);


        if (
          !grouped.evidenceList.includes(
            evidence
          )
        ) {

          grouped.evidenceList.push(
            evidence
          );

        }


        if (
          Array.isArray(
            indicator.matches
          )
        ) {

          indicator.matches.forEach(
            match => {

              if (
                !grouped.matches.includes(
                  match
                )
              ) {

                grouped.matches.push(
                  match
                );

              }

            }
          );

        }

      }
    );


    const uniqueIndicators =
      Array.from(
        groupedIndicators.values()
      ).map(
        indicator => ({

          ...indicator,

          evidence:
            indicator.evidenceList.join(
              ", "
            ),

          description:
            indicator.description ||
            indicatorDefaults[
              indicator.type
            ] ||
            "Suspicious security characteristic detected."

        })
      );


    /* =========================
       DETAILED SECURITY REASONING
    ========================= */

    function renderDetailedSecurityReasoning(
      score,
      indicators
    ) {

      const types =
        indicators.map(
          indicator =>
            indicator.type
        );


      const messageSignals = [];

      const urlSignals = [];

      const reinforcementSignals = [];


      if (
        types.includes("credentials")
      ) {

        messageSignals.push(
          [
            "🔐",
            "Credential request",
            "+25"
          ]
        );

      }


      if (
        types.includes("financial")
      ) {

        messageSignals.push(
          [
            "💳",
            "Financial risk",
            "+25"
          ]
        );

      }


      if (
        types.includes("urgency")
      ) {

        messageSignals.push(
          [
            "⏱️",
            "Urgency pressure",
            "+15"
          ]
        );

      }


      if (
        types.includes("threats")
      ) {

        messageSignals.push(
          [
            "⚠️",
            "Threat / fear tactic",
            "+15"
          ]
        );

      }


      if (
        types.includes("impersonation")
      ) {

        messageSignals.push(
          [
            "🏢",
            "Possible impersonation",
            "+10"
          ]
        );

      }


      indicators
        .filter(
          indicator =>
            indicator.type === "url"
        )
        .forEach(
          indicator => {

            const evidence =
              (
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
                [
                  "🔗",
                  "HTTP instead of HTTPS",
                  "+15"
                ]
              );

            }


            if (
              evidence.includes(
                "suspicious url keywords"
              )
            ) {

              urlSignals.push(
                [
                  "🔎",
                  "Suspicious URL keywords",
                  "+15"
                ]
              );

            }


            if (
              evidence.includes(
                "hyphen"
              )
            ) {

              urlSignals.push(
                [
                  "➖",
                  "Excessive hyphens",
                  "+10"
                ]
              );

            }


            if (
              evidence.includes(
                "long domain"
              )
            ) {

              urlSignals.push(
                [
                  "🌐",
                  "Unusually long domain",
                  "+10"
                ]
              );

            }


            if (
              evidence.includes(
                "direct ip"
              )
            ) {

              urlSignals.push(
                [
                  "🌐",
                  "Direct IP address",
                  "+25"
                ]
              );

            }


            if (
              evidence.includes("@")
            ) {

              urlSignals.push(
                [
                  "⚠️",
                  "URL contains @ symbol",
                  "+20"
                ]
              );

            }

          }
        );


      if (
        types.includes("credentials") &&
        types.includes("url")
      ) {

        reinforcementSignals.push(
          [
            "🔐",
            "Credentials + suspicious URL",
            "+5"
          ]
        );

      }


      if (
        types.includes("financial") &&
        types.includes("url")
      ) {

        reinforcementSignals.push(
          [
            "💳",
            "Financial risk + suspicious URL",
            "+4"
          ]
        );

      }


      if (
        types.includes("urgency") &&
        types.includes("credentials")
      ) {

        reinforcementSignals.push(
          [
            "⏱️",
            "Urgency + credentials",
            "+3"
          ]
        );

      }


      if (
        types.includes("threats") &&
        types.includes("urgency")
      ) {

        reinforcementSignals.push(
          [
            "⚠️",
            "Threat + urgency",
            "+3"
          ]
        );

      }


      if (
        types.includes("impersonation") &&
        types.includes("credentials")
      ) {

        reinforcementSignals.push(
          [
            "🏢",
            "Impersonation + credentials",
            "+2"
          ]
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
          [
            "🎯",
            "Strong phishing pattern",
            "+4"
          ]
        );

      }


      const section =
        (
          title,
          signals
        ) => {

          if (!signals.length) {

            return `
              <div
                style="
                  margin-top:14px;
                  padding:12px;
                  border-radius:10px;
                  background:rgba(255,255,255,.03);
                "
              >

                <strong>
                  ${title}
                </strong>

                <div
                  style="
                    margin-top:6px;
                    opacity:.65;
                  "
                >
                  No major signals detected.
                </div>

              </div>
            `;

          }


          return `
            <div
              style="
                margin-top:14px;
                padding:12px;
                border-radius:10px;
                background:rgba(255,255,255,.03);
              "
            >

              <strong>
                ${title}
              </strong>

              <div
                style="
                  margin-top:8px;
                "
              >

                ${signals
                  .map(
                    signal => `
                      <div
                        style="
                          display:flex;
                          justify-content:space-between;
                          gap:16px;
                          padding:7px 0;
                          border-bottom:
                            1px solid
                            rgba(255,255,255,.06);
                        "
                      >

                        <span>
                          ${signal[0]}
                          ${escapeHTML(
                            signal[1]
                          )}
                        </span>

                        <strong>
                          ${signal[2]}
                        </strong>

                      </div>
                    `
                  )
                  .join("")}

              </div>

            </div>
          `;

        };


      return `
        <div
          style="
            margin-top:18px;
            padding-top:18px;
            border-top:
              1px solid
              rgba(255,255,255,.10);
          "
        >

          <div
            style="
              font-size:1.05rem;
              font-weight:700;
            "
          >
            🧠 WHY ${score}/100?
          </div>

          <div
            style="
              font-size:.85rem;
              opacity:.7;
              margin-top:5px;
            "
          >
            The score is explained using detected
            security signals and their interactions.
          </div>

          ${section(
            "MESSAGE SIGNALS",
            messageSignals
          )}

          ${section(
            "URL SIGNALS",
            urlSignals
          )}

          ${section(
            "CROSS-SIGNAL REINFORCEMENT",
            reinforcementSignals
          )}

          <div
            style="
              display:flex;
              justify-content:space-between;
              align-items:center;
              margin-top:16px;
              padding:13px;
              border-radius:10px;
              background:rgba(255,255,255,.05);
            "
          >

            <strong>
              FINAL RISK SCORE
            </strong>

            <strong>
              ${score}/100
            </strong>

          </div>

        </div>
      `;

    }


    /* Display after uniqueIndicators has been created. */

    if (scoreBreakdownElement) {

      const reasoning =
        document.createElement(
          "div"
        );

      reasoning.id =
        "detailedSecurityReasoning";

      reasoning.innerHTML =
        renderDetailedSecurityReasoning(
          totalScore,
          uniqueIndicators
        );

      scoreBreakdownElement.appendChild(
        reasoning
      );

    }


    /*
      Render indicators.
    */

    if (
      uniqueIndicators.length === 0
    ) {

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

    }

    else {

      uniqueIndicators.forEach(
        indicator => {

          const div =
            document.createElement("div");


          div.className =
            "indicator";


          /*
            Give brand mismatch a dedicated
            visual identity.
          */

          if (
            indicator.type ===
            "brand_mismatch"
          ) {

            div.style.borderLeftColor =
              "#a855f7";

          }


          const displayTitle =
            indicator.type ===
            "brand_mismatch"

              ? "Brand / Domain Mismatch"

              : indicator.title;


          const displayDescription =
            indicator.type ===
            "brand_mismatch"

              ? (
                  indicator.evidence ||
                  indicator.description ||
                  "A trusted brand is referenced, but the detected URL domain does not match a recognized official domain."
                )

              : indicator.description;


          div.innerHTML = `

            <strong>

              ${
                indicator.type ===
                "brand_mismatch"

                  ? "🏢"

                  : "⚠️"
              }

              ${escapeHTML(
                displayTitle
              )}

            </strong>


            <span>

              ${escapeHTML(
                displayDescription
              )}

            </span>

          `;


          indicatorsElement.appendChild(
            div
          );

        }
      );

    }


    /* =========================
       RISK FACTORS
    ========================= */

    riskFactorsElement.innerHTML =
      "";


    const riskFactors =
      data.risk_factors || [];


    const uniqueRiskFactors =
      [
        ...new Set(
          riskFactors
        )
      ];


    if (
      uniqueRiskFactors.length === 0
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

    }

    else {

      uniqueRiskFactors.forEach(
        (
          factor,
          index
        ) => {

          const div =
            document.createElement(
              "div"
            );


          div.className =
            "indicator";


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

              ${escapeHTML(
                factor
              )}

            </span>

          `;


          riskFactorsElement.appendChild(
            div
          );

        }
      );

    }


    /* =========================
       EXPLANATION
    ========================= */

    if (
      totalScore >= 60
    ) {

      explanationElement.textContent =
        "Multiple indicators commonly associated with scams, phishing, or social engineering were detected. Treat this content cautiously and verify it independently.";

    }

    else if (
      totalScore >= 35
    ) {

      explanationElement.textContent =
        "Some suspicious characteristics were detected. This does not prove malicious intent, but the content deserves additional verification.";

    }

    else {

      explanationElement.textContent =
        "No strong scam indicators were detected by the current security rules. This does not guarantee that the content is safe.";

    }


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

    const ai =
      data.ai_analysis ||
      data.ai ||
      null;


    if (
      ai &&
      ai.status === "success" &&
      ai.analysis
    ) {

      aiAnalysisElement.innerHTML = `

        <strong>
          🤖 AI Security Analysis
        </strong>

        <p>
          ${escapeHTML(
            cleanAIAnalysis(
              ai.analysis
            )
          )
            .replace(
              /\n\n/g,
              "</p><p>"
            )
            .replace(
              /\n/g,
              "<br>"
            )}
        </p>

        <small>
          AI-assisted analysis generated by ScamShield.
          This result is advisory and should not be treated
          as absolute certainty.
        </small>

      `;

    }

    else if (
      ai &&
      ai.status === "error"
    ) {

      aiAnalysisElement.innerHTML = `

        <strong>
          ⚠️ AI Analysis Error
        </strong>

        <p>
          The AI service could not complete
          the AI analysis.
        </p>

        ${
          ai.error
            ? `<small>${escapeHTML(
                ai.error
              )}</small>`
            : ""
        }

      `;

    }

    else {

      aiAnalysisElement.innerHTML = `

        <strong>
          🛡️ Rule-Based Security Analysis
        </strong>

        <p>
          AI analysis is currently unavailable.
          The security engine completed the analysis
          using explainable security rules,
          message indicators, and URL analysis.
        </p>

      `;

    }


    /* =========================
       RECOMMENDATIONS
    ========================= */

    recommendationsElement.innerHTML =
      "";


    const recommendations =
      getRecommendations(
        totalScore,
        allIndicators
      );


    recommendationsElement.innerHTML =
      recommendations
        .map(
          recommendation =>
            `<p>${recommendation}</p>`
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


    const threatReport =
      document.getElementById(
        "threatReport"
      );


    if (threatReport) {

      threatReport.scrollIntoView({
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


    loading.classList.add("hidden");


    alert(
      "Analysis error: " +
      error.message
    );

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
  .querySelectorAll(
    "[data-example]"
  )
  .forEach(
    button => {

      button.addEventListener(
        "click",
        () => {

          const type =
            button.dataset.example;


          inputText.value =
            examples[type];


          inputText.focus();

        }
      );

    }
  );


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

    results.classList.add("hidden");

    loading.classList.add("hidden");

  }
);


/* =========================
   CTRL + ENTER
========================= */

inputText.addEventListener(
  "keydown",
  event => {

    if (
      event.ctrlKey &&
      event.key === "Enter"
    ) {

      analyze();

    }

  }
);


/* =========================
   SMART SECURITY RECOMMENDATIONS
========================= */

function getRecommendations(
  score,
  indicators
) {

  const recommendations = [];

  const types =
    indicators.map(
      indicator =>
        indicator.type
    );


  /* Credential protection */

  if (
    types.includes(
      "credentials"
    )
  ) {

    recommendations.push(
      "🔐 Do not enter your password, OTP, security code, or other credentials in response to this message."
    );

  }


  /* Suspicious URL */

  if (
    types.includes("url")
  ) {

    recommendations.push(
      "🔗 Do not open the detected link. If you need to access the service, open its official website or app directly."
    );

  }


  /* Financial protection */

  if (
    types.includes("financial")
  ) {

    recommendations.push(
      "🏦 Do not send money or provide banking information through this message. Verify the request using an official channel."
    );

  }


  /* Urgency */

  if (
    types.includes("urgency")
  ) {

    recommendations.push(
      "⏸️ Do not let urgency pressure you into acting immediately. Stop and verify the request independently."
    );

  }


  /* Threats */

  if (
    types.includes("threats")
  ) {

    recommendations.push(
      "⚠️ Do not respond to threats or account-closure warnings until you independently verify the situation."
    );

  }


  /* Impersonation */

  if (
    types.includes("impersonation")
  ) {

    recommendations.push(
      "🏢 Verify the sender through the organization's official website, app, or known contact information—not through the message."
    );

  }


  /* Rewards */

  if (
    types.includes("rewards")
  ) {

    recommendations.push(
      "🎁 Be cautious with unexpected prizes or rewards. Do not provide personal or financial information to claim them."
    );

  }


  /* General recommendation */

  if (
    score >= 80
  ) {

    recommendations.push(
      "🛑 Recommended action: do not click, reply, download attachments, or provide sensitive information."
    );

  }

  else if (
    score >= 50
  ) {

    recommendations.push(
      "🟠 Recommended action: treat this content as suspicious and verify it through an independent trusted source."
    );

  }

  else if (
    score >= 25
  ) {

    recommendations.push(
      "🟡 Recommended action: review the message carefully and verify unexpected requests before taking action."
    );

  }

  else {

    recommendations.push(
      "🟢 No strong scam indicators were detected, but remain cautious with unexpected requests or links."
    );

  }


  return recommendations;
}
