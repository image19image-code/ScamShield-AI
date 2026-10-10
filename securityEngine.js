// =========================================================
// SCAM PATTERNS
// =========================================================

export const SCAM_PATTERNS = {
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
    "respond now",
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
    "access code",
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
    "download now",
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
    "banking information",
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
    "lose access",
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
    "reward",
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
    "account security",
  ],
};

// =========================================================
// CATEGORY WEIGHTS
// =========================================================

export const CATEGORY_WEIGHTS = {
  credentials: 30,
  financial: 28,
  threats: 20,
  rewards: 18,
  urgency: 14,
  impersonation: 10,
  suspicious_action: 10,
};

// =========================================================
// TEXT ANALYSIS
// =========================================================

export function analyzeText(text) {
  const content = (text || "").toLowerCase().replace(/\s+/g, " ").trim();
  const indicators = [];
  const matchedCategories = [];

  for (const [category, patterns] of Object.entries(SCAM_PATTERNS)) {
    const categoryMatches = [];

    for (const pattern of patterns) {
      if (content.includes(pattern)) {
        categoryMatches.push(pattern);
      }
    }

    if (categoryMatches.length > 0) {
      matchedCategories.push(category);
      for (const pattern of categoryMatches) {
        indicators.push({
          type: category,
          evidence: pattern,
        });
      }
    }
  }

  let rawScore = matchedCategories.reduce(
    (sum, cat) => sum + (CATEGORY_WEIGHTS[cat] || 0),
    0
  );

  rawScore = Math.min(rawScore, 70);

  return {
    score: rawScore,
    indicators,
    categories: matchedCategories,
  };
}

// =========================================================
// URL EXTRACTION
// =========================================================

export function extractUrls(text) {
  const content = text || "";
  const regex = /https?:\/\/[^\s<>\]\)"']+/gi;
  const urls = content.match(regex) || [];

  const cleaned = urls.map((url) => url.replace(/[.,!?;:]+$/, "")).filter(Boolean);
  return [...new Set(cleaned)];
}

// =========================================================
// BRAND / DOMAIN MISMATCH
// =========================================================

export const TRUSTED_BRANDS = {
  microsoft: ["microsoft.com", "live.com", "office.com", "outlook.com"],
  apple: ["apple.com", "icloud.com"],
  amazon: ["amazon.com", "amazon.co.uk", "amazon.de"],
  paypal: ["paypal.com"],
  google: ["google.com", "googleusercontent.com"],
  netflix: ["netflix.com"],
};

export function analyzeBrandDomainMismatch(text) {
  const urls = extractUrls(text);
  if (!urls.length) {
    return { score: 0, indicators: [] };
  }

  const textLower = (text || "").toLowerCase();
  let score = 0;
  const indicators = [];

  for (const [brand, officialDomains] of Object.entries(TRUSTED_BRANDS)) {
    if (!textLower.includes(brand)) continue;

    for (const url of urls) {
      try {
        const parsed = new URL(url);
        const hostname = (parsed.hostname || "").toLowerCase();
        if (!hostname) continue;

        const isOfficial = officialDomains.some(
          (dom) => hostname === dom || hostname.endsWith("." + dom)
        );

        if (!isOfficial) {
          score += 20;
          const brandTitle = brand.charAt(0).toUpperCase() + brand.slice(1);
          indicators.push({
            type: "brand_mismatch",
            evidence: `Message references ${brandTitle}, but the detected domain does not match a recognized official ${brandTitle} domain.`,
          });
        }
      } catch {
        // invalid URL
      }
    }
  }

  return {
    score: Math.min(score, 40),
    indicators,
  };
}

// =========================================================
// URL ANALYSIS
// =========================================================

export const SUSPICIOUS_URL_WORDS = [
  "verify",
  "login",
  "secure",
  "account",
  "update",
  "confirm",
  "password",
  "wallet",
  "claim",
  "signin",
  "sign-in",
  "payment",
  "billing",
  "unlock",
  "recovery",
  "support",
  "security",
];

export const SHORTENER_DOMAINS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "is.gd",
  "ow.ly",
  "shorturl.at",
  "cutt.ly",
  "rebrand.ly",
]);

function isIpv4(hostname) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

export function analyzeUrls(text) {
  const urls = extractUrls(text);
  let score = 0;
  const indicators = [];

  for (const url of urls) {
    try {
      const parsed = new URL(url);
      const hostname = (parsed.hostname || "").toLowerCase();

      // 1. HTTP instead of HTTPS
      if (parsed.protocol === "http:") {
        score += 15;
        indicators.push({
          type: "url",
          evidence: "URL uses HTTP instead of HTTPS",
        });
      }

      // 2. IP ADDRESS
      if (isIpv4(hostname)) {
        score += 25;
        indicators.push({
          type: "url",
          evidence: "URL uses an IP address instead of a domain name",
        });
      }

      // 3. LONG DOMAIN
      if (hostname.length > 35) {
        score += 10;
        indicators.push({
          type: "url",
          evidence: "Unusually long domain",
        });
      }

      // 4. SUSPICIOUS KEYWORDS
      const keywordMatches = SUSPICIOUS_URL_WORDS.filter((word) =>
        hostname.includes(word)
      );
      if (keywordMatches.length > 0) {
        score += 15;
        indicators.push({
          type: "url",
          evidence: `Suspicious URL keywords: ${keywordMatches.join(", ")}`,
        });
      }

      // 5. COMPLEX SUBDOMAINS
      const parts = hostname.split(".").filter(Boolean);
      if (parts.length >= 5) {
        score += 15;
        indicators.push({
          type: "url",
          evidence: "Complex subdomain structure",
        });
      }

      // 6. @ SYMBOL
      if (url.includes("@")) {
        score += 20;
        indicators.push({
          type: "url",
          evidence: "URL contains an @ symbol that may obscure the real destination",
        });
      }

      // 7. NON-STANDARD PORT
      if (parsed.port && parsed.port !== "80" && parsed.port !== "443") {
        score += 10;
        indicators.push({
          type: "url",
          evidence: `URL uses a non-standard port: ${parsed.port}`,
        });
      }

      // 8. URL SHORTENER
      if (SHORTENER_DOMAINS.has(hostname)) {
        score += 10;
        indicators.push({
          type: "url",
          evidence: "URL uses a link-shortening service that hides the final destination",
        });
      }

      // 9. EXCESSIVE HYPHENS
      const hyphenCount = (hostname.match(/-/g) || []).length;
      if (hyphenCount >= 3) {
        score += 10;
        indicators.push({
          type: "url",
          evidence: "Domain contains an unusually high number of hyphens",
        });
      }

      // 10. VERY LONG URL
      if (url.length > 150) {
        score += 10;
        indicators.push({
          type: "url",
          evidence: "URL is unusually long",
        });
      }

      // 11. ENCODED CHARACTERS
      if (url.includes("%")) {
        score += 5;
        indicators.push({
          type: "url",
          evidence: "URL contains encoded characters",
        });
      }

      // 12. MULTIPLE SUBDOMAIN TOKENS
      if (parts.length >= 4) {
        const subdomainTokens = parts.slice(0, -2);
        const suspiciousWords = ["login", "verify", "secure", "account", "payment", "support"];
        const hasSuspiciousToken = subdomainTokens.some((tok) =>
          suspiciousWords.some((w) => tok.includes(w))
        );
        if (hasSuspiciousToken) {
          score += 10;
          indicators.push({
            type: "url",
            evidence: "Suspicious security-related subdomain",
          });
        }
      }
    } catch {
      score += 20;
      indicators.push({
        type: "url",
        evidence: "URL could not be safely parsed",
      });
    }
  }

  return {
    score: Math.min(score, 60),
    urls_found: urls,
    indicators,
  };
}

// =========================================================
// THREAT LEVEL
// =========================================================

export function getThreatLevel(score) {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH RISK";
  if (score >= 35) return "MEDIUM RISK";
  return "LOW RISK";
}

// =========================================================
// CROSS-SIGNAL REINFORCEMENT
// =========================================================

export function calculateReinforcement(categories) {
  const catSet = new Set(categories);
  let reinforcement = 0;

  if (catSet.has("rewards") && catSet.has("urgency")) reinforcement += 2;
  if (catSet.has("rewards") && catSet.has("suspicious_action")) reinforcement += 2;
  if (catSet.has("urgency") && catSet.has("suspicious_action")) reinforcement += 2;

  if (catSet.has("credentials") && catSet.has("suspicious_url")) reinforcement += 3;
  if (catSet.has("financial") && catSet.has("suspicious_url")) reinforcement += 2;
  if (catSet.has("urgency") && catSet.has("credentials")) reinforcement += 2;
  if (catSet.has("threats") && catSet.has("urgency")) reinforcement += 2;
  if (catSet.has("impersonation") && catSet.has("credentials")) reinforcement += 2;

  const strongPhishing =
    catSet.has("credentials") &&
    catSet.has("suspicious_url") &&
    (catSet.has("urgency") || catSet.has("threats") || catSet.has("impersonation"));

  if (strongPhishing) reinforcement += 5;

  return Math.min(reinforcement, 20);
}

// =========================================================
// RECOMMENDED ACTION
// =========================================================

export function getRecommendedAction(score, categories) {
  if (score >= 80) {
    return (
      "Do not click links, send money, or provide " +
      "passwords or security codes. Verify the message " +
      "through an independent official channel."
    );
  }
  if (score >= 60) {
    return (
      "Treat this message as high risk. Avoid interacting " +
      "with links or requests for sensitive information " +
      "and verify the sender independently."
    );
  }
  if (score >= 35) {
    return (
      "Pause before interacting. Check the sender, " +
      "verify the request through an official source, " +
      "and avoid sharing sensitive information."
    );
  }
  if (categories && categories.length > 0) {
    return (
      "No major threat pattern was confirmed, but " +
      "remain cautious and verify unexpected requests."
    );
  }
  return (
    "No significant risk signals were detected. " +
    "Continue using normal security precautions."
  );
}

// =========================================================
// EXPLAINABLE SECURITY DECISION
// =========================================================

export function buildExplanation(totalScore, categories, indicators) {
  if (totalScore >= 80) {
    return (
      "Multiple strong indicators associated with " +
      "phishing, scams, or social engineering were " +
      "detected. The combination of signals creates " +
      "a high-risk warning pattern."
    );
  }
  if (totalScore >= 60) {
    return (
      "Several independent suspicious signals were " +
      "detected. Their combination increases the " +
      "risk that this message may be a scam, phishing " +
      "attempt, or social-engineering message."
    );
  }
  if (totalScore >= 35) {
    return (
      "The message contains one or more suspicious " +
      "characteristics. These signals do not prove " +
      "malicious intent, but the content should be " +
      "verified before taking action."
    );
  }
  if (indicators && indicators.length > 0) {
    const detected = [...categories].sort().join(", ");
    return (
      `Some security signals were detected (${detected}), ` +
      "but the available evidence is currently limited. " +
      "Treat unexpected requests with caution."
    );
  }
  return (
    "No significant scam indicators were detected " +
    "by the current security rules. This does not " +
    "guarantee that the content is safe."
  );
}

// =========================================================
// SCORE BREAKDOWN
// =========================================================

export function buildScoreBreakdown(
  textResult,
  urlResult,
  brandResult,
  textContribution,
  urlContribution,
  reinforcement
) {
  const categories = new Set(textResult.categories || []);

  const messageDetails = [];
  const knownCategories = [
    "credentials",
    "financial",
    "urgency",
    "threats",
    "impersonation",
    "rewards",
    "suspicious_action",
  ];

  for (const cat of knownCategories) {
    if (categories.has(cat)) {
      messageDetails.push({
        type: cat,
        label: cat.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
      });
    }
  }

  const urlDetails = (urlResult.indicators || []).map((i) => i.evidence || "");
  const brandDetails = (brandResult.indicators || []).map((i) => i.evidence || "");

  return {
    message: {
      contribution: textContribution,
      maximum: 55,
      signals: messageDetails,
    },
    url: {
      contribution: urlContribution,
      maximum: 25,
      signals: urlDetails,
    },
    brand: {
      included_in_url_contribution: true,
      signals: brandDetails,
    },
    reinforcement: {
      contribution: reinforcement,
      maximum: 20,
    },
    total: Math.min(textContribution + urlContribution + reinforcement, 100),
  };
}

// =========================================================
// MAIN SECURITY ANALYSIS
// =========================================================

export function analyzeMessage(text) {
  const content = text || "";

  // 1. Individual analyses
  const textResult = analyzeText(content);
  const urlResult = analyzeUrls(content);
  const brandResult = analyzeBrandDomainMismatch(content);

  // 2. Combine indicators
  const allIndicators = [
    ...textResult.indicators,
    ...urlResult.indicators,
    ...brandResult.indicators,
  ];

  const uniqueIndicators = [];
  const seen = new Set();
  for (const ind of allIndicators) {
    const key = `${ind.type}:${ind.evidence}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueIndicators.push(ind);
    }
  }

  // 3. Security categories
  const categories = [...textResult.categories];
  if (urlResult.urls_found && urlResult.urls_found.length > 0) {
    categories.push("suspicious_url");
  }
  const uniqueCategories = [...new Set(categories)];

  // 4. Score components
  const textScore = Math.min(Math.max(textResult.score, 0), 70);
  const urlScore = Math.min(Math.max(urlResult.score, 0), 60);
  const brandScore = Math.min(Math.max(brandResult.score, 0), 40);

  const textContribution = Math.round((textScore / 70) * 55);
  const combinedUrlScore = Math.min(urlScore + brandScore, 60);
  const urlContribution = Math.round((combinedUrlScore / 60) * 25);

  // 5. Reinforcement
  const reinforcement = calculateReinforcement(uniqueCategories);

  // 6. Total score
  const totalScore = Math.min(
    textContribution + urlContribution + reinforcement,
    100
  );

  // 7. Threat level
  const threatLevel = getThreatLevel(totalScore);

  // 8. Threat category
  let category = "Suspicious Content";
  const catSet = new Set(uniqueCategories);

  if (uniqueCategories.length === 0) {
    category = "No significant threat detected";
  } else if (catSet.has("credentials") && catSet.has("suspicious_url")) {
    category = "Credential Phishing";
  } else if (catSet.has("financial") && catSet.has("suspicious_url")) {
    category = "Financial Phishing";
  } else if (catSet.has("financial")) {
    category = "Financial Scam";
  } else if (
    catSet.has("rewards") &&
    (catSet.has("urgency") || catSet.has("suspicious_action"))
  ) {
    category = "Reward Scam";
  } else if (catSet.has("suspicious_url")) {
    category = "Suspicious Link";
  } else if (catSet.has("impersonation")) {
    category = "Impersonation";
  } else if (catSet.has("threats")) {
    category = "Social Engineering";
  } else if (catSet.has("credentials")) {
    category = "Credential Theft Attempt";
  } else if (catSet.has("urgency")) {
    category = "Social Engineering";
  }

  // 9. Risk factors
  const riskFactors = [];
  if (catSet.has("urgency")) {
    riskFactors.push(
      "Urgency pressure: the message pushes the recipient to act quickly without taking time to verify the request."
    );
  }
  if (catSet.has("credentials")) {
    riskFactors.push(
      "Credential harvesting risk: the message requests or references sensitive authentication information such as passwords or security codes."
    );
  }
  if (catSet.has("financial")) {
    riskFactors.push(
      "Financial risk: the message involves money, payment, banking information, or cryptocurrency."
    );
  }
  if (catSet.has("threats")) {
    riskFactors.push(
      "Threat-based manipulation: the message uses possible account suspension or consequences to pressure the recipient."
    );
  }
  if (catSet.has("impersonation")) {
    riskFactors.push(
      "Possible impersonation: the message uses language associated with a trusted organization or support service."
    );
  }
  if (catSet.has("rewards")) {
    riskFactors.push(
      "Reward manipulation: the message uses prizes, unexpected benefits, or winnings to encourage interaction."
    );
  }
  if (catSet.has("suspicious_action")) {
    riskFactors.push(
      "Suspicious action request: the message encourages the recipient to click, open, claim, or interact."
    );
  }

  for (const ind of urlResult.indicators) {
    if (ind.evidence) {
      riskFactors.push(`Suspicious URL characteristic: ${ind.evidence}.`);
    }
  }

  for (const ind of brandResult.indicators) {
    if (ind.evidence) {
      riskFactors.push(`Brand/domain mismatch: ${ind.evidence}`);
    }
  }

  const uniqueRiskFactors = [...new Set(riskFactors)];

  // 10. Explanations
  const explanation = buildExplanation(totalScore, uniqueCategories, uniqueIndicators);
  const recommendedAction = getRecommendedAction(totalScore, uniqueCategories);
  const scoreBreakdown = buildScoreBreakdown(
    textResult,
    urlResult,
    brandResult,
    textContribution,
    urlContribution,
    reinforcement
  );

  return {
    score: totalScore,
    text_contribution: textContribution,
    url_contribution: urlContribution,
    brand_contribution: brandScore,
    reinforcement_score: reinforcement,
    threat_level: threatLevel,
    category,
    categories: uniqueCategories,
    indicators: uniqueIndicators,
    risk_factors: uniqueRiskFactors,
    text_score: textScore,
    url_score: urlScore,
    brand_score: brandScore,
    urls_found: urlResult.urls_found,
    explanation,
    recommended_action: recommendedAction,
    score_breakdown: scoreBreakdown,
    ai_analysis: {
      status: "success",
      analysis: `Threat Type: ${category}\n\nSecurity Assessment: ${explanation}\n\nRecommended Action: ${recommendedAction}`
    },
    message: content,
  };
}
