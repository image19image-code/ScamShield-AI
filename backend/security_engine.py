import os
import re
from urllib.parse import urlparse

from huggingface_hub import InferenceClient


# =========================================================
# CONFIG
# =========================================================

AI_MODEL = "openai/gpt-oss-20b"

# Final score allocation:
# Message analysis: 55
# URL + domain analysis: 25
# Cross-signal reinforcement: 20
#
# Total = 100 exactly.


# =========================================================
# SCAM PATTERNS
# =========================================================

SCAM_PATTERNS = {
    "urgency": [
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

    "credentials": [
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

    "suspicious_action": [
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

    "financial": [
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

    "threats": [
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

    "rewards": [
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

    "impersonation": [
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
}


# =========================================================
# CATEGORY WEIGHTS
# =========================================================

CATEGORY_WEIGHTS = {
    "credentials": 30,
    "financial": 28,
    "threats": 20,
    "rewards": 18,
    "urgency": 14,
    "impersonation": 10,
    "suspicious_action": 10,
}


# =========================================================
# TEXT ANALYSIS
# =========================================================

def analyze_text(text: str):
    text = text or ""

    text_lower = re.sub(
        r"\s+",
        " ",
        text.lower()
    ).strip()

    indicators = []
    matched_categories = []

    for category, patterns in SCAM_PATTERNS.items():
        category_matches = []

        for pattern in patterns:
            if pattern in text_lower:
                category_matches.append(pattern)

        if category_matches:
            matched_categories.append(category)

            for pattern in category_matches:
                indicators.append({
                    "type": category,
                    "evidence": pattern
                })

    raw_score = sum(
        CATEGORY_WEIGHTS.get(category, 0)
        for category in matched_categories
    )

    # Raw message score is intentionally capped before scaling.
    raw_score = min(raw_score, 70)

    return {
        "score": raw_score,
        "indicators": indicators,
        "categories": matched_categories
    }


# =========================================================
# URL EXTRACTION
# =========================================================

def extract_urls(text: str):
    text = text or ""

    urls = re.findall(
        r"https?://[^\s<>\]\)\"']+",
        text,
        flags=re.IGNORECASE
    )

    cleaned = []

    for url in urls:
        url = url.rstrip(".,!?;:")

        if url:
            cleaned.append(url)

    return list(dict.fromkeys(cleaned))


# =========================================================
# BRAND / DOMAIN MISMATCH
# =========================================================

TRUSTED_BRANDS = {
    "microsoft": [
        "microsoft.com",
        "live.com",
        "office.com",
        "outlook.com",
    ],

    "apple": [
        "apple.com",
        "icloud.com",
    ],

    "amazon": [
        "amazon.com",
        "amazon.co.uk",
        "amazon.de",
    ],

    "paypal": [
        "paypal.com",
    ],

    "google": [
        "google.com",
        "googleusercontent.com",
    ],

    "netflix": [
        "netflix.com",
    ],
}


def analyze_brand_domain_mismatch(text: str):
    urls = extract_urls(text)

    if not urls:
        return {
            "score": 0,
            "indicators": []
        }

    text_lower = text.lower()

    score = 0
    indicators = []

    for brand, official_domains in TRUSTED_BRANDS.items():
        if brand not in text_lower:
            continue

        for url in urls:
            try:
                parsed = urlparse(url)

                hostname = (
                    parsed.hostname or ""
                ).lower()

                if not hostname:
                    continue

                is_official = any(
                    hostname == domain
                    or hostname.endswith("." + domain)
                    for domain in official_domains
                )

                if not is_official:
                    score += 20

                    indicators.append({
                        "type": "brand_mismatch",
                        "evidence": (
                            f"Message references {brand.title()}, "
                            f"but the detected domain does not match "
                            f"a recognized official {brand.title()} domain."
                        )
                    })

            except Exception:
                continue

    return {
        "score": min(score, 40),
        "indicators": indicators
    }


# =========================================================
# URL ANALYSIS
# =========================================================

SUSPICIOUS_URL_WORDS = [
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
]

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "shorturl.at",
    "cutt.ly",
    "rebrand.ly",
}


def is_ipv4(hostname: str):
    return bool(
        re.fullmatch(
            r"(?:\d{1,3}\.){3}\d{1,3}",
            hostname
        )
    )


def analyze_urls(text: str):
    urls = extract_urls(text)

    score = 0
    indicators = []

    for url in urls:
        try:
            parsed = urlparse(url)

            hostname = (
                parsed.hostname or ""
            ).lower()

            # -------------------------------------------------
            # 1. HTTP instead of HTTPS
            # -------------------------------------------------

            if parsed.scheme.lower() == "http":
                score += 15

                indicators.append({
                    "type": "url",
                    "evidence":
                        "URL uses HTTP instead of HTTPS"
                })

            # -------------------------------------------------
            # 2. IP ADDRESS
            # -------------------------------------------------

            if is_ipv4(hostname):
                score += 25

                indicators.append({
                    "type": "url",
                    "evidence":
                        "URL uses an IP address instead of a domain name"
                })

            # -------------------------------------------------
            # 3. LONG DOMAIN
            # -------------------------------------------------

            if len(hostname) > 35:
                score += 10

                indicators.append({
                    "type": "url",
                    "evidence":
                        "Unusually long domain"
                })

            # -------------------------------------------------
            # 4. SUSPICIOUS KEYWORDS
            # -------------------------------------------------

            keyword_matches = [
                word
                for word in SUSPICIOUS_URL_WORDS
                if word in hostname
            ]

            if keyword_matches:
                score += 15

                indicators.append({
                    "type": "url",
                    "evidence":
                        "Suspicious URL keywords: "
                        + ", ".join(keyword_matches)
                })

            # -------------------------------------------------
            # 5. COMPLEX SUBDOMAINS
            # -------------------------------------------------

            parts = [
                part
                for part in hostname.split(".")
                if part
            ]

            if len(parts) >= 5:
                score += 15

                indicators.append({
                    "type": "url",
                    "evidence":
                        "Complex subdomain structure"
                })

            # -------------------------------------------------
            # 6. @ SYMBOL
            # -------------------------------------------------

            if "@" in url:
                score += 20

                indicators.append({
                    "type": "url",
                    "evidence":
                        "URL contains an @ symbol that may obscure "
                        "the real destination"
                })

            # -------------------------------------------------
            # 7. NON-STANDARD PORT
            # -------------------------------------------------

            try:
                port = parsed.port

                if port is not None and port not in [80, 443]:
                    score += 10

                    indicators.append({
                        "type": "url",
                        "evidence":
                            f"URL uses a non-standard port: {port}"
                    })

            except ValueError:
                score += 15

                indicators.append({
                    "type": "url",
                    "evidence":
                        "URL contains an invalid port definition"
                })

            # -------------------------------------------------
            # 8. URL SHORTENER
            # -------------------------------------------------

            if hostname in SHORTENER_DOMAINS:
                score += 10

                indicators.append({
                    "type": "url",
                    "evidence":
                        "URL uses a link-shortening service "
                        "that hides the final destination"
                })

            # -------------------------------------------------
            # 9. EXCESSIVE HYPHENS
            # -------------------------------------------------

            hyphen_count = hostname.count("-")

            if hyphen_count >= 3:
                score += 10

                indicators.append({
                    "type": "url",
                    "evidence":
                        "Domain contains an unusually high "
                        "number of hyphens"
                })

            # -------------------------------------------------
            # 10. VERY LONG URL
            # -------------------------------------------------

            if len(url) > 150:
                score += 10

                indicators.append({
                    "type": "url",
                    "evidence":
                        "URL is unusually long"
                })

            # -------------------------------------------------
            # 11. ENCODED CHARACTERS
            # -------------------------------------------------

            if "%" in url:
                score += 5

                indicators.append({
                    "type": "url",
                    "evidence":
                        "URL contains encoded characters"
                })

            # -------------------------------------------------
            # 12. MULTIPLE SUBDOMAIN TOKENS
            # -------------------------------------------------

            if len(parts) >= 4:
                suspicious_subdomain_tokens = [
                    token
                    for token in parts[:-2]
                    if any(
                        word in token
                        for word in [
                            "login",
                            "verify",
                            "secure",
                            "account",
                            "payment",
                            "support"
                        ]
                    )
                ]

                if suspicious_subdomain_tokens:
                    score += 10

                    indicators.append({
                        "type": "url",
                        "evidence":
                            "Suspicious security-related subdomain"
                    })

        except Exception:
            score += 20

            indicators.append({
                "type": "url",
                "evidence":
                    "URL could not be safely parsed"
            })

    return {
        "score": min(score, 60),
        "urls_found": urls,
        "indicators": indicators
    }


# =========================================================
# THREAT LEVEL
# =========================================================

def get_threat_level(score: int):
    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH RISK"

    if score >= 35:
        return "MEDIUM RISK"

    return "LOW RISK"


# =========================================================
# AI RESPONSE EXTRACTION
# =========================================================

def extract_ai_content(response):
    """
    Safely extract final assistant content.

    gpt-oss is a reasoning model, but only final content should
    be shown to the user. Internal reasoning must never be exposed.
    """

    if response is None:
        return ""

    choices = getattr(
        response,
        "choices",
        None
    )

    if not choices:
        return ""

    first_choice = choices[0]

    message = getattr(
        first_choice,
        "message",
        None
    )

    if message is None:
        return ""

    content = getattr(
        message,
        "content",
        None
    )

    if isinstance(content, str):
        return content.strip()

    if isinstance(content, list):
        parts = []

        for item in content:
            if isinstance(item, str):
                parts.append(item)

            elif isinstance(item, dict):
                text = item.get("text")

                if isinstance(text, str):
                    parts.append(text)

        return "".join(parts).strip()

    if content is not None:
        return str(content).strip()

    return ""


# =========================================================
# AI ANALYSIS
# =========================================================

def _run_ai_request(client, text: str, retry=False):
    system_prompt = """
You are ScamShield AI, a defensive cybersecurity analysis assistant.

Reasoning: low

Analyze suspicious messages for phishing, scams, fraud, and social engineering.

You must return a concise FINAL ANSWER in the assistant content.
Do not return only internal reasoning.

Never expose internal chain-of-thought.

Do not provide instructions for stealing credentials,
bypassing security, attacking systems, or committing fraud.

Do not claim certainty when the evidence is ambiguous.
""".strip()

    user_prompt = f"""
Analyze this message defensively:

--- MESSAGE START ---
{text[:12000]}
--- MESSAGE END ---

Return ONLY this format:

Threat type:
<one concise classification>

Why it is suspicious:
<2 to 4 concise reasons>

Recommended safe action:
<2 to 4 concise defensive actions>

Keep the answer concise.
""".strip()

    if retry:
        user_prompt += """

Make sure you provide visible final answer text.
Do not leave the final response empty.
"""

    response = client.chat_completion(
        model=AI_MODEL,
        messages=[
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            }
        ],
        max_tokens=500,
        temperature=0.1,
        top_p=0.9
    )

    return extract_ai_content(response)


def analyze_with_ai(text: str):
    token = os.getenv("HF_TOKEN")

    if not token:
        return {
            "status": "error",
            "analysis": "",
            "error": "HF_TOKEN is missing."
        }

    try:
        client = InferenceClient(
            provider="auto",
            token=token,
            timeout=30
        )

        analysis = _run_ai_request(
            client,
            text,
            retry=False
        )

        if analysis:
            return {
                "status": "success",
                "analysis": analysis
            }

        # Retry once if the provider returned no visible final content.
        analysis = _run_ai_request(
            client,
            text,
            retry=True
        )

        if analysis:
            return {
                "status": "success",
                "analysis": analysis
            }

        return {
            "status": "error",
            "analysis": "",
            "error":
                "The AI provider returned no final answer."
        }

    except Exception as error:
        print("========== AI ERROR ==========")
        print(
            "AI ERROR TYPE:",
            type(error).__name__
        )
        print(
            "AI ERROR MESSAGE:",
            repr(error)
        )
        print("==============================")

        return {
            "status": "error",
            "analysis": "",
            "error":
                f"{type(error).__name__}: {str(error)}"
        }


# =========================================================
# CROSS-SIGNAL REINFORCEMENT
# =========================================================

def calculate_reinforcement(categories):
    categories = set(categories)

    reinforcement = 0

    # Reward pattern
    if (
        "rewards" in categories
        and "urgency" in categories
    ):
        reinforcement += 2

    if (
        "rewards" in categories
        and "suspicious_action" in categories
    ):
        reinforcement += 2

    if (
        "urgency" in categories
        and "suspicious_action" in categories
    ):
        reinforcement += 2

    # Credential phishing pattern
    if (
        "credentials" in categories
        and "suspicious_url" in categories
    ):
        reinforcement += 3

    if (
        "financial" in categories
        and "suspicious_url" in categories
    ):
        reinforcement += 2

    if (
        "urgency" in categories
        and "credentials" in categories
    ):
        reinforcement += 2

    if (
        "threats" in categories
        and "urgency" in categories
    ):
        reinforcement += 2

    if (
        "impersonation" in categories
        and "credentials" in categories
    ):
        reinforcement += 2

    # Strong phishing combination
    strong_phishing_pattern = (
        "credentials" in categories
        and "suspicious_url" in categories
        and (
            "urgency" in categories
            or "threats" in categories
            or "impersonation" in categories
        )
    )

    if strong_phishing_pattern:
        reinforcement += 5

    # Reinforcement is now capped at 20,
    # keeping the total system mathematically bounded.
    return min(
        reinforcement,
        20
    )


# =========================================================
# RECOMMENDED ACTION
# =========================================================

def get_recommended_action(
    score,
    categories
):
    categories = set(categories)

    if score >= 80:
        return (
            "Do not click links, send money, or provide "
            "passwords or security codes. Verify the message "
            "through an independent official channel."
        )

    if score >= 60:
        return (
            "Treat this message as high risk. Avoid interacting "
            "with links or requests for sensitive information "
            "and verify the sender independently."
        )

    if score >= 35:
        return (
            "Pause before interacting. Check the sender, "
            "verify the request through an official source, "
            "and avoid sharing sensitive information."
        )

    if categories:
        return (
            "No major threat pattern was confirmed, but "
            "remain cautious and verify unexpected requests."
        )

    return (
        "No significant risk signals were detected. "
        "Continue using normal security precautions."
    )


# =========================================================
# EXPLAINABLE SECURITY DECISION
# =========================================================

def build_explanation(
    total_score,
    categories,
    indicators
):
    categories = set(categories)

    if total_score >= 80:
        return (
            "Multiple strong indicators associated with "
            "phishing, scams, or social engineering were "
            "detected. The combination of signals creates "
            "a high-risk warning pattern."
        )

    if total_score >= 60:
        return (
            "Several independent suspicious signals were "
            "detected. Their combination increases the "
            "risk that this message may be a scam, phishing "
            "attempt, or social-engineering message."
        )

    if total_score >= 35:
        return (
            "The message contains one or more suspicious "
            "characteristics. These signals do not prove "
            "malicious intent, but the content should be "
            "verified before taking action."
        )

    if indicators:
        detected = ", ".join(
            sorted(categories)
        )

        return (
            "Some security signals were detected "
            f"({detected}), but the available evidence "
            "is currently limited. Treat unexpected "
            "requests with caution."
        )

    return (
        "No significant scam indicators were detected "
        "by the current security rules. This does not "
        "guarantee that the content is safe."
    )


# =========================================================
# SCORE BREAKDOWN
# =========================================================

def build_score_breakdown(
    text_result,
    url_result,
    brand_result,
    text_contribution,
    url_contribution,
    reinforcement
):
    categories = set(
        text_result.get(
            "categories",
            []
        )
    )

    message_details = []

    for category in [
        "credentials",
        "financial",
        "urgency",
        "threats",
        "impersonation",
        "rewards",
        "suspicious_action",
    ]:
        if category in categories:
            message_details.append({
                "type": category,
                "label": category.replace(
                    "_",
                    " "
                ).title()
            })

    url_details = []

    for indicator in (
        url_result.get(
            "indicators",
            []
        )
    ):
        url_details.append(
            indicator.get(
                "evidence",
                ""
            )
        )

    brand_details = []

    for indicator in (
        brand_result.get(
            "indicators",
            []
        )
    ):
        brand_details.append(
            indicator.get(
                "evidence",
                ""
            )
        )

    return {
        "message": {
            "contribution": text_contribution,
            "maximum": 55,
            "signals": message_details
        },

        "url": {
            "contribution": url_contribution,
            "maximum": 25,
            "signals": url_details
        },

        "brand": {
            "included_in_url_contribution": True,
            "signals": brand_details
        },

        "reinforcement": {
            "contribution": reinforcement,
            "maximum": 20
        },

        "total": min(
            text_contribution
            + url_contribution
            + reinforcement,
            100
        )
    }


# =========================================================
# MAIN SECURITY ANALYSIS
# =========================================================

def analyze_message(text: str):
    text = text or ""

    # -----------------------------------------------------
    # INDIVIDUAL ANALYSES
    # -----------------------------------------------------

    text_result = analyze_text(text)

    url_result = analyze_urls(text)

    brand_result = analyze_brand_domain_mismatch(
        text
    )

    # AI is optional.
    # It never controls the final security score.
    ai_result = analyze_with_ai(
        text
    )

    # -----------------------------------------------------
    # COMBINE INDICATORS
    # -----------------------------------------------------

    indicators = (
        text_result["indicators"]
        + url_result["indicators"]
        + brand_result["indicators"]
    )

    # Remove exact duplicate indicators.
    unique_indicators = []

    seen = set()

    for indicator in indicators:
        key = (
            indicator.get("type"),
            indicator.get("evidence")
        )

        if key not in seen:
            seen.add(key)
            unique_indicators.append(
                indicator
            )

    # -----------------------------------------------------
    # SECURITY CATEGORIES
    # -----------------------------------------------------

    categories = list(
        text_result["categories"]
    )

    if url_result["urls_found"]:
        categories.append(
            "suspicious_url"
        )

    categories = list(
        dict.fromkeys(categories)
    )

    # -----------------------------------------------------
    # SCORE COMPONENTS
    # -----------------------------------------------------

    text_score = min(
        max(
            int(text_result["score"]),
            0
        ),
        70
    )

    url_score = min(
        max(
            int(url_result["score"]),
            0
        ),
        60
    )

    brand_score = min(
        max(
            int(brand_result["score"]),
            0
        ),
        40
    )

    # Message = 55 points maximum.
    text_contribution = round(
        (text_score / 70) * 55
    )

    # Combine URL characteristics + domain mismatch
    # into the single 25-point URL/domain component.
    combined_url_score = min(
        url_score + brand_score,
        60
    )

    url_contribution = round(
        (combined_url_score / 60) * 25
    )

    # -----------------------------------------------------
    # CROSS-SIGNAL REINFORCEMENT
    # -----------------------------------------------------

    reinforcement = calculate_reinforcement(
        categories
    )

    # -----------------------------------------------------
    # FINAL SCORE
    # -----------------------------------------------------

    total_score = min(
        text_contribution
        + url_contribution
        + reinforcement,
        100
    )

    # -----------------------------------------------------
    # THREAT LEVEL
    # -----------------------------------------------------

    threat_level = get_threat_level(
        total_score
    )

    # -----------------------------------------------------
    # THREAT CATEGORY
    # -----------------------------------------------------

    if not categories:
        category = (
            "No significant threat detected"
        )

    elif (
        "credentials" in categories
        and "suspicious_url" in categories
    ):
        category = "Credential Phishing"

    elif (
        "financial" in categories
        and "suspicious_url" in categories
    ):
        category = "Financial Phishing"

    elif "financial" in categories:
        category = "Financial Scam"

    elif (
        "rewards" in categories
        and (
            "urgency" in categories
            or "suspicious_action" in categories
        )
    ):
        category = "Reward Scam"

    elif "suspicious_url" in categories:
        category = "Suspicious Link"

    elif "impersonation" in categories:
        category = "Impersonation"

    elif "threats" in categories:
        category = "Social Engineering"

    elif "credentials" in categories:
        category = "Credential Theft Attempt"

    elif "urgency" in categories:
        category = "Social Engineering"

    else:
        category = "Suspicious Content"

    # -----------------------------------------------------
    # RISK FACTORS
    # -----------------------------------------------------

    risk_factors = []

    if "urgency" in categories:
        risk_factors.append(
            "Urgency pressure: the message pushes "
            "the recipient to act quickly without "
            "taking time to verify the request."
        )

    if "credentials" in categories:
        risk_factors.append(
            "Credential harvesting risk: the message "
            "requests or references sensitive authentication "
            "information such as passwords or security codes."
        )

    if "financial" in categories:
        risk_factors.append(
            "Financial risk: the message involves money, "
            "payment, banking information, or cryptocurrency."
        )

    if "threats" in categories:
        risk_factors.append(
            "Threat-based manipulation: the message uses "
            "possible account suspension or consequences "
            "to pressure the recipient."
        )

    if "impersonation" in categories:
        risk_factors.append(
            "Possible impersonation: the message uses "
            "language associated with a trusted organization "
            "or support service."
        )

    if "rewards" in categories:
        risk_factors.append(
            "Reward manipulation: the message uses prizes, "
            "unexpected benefits, or winnings to encourage "
            "interaction."
        )

    if "suspicious_action" in categories:
        risk_factors.append(
            "Suspicious action request: the message "
            "encourages the recipient to click, open, "
            "claim, or interact."
        )

    # URL risk factors
    for indicator in url_result["indicators"]:
        evidence = indicator.get(
            "evidence",
            ""
        )

        if evidence:
            risk_factors.append(
                "Suspicious URL characteristic: "
                + evidence
                + "."
            )

    # Brand mismatch
    for indicator in brand_result["indicators"]:
        evidence = indicator.get(
            "evidence",
            ""
        )

        if evidence:
            risk_factors.append(
                "Brand/domain mismatch: "
                + evidence
            )

    risk_factors = list(
        dict.fromkeys(
            risk_factors
        )
    )

    # -----------------------------------------------------
    # EXPLANATION
    # -----------------------------------------------------

    explanation = build_explanation(
        total_score,
        categories,
        unique_indicators
    )

    # -----------------------------------------------------
    # RECOMMENDED ACTION
    # -----------------------------------------------------

    recommended_action = (
        get_recommended_action(
            total_score,
            categories
        )
    )

    # -----------------------------------------------------
    # SCORE BREAKDOWN
    # -----------------------------------------------------

    score_breakdown = (
        build_score_breakdown(
            text_result,
            url_result,
            brand_result,
            text_contribution,
            url_contribution,
            reinforcement
        )
    )

    # -----------------------------------------------------
    # FINAL REPORT
    # -----------------------------------------------------

    return {
        "score": total_score,

        "text_contribution":
            text_contribution,

        "url_contribution":
            url_contribution,

        "brand_contribution":
            brand_score,

        "reinforcement_score":
            reinforcement,

        "threat_level":
            threat_level,

        "category":
            category,

        "categories":
            categories,

        "indicators":
            unique_indicators,

        "risk_factors":
            risk_factors,

        "text_score":
            text_score,

        "url_score":
            url_score,

        "brand_score":
            brand_score,

        "urls_found":
            url_result["urls_found"],

        "explanation":
            explanation,

        "recommended_action":
            recommended_action,

        "score_breakdown":
            score_breakdown,

        "ai_analysis":
            ai_result,

        "message":
            text
    }


