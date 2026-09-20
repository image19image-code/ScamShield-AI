import os
import re
from urllib.parse import urlparse

from huggingface_hub import InferenceClient


# =========================================================
# SCAM PATTERNS
# =========================================================

SCAM_PATTERNS = {

    "urgency": [
        "urgent",
        "immediately",
        "act now",
        "right now",
        "within 24 hours",
        "expires",
        "last chance",
    ],

    "credentials": [
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
        "update your account",
        "enter your password",
        "provide your password",
        "type your password",
        "submit your password",
        "password to confirm",
        "password to verify",
        "login with your password",
    ],

    "suspicious_action": [
        "click here",
        "click the link",
        "click this link",
        "open the link",
        "follow the link",
        "confirm your identity",
        "review your account",
        "verify now",
        "click to verify",
        "click here to claim",
        "click to claim",
        "claim now",
        "claim your prize",
        "claim your reward",
        "tap here",
        "open now",
    ],

    "financial": [
        "credit card",
        "bank account",
        "payment",
        "send money",
        "transfer money",
        "bitcoin",
        "crypto",
        "wallet",
        "refund",
        "fee",
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
    ],

    "rewards": [
        "winner",
        "you won",
        "prize",
        "free money",
        "claim your reward",
        "lottery",
        "congratulations",
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
    ],
}


# =========================================================
# TEXT ANALYSIS
# =========================================================

def analyze_text(text: str):

    text = text or ""
    text_lower = re.sub(r"\s+", " ", text.lower()).strip()

    indicators = []
    matched_categories = []

    for category, patterns in SCAM_PATTERNS.items():

        category_found = False

        for pattern in patterns:

            if pattern in text_lower:

                indicators.append({
                    "type": category,
                    "evidence": pattern
                })

                category_found = True

        if category_found:
            matched_categories.append(category)

    # -----------------------------------------------------
    # CATEGORY WEIGHTS
    # -----------------------------------------------------

    category_weights = {

        "credentials": 30,

        "financial": 28,

        "threats": 20,

        "rewards": 18,

        "urgency": 14,

        "impersonation": 10,

        "suspicious_action": 10,
    }

    score = 0

    for category in matched_categories:
        score += category_weights.get(category, 0)

    return {
        "score": min(score, 70),
        "indicators": indicators,
        "categories": matched_categories
    }


# =========================================================
# URL EXTRACTION
# =========================================================

def extract_urls(text: str):

    text = text or ""

    return re.findall(
        r"https?://[^\s<>\"']+",
        text,
        flags=re.IGNORECASE
    )


# =========================================================
# BRAND / DOMAIN MISMATCH
# =========================================================

def analyze_brand_domain_mismatch(text: str):

    urls = extract_urls(text)

    if not urls:

        return {
            "score": 0,
            "indicators": []
        }

    trusted_brands = {

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
    }

    text_lower = text.lower()

    score = 0
    indicators = []

    for brand, official_domains in trusted_brands.items():

        if brand not in text_lower:
            continue

        for url in urls:

            try:

                parsed = urlparse(url)

                hostname = (
                    parsed.hostname or ""
                ).lower()

                is_official = any(
                    hostname == domain
                    or hostname.endswith("." + domain)
                    for domain in official_domains
                )

                if not is_official:

                    score += 20

                    indicators.append({
                        "type": "brand_mismatch",
                        "evidence":
                            f"Message references {brand.title()}, "
                            f"but the detected domain does not match "
                            f"a recognized official {brand.title()} domain."
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

def analyze_urls(text: str):

    urls = extract_urls(text)

    score = 0

    indicators = []

    suspicious_words = [
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
        "payment",
        "billing",
        "unlock",
        "recovery",
    ]

    shortener_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "ow.ly",
        "shorturl.at",
        "cutt.ly",
        "rebrand.ly",
    ]

    for url in urls:

        try:

            parsed = urlparse(url)

            hostname = parsed.hostname or ""
            hostname_lower = hostname.lower()

            # -------------------------------------------------
            # 1. HTTP
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

            if re.match(
                r"^\d{1,3}(\.\d{1,3}){3}$",
                hostname
            ):

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

            matches = [
                word
                for word in suspicious_words
                if word in hostname_lower
            ]

            if matches:

                score += 15

                indicators.append({
                    "type": "url",
                    "evidence":
                        "Suspicious URL keywords: "
                        + ", ".join(matches)
                })

            # -------------------------------------------------
            # 5. COMPLEX SUBDOMAINS
            # -------------------------------------------------

            parts = hostname.split(".")

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

            if parsed.port is not None:

                if parsed.port not in [80, 443]:

                    score += 10

                    indicators.append({
                        "type": "url",
                        "evidence":
                            f"URL uses a non-standard port: "
                            f"{parsed.port}"
                    })

            # -------------------------------------------------
            # 8. URL SHORTENER
            # -------------------------------------------------

            if hostname_lower in shortener_domains:

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

            if hostname.count("-") >= 3:

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

    if score >= 75:
        return "CRITICAL"

    elif score >= 50:
        return "HIGH RISK"

    elif score >= 25:
        return "MEDIUM RISK"

    else:
        return "LOW RISK"


# =========================================================
# AI ANALYSIS
# =========================================================

def analyze_with_ai(text: str):

    token = os.getenv("HF_TOKEN")

    # AI is optional.
    # The security engine works without it.

    if not token:

        return {
            "status": "unavailable",
            "analysis":
                "AI enhancement is unavailable. "
                "The deterministic security engine "
                "completed the analysis."
        }

    try:

        client = InferenceClient(
            provider="hf-inference",
            token=token
        )

        prompt = f"""
You are a cybersecurity assistant.

Analyze the following message for phishing,
scams, social engineering, or suspicious behavior.

Message:

{text}

Return a short defensive analysis with:

1. Main threat type
2. Why it may be suspicious
3. Recommended safe action

Do not claim certainty.

Do not provide instructions for attacking systems
or stealing information.
"""

        response = client.chat_completion(
            model="HuggingFaceH4/zephyr-7b-beta",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            max_tokens=300,
            temperature=0.2
        )

        analysis = (
            response.choices[0]
            .message
            .content
        )

        return {
            "status": "success",
            "analysis": analysis
        }

    except Exception as e:

        print(
            "AI ERROR TYPE:",
            type(e).__name__
        )

        print(
            "AI ERROR MESSAGE:",
            str(e)
        )

        return {
            "status": "unavailable",
            "analysis":
                "AI enhancement is temporarily unavailable. "
                "The security engine completed the analysis."
        }


# =========================================================
# CROSS-SIGNAL REINFORCEMENT
# =========================================================

def calculate_reinforcement(categories):

    categories = set(categories)

    reinforcement = 0

    # Reward scams
    if "rewards" in categories and "urgency" in categories:
        reinforcement += 10

    if (
        "rewards" in categories
        and "suspicious_action" in categories
    ):
        reinforcement += 10

    if (
        "urgency" in categories
        and "suspicious_action" in categories
    ):
        reinforcement += 8

    # Three-way reward pattern
    if (
        "rewards" in categories
        and "urgency" in categories
        and "suspicious_action" in categories
    ):
        reinforcement += 15

    # Phishing combinations
    if (
        "credentials" in categories
        and "suspicious_url" in categories
    ):
        reinforcement += 10

    if (
        "financial" in categories
        and "suspicious_url" in categories
    ):
        reinforcement += 8

    if (
        "urgency" in categories
        and "credentials" in categories
    ):
        reinforcement += 6

    if (
        "threats" in categories
        and "urgency" in categories
    ):
        reinforcement += 6

    if (
        "impersonation" in categories
        and "credentials" in categories
    ):
        reinforcement += 6

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
        reinforcement += 10

    # Prevent excessive stacking.
    return min(reinforcement, 30)


# =========================================================
# RECOMMENDED ACTION
# =========================================================

def get_recommended_action(score, categories):

    categories = set(categories)

    if score >= 75:

        return (
            "Do not click links, send money, or provide "
            "passwords or security codes. Verify the message "
            "through an independent official channel."
        )

    if score >= 50:

        return (
            "Treat this message as high risk. Avoid interacting "
            "with links or requests for sensitive information "
            "and verify the sender independently."
        )

    if score >= 25:

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

    if total_score >= 75:

        return (
            "Multiple strong indicators associated with "
            "phishing, scams, or social engineering were "
            "detected. The combination of signals creates "
            "a high-confidence warning pattern."
        )

    if total_score >= 50:

        return (
            "Several independent suspicious signals were "
            "detected. Their combination increases the "
            "risk that this message may be a scam, phishing "
            "attempt, or social-engineering message."
        )

    if total_score >= 25:

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
# MAIN SECURITY ANALYSIS
# =========================================================

def analyze_message(text: str):

    text = text or ""

    # -----------------------------------------------------
    # INDIVIDUAL ANALYSES
    # -----------------------------------------------------

    text_result = analyze_text(text)

    url_result = analyze_urls(text)

    brand_result = analyze_brand_domain_mismatch(text)

    # AI is optional and does not affect core scoring.
    ai_result = analyze_with_ai(text)

    # -----------------------------------------------------
    # COMBINE INDICATORS
    # -----------------------------------------------------

    indicators = (
        text_result["indicators"]
        + url_result["indicators"]
        + brand_result["indicators"]
    )

    # -----------------------------------------------------
    # BUILD SECURITY CATEGORIES
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

    text_score = text_result["score"]

    url_score = url_result["score"]

    brand_score = brand_result["score"]

    # Text has the largest influence because the actual
    # social-engineering content is often more important
    # than URL appearance alone.

    text_contribution = round(
        (text_score / 70) * 65
    )

    url_contribution = round(
        (url_score / 60) * 25
    )

    brand_contribution = round(
        (brand_score / 40) * 10
    )

    base_score = (
        text_contribution
        + url_contribution
        + brand_contribution
    )

    # -----------------------------------------------------
    # CROSS-SIGNAL REINFORCEMENT
    # -----------------------------------------------------

    reinforcement = calculate_reinforcement(
        categories
    )

    total_score = min(
        base_score + reinforcement,
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
            "the recipient to interact."
        )

    if "suspicious_action" in categories:

        risk_factors.append(
            "Suspicious action request: the message "
            "encourages the recipient to click, open, "
            "claim, or interact immediately."
        )

    # -----------------------------------------------------
    # URL RISK FACTORS
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # BRAND / DOMAIN MISMATCH
    # -----------------------------------------------------

    brand_mismatch_detected = any(
        indicator.get("type") == "brand_mismatch"
        for indicator in brand_result["indicators"]
    )

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

    # -----------------------------------------------------
    # REMOVE DUPLICATES
    # -----------------------------------------------------

    risk_factors = list(
        dict.fromkeys(risk_factors)
    )

    # -----------------------------------------------------
    # EXPLANATION
    # -----------------------------------------------------

    explanation = build_explanation(
        total_score,
        categories,
        indicators
    )

    # -----------------------------------------------------
    # RECOMMENDED ACTION
    # -----------------------------------------------------

    recommended_action = get_recommended_action(
        total_score,
        categories
    )

    # -----------------------------------------------------
    # FINAL SECURITY REPORT
    # -----------------------------------------------------

    return {

        "score":
            total_score,

        "text_contribution":
            text_contribution,

        "url_contribution":
            url_contribution,

        "brand_contribution":
            brand_contribution,

        "threat_level":
            threat_level,

        "category":
            category,

        "categories":
            categories,

        "indicators":
            indicators,

        "risk_factors":
            risk_factors,

        "reinforcement_score":
            reinforcement,

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

        "ai_analysis":
            ai_result,

        "message":
            text
    }
