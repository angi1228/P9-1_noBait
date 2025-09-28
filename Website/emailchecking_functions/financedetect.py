import re
from typing import Tuple, List

def check_financial_request(content: str) -> Tuple[float, List[str]]:
    """
    Detects requests for payments, bank/account details, or monetary amounts.
    Returns: (score: float, reasons: list[str])
    - score is a small heuristic number (you can scale/weight later).
    - reasons contains short text explanations for the flags raised.
    """
    reasons = []
    score = 0.0
    lower = content.lower()

    # Simple keyword signals for payment / financial actions
    payment_keywords = [
        "pay now", "payment", "invoice", "wire transfer", "bank transfer",
        "send payment", "make payment", "pay immediately", "urgent payment",
        "overdue", "outstanding balance", "settle account", "payable to",
        "payment required", "transfer funds", "deposit to"
    ]
    if any(k in lower for k in payment_keywords):
        score += 2.0
        reasons.append("Request or mention of payment / invoice")

    # Phrases that request banking or account details
    account_phrases = [
        "account number", "bank account", "routing number", "iban", "swift",
        "bsb", "account no", "acct no", "account #:"
    ]
    if any(p in lower for p in account_phrases):
        score += 2.0
        reasons.append("Request for bank or account details")

    # Detect currency amounts in common forms: $100, USD 100, 100 SGD, £100, €100
    # This regex is permissive: currency symbol optionally followed by spaces and digits
    currency_regex = re.compile(
        r"(\$\s?\d{1,3}(?:[,0-9]{0,}|(?:[0-9]{3},)*\d{3})(?:\.\d+)?|"
        r"£\s?\d+(?:\.\d+)?|€\s?\d+(?:\.\d+)?|"
        r"\b\d+(?:,\d{3})*(?:\.\d+)?\s?(usd|sgd|aud|eur|gbp|rm|php|idr|vnd)\b)",
        re.IGNORECASE
    )
    if currency_regex.search(content):
        score += 1.0
        reasons.append("Mention of a monetary amount or currency")

    # Detect specific phrases asking to "confirm" or "send" payment details quickly (urgency + money)
    urgent_money_phrases = [
        "send your bank", "send account", "please confirm payment", "provide bank",
        "provide account", "please transfer", "transfer now", "immediate payment required",
        "asap payment", "urgent transfer"
    ]
    if any(u in lower for u in urgent_money_phrases):
        score += 1.0
        reasons.append("Urgent request related to payment or bank details")

    # Detect requests for payment methods (paypal, venmo, zelle, cashapp)
    payment_methods = ["paypal", "venmo", "zelle", "cashapp", "western union", "moneygram"]
    if any(pm in lower for pm in payment_methods):
        score += 0.5
        reasons.append("Mention of third-party payment method")

    # Detect suspicious patterns: long digit sequences labelled 'account' that might be account/card numbers
    # (e.g., "account number: 1234567890" or sequences of 8-16 digits)
    if re.search(r"(account (number|no|#)\s*:?\s*\d{6,16})", lower) or re.search(r"\b\d{8,16}\b", lower):
        score += 1.5
        reasons.append("Possible bank/account/card number present")

    # Final normalization / optional cap (if you want scores to stay small)
    # You can change the cap or remove it depending on how you aggregate scores.
    if score > 10.0:
        score = 10.0

    return score, reasons