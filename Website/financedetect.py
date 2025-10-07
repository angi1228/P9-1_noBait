import re
from typing import Tuple, List

def check_financial_request(content: str) -> Tuple[float, str]:
    """
    Detects requests for payments, bank/account details, or monetary amounts.
    Returns a score (0-100) and combined reasons for detection as a string.
    """
    reasons = ""
    score = 0
    lower = content.lower()

    # Combined payment and account-related keywords
    payment_or_account_keywords = [
        # Payment related
        "pay now", "payment", "invoice", "wire transfer", "bank transfer",
        "send payment", "make payment", "pay immediately", "urgent payment",
        "overdue", "outstanding balance", "settle account", "payable to",
        "payment required", "transfer funds", "deposit to",
        # Account related
        "account number", "bank account", "routing number", "iban", "swift",
        "bsb", "account no", "acct no", "account #:"
    ]
    if any(k in lower for k in payment_or_account_keywords):
        score += 40
        reasons += "Request or mention of payment or account details; "

    # Monetary amounts
    currency_regex = re.compile(
        r"(\$\s?\d{1,3}(?:[,0-9]{0,}|(?:[0-9]{3},)*\d{3})(?:\.\d+)?|"
        r"£\s?\d+(?:\.\d+)?|€\s?\d+(?:\.\d+)?|"
        r"\b\d+(?:,\d{3})*(?:\.\d+)?\s?(usd|sgd|aud|eur|gbp|rm|php|idr|vnd)\b)",
        re.IGNORECASE
    )
    if currency_regex.search(content):
        score += 10
        reasons += "Mention of a monetary amount or currency; "

    # Urgent money-related requests
    urgent_money_phrases = [
        "send your bank", "send account", "please confirm payment", "provide bank",
        "provide account", "please transfer", "transfer now", "immediate payment required",
        "asap payment", "urgent transfer"
    ]
    if any(u in lower for u in urgent_money_phrases):
        score += 20
        reasons += "Urgent request related to payment or bank details; "

    # Third-party payment methods
    payment_methods = ["paypal", "venmo", "zelle", "cashapp", "western union", "moneygram"]
    if any(pm in lower for pm in payment_methods):
        score += 15
        reasons += "Mention of third-party payment method; "

    # Suspicious long digit sequences
    if re.search(r"(account (number|no|#)\s*:?\s*\d{6,16})", lower) or re.search(r"\b\d{8,16}\b", lower):
        score += 25
        reasons += "Possible bank/account/card number present; "

    # Cap score at 100
    score = min(score, 100)

    # Remove trailing semicolon and space
    reasons = reasons.strip("; ").strip()

    return score, reasons
