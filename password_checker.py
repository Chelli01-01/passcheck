import math
import getpass


def load_common_words(path: str = "common_words.txt") -> set[str]:
    """
    Load a newline-separated list of common words.
    Returns an empty set if the file is missing.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return {
                line.strip().lower()
                for line in f
                if line.strip() and not line.lstrip().startswith("#")
            }
    except FileNotFoundError:
        return set()


def find_dictionary_hits(password: str, common_words: set[str]) -> list[str]:
    """
    Return a list of common words found inside the password (case-insensitive).
    Example: 'Admin123!' -> ['admin']
    """
    s = password.lower()
    hits = [w for w in common_words if len(w) >= 4 and w in s]
    hits.sort(key=len, reverse=True)
    return hits


def estimate_entropy_bits(password: str) -> float:
    """Rough estimate: len(password) * log2(character_set_size)."""
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(not c.isalnum() for c in password):
        charset += 33  # conservative symbol estimate

    if charset == 0:
        return 0.0

    return len(password) * math.log2(charset)


def has_simple_sequence(password: str, min_len: int = 4) -> bool:
    """Detect sequences like abcd/1234 or dcba/4321 (case-insensitive)."""
    s = password.lower()
    for i in range(len(s) - min_len + 1):
        chunk = s[i : i + min_len]
        diffs = [ord(chunk[j + 1]) - ord(chunk[j]) for j in range(min_len - 1)]
        if all(d == 1 for d in diffs) or all(d == -1 for d in diffs):
            return True
    return False


def has_repeated_run(password: str, run_len: int = 4) -> bool:
    """Detect repeated characters like 'aaaa' or '1111'."""
    if run_len <= 1:
        return False

    count = 1
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            count += 1
            if count >= run_len:
                return True
        else:
            count = 1
    return False


def strength_label(score: int) -> str:
    if score < 30:
        return "VERY WEAK"
    if score < 50:
        return "WEAK"
    if score < 70:
        return "OKAY"
    return "STRONG"


def calculate_score_and_suggestions(password: str) -> tuple[int, list[str], list[str], float]:
    """
    Returns:
      score (0..100),
      findings (what we detected),
      suggestions (how to improve),
      entropy_bits (rough estimate)
    """
    findings: list[str] = []
    suggestions: list[str] = []

    length = len(password)
    entropy = estimate_entropy_bits(password)

    # --- Score components ---
    score = 0

    # Dictionary check (penalty)
    common_words = load_common_words()
    hits = find_dictionary_hits(password, common_words)
    if hits:
        findings.append(f"Contains common word(s): {', '.join(hits[:3])}.")
        suggestions.append("Avoid common words/names; use random phrases or a password manager.")
        score -= 25

    # 1) Length (max ~40)
    if length == 0:
        findings.append("Password is empty.")
        suggestions.append("Use a password manager to generate a long random password.")
        return 0, findings, _dedupe_preserve_order(suggestions), entropy

    if length < 8:
        findings.append("Too short (< 8 characters).")
        suggestions.append("Increase length to at least 12–14 characters.")
        score += 5
    elif length < 12:
        findings.append("Short (8–11 characters).")
        suggestions.append("Increase length to 12–14+ characters.")
        score += 20
    elif length < 16:
        findings.append("Good length (12–15 characters).")
        score += 32
    else:
        findings.append("Great length (16+ characters).")
        score += 40

    # 2) Variety (max ~40)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    categories = sum([has_lower, has_upper, has_digit, has_symbol])
    findings.append(f"Character types used: {categories}/4.")
    score += categories * 10

    if categories < 3:
        suggestions.append("Mix uppercase, lowercase, digits, and symbols.")

    # 3) Entropy bonus (max ~20)
    if entropy < 40:
        findings.append(f"Low estimated entropy (~{entropy:.1f} bits).")
        suggestions.append("Make it longer and less predictable.")
    elif entropy < 70:
        findings.append(f"Moderate estimated entropy (~{entropy:.1f} bits).")
        score += 10
    else:
        findings.append(f"High estimated entropy (~{entropy:.1f} bits).")
        score += 20

    # 4) Pattern penalties
    if has_simple_sequence(password):
        findings.append("Contains a simple sequence (e.g., 1234 / abcd).")
        suggestions.append("Avoid sequences like 1234 or abcd.")
        score -= 15

    if has_repeated_run(password):
        findings.append("Contains repeated characters (e.g., aaaa / 1111).")
        suggestions.append("Avoid repeated characters like aaaa.")
        score -= 15

    # Clamp score
    score = max(0, min(score, 100))

    return score, findings, _dedupe_preserve_order(suggestions), entropy


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def analyze_and_print(password: str) -> None:
    score, findings, suggestions, entropy = calculate_score_and_suggestions(password)

    print("\nPassword analysis")
    print("-----------------")
    print(f"Score: {score}/100")
    print(f"Strength: {strength_label(score)}")
    print(f"Estimated entropy: {entropy:.1f} bits")

    print("\nFindings:")
    for f in findings:
        print(f"- {f}")

    print("\nSuggestions:")
    if suggestions:
        for s in suggestions:
            print(f"- {s}")
    else:
        print("- Looks good. Keep using unique passwords per site.")


def main() -> None:
    password = getpass.getpass("Enter password: ")
    analyze_and_print(password)


if __name__ == "__main__":
    main()
