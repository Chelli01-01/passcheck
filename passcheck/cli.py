import argparse
import getpass
import json
import sys

from .core import calculate_score_and_suggestions, strength_label


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="passcheck",
        description="Local password strength checker (prompts with hidden input by default).",
    )
    p.add_argument("--password", help="Password to analyze (may be saved in shell history).")
    p.add_argument("--json", action="store_true", help="Output results as JSON.")
    p.add_argument("--score-only", action="store_true", help="Only print the numeric score (0-100).")
    p.add_argument("--no-input", action="store_true", help="Do not prompt. Require --password.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.password is not None:
        password = args.password
    else:
        if args.no_input:
            print("Error: --no-input was set but no --password was provided.", file=sys.stderr)
            return 2
        password = getpass.getpass("Enter password: ")

    score, findings, suggestions, entropy = calculate_score_and_suggestions(password)

    if args.score_only:
        print(score)
        return 0

    if args.json:
        payload = {
            "score": score,
            "strength": strength_label(score),
            "entropy_bits": round(entropy, 2),
            "findings": findings,
            "suggestions": suggestions,
        }
        print(json.dumps(payload, indent=2))
        return 0

    # Human-friendly output
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

    return 0
