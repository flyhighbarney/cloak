// Mirror of internal/dlp/patterns/patterns.go. Keep these in sync manually
// when new detection kinds are added on the Go side. A future task
// (T-PATTERN-SYNC) will generate this file from the Go source.

export type Kind =
  | "ssn"
  | "credit_card"
  | "email"
  | "api_key"
  | "aws_key"
  | "github_token"
  | "private_key";

export interface Pattern {
  kind: Kind;
  regex: RegExp;
  validate?: (raw: string) => boolean;
}

export const patterns: Pattern[] = [
  { kind: "ssn", regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  { kind: "credit_card", regex: /\b(?:\d[ -]?){13,19}\b/g, validate: isLuhnValid },
  {
    kind: "email",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g,
  },
  {
    kind: "api_key",
    regex: /\b(?:sk|pk|api[_-]?key|token|secret)[_-][A-Za-z0-9-]{16,64}\b/gi,
  },
  { kind: "aws_key", regex: /\bAKIA[0-9A-Z]{16}\b/g },
  {
    kind: "github_token",
    regex: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g,
  },
  {
    kind: "private_key",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
];

export function isLuhnValid(raw: string): boolean {
  const digits: number[] = [];
  for (const c of raw) {
    if (c >= "0" && c <= "9") {
      digits.push(c.charCodeAt(0) - 48);
    }
  }
  if (digits.length < 13 || digits.length > 19) {
    return false;
  }
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits[i];
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export interface Finding {
  kind: Kind;
  start: number;
  end: number;
  text: string;
}

export function scan(text: string): Finding[] {
  const findings: Finding[] = [];
  for (const p of patterns) {
    // Clone regex so multiple calls stay stateless.
    const rx = new RegExp(p.regex.source, p.regex.flags);
    let m: RegExpExecArray | null;
    while ((m = rx.exec(text)) !== null) {
      const matched = m[0];
      if (p.validate && !p.validate(matched)) continue;
      findings.push({
        kind: p.kind,
        start: m.index,
        end: m.index + matched.length,
        text: matched,
      });
      if (m.index === rx.lastIndex) rx.lastIndex++; // avoid zero-width loops
    }
  }
  return findings;
}

// Human-readable label per kind, used in diagnostic messages.
export function label(k: Kind): string {
  switch (k) {
    case "ssn":
      return "US Social Security number";
    case "credit_card":
      return "credit card number";
    case "email":
      return "email address";
    case "api_key":
      return "API key";
    case "aws_key":
      return "AWS access key";
    case "github_token":
      return "GitHub token";
    case "private_key":
      return "PEM private key";
  }
}
