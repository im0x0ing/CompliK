const SENSITIVE_KEY = /pass|secret|token|apikey|api_key|authorization|credential|private[_-]?key/i;

export function maskSensitiveJson(source: string) {
  try {
    return JSON.stringify(maskValue(JSON.parse(source)), null, 2);
  } catch {
    return maskPlaintextSecrets(source);
  }
}

function maskValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(maskValue);
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, nested]) => [
        key,
        SENSITIVE_KEY.test(key) && typeof nested === "string" ? maskSecret(nested) : maskValue(nested),
      ]),
    );
  }

  return value;
}

function maskSecret(value: string) {
  if (value.length <= 4) {
    return "****";
  }
  return `${value.slice(0, 2)}****${value.slice(-2)}`;
}

function maskPlaintextSecrets(source: string) {
  return source.replace(
    /("?(?:apiKey|api_key|password|token|secret)"?\s*[:=]\s*")([^"]+)(")/gi,
    (_match, prefix: string, secret: string, suffix: string) => `${prefix}${maskSecret(secret)}${suffix}`,
  );
}
