"use client";

// Types for the Elderly Training CTF
export type Verdict = "phish" | "benign" | "scam" | "legit" | "unsafe" | "safe";
export type Indicator = string;
export type ChallengeResult = {
  id: string;
  solved: boolean;
  points: number;
  selections: { verdict?: Verdict; indicators: Indicator[] };
  solvedAt?: string;
  serverFlag?: string;
};

const USER_KEY = "elderly-ctf-user";
const FLAG_PREFIX = "CYBERCANE";

// Deterministic lightweight hash → 12 lowercase hex chars
export function pseudoHash(input: string): string {
  let h1 = 0x811c9dc5 >>> 0; // FNV offset basis
  let h2 = 0x9e3779b9 >>> 0; // golden ratio prime
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    // FNV-1a like
    h1 ^= c;
    h1 = (h1 + ((h1 << 1) >>> 0) + ((h1 << 4) >>> 0) + ((h1 << 7) >>> 0) + ((h1 << 8) >>> 0) + ((h1 << 24) >>> 0)) >>> 0;
    // Jenkins-ish mix
    h2 ^= (c + h2 + ((h2 << 6) >>> 0) + ((h2 >>> 2) >>> 0)) >>> 0;
  }
  // Derive 6 bytes from 32-bit accumulators → 12 hex chars, no BigInt
  const m1 = (h1 ^ ((h2 << 13) | (h2 >>> 19))) >>> 0;
  const m2 = (h2 ^ ((h1 << 11) | (h1 >>> 21))) >>> 0;
  const b0 = (m1) & 0xff;
  const b1 = (m1 >>> 8) & 0xff;
  const b2 = (m1 >>> 16) & 0xff;
  const b3 = (m2) & 0xff;
  const b4 = (m2 >>> 8) & 0xff;
  const b5 = ((m1 ^ m2) >>> 16) & 0xff;
  return [b0, b1, b2, b3, b4, b5].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Stable UUIDv4 stored in localStorage
export function userId(): string {
  if (typeof window === "undefined") return "anonymous";
  try {
    const existing = window.localStorage.getItem(USER_KEY);
    if (existing) return existing;
    const id = typeof crypto !== "undefined" && "randomUUID" in crypto
      ? (crypto as Crypto).randomUUID()
      : `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`.replace(/[xy]/g, (ch) => {
          const r = (Math.random() * 16) | 0;
          const v = ch === "x" ? r : (r & 0x3) | 0x8;
          return v.toString(16);
        });
    window.localStorage.setItem(USER_KEY, id);
    return id;
  } catch {
    return "anonymous";
  }
}

// Build a deterministic, client-computed cosmetic flag
export function buildClientFlag(challengeId: string, payload: string): string {
  const id = userId();
  const token = pseudoHash(`${id}:${challengeId}:${payload}`);
  return `${FLAG_PREFIX}{${token}}`;
}

// Ask the server for a verified flag (HMAC-based)
export async function verifyServerFlag(challengeId: string, payload: string): Promise<string> {
  const id = userId();
  const res = await fetch("/api/ctf/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challengeId, payload, userId: id }),
  });
  if (!res.ok) {
    throw new Error("Failed to verify flag");
  }
  const data = (await res.json()) as { flag?: string };
  if (!data.flag) throw new Error("Invalid server response");
  return data.flag;
}

// Helpers for select-none flag chip styling
export function flagChipClassName(extra: string = ""): string {
  return (
    "select-none inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-mono " +
    "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-300 dark:border-emerald-700 " +
    extra
  );
}


