export type Verdict = "benign" | "needs_review" | "phishing";

export type ScanResponse = {
  verdict: Verdict;
  score: number;
  reasons: string[];
  indicators: Record<string, unknown>;
  redactions: { types: Record<string, number>; count: number };
  redacted_body: string;
};

// Mirrors api/app/schemas.py EmailIn
export type EmailIn = {
  sender: string;
  receiver?: string;
  subject: string;
  body: string;
  url: 0 | 1;
};

export type Neighbor = {
  id: number;
  label: 0 | 1 | null;
  subject?: string;
  body?: string;
  similarity: number; // 0..1
  redactions?: {
    types: Record<string, number>;
    count: number;
  };
};

export type AIAnalyzeOut = {
  phase1: ScanResponse;
  neighbors: Neighbor[];
  phish_neighbors: Neighbor[];
  ai_verdict: Verdict;
  ai_label: 0 | 1; // 1 = phishing, 0 = legit
  ai_score: number; // 0..10 higher = more likely phishing
  ai_reasons: string[]; // 3-5 concise bullets
};

// Minimal persisted payload for restoring a previous scan session
export type PersistedScan = {
  input: EmailIn;
  domain: string;
  phase1: ScanResponse;
  neighborsTop3: Neighbor[];
  ai: Pick<AIAnalyzeOut, "ai_verdict" | "ai_label" | "ai_score" | "ai_reasons">;
  savedAt: number; // epoch ms
};

// Row used by dashboard history list
export type HistoryItem = PersistedScan & { id: string };


