export type Token = { text: string; start: number; end: number };
export type Sentence = { text: string; start: number; end: number; tokens: Token[] };
export type HighlightRange = { start: number; end: number; strength: "partial" | "strong" };

// Basic sentence splitter that preserves indices
export function splitSentences(text: string): Sentence[] {
  const sentences: Sentence[] = [];
  const regex = /[^.!?\n]+[.!?\n]?/g; // rough split on punctuation/newlines
  let match: RegExpExecArray | null;
  while ((match = regex.exec(text)) !== null) {
    const sentText = match[0];
    const start = match.index;
    const end = start + sentText.length;
    const tokens = tokenize(sentText, start);
    sentences.push({ text: sentText, start, end, tokens });
  }
  return sentences.length ? sentences : [{ text, start: 0, end: text.length, tokens: tokenize(text, 0) }];
}

// Tokenize words and keep original indices (offset is added to token indices)
export function tokenize(text: string, offset: number = 0): Token[] {
  const tokens: Token[] = [];
  const word = /[A-Za-z0-9]+(?:'[A-Za-z0-9]+)?/g;
  let match: RegExpExecArray | null;
  while ((match = word.exec(text)) !== null) {
    const start = offset + match.index;
    const end = start + match[0].length;
    tokens.push({ text: match[0].toLowerCase(), start, end });
  }
  return tokens;
}

// removed unused lcsLength helper to satisfy linter

// Simple Jaccard similarity of token sets
function jaccard(a: Set<string>, b: Set<string>): number {
  let intersection = 0;
  for (const t of a) if (b.has(t)) intersection++;
  const union = a.size + b.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

export type SimilarityOptions = {
  neighborSimilarity: number; // 0..1 overall similarity (used as gate)
  sentenceThreshold?: number; // default 0.5
  strongTokenThreshold?: number; // default 0.9 (near-exact span when overall LCS ratio >= threshold)
  strongSpanMinTokens?: number; // default 4
};

// Compute highlight ranges across two texts using sentence-level matching then token-level scoring
export function computeHighlightRanges(
  sourceText: string,
  neighborText: string,
  opts: SimilarityOptions
): { source: HighlightRange[]; neighbor: HighlightRange[]; matchedSentences: { sourceIdx: number; neighborIdx: number }[] } {
  const sentenceThreshold = opts.sentenceThreshold ?? 0.5;
  const strongTokenThreshold = opts.strongTokenThreshold ?? 0.9;
  const strongSpanMinTokens = opts.strongSpanMinTokens ?? 4;

  const srcSents = splitSentences(sourceText);
  const nbrSents = splitSentences(neighborText);

  const matchedPairs: { sourceIdx: number; neighborIdx: number }[] = [];
  const sourceRanges: HighlightRange[] = [];
  const neighborRanges: HighlightRange[] = [];

  if (opts.neighborSimilarity <= 0.3) {
    return { source: [], neighbor: [], matchedSentences: [] };
  }

  // For each source sentence, find best matching neighbor sentence by Jaccard
  for (let i = 0; i < srcSents.length; i++) {
    const a = srcSents[i];
    const aSet = new Set(a.tokens.map((t) => t.text));
    let best = -1;
    let bestScore = 0;
    for (let j = 0; j < nbrSents.length; j++) {
      const b = nbrSents[j];
      const score = jaccard(aSet, new Set(b.tokens.map((t) => t.text)));
      if (score > bestScore) {
        bestScore = score;
        best = j;
      }
    }
    if (best >= 0 && bestScore >= sentenceThreshold) {
      matchedPairs.push({ sourceIdx: i, neighborIdx: best });
      // token-level highlighting using LCS with backtracking to get matching pairs
      const aTokens = a.tokens;
      const bTokens = nbrSents[best].tokens;
      const aWords = aTokens.map((t) => t.text);
      const bWords = bTokens.map((t) => t.text);

      const m = aWords.length, n = bWords.length;
      if (m === 0 || n === 0) continue;
      const dp = new Array(m + 1).fill(0).map(() => new Array(n + 1).fill(0));
      for (let ii = 1; ii <= m; ii++) {
        for (let jj = 1; jj <= n; jj++) {
          dp[ii][jj] = aWords[ii - 1] === bWords[jj - 1] ? dp[ii - 1][jj - 1] + 1 : Math.max(dp[ii - 1][jj], dp[ii][jj - 1]);
        }
      }

      const lcsLen = dp[m][n];
      const globalRatio = lcsLen / (Math.max(m, n) || 1);
      const globalStrong = globalRatio >= strongTokenThreshold;

      // Backtrack to get matching index pairs
      const pairs: Array<{ ai: number; bj: number }> = [];
      let ii = m, jj = n;
      while (ii > 0 && jj > 0) {
        if (aWords[ii - 1] === bWords[jj - 1]) {
          pairs.push({ ai: ii - 1, bj: jj - 1 });
          ii--;
          jj--;
        } else if (dp[ii - 1][jj] >= dp[ii][jj - 1]) {
          ii--;
        } else {
          jj--;
        }
      }
      pairs.reverse();

      // Group contiguous pairs into spans and convert to char ranges
      let spanStart = 0;
      for (let k = 0; k < pairs.length; k++) {
        const isLast = k === pairs.length - 1;
        const cur = pairs[k];
        const next = isLast ? null : pairs[k + 1];
        const contiguous = next && next.ai === cur.ai + 1 && next.bj === cur.bj + 1;
        if (!contiguous) {
          const first = pairs[spanStart];
          const last = pairs[k];
          const spanLen = (last.ai - first.ai) + 1;
          const strength: HighlightRange["strength"] = globalStrong || spanLen >= strongSpanMinTokens ? "strong" : "partial";
          // Source range
          sourceRanges.push({ start: aTokens[first.ai].start, end: aTokens[last.ai].end, strength });
          // Neighbor range
          neighborRanges.push({ start: bTokens[first.bj].start, end: bTokens[last.bj].end, strength });
          spanStart = k + 1;
        }
      }
    }
  }

  return { source: sourceRanges, neighbor: neighborRanges, matchedSentences: matchedPairs };
}


