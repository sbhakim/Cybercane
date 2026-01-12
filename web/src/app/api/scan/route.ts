import { NextRequest, NextResponse } from "next/server";

type Verdict = "benign" | "needs_review" | "phishing";

type ScanResponse = {
  verdict: Verdict;
  score: number;
  reasons: string[];
  indicators: Record<string, unknown>;
  redactions: { types: Record<string, number>; count: number };
  redacted_body: string;
};

function resolveApiBaseUrl(): string {
  const internal = process.env.INTERNAL_API_URL;
  const publicUrl = process.env.NEXT_PUBLIC_API_URL;
  return internal || publicUrl || "http://localhost:8000";
}

function computeUrlFlag(text: string): number {
  return /https?:\/\//i.test(text) ? 1 : 0;
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json().catch(() => ({}));

    const from = (body?.from ?? "").toString();
    const to = body?.to ? body.to.toString() : undefined;
    const subject = (body?.subject ?? "").toString();
    const content = (body?.body ?? "").toString();

    if (!from || !subject || !content) {
      return NextResponse.json(
        { error: "Missing required fields: from, subject, body" },
        { status: 400 }
      );
    }

    const payload = {
      sender: from,
      receiver: to,
      subject,
      body: content,
      url: computeUrlFlag(content),
    };

    const base = resolveApiBaseUrl();
    const upstream = await fetch(`${base}/scan`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!upstream.ok) {
      let detail: unknown = null;
      try {
        detail = await upstream.json();
      } catch {
        detail = await upstream.text();
      }
      return NextResponse.json(
        { error: "Upstream scan failed", status: upstream.status, detail },
        { status: 502 }
      );
    }

    const data = (await upstream.json()) as ScanResponse;
    return NextResponse.json<ScanResponse>(data);
  } catch (err) {
    return NextResponse.json(
      { error: "Unexpected server error", detail: `${err}` },
      { status: 500 }
    );
  }
}


