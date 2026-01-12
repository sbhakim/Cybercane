import { NextRequest, NextResponse } from "next/server";

// POST /api/ctf/verify
// Body: { challengeId: string, payload: string, userId: string }

function json(status: number, data: unknown) {
  return NextResponse.json(data, { status });
}

function textToUint8(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function toArrayBuffer(str: string): ArrayBuffer {
  const u8 = textToUint8(str);
  // Create a standalone ArrayBuffer (not SharedArrayBuffer) using slice
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

async function hmac256(key: string, msg: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, toArrayBuffer(msg));
  const bytes = new Uint8Array(sig);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

export async function POST(req: NextRequest) {
  try {
    const contentType = req.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      return json(415, { error: "Unsupported Media Type" });
    }

    const body = (await req.json()) as {
      challengeId?: unknown;
      payload?: unknown;
      userId?: unknown;
    };

    const challengeId = typeof body.challengeId === "string" ? body.challengeId.trim() : "";
    const payload = typeof body.payload === "string" ? body.payload.trim() : "";
    const userId = typeof body.userId === "string" ? body.userId.trim() : "";

    if (!challengeId || !payload || !userId) {
      return json(400, { error: "Invalid request" });
    }

    const secret = process.env.CTF_SECRET || "devsecret";
    const message = `${userId}:${challengeId}:${payload}`;
    const token = await hmac256(secret, message);
    const flag = `CYBERCANE{${token.slice(0, 12)}}`;

    return json(200, { flag });
  } catch {
    // Do not leak payloads or internal errors
    return json(500, { error: "Server error" });
  }
}

export const runtime = "edge"; // lightweight and fast


