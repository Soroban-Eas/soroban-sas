import { NextRequest, NextResponse } from "next/server";
import { defaultSasClient } from "@/lib/sas/client";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const uid = searchParams.get("uid");

  if (!uid) {
    return NextResponse.json(
      { error: "Query parameter 'uid' is required." },
      { status: 400 }
    );
  }

  try {
    const verdict = await defaultSasClient.verifyAttestation(uid);
    return NextResponse.json(verdict);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal verification error" },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  try {
    const { uid } = await req.json();
    if (!uid) {
      return NextResponse.json(
        { error: "Payload field 'uid' is required." },
        { status: 400 }
      );
    }
    const verdict = await defaultSasClient.verifyAttestation(uid);
    return NextResponse.json(verdict);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal verification error" },
      { status: 500 }
    );
  }
}
