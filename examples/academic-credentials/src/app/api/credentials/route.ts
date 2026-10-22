import { NextRequest, NextResponse } from "next/server";
import { defaultSasClient } from "@/lib/sas/client";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const recipient = searchParams.get("recipient");
  const uid = searchParams.get("uid");

  try {
    if (uid) {
      const record = await defaultSasClient.getCredentialByUid(uid);
      if (!record) {
        return NextResponse.json(
          { error: "Credential not found" },
          { status: 404 }
        );
      }
      return NextResponse.json(record);
    }

    if (recipient) {
      const records = await defaultSasClient.getCredentialsByRecipient(recipient);
      return NextResponse.json(records);
    }

    const all = await defaultSasClient.getAllCredentials();
    return NextResponse.json(all);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Failed to fetch credentials" },
      { status: 500 }
    );
  }
}
