import { NextRequest, NextResponse } from "next/server";
import { defaultSasClient } from "@/lib/sas/client";

export async function POST(req: NextRequest) {
  try {
    const { uid } = await req.json();

    if (!uid) {
      return NextResponse.json(
        { error: "Field 'uid' is required to revoke an attestation." },
        { status: 400 }
      );
    }

    const success = await defaultSasClient.revokeCredential(uid);
    if (!success) {
      return NextResponse.json(
        { error: "Attestation could not be revoked (not found or irrevocable)." },
        { status: 400 }
      );
    }

    return NextResponse.json({
      success: true,
      message: `Attestation ${uid} successfully revoked.`,
    });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal revocation error" },
      { status: 500 }
    );
  }
}
