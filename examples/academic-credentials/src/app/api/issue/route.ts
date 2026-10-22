import { NextRequest, NextResponse } from "next/server";
import { defaultSasClient } from "@/lib/sas/client";
import { IssueCredentialRequest } from "@/lib/sas/types";
import { MOCK_UNIVERSITIES } from "@/lib/store/mockData";

export async function POST(req: NextRequest) {
  try {
    const body: IssueCredentialRequest = await req.json();

    // 1. Basic validation
    if (!body.recipient || !body.degree || !body.institution || !body.graduation_year || !body.gpa) {
      return NextResponse.json(
        {
          error: "Missing required fields. Required: recipient, degree, institution, graduation_year, gpa",
        },
        { status: 400 }
      );
    }

    // 2. Validate Stellar address format (56 chars, begins with G)
    const stellarAddressRegex = /^G[A-Z2-7]{55}$/;
    if (!stellarAddressRegex.test(body.recipient.trim())) {
      return NextResponse.json(
        {
          error: "Invalid student recipient Stellar address. Must be a valid G... StrKey (56 characters).",
        },
        { status: 400 }
      );
    }

    // 3. Determine issuing authority address
    // In production, derived from the server's UNIVERSITY_ISSUER_SECRET_KEY
    const issuerAddress =
      MOCK_UNIVERSITIES.find((u) =>
        u.name.toLowerCase().includes(body.institution.toLowerCase())
      )?.address || MOCK_UNIVERSITIES[0].address;

    // 4. Issue the academic attestation
    const { uid, record } = await defaultSasClient.issueCredential(
      body,
      issuerAddress
    );

    return NextResponse.json({
      success: true,
      message: "Academic credential issued successfully as a non-transferable Soroban attestation.",
      uid,
      attestation: record,
      verificationUrl: `/badge/${uid}`,
    });
  } catch (err) {
    console.error("Issuance error:", err);
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal server error" },
      { status: 500 }
    );
  }
}
