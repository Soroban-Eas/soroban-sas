import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SASDemoApp } from "../src/index.js";
import {
  DefaultTestnetStory,
  LocalNetworkBobStory,
} from "../src/stories/SAS.stories.js";

describe("SASDemoApp and Storybook stories", () => {
  it("renders hook states and responds to account switching, network switching, and event triggers", async () => {
    render(<SASDemoApp />);

    // Verify initial schema, attestation, and recipient attestations load
    await waitFor(() => {
      expect(screen.getByTestId("schema-details")).toHaveTextContent(
        "verified bool, kyc_level u32, provider String",
      );
      expect(screen.getByTestId("attestation-status")).toHaveTextContent("Active");
      expect(screen.getByTestId("recipient-attestation-list")).toHaveTextContent(
        "stellar-id",
      );
    });

    expect(screen.getByTestId("active-network")).toHaveTextContent("testnet");

    // Switch account to Bob -> recipient attestations re-fetch automatically
    fireEvent.click(screen.getByTestId("switch-account-bob"));

    await waitFor(() => {
      expect(screen.getByTestId("recipient-attestation-list")).toHaveTextContent(
        "anchor-kyc",
      );
    });

    // Switch network to local
    fireEvent.click(screen.getByTestId("switch-network-local"));
    await waitFor(() => {
      expect(screen.getByTestId("active-network")).toHaveTextContent("local");
    });

    // Trigger AttestationIssued event -> adds a new attestation and updates view
    fireEvent.click(screen.getByTestId("trigger-issue-event"));

    await waitFor(() => {
      expect(screen.getByTestId("last-event-type")).toHaveTextContent(
        "AttestationIssued",
      );
      expect(screen.getByTestId("attestation-payload")).toHaveTextContent(
        "provider=event-trigger",
      );
    });

    // Trigger AttestationRevoked event -> updates status to Revoked
    fireEvent.click(screen.getByTestId("trigger-revoke-event"));

    await waitFor(() => {
      expect(screen.getByTestId("last-event-type")).toHaveTextContent(
        "AttestationRevoked",
      );
      expect(screen.getByTestId("attestation-status")).toHaveTextContent("Revoked");
    });
  });

  it("renders Storybook stories cleanly", async () => {
    const { unmount } = render(
      DefaultTestnetStory.render(DefaultTestnetStory.args),
    );
    await waitFor(() => {
      expect(screen.getByTestId("active-network")).toHaveTextContent("testnet");
    });
    unmount();

    render(LocalNetworkBobStory.render(LocalNetworkBobStory.args));
    await waitFor(() => {
      expect(screen.getByTestId("active-network")).toHaveTextContent("local");
      expect(screen.getByTestId("recipient-attestation-list")).toHaveTextContent(
        "anchor-kyc",
      );
    });
  });
});
