import { useCallback, useEffect, useRef, useState } from "react";
import { useSAS } from "../context.js";
import type {
  AccountChangedEvent,
  AttestationIssuedEvent,
  AttestationRevokedEvent,
  BatchAttestedEvent,
  BatchRevokedEvent,
  NetworkChangedEvent,
  SASEvent,
  SchemaRegisteredEvent,
} from "../types.js";

export interface UseSASEventsOptions {
  onEvent?: (event: SASEvent) => void;
  onAttestationIssued?: (event: AttestationIssuedEvent) => void;
  onAttestationRevoked?: (event: AttestationRevokedEvent) => void;
  onSchemaRegistered?: (event: SchemaRegisteredEvent) => void;
  onBatchAttested?: (event: BatchAttestedEvent) => void;
  onBatchRevoked?: (event: BatchRevokedEvent) => void;
  onAccountChanged?: (event: AccountChangedEvent) => void;
  onNetworkChanged?: (event: NetworkChangedEvent) => void;
}

export interface UseSASEventsResult {
  /** Most recently received SAS event, or null if none yet. */
  lastEvent: SASEvent | null;
  /** History of received SAS events since mount or last clear. */
  events: SASEvent[];
  /** Emits a SAS event through the provider and invalidates affected queries. */
  emitEvent: (event: SASEvent) => void;
  /** Clears the local event history log. */
  clearEvents: () => void;
}

/**
 * Subscribes to SAS event-based triggers (`AttestationIssued`, `AttestationRevoked`,
 * `SchemaRegistered`, `BatchAttested`, `BatchRevoked`, `AccountChanged`, `NetworkChanged`)
 * and exposes event history and a trigger helper.
 */
export function useSASEvents(
  options?: UseSASEventsOptions,
): UseSASEventsResult {
  const { subscribeToEvents, emitEvent } = useSAS();
  const [events, setEvents] = useState<SASEvent[]>([]);
  const optionsRef = useRef(options);
  optionsRef.current = options;

  useEffect(() => {
    const unsubscribe = subscribeToEvents((event) => {
      setEvents((prev) => [...prev, event]);
      const handlers = optionsRef.current;
      if (!handlers) return;
      handlers.onEvent?.(event);
      switch (event.type) {
        case "AttestationIssued":
          handlers.onAttestationIssued?.(event);
          break;
        case "AttestationRevoked":
          handlers.onAttestationRevoked?.(event);
          break;
        case "SchemaRegistered":
          handlers.onSchemaRegistered?.(event);
          break;
        case "BatchAttested":
          handlers.onBatchAttested?.(event);
          break;
        case "BatchRevoked":
          handlers.onBatchRevoked?.(event);
          break;
        case "AccountChanged":
          handlers.onAccountChanged?.(event);
          break;
        case "NetworkChanged":
          handlers.onNetworkChanged?.(event);
          break;
      }
    });
    return unsubscribe;
  }, [subscribeToEvents]);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  return {
    lastEvent: events.length > 0 ? events[events.length - 1] : null,
    events,
    emitEvent,
    clearEvents,
  };
}
