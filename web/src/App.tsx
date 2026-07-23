// HITL approval app (T39) + observability dashboard (T40). The UI only renders state and relays
// approve/reject to the gateway UI API; enforcement stays server-side.

import { useCallback, useEffect, useState } from "react";
import type { JSX } from "react";
import type { Approval, GovernanceReport, UiClient } from "./api";

export function HitlApp({ client }: { client: UiClient }): JSX.Element {
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [error, setError] = useState<string>("");

  const refresh = useCallback(async () => {
    try {
      setApprovals(await client.listApprovals());
    } catch (e) {
      setError(String(e));
    }
  }, [client]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const decide = async (id: string, approved: boolean) => {
    await client.resolve(id, approved);
    await refresh();
  };

  return (
    <section>
      <h2>Pending approvals</h2>
      {error && <p role="alert">{error}</p>}
      {approvals.length === 0 && <p>No pending approvals.</p>}
      <ul>
        {approvals.map((a) => (
          <li key={a.id}>
            <code>{a.tool}</code> — {JSON.stringify(a.args)}
            <button onClick={() => void decide(a.id, true)}>Approve</button>
            <button onClick={() => void decide(a.id, false)}>Reject</button>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function Dashboard({ report }: { report: GovernanceReport }): JSX.Element {
  return (
    <section>
      <h2>Governance</h2>
      <p>Total decisions: {report.summary.total}</p>
      <p>Blocks: {report.summary.block_count}</p>
      <h3>Controls evidenced</h3>
      <ul>
        {report.summary.controls_evidenced.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
    </section>
  );
}

// Sanitizer visual harness (T40): show raw vs sanitized output side by side. The actual sanitization
// runs server-side (Rust/Python); this only displays the result a reviewer should see.
export function SanitizePreview({ raw, clean }: { raw: string; clean: string }): JSX.Element {
  return (
    <section>
      <h2>Sanitizer preview</h2>
      <pre data-testid="raw">{raw}</pre>
      <pre data-testid="clean">{clean}</pre>
    </section>
  );
}
