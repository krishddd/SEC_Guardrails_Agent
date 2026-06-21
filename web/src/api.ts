// Typed client for the gateway UI API (T38). No security logic here — it only displays state and
// relays an operator's approve/reject. All calls carry the bearer token.

export interface Approval {
  id: string;
  tool: string;
  args: Record<string, unknown>;
  expires_at: number;
}

export interface GovernanceReport {
  summary: {
    total: number;
    by_decision: Record<string, number>;
    block_count: number;
    controls_evidenced: string[];
  };
  control_map: Record<string, unknown>;
}

export interface ResolveResult {
  id: string;
  status: string;
}

interface FetchResponse {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}

export type Fetcher = (url: string, init?: Record<string, unknown>) => Promise<FetchResponse>;

export class UiClient {
  constructor(
    private readonly base: string,
    private readonly token: string,
    private readonly fetcher: Fetcher,
  ) {}

  private headers(): Record<string, string> {
    return { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" };
  }

  async listApprovals(): Promise<Approval[]> {
    const resp = await this.fetcher(`${this.base}/ui/approvals`, { headers: this.headers() });
    if (!resp.ok) throw new Error(`listApprovals failed: ${resp.status}`);
    return (await resp.json()) as Approval[];
  }

  async resolve(id: string, approved: boolean): Promise<ResolveResult> {
    const resp = await this.fetcher(`${this.base}/ui/approvals/${id}`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({ approved }),
    });
    if (!resp.ok) throw new Error(`resolve failed: ${resp.status}`);
    return (await resp.json()) as ResolveResult;
  }

  async report(): Promise<GovernanceReport> {
    const resp = await this.fetcher(`${this.base}/ui/report`, { headers: this.headers() });
    if (!resp.ok) throw new Error(`report failed: ${resp.status}`);
    return (await resp.json()) as GovernanceReport;
  }
}
