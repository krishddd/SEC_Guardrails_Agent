import { describe, expect, it } from "vitest";
import { UiClient, type Fetcher } from "./api";

function fakeFetcher(body: unknown, ok = true, status = 200): { calls: string[]; fetcher: Fetcher } {
  const calls: string[] = [];
  const fetcher: Fetcher = async (url, init) => {
    calls.push(`${(init?.method as string) ?? "GET"} ${url}`);
    return { ok, status, json: async () => body };
  };
  return { calls, fetcher };
}

describe("UiClient", () => {
  it("lists approvals with bearer auth", async () => {
    const { calls, fetcher } = fakeFetcher([{ id: "a1", tool: "send_email", args: {}, expires_at: 1 }]);
    const client = new UiClient("http://gw", "tok", fetcher);
    const rows = await client.listApprovals();
    expect(rows[0].id).toBe("a1");
    expect(calls[0]).toBe("GET http://gw/ui/approvals");
  });

  it("posts a resolve decision", async () => {
    const { calls, fetcher } = fakeFetcher({ id: "a1", status: "approved" });
    const client = new UiClient("http://gw", "tok", fetcher);
    const res = await client.resolve("a1", true);
    expect(res.status).toBe("approved");
    expect(calls[0]).toBe("POST http://gw/ui/approvals/a1");
  });

  it("throws on a non-ok response (default-deny surfaces as an error)", async () => {
    const { fetcher } = fakeFetcher({}, false, 401);
    const client = new UiClient("http://gw", "bad", fetcher);
    await expect(client.listApprovals()).rejects.toThrow("401");
  });

  it("reads the governance report", async () => {
    const report = {
      summary: { total: 3, by_decision: { block: 1 }, block_count: 1, controls_evidenced: ["Art. 12"] },
      control_map: {},
    };
    const { fetcher } = fakeFetcher(report);
    const client = new UiClient("http://gw", "tok", fetcher);
    expect((await client.report()).summary.block_count).toBe(1);
  });
});
