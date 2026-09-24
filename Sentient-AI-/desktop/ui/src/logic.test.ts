/**
 * Unit tests for the pure logic: key format rules, elapsed-time text, log-line cleanup, safe
 * links, phase classification and the step-1 check rows.
 *
 * Why it exists: These rules decide what people are told and whether they may continue; they
 * are cheap to test exhaustively without rendering anything.
 */

import { describe, expect, it } from "vitest";
import { buildRows, checkNote } from "./checks";
import { cleanLogLines, errorText, formatElapsed, formatGb, httpsUrl } from "./format";
import { encryptionKeyProblem, secretKeyProblem } from "./keys";
import { classifyPhase, phaseLabel } from "./phase";
import { WORDS } from "./platform";
import { readyReport } from "./test/bridge";

// 32 random bytes, base64 (standard alphabet) — a well-formed ENCRYPTION_KEY.
const GOOD_ENC = "q83vASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4k=";

describe("secretKeyProblem", () => {
  it("accepts 32+ printable characters", () => {
    expect(secretKeyProblem("a".repeat(32))).toBe("");
    expect(secretKeyProblem("Zx9-_.~!%^&*()[]{}<>?,;:|=+@abcdef")).toBe("");
  });

  it("rejects short keys and says how long they are", () => {
    expect(secretKeyProblem("")).toMatch(/Enter a SECRET_KEY/);
    expect(secretKeyProblem("a".repeat(31))).toMatch(/at least 32 characters \(this one has 31\)/);
  });

  it("rejects whitespace, shell/.env metacharacters, non-ASCII and placeholders", () => {
    expect(secretKeyProblem(`${"a".repeat(32)} b`)).toMatch(/spaces/);
    expect(secretKeyProblem(`${"a".repeat(32)}$`)).toMatch(/quotes, backticks, backslashes, \$ or #/);
    expect(secretKeyProblem(`${"a".repeat(32)}#`)).toMatch(/\$ or #/);
    expect(secretKeyProblem(`${"a".repeat(32)}é`)).toMatch(/ASCII/);
    expect(secretKeyProblem(`changeme${"x".repeat(30)}`)).toMatch(/placeholder/);
    expect(secretKeyProblem("a".repeat(513))).toMatch(/at most 512/);
  });
});

describe("encryptionKeyProblem", () => {
  it("accepts base64 of exactly 32 bytes, standard or URL-safe", () => {
    expect(encryptionKeyProblem(GOOD_ENC)).toBe("");
    expect(encryptionKeyProblem(GOOD_ENC.replace(/\+/g, "-").replace(/\//g, "_"))).toBe("");
  });

  it("rejects other lengths and says what it decodes to", () => {
    expect(encryptionKeyProblem(btoa("x".repeat(16)))).toMatch(/exactly 32 bytes \(this one decodes to 16\)/);
    expect(encryptionKeyProblem(btoa("x".repeat(33)))).toMatch(/decodes to 33/);
  });

  it("rejects non-base64 text and bad padding", () => {
    expect(encryptionKeyProblem("")).toMatch(/Enter an ENCRYPTION_KEY/);
    expect(encryptionKeyProblem("not base64 at all")).toMatch(/spaces/);
    expect(encryptionKeyProblem("!!!!")).toMatch(/must be base64/);
    expect(encryptionKeyProblem(GOOD_ENC.slice(0, -1))).toMatch(/padding/);
  });
});

describe("format helpers", () => {
  it("formats elapsed time like a clock", () => {
    expect(formatElapsed(0)).toBe("0:00");
    expect(formatElapsed(247)).toBe("4:07");
    expect(formatElapsed(3725)).toBe("1:02:05");
    expect(formatElapsed(-5)).toBe("0:00");
    expect(formatElapsed(undefined)).toBe("0:00");
  });

  it("cleans log lines: colours, carriage-return redraws, embedded newlines", () => {
    expect(cleanLogLines("\u001b[32mok\u001b[0m")).toEqual(["ok"]);
    expect(cleanLogLines("10%\r50%\r100%")).toEqual(["100%"]);
    expect(cleanLogLines("one\ntwo\n")).toEqual(["one", "two"]);
    expect(cleanLogLines("")).toEqual([""]);
    expect(cleanLogLines("x".repeat(5000))[0]).toHaveLength(2000);
  });

  it("only lets https links through", () => {
    expect(httpsUrl("https://www.docker.com/")).toBe("https://www.docker.com/");
    expect(httpsUrl("http://example.com")).toBeNull();
    expect(httpsUrl("javascript:alert(1)")).toBeNull();
    expect(httpsUrl("file:///etc/passwd")).toBeNull();
    expect(httpsUrl(undefined)).toBeNull();
  });

  it("turns rejected invokes into text", () => {
    expect(errorText("docker not found")).toBe("docker not found");
    expect(errorText(new Error("boom"))).toBe("boom");
    expect(errorText({ message: "from rust" })).toBe("from rust");
    expect(errorText(42)).toBe("Unknown error.");
  });

  it("rounds disk space sensibly", () => {
    expect(formatGb(182.4)).toBe("182");
    expect(formatGb(7.46)).toBe("7.5");
  });
});

describe("phases", () => {
  it("classifies known phases and treats unknown ones as still working", () => {
    expect(classifyPhase(null)).toBe("idle");
    expect(classifyPhase({ phase: "idle", elapsed_s: 0 })).toBe("idle");
    expect(classifyPhase({ phase: "building", elapsed_s: 3 })).toBe("working");
    expect(classifyPhase({ phase: "some_new_phase", elapsed_s: 3 })).toBe("working");
    expect(classifyPhase({ phase: "healthy", elapsed_s: 3 })).toBe("healthy");
    expect(classifyPhase({ phase: "running", elapsed_s: 3 })).toBe("healthy");
    expect(classifyPhase({ phase: "stopped", elapsed_s: 0 })).toBe("stopped");
    expect(classifyPhase({ phase: "failed", elapsed_s: 3 })).toBe("failed");
    expect(classifyPhase({ phase: "building", elapsed_s: 3, error: "exit 1" })).toBe("failed");
  });

  it("labels phases for people", () => {
    expect(phaseLabel({ phase: "building", elapsed_s: 0 })).toBe("Building images…");
    expect(phaseLabel({ phase: "waiting_frontend", elapsed_s: 0 })).toBe("Waiting for the web app…");
    expect(phaseLabel({ phase: "mystery", elapsed_s: 0 })).toBe("Working…");
    expect(phaseLabel({ phase: "healthy", elapsed_s: 0 })).toBe("Crawler AI is running ✓");
  });
});

describe("buildRows / checkNote", () => {
  const mac = WORDS.mac;

  it("passes everything on a ready machine", () => {
    const report = readyReport();
    const rows = buildRows(report, mac);
    expect(rows.map((r) => [r.id, r.state])).toEqual([
      ["docker_installed", "ok"],
      ["docker_running", "ok"],
      ["compose_v2", "ok"],
      ["ports", "ok"],
      ["disk", "ok"],
      ["env", "info"],
    ]);
    expect(rows.find((r) => r.id === "ports")?.title).toBe("Ports 3000, 8000, 5432 and 6379");
    expect(checkNote(report, rows)).toEqual({ tone: "ok", text: "Everything looks good." });
  });

  it("explains a missing Docker Desktop with the OS-specific name and a download link", () => {
    const report = readyReport({ docker_installed: false, docker_running: false, compose_v2: false, ready: false });
    const rows = buildRows(report, WORDS.windows);
    const docker = rows.find((r) => r.id === "docker_installed");
    expect(docker?.state).toBe("bad");
    expect(docker?.fixes[0].text).toMatch(/Docker Desktop for Windows/);
    expect(docker?.fixes[0].url).toMatch(/^https:\/\/www\.docker\.com\//);
    expect(rows.find((r) => r.id === "docker_running")?.state).toBe("skip");
    expect(checkNote(report, rows).tone).toBe("bad");
  });

  it("offers Open Docker Desktop when installed but not running", () => {
    const rows = buildRows(readyReport({ docker_running: false, ready: false }), mac);
    const running = rows.find((r) => r.id === "docker_running");
    expect(running?.state).toBe("bad");
    expect(running?.openDocker).toBe(true);
  });

  it("warns about busy ports and low disk, preferring Rust's fix text", () => {
    const report = readyReport({
      ports: [
        { port: 3000, service: "web app", free: false, holder: "node" },
        { port: 8000, service: "backend", free: true, holder: null },
      ],
      disk_free_gb: 4.2,
      fixes: [{ id: "disk", severity: "warning", text: "Only 4.2 GB free (from Rust)." }],
    });
    const rows = buildRows(report, mac);
    const ports = rows.find((r) => r.id === "ports");
    expect(ports?.state).toBe("warn");
    expect(ports?.fixes[0].text).toMatch(/Port 3000 \(web app\) is in use by node/);
    const disk = rows.find((r) => r.id === "disk");
    expect(disk?.state).toBe("warn");
    expect(disk?.fixes[0].text).toBe("Only 4.2 GB free (from Rust).");
    expect(checkNote(report, rows).tone).toBe("info");
  });

  it("treats ports held by our own running stack as fine", () => {
    const rows = buildRows(
      readyReport({
        existing_stack: true,
        ports: [
          { port: 3000, service: "web app", free: false, holder: "com.docker.backend", ours: true },
          { port: 8000, service: "backend", free: false, holder: "com.docker.backend", ours: true },
        ],
      }),
      mac,
    );
    const ports = rows.find((r) => r.id === "ports");
    expect(ports?.state).toBe("ok");
    expect(ports?.detail).toBe("In use by your running Crawler AI, which is fine.");
  });

  it("shows fixes with ids it doesn't know yet", () => {
    const rows = buildRows(
      readyReport({ fixes: [{ id: "virtualization", severity: "error", text: "Turn on virtualization." }] }),
      mac,
    );
    const extra = rows.find((r) => r.id === "virtualization");
    expect(extra?.state).toBe("bad");
    expect(extra?.fixes[0].text).toBe("Turn on virtualization.");
  });
});
