/**
 * Tests for the document upload calls: uploadFile sends the raw file as the body with its type
 * and an encoded X-File-Name, a refusal reads as the server's sentence, deleteFile forgets by id,
 * and file_ids ride along in both send bodies only when there are some.
 *
 * Why it exists: an upload that base64-encoded the file into JSON, sent a raw non-ASCII name in
 * a header, or dropped file_ids from the turn would each break document chat silently.
 */

import { describe, expect, it } from "vitest";
import { deleteFile, sendMessage, streamMessage, uploadFile } from "@/services/api";
import { jsonResponse, mockFetch } from "@/test/http";

function doneStream(): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('event: done\ndata: {"content":"ok"}\n\n'));
      controller.close();
    },
  });
  return { ok: true, status: 200, statusText: "OK", body } as unknown as Response;
}

describe("uploadFile", () => {
  it("sends the raw file with its type and an encoded name", async () => {
    localStorage.setItem("auth_token", "tok-1");
    const fetchMock = mockFetch(() => jsonResponse(201, { id: "f-1", name: "Résumé 2026.pdf" }));
    const file = new File(["%PDF-1.4"], "Résumé 2026.pdf", { type: "application/pdf" });

    const result = await uploadFile(file);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/files");
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe(file);
    const headers = init?.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/pdf");
    expect(headers["X-File-Name"]).toBe("R%C3%A9sum%C3%A9%202026.pdf");
    expect(headers.Authorization).toBe("Bearer tok-1");
    expect(result.id).toBe("f-1");
  });

  it("falls back to a generic type when the browser gives none", async () => {
    const fetchMock = mockFetch(() => jsonResponse(201, { id: "f-2" }));
    await uploadFile(new File(["a,b"], "grades.csv"));
    const headers = fetchMock.mock.calls[0][1]?.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/octet-stream");
  });

  it("rejects with the server's sentence", async () => {
    mockFetch(() =>
      jsonResponse(422, {
        detail: "This file is password-protected. Save a copy without a password and send it again.",
        code: "encrypted",
      }),
    );
    await expect(uploadFile(new File(["x"], "locked.pdf"))).rejects.toThrow(
      "This file is password-protected.",
    );
  });
});

describe("deleteFile", () => {
  it("forgets an upload by id", async () => {
    const fetchMock = mockFetch(() => jsonResponse(204, {}));
    await deleteFile("f-1");
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/files/f-1");
    expect(init?.method).toBe("DELETE");
  });
});

describe("file_ids in the send bodies", () => {
  it("adds file_ids to a streamed turn", async () => {
    const fetchMock = mockFetch(() => doneStream());
    await streamMessage("c1", "summarize", {}, undefined, undefined, ["f-1", "f-2"]);
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
      content: "summarize",
      file_ids: ["f-1", "f-2"],
    });
  });

  it("adds file_ids beside images to a buffered turn", async () => {
    const fetchMock = mockFetch(() => jsonResponse(201, {}));
    await sendMessage("c1", "", ["data:image/png;base64,AA=="], ["f-3"]);
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
      content: "",
      images: ["data:image/png;base64,AA=="],
      file_ids: ["f-3"],
    });
  });

  it("leaves file_ids out when there are none", async () => {
    const fetchMock = mockFetch(() => doneStream());
    await streamMessage("c1", "hi", {}, undefined, undefined, []);
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({ content: "hi" });
  });
});
