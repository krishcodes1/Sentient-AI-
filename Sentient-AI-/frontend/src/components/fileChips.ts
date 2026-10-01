/**
 * Helpers for document attachments shared by the composer and the chat thread: which files the
 * server reads (by extension), the file input's accept list, the attachment entry built from an
 * upload, and a chip's label ("syllabus.pdf · 12 pages · 3 scanned pages unread").
 *
 * Why it exists: ChatComposer shows a chip while a document uploads and Chat.tsx shows the same
 * chip on the sent message and on a reloaded thread; one module keeps the wording and the type
 * list identical in both (and out of the component files, for React fast refresh).
 */

import type { FileAttachment, UploadedFile } from "@/types";

/** The document types the server reads, by extension (backend/services/files/detect.py). */
export const DOCUMENT_EXTENSIONS = [
  ".pdf",
  ".docx",
  ".pptx",
  ".xlsx",
  ".csv",
  ".tsv",
  ".txt",
  ".text",
  ".log",
  ".md",
  ".markdown",
  ".html",
  ".htm",
  ".json",
];

/** Older Office formats the server refuses with advice (detect.py LEGACY_OFFICE_EXTENSIONS). */
export const LEGACY_OFFICE_EXTENSIONS = [".doc", ".xls", ".ppt"];

/** The file input's accept list: images keep their own path. */
export const ACCEPT = ["image/*", ...DOCUMENT_EXTENSIONS].join(",");

export function isDocument(file: File): boolean {
  const name = (file.name || "").toLowerCase();
  return DOCUMENT_EXTENSIONS.some((ext) => name.endsWith(ext));
}

export function isLegacyOffice(file: File): boolean {
  const name = (file.name || "").toLowerCase();
  return LEGACY_OFFICE_EXTENSIONS.some((ext) => name.endsWith(ext));
}

/** Why a file is not uploaded, in the server's words for an older Office file
 * (backend/services/files/messages.py LEGACY_OFFICE). */
export function unreadableFileMessage(file: File): string {
  const name = file.name || "that file";
  if (isLegacyOffice(file)) {
    return `${name} is an older Office format (.doc/.xls/.ppt). Save it as .docx/.xlsx/.pptx or PDF and send it again.`;
  }
  return `Crawler can't read ${name}. Attach images, PDF, Word (.docx), PowerPoint (.pptx), Excel (.xlsx), CSV, text, Markdown, HTML or JSON files.`;
}

export function asAttachment(up: UploadedFile): FileAttachment {
  return {
    kind: "file",
    file_id: up.id,
    name: up.name,
    media_type: up.media_type,
    doc_kind: up.kind,
    pages: up.pages,
    chars: up.chars,
    size_bytes: up.size_bytes,
    scanned_pages_unread: up.scanned_pages_unread,
  };
}

/** "syllabus.pdf · 12 pages · 3 scanned pages unread" */
export function fileChipLabel(
  file: Pick<FileAttachment, "name" | "pages" | "doc_kind" | "scanned_pages_unread">,
): string {
  const parts = [file.name];
  if (file.pages) {
    const unit =
      file.doc_kind === "pptx" ? "slide" : file.doc_kind === "xlsx" ? "sheet" : "page";
    parts.push(`${file.pages} ${unit}${file.pages === 1 ? "" : "s"}`);
  }
  const unread = file.scanned_pages_unread?.length ?? 0;
  if (unread > 0) {
    parts.push(`${unread} scanned page${unread === 1 ? "" : "s"} unread`);
  }
  return parts.join(" · ");
}
