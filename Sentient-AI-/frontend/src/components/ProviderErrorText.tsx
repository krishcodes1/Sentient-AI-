/**
 * Renders a failed turn's text, turning the fix pointer the api layer appended to a provider
 * failure into a link to Settings.
 *
 * Why it exists: Chat shows provider failures as bubbles, and only this component knows how to
 * find the exact sentence withFixPointer added so the link replaces just that.
 */

import { Link } from "react-router-dom";
import { withFixPointer, type ProviderErrorInfo } from "@/services/api";

/**
 * A failed turn's text, with the fix pointer the api layer appended to a
 * provider failure ("Change it in Settings." / "Open /setup to finish
 * setup.") turned into a link to Settings.
 *
 * Both kinds point at Settings. Chat is only reachable once setup is
 * finished, and by then /setup just sends you home: the owner fixes this
 * Crawler's provider in Settings ▸ Server, and anyone else changes their
 * own choice under LLM provider. Any other text renders unchanged.
 */
export default function ProviderErrorText({ text, info }: { text: string; info?: ProviderErrorInfo }) {
  const pointer = info ? withFixPointer("", info) : "";
  if (!pointer || !text.endsWith(pointer)) return <>{text}</>;
  const lead = text.slice(0, text.length - pointer.length);
  return (
    <>
      {lead} {info?.setup_url?.trim() ? "Set it up in" : "Change it in"}{" "}
      <Link to="/settings" className="underline font-semibold">
        Settings
      </Link>
      .
    </>
  );
}
