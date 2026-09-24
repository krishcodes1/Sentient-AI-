/**
 * The owner-only Settings > Server section: this Crawler's AI provider (via ProviderForm) and the
 * switch for whether new accounts may be created.
 *
 * Why it exists: What the setup wizard decided for the whole install has to be changeable
 * afterwards without re-running it; Settings renders this only for is_admin accounts.
 */

import { useEffect, useId, useState } from "react";
import { Loader2, Lock } from "lucide-react";
import { ErrorAlert, ResultLine } from "@/components/FormFeedback";
import ProviderForm from "@/components/ProviderForm";
import { errorText, panelStyle } from "@/components/formStyles";
import { ApiError, getSetupStatus, updateRegistration } from "@/services/api";
import type { SetupStatus } from "@/types";

const boxStyle = { background: "var(--bg-input)", border: "1px solid var(--claw-border)" };

/**
 * Settings ▸ Server: what the setup wizard decided for the whole Crawler,
 * for the owner to change afterwards without re-running it — the AI
 * provider every account follows by default, and whether new accounts may
 * be created. Settings renders this only for the owner (`is_admin`); the
 * server enforces the same on every call here.
 */
export default function ServerSettings() {
  const headingId = useId();
  const signupsLabelId = useId();
  const signupsHelpId = useId();
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [signupsBusy, setSignupsBusy] = useState(false);
  const [signupsFeedback, setSignupsFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    let cancelled = false;
    getSetupStatus()
      .then((s) => {
        if (cancelled) return;
        setStatus(s);
        setLoadError("");
      })
      .catch((err) => {
        if (!cancelled) setLoadError(errorText(err, "This Crawler's settings could not be loaded."));
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  // After "Clear stored keys": re-read, so the notice goes once the server
  // agrees the keys are gone. A failure leaves things as they were; the
  // button already reported its own outcome.
  const reloadStatus = () => {
    getSetupStatus()
      .then(setStatus)
      .catch(() => {});
  };

  const locked = !!status?.registration_env_locked;
  const open = !!status?.registration_open;

  const toggleSignups = async () => {
    if (!status || locked) return;
    const allow = !open;
    setSignupsBusy(true);
    setSignupsFeedback(null);
    try {
      await updateRegistration(allow);
      setStatus((s) => s && { ...s, registration_open: allow });
      setSignupsFeedback({
        ok: true,
        text: allow ? "Sign-ups are open." : "Sign-ups are closed.",
      });
    } catch (err) {
      // 409: .env locks it closed after all (set since this page loaded).
      // Show the server's own sentence and stop offering the switch.
      if (err instanceof ApiError && err.status === 409) {
        setStatus((s) => s && { ...s, registration_open: false, registration_env_locked: true });
      }
      setSignupsFeedback({ ok: false, text: errorText(err, "Sign-ups could not be changed.") });
    } finally {
      setSignupsBusy(false);
    }
  };

  return (
    <section aria-labelledby={headingId} className="rounded-[14px] p-6" style={panelStyle}>
      <div className="eyebrow mb-1">Owner</div>
      <h2 id={headingId} className="mb-1">
        Server
      </h2>
      <p className="text-sm mb-4" style={{ color: "var(--text-secondary)" }}>
        Settings for this whole Crawler, not just your account. Only the owner sees them.
      </p>

      <div className="space-y-4">
        <div className="rounded-[10px] p-4" style={boxStyle}>
          <h3 className="text-sm font-semibold mb-1" style={{ color: "var(--text-primary)" }}>
            AI provider for this Crawler
          </h3>
          <p className="text-xs mb-4" style={{ color: "var(--text-muted)" }}>
            Every account uses this unless it picks its own under LLM provider. A change is
            tested before it can be saved.
          </p>
          <ProviderForm
            compact
            secretsUnreadable={!!status?.secrets_unreadable}
            onSecretsCleared={reloadStatus}
          />
        </div>

        <div className="rounded-[10px] p-4" style={boxStyle}>
          <h3 className="text-sm font-semibold mb-3" style={{ color: "var(--text-primary)" }}>
            Who can create accounts
          </h3>
          {loadError ? (
            <ErrorAlert>
              {loadError}{" "}
              <button
                type="button"
                className="underline font-medium"
                onClick={() => {
                  setLoadError("");
                  setAttempt((n) => n + 1);
                }}
              >
                Try again
              </button>
            </ErrorAlert>
          ) : !status ? (
            <p className="text-sm" style={{ color: "var(--text-muted)" }}>
              Checking…
            </p>
          ) : (
            <>
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="min-w-0">
                  <p id={signupsLabelId} className="text-sm" style={{ color: "var(--text-primary)" }}>
                    Allow other people to create accounts on this Crawler
                  </p>
                  <p id={signupsHelpId} className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
                    {locked ? (
                      <span className="inline-flex items-center gap-1.5">
                        <Lock className="w-3.5 h-3.5 shrink-0" aria-hidden />
                        <span>Locked closed by ALLOW_REGISTRATION=false in .env</span>
                      </span>
                    ) : open ? (
                      "Anyone who can reach this Crawler can sign up from the login page."
                    ) : (
                      "Only accounts that already exist can sign in."
                    )}
                  </p>
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-checked={open}
                  aria-labelledby={signupsLabelId}
                  aria-describedby={signupsHelpId}
                  disabled={locked || signupsBusy}
                  onClick={() => void toggleSignups()}
                  className="inline-flex items-center justify-center px-4 rounded-[10px] text-sm font-medium transition-colors disabled:opacity-50"
                  style={{
                    minHeight: 44,
                    background: open ? "var(--fill-success)" : "var(--claw-panel)",
                    border: open ? "1px solid var(--border-success)" : "1px solid var(--claw-border)",
                    color: open ? "var(--accent-success)" : "var(--text-muted)",
                  }}
                >
                  {signupsBusy ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : open ? "On" : "Off"}
                </button>
              </div>
              {signupsFeedback && (
                <div className="mt-3">
                  <ResultLine ok={signupsFeedback.ok}>{signupsFeedback.text}</ResultLine>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </section>
  );
}
