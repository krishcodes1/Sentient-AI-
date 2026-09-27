/**
 * PaymentCardSettings: the owner's Settings ▸ Payment card section — the masked card the vault
 * holds (brand and last four), a form to store or replace one, and Delete with confirmation.
 *
 * Why it exists: The card is entered here, on the owner's own machine, and nowhere else (never in
 * chat). The form posts it once and keeps nothing; the server answers only with the masked view;
 * and a container install, which has no Keychain or DPAPI for the vault key, shows the reason the
 * server gives (GET /vault/items `available: false`, or a 409 on save) instead of a form that
 * could not work: nobody should type a card number into a form that cannot keep it.
 */

import { useEffect, useId, useState } from "react";
import { CreditCard, Loader2, Trash2 } from "lucide-react";
import ConfirmDialog from "@/components/ConfirmDialog";
import { ErrorAlert, ResultLine } from "@/components/FormFeedback";
import {
  errorText,
  inputCls,
  inputStyle,
  labelCls,
  panelStyle,
  primaryCls,
  primaryStyle,
  secondaryCls,
  secondaryStyle,
} from "@/components/formStyles";
import { ApiError, deleteVaultItem, getVaultItems, saveVaultCard } from "@/services/api";
import type { VaultItemView } from "@/types";

const boxStyle = { background: "var(--bg-input)", border: "1px solid var(--claw-border)" };

const UNAVAILABLE_FALLBACK =
  "Cards can't be stored in a container install. Install Crawler on your Mac or PC to buy things.";

/**
 * Brand from the leading digits, for the badge beside the number field as it
 * is typed. The server decides the stored brand; this is only a hint that
 * the number is being read right.
 */
function brandOf(digits: string): string | null {
  if (/^4/.test(digits)) return "Visa";
  if (/^(5[1-5]|2[2-7])/.test(digits)) return "Mastercard";
  if (/^3[47]/.test(digits)) return "Amex";
  if (/^(6011|65|64[4-9])/.test(digits)) return "Discover";
  return null;
}

/** "MM/YY" or "MM/YYYY" → month and four-digit year, or null when unreadable. */
function parseExpiry(text: string): { month: number; year: number } | null {
  const m = /^\s*(\d{1,2})\s*\/\s*(\d{2}|\d{4})\s*$/.exec(text);
  if (!m) return null;
  const month = Number(m[1]);
  if (month < 1 || month > 12) return null;
  const year = m[2].length === 2 ? 2000 + Number(m[2]) : Number(m[2]);
  return { month, year };
}

/** Digits in groups of four, the way the number is printed on the card. */
function groupDigits(digits: string): string {
  return digits.replace(/(\d{4})(?=\d)/g, "$1 ");
}

/**
 * Settings ▸ Payment card. Settings renders it only for the owner
 * (`is_admin`); the server enforces the same on every call here. The
 * number and CVC live in component state only until Save, and the state
 * is cleared as soon as the server has answered.
 */
export default function PaymentCardSettings() {
  const headingId = useId();
  const ids = { number: useId(), expiry: useId(), cvc: useId(), name: useId() };

  const [card, setCard] = useState<VaultItemView | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState("");
  // The server's reason there is no vault on this install (the list's
  // `available: false`, or a 409 on save). Replaces the form.
  const [unavailable, setUnavailable] = useState("");
  const [attempt, setAttempt] = useState(0);

  // Entry fields. `number` holds digits only; the input shows them grouped.
  const [number, setNumber] = useState("");
  const [expiry, setExpiry] = useState("");
  const [cvc, setCvc] = useState("");
  const [name, setName] = useState("");
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getVaultItems()
      .then(({ items, available, reason }) => {
        if (cancelled) return;
        setCard(items.find((item) => item.kind === "card") ?? null);
        setLoadError("");
        if (!available) setUnavailable(reason || UNAVAILABLE_FALLBACK);
      })
      .catch((err) => {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 409) {
          setUnavailable(errorText(err, UNAVAILABLE_FALLBACK));
        } else {
          setLoadError(errorText(err, "The stored card could not be checked."));
        }
      })
      .finally(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const clearForm = () => {
    setNumber("");
    setExpiry("");
    setCvc("");
    setName("");
  };

  const handleSave = async () => {
    setFeedback(null);
    // Checked here so an obvious slip is caught before the number leaves
    // the page at all; the server repeats these and adds the Luhn check.
    if (number.length < 12 || number.length > 19) {
      setFeedback({ ok: false, text: "Enter the card number (12 to 19 digits)." });
      return;
    }
    const exp = parseExpiry(expiry);
    if (!exp) {
      setFeedback({ ok: false, text: "Enter the expiry as MM/YY." });
      return;
    }
    const now = new Date();
    if (exp.year < now.getFullYear() || (exp.year === now.getFullYear() && exp.month < now.getMonth() + 1)) {
      setFeedback({ ok: false, text: "That card has expired." });
      return;
    }
    if (!/^\d{3,4}$/.test(cvc)) {
      setFeedback({ ok: false, text: "Enter the 3- or 4-digit security code." });
      return;
    }
    if (!name.trim()) {
      setFeedback({ ok: false, text: "Enter the name on the card." });
      return;
    }

    setSaving(true);
    try {
      const view = await saveVaultCard({
        number,
        exp_month: exp.month,
        exp_year: exp.year,
        cvc,
        name: name.trim(),
      });
      setCard(view);
      clearForm();
      setFeedback({ ok: true, text: `Saved ${view.masked}.` });
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        // No vault here after all; nothing typed can be kept for later.
        clearForm();
        setUnavailable(errorText(err, UNAVAILABLE_FALLBACK));
      } else {
        setFeedback({ ok: false, text: errorText(err, "The card could not be saved.") });
      }
    } finally {
      setSaving(false);
    }
  };

  // Thrown errors surface inside ConfirmDialog's own banner.
  const handleDelete = async () => {
    if (!card) return;
    await deleteVaultItem(card.id);
    setCard(null);
    setConfirmDelete(false);
    setFeedback({ ok: true, text: "Card deleted." });
  };

  const brand = brandOf(number);

  return (
    <section aria-labelledby={headingId} className="rounded-[14px] p-6" style={panelStyle}>
      <div className="eyebrow mb-1">Purchases</div>
      <h2 id={headingId} className="mb-1">
        Payment card
      </h2>
      <p className="text-sm mb-4" style={{ color: "var(--text-secondary)" }}>
        Stored encrypted; the key never leaves this computer&apos;s Keychain /
        Windows account. Crawler fills it only at a checkout you approved.
      </p>

      {unavailable ? (
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          {unavailable}
        </p>
      ) : loadError ? (
        <ErrorAlert>
          {loadError}{" "}
          <button
            type="button"
            className="underline font-medium"
            onClick={() => {
              setLoadError("");
              setLoaded(false);
              setAttempt((n) => n + 1);
            }}
          >
            Try again
          </button>
        </ErrorAlert>
      ) : !loaded ? (
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Checking…
        </p>
      ) : (
        <div className="space-y-4">
          {card && (
            <div
              className="flex items-center justify-between gap-3 flex-wrap rounded-[10px] p-4"
              style={boxStyle}
            >
              <div className="flex items-center gap-3 min-w-0">
                <CreditCard
                  className="w-5 h-5 shrink-0"
                  style={{ color: "var(--accent-primary)" }}
                  aria-hidden
                />
                <div className="min-w-0">
                  <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
                    {card.masked}
                  </p>
                  <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                    {/* A card stored from this form has no label of its own: the
                        server names it by its masked text, so say that once. */}
                    {card.label && card.label !== card.masked ? `${card.label} · ` : ""}
                    {card.last_used_at
                      ? `last used ${new Date(card.last_used_at).toLocaleDateString()}`
                      : "not used yet"}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setConfirmDelete(true)}
                className={secondaryCls}
                style={{
                  ...secondaryStyle,
                  color: "var(--accent-danger)",
                  border: "1px solid var(--border-danger)",
                }}
              >
                <Trash2 className="w-4 h-4" aria-hidden />
                Delete
              </button>
            </div>
          )}

          <form
            autoComplete="off"
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              void handleSave();
            }}
          >
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              {card
                ? "Enter a card below to replace it."
                : "No card is stored. Crawler cannot buy anything until you add one."}
            </p>
            <div>
              <label htmlFor={ids.number} className={labelCls}>
                Card number
              </label>
              <div className="relative">
                <input
                  id={ids.number}
                  type="text"
                  inputMode="numeric"
                  autoComplete="off"
                  spellCheck={false}
                  value={groupDigits(number)}
                  onChange={(e) => setNumber(e.target.value.replace(/\D/g, "").slice(0, 19))}
                  placeholder="1234 5678 9012 3456"
                  className={`${inputCls} pr-24 mono-num`}
                  style={inputStyle}
                />
                {brand && (
                  <span
                    className="absolute right-3 top-1/2 -translate-y-1/2 inline-flex items-center gap-1 text-xs font-semibold"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    <CreditCard className="w-3.5 h-3.5" aria-hidden />
                    {brand}
                  </span>
                )}
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor={ids.expiry} className={labelCls}>
                  Expiry (MM/YY)
                </label>
                <input
                  id={ids.expiry}
                  type="text"
                  inputMode="numeric"
                  autoComplete="off"
                  spellCheck={false}
                  maxLength={7}
                  value={expiry}
                  onChange={(e) => setExpiry(e.target.value)}
                  placeholder="MM/YY"
                  className={`${inputCls} mono-num`}
                  style={inputStyle}
                />
              </div>
              <div>
                <label htmlFor={ids.cvc} className={labelCls}>
                  CVC
                </label>
                <input
                  id={ids.cvc}
                  type="password"
                  inputMode="numeric"
                  autoComplete="off"
                  maxLength={4}
                  value={cvc}
                  onChange={(e) => setCvc(e.target.value.replace(/\D/g, ""))}
                  placeholder="123"
                  className={`${inputCls} mono-num`}
                  style={inputStyle}
                />
              </div>
            </div>
            <div>
              <label htmlFor={ids.name} className={labelCls}>
                Name on card
              </label>
              <input
                id={ids.name}
                type="text"
                autoComplete="off"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className={inputCls}
                style={inputStyle}
              />
            </div>
            <div className="flex items-center gap-3 flex-wrap">
              <button type="submit" disabled={saving} className={primaryCls} style={primaryStyle}>
                {saving ? (
                  <Loader2 className="w-4 h-4 animate-spin" aria-hidden />
                ) : (
                  <CreditCard className="w-4 h-4" aria-hidden />
                )}
                {card ? "Replace card" : "Save card"}
              </button>
              {feedback && <ResultLine ok={feedback.ok}>{feedback.text}</ResultLine>}
            </div>
          </form>
        </div>
      )}

      <ConfirmDialog
        open={confirmDelete}
        danger
        title="Delete the stored card?"
        message="Crawler will not be able to buy anything until you add a card again."
        confirmLabel="Delete card"
        onCancel={() => setConfirmDelete(false)}
        onConfirm={handleDelete}
      />
    </section>
  );
}
