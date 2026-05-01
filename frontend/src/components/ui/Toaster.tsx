import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";

export type ToastVariant = "default" | "success" | "error" | "warning" | "info";

export interface ToastInput {
  title?: string;
  description?: string;
  variant?: ToastVariant;
  duration?: number;
}

interface ToastItem extends Required<Omit<ToastInput, "title" | "description">> {
  id: string;
  title?: string;
  description?: string;
  // Internal state for fade-out animation.
  closing: boolean;
}

interface ToastContextValue {
  toast: (input: ToastInput) => string;
  dismiss: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

// ── Module-level event bus so non-component callers (api.ts) can fire toasts ──
type Subscriber = (input: ToastInput) => void;
const subscribers = new Set<Subscriber>();

function emit(input: ToastInput) {
  subscribers.forEach((fn) => {
    try {
      fn(input);
    } catch {
      /* swallow — one bad subscriber shouldn't break others */
    }
  });
}

export const toast = {
  default: (input: Omit<ToastInput, "variant">) => emit({ ...input, variant: "default" }),
  success: (input: Omit<ToastInput, "variant">) => emit({ ...input, variant: "success" }),
  error: (input: Omit<ToastInput, "variant">) => emit({ ...input, variant: "error" }),
  warning: (input: Omit<ToastInput, "variant">) => emit({ ...input, variant: "warning" }),
  info: (input: Omit<ToastInput, "variant">) => emit({ ...input, variant: "info" }),
};

const VARIANT_STYLES: Record<ToastVariant, { border: string; accent: string; label: string }> = {
  default: {
    border: "border-zinc-700",
    accent: "bg-zinc-500",
    label: "Notification",
  },
  success: {
    border: "border-emerald-500/60",
    accent: "bg-emerald-400",
    label: "Success",
  },
  error: {
    border: "border-rose-500/70",
    accent: "bg-rose-400",
    label: "Error",
  },
  warning: {
    border: "border-amber-500/60",
    accent: "bg-amber-400",
    label: "Warning",
  },
  info: {
    border: "border-cyan-500/60",
    accent: "bg-cyan-400",
    label: "Info",
  },
};

let toastIdCounter = 0;
function nextId() {
  toastIdCounter += 1;
  return `t-${Date.now()}-${toastIdCounter}`;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.map((t) => (t.id === id ? { ...t, closing: true } : t)));
    // Remove after the CSS transition finishes (~200ms).
    const removeAfter = setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 220);
    const existing = timers.current.get(id);
    if (existing) clearTimeout(existing);
    timers.current.set(`${id}-remove`, removeAfter);
  }, []);

  const pushToast = useCallback(
    (input: ToastInput) => {
      const id = nextId();
      const duration = input.duration ?? 4000;
      const item: ToastItem = {
        id,
        title: input.title,
        description: input.description,
        variant: input.variant ?? "default",
        duration,
        closing: false,
      };
      setToasts((prev) => [...prev, item]);
      if (duration > 0) {
        const handle = setTimeout(() => dismiss(id), duration);
        timers.current.set(id, handle);
      }
      return id;
    },
    [dismiss]
  );

  // Bridge module-level emitter into provider state.
  useEffect(() => {
    const sub: Subscriber = (input) => pushToast(input);
    subscribers.add(sub);
    return () => {
      subscribers.delete(sub);
    };
  }, [pushToast]);

  // Cleanup any pending timers on unmount.
  useEffect(() => {
    const t = timers.current;
    return () => {
      t.forEach((handle) => clearTimeout(handle));
      t.clear();
    };
  }, []);

  const value = useMemo<ToastContextValue>(
    () => ({ toast: pushToast, dismiss }),
    [pushToast, dismiss]
  );

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ToastViewport toasts={toasts} dismiss={dismiss} />
    </ToastContext.Provider>
  );
}

function ToastViewport({
  toasts,
  dismiss,
}: {
  toasts: ToastItem[];
  dismiss: (id: string) => void;
}) {
  return (
    <div
      aria-live="polite"
      aria-atomic="false"
      className="pointer-events-none fixed z-[1000] flex flex-col gap-2 px-3 left-0 right-0 bottom-0 pb-[env(safe-area-inset-bottom)] sm:left-auto sm:right-4 sm:top-4 sm:bottom-auto sm:w-[360px] sm:px-0 sm:pb-0"
    >
      {toasts.map((t) => {
        const styles = VARIANT_STYLES[t.variant];
        return (
          <div
            key={t.id}
            role="status"
            className={[
              "pointer-events-auto relative w-full rounded-lg border bg-black/95 backdrop-blur",
              "text-zinc-100 shadow-[0_8px_24px_rgba(0,0,0,0.6)]",
              "transform transition-all duration-200 ease-out",
              styles.border,
              t.closing ? "opacity-0 translate-y-2 sm:translate-y-0 sm:translate-x-2" : "opacity-100",
            ].join(" ")}
          >
            <span className={["absolute left-0 top-0 h-full w-[3px] rounded-l-lg", styles.accent].join(" ")} aria-hidden />
            <div className="flex items-start gap-3 p-3 pl-4">
              <div className="min-w-0 flex-1">
                <span className="sr-only">{styles.label}: </span>
                {t.title && (
                  <p className="text-[13px] font-semibold leading-tight tracking-tight">{t.title}</p>
                )}
                {t.description && (
                  <p className={["text-[12px] leading-snug text-zinc-300", t.title ? "mt-1" : ""].join(" ")}>
                    {t.description}
                  </p>
                )}
              </div>
              <button
                type="button"
                aria-label="Dismiss notification"
                onClick={() => dismiss(t.id)}
                className="shrink-0 rounded-md p-1 text-zinc-500 transition-colors hover:bg-white/5 hover:text-zinc-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M18 6 6 18" />
                  <path d="m6 6 12 12" />
                </svg>
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/**
 * Hook returning `{ toast, dismiss }`. Must be called inside a `<ToastProvider>`.
 * For non-component callers (e.g. services/api.ts), import the singleton `toast` instead.
 */
export function useToastContext(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error("useToast must be used within <ToastProvider>");
  }
  return ctx;
}

export default ToastProvider;
