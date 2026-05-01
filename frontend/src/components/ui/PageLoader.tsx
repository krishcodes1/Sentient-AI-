/** Suspense fallback for lazy-loaded routes. Centered spinner. */
export default function PageLoader() {
  return (
    <div className="flex items-center justify-center min-h-[60vh]" role="status" aria-label="Loading">
      <div className="w-6 h-6 rounded-full border-2 border-[var(--text-muted)] border-t-transparent animate-spin" />
      <span className="sr-only">Loading…</span>
    </div>
  );
}
