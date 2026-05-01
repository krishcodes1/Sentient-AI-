/**
 * Hook + singleton toast API.
 *
 * Inside React components: `const { toast, dismiss } = useToast()`.
 * Outside React (e.g. services/api.ts): `import { toast } from "@/hooks/useToast"`
 * and call `toast.error({ title: "..." })`.
 */
import { toast, useToastContext } from "@/components/ui/Toaster";
import type { ToastInput, ToastVariant } from "@/components/ui/Toaster";

export function useToast() {
  return useToastContext();
}

export { toast };
export type { ToastInput, ToastVariant };
