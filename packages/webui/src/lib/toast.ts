/**
 * Toast plumbing — EVERY user-visible notification goes through the
 * family stack (HkToast + useToast), never inline DOM. Errors are
 * localized through the error-path channel; the raw server message stays
 * in the console for debugging.
 */

import { useToast } from "@celestia-island/hikari";

import { localizeError } from "./i18n";

const toast = useToast();

/** Localize and toast an RPC/application failure. Session expiry stays
 *  SILENT: the global Session.Required hook is already redirecting to the
 *  login page — a dead toast over the redirect is noise the user flagged. */
export function toastError(e: unknown): void {
  const raw = e instanceof Error ? e.message : String(e);
  console.error(raw);
  if (raw.startsWith("Session.Required:")) return;
  toast.error(localizeError(raw));
}

/** Success notice. */
export function toastSuccess(message: string): void {
  toast.success(message);
}

/** Warning notice. */
export function toastWarning(message: string): void {
  toast.warning(message);
}

/** Info notice. */
export function toastInfo(message: string): void {
  toast.info(message);
}