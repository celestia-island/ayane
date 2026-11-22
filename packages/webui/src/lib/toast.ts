/**
 * Toast plumbing — EVERY user-visible notification goes through the
 * family stack (HkToast + useToast), never inline DOM. Errors are
 * localized through the error-path channel; the raw server message stays
 * in the console for debugging.
 */

import { useToast } from "@celestia-island/hikari";

import { localizeError } from "./i18n";

const toast = useToast();

/** Localize and toast an RPC/application failure. */
export function toastError(e: unknown): void {
  const raw = e instanceof Error ? e.message : String(e);
  // Keep the full path+prose in the console: the toast carries the
  // localized voice, the console carries the machine channel.
  console.error(raw);
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