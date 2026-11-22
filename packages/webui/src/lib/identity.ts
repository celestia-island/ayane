/**
 * The active mailbox identity — which mailbox (the account's own or a
 * shared mailbox it is a member of) the roster, reader and composer
 * operate on. The header picker writes it; every mail.* call forwards it
 * as the `as` param.
 */
import { computed, ref } from "vue";

import { rpc } from "./rpc";

export interface MailIdentity {
  address: string;
  display_name: string;
  kind: "personal" | "shared";
}

const STORAGE_KEY = "ayane.identity";

const current = ref<string>(localStorage.getItem(STORAGE_KEY) || "");
const identities = ref<MailIdentity[]>([]);
let loading: Promise<void> | null = null;

/** Load the account's identities (own + member shared mailboxes). */
export function loadIdentities(): Promise<void> {
  if (loading) return loading;
  loading = rpc
    .call<{ identities: MailIdentity[] }>("mail.fromAddresses")
    .then((result) => {
      identities.value = result.identities;
      // A stored pick that no longer belongs to the account falls back to
      // the personal identity.
      if (!result.identities.some((identity) => identity.address === current.value)) {
        current.value = result.identities[0]?.address ?? "";
        localStorage.setItem(STORAGE_KEY, current.value);
      }
    })
    .catch(() => undefined)
    .finally(() => {
      loading = null;
    });
  return loading;
}

/** The selected identity's address ("" before the first load resolves). */
export function currentIdentity(): string {
  return current.value;
}

/** Switch the active identity; the roster/reader reload through it. */
export function setCurrentIdentity(address: string): void {
  current.value = address;
  localStorage.setItem(STORAGE_KEY, address);
}

/** The loaded identity list (for pickers). */
export function identityList() {
  return identities.value;
}

/** The selected identity record. */
export const selectedIdentity = computed<MailIdentity | null>(
  () => identities.value.find((identity) => identity.address === current.value) ?? null,
);
