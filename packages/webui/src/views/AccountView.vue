<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { Link2, Link2Off } from "lucide-vue-next";

import {
  HkButton,
  HkConfirmDialog,
  HkSectionCard,
  HkTag,
  type HkLoginDiscovery,
} from "@celestia-island/hikari";

import { oauthErrorKey, t } from "../lib/i18n";
import { rpc } from "../lib/rpc";
import { toastError, toastSuccess, toastWarning } from "../lib/toast";

/**
 * Linked sign-ins of the signed-in mailbox. A provider proves an identity;
 * linking it to THIS mailbox is the one place that happens, and only from
 * an authenticated session — an unlinked provider account can never sign
 * in, and no mailbox is ever requested here. Unlinking is always allowed:
 * an own-domain account keeps its password whatever is linked.
 */
interface LinkedIdentity {
  provider: string;
  subject: string;
  created_at: string | null;
  last_login_at: string | null;
}

const route = useRoute();
const router = useRouter();

const identities = ref<LinkedIdentity[]>([]);
/** Every provider this deployment offers (from the login policy). */
const providers = ref<string[]>([]);
const loading = ref(true);
/** The provider whose link/unlink is in flight. */
const busy = ref<string | null>(null);
/** The row the unlink confirm is armed on (the dialog owns the rest). */
const unlinkTarget = ref<LinkedIdentity | null>(null);

/** The server localises nothing: a provider is named by its id, here. */
function providerLabel(id: string): string {
  const key = `login.provider.${id}`;
  const label = t(key);
  return label === key ? id : label;
}

const unlinkedProviders = computed(() =>
  providers.value.filter(
    (provider) => !identities.value.some((identity) => identity.provider === provider),
  ),
);

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleDateString();
}

async function load(): Promise<void> {
  loading.value = true;
  try {
    const [linked, policy] = await Promise.all([
      rpc.call<{ identities: LinkedIdentity[] }>("session.identities"),
      rpc.call<HkLoginDiscovery>("session.loginPolicy"),
    ]);
    identities.value = linked.identities;
    providers.value = (policy.methods ?? [])
      .filter((method) => method.kind === "oauth")
      .map((method) => method.id);
  } catch (e) {
    toastError(e);
  } finally {
    loading.value = false;
  }
}

/** Leave for the provider: the server issues a one-time ticket and the
 *  browser carries this session's mailbox through the round trip. */
async function link(provider: string): Promise<void> {
  if (busy.value !== null) return;
  busy.value = provider;
  try {
    const result = await rpc.call<{ href: string }>("session.linkIdentity", { provider });
    const href = result.href;
    if (href.startsWith("/") && !href.startsWith("//")) {
      window.location.assign(href);
      return;
    }
    toastError(new Error("Session.OAuthFailed: the sign-in target is not a same-origin path"));
  } catch (e) {
    toastError(e);
  } finally {
    busy.value = null;
  }
}

async function confirmUnlink(): Promise<void> {
  const row = unlinkTarget.value;
  if (!row) return;
  busy.value = row.provider;
  try {
    await rpc.call("session.unlinkIdentity", { provider: row.provider });
    toastSuccess(t("account.linked.unlinked", { provider: providerLabel(row.provider) }));
    unlinkTarget.value = null;
    await load();
  } catch (e) {
    toastError(e);
  } finally {
    busy.value = null;
  }
}

onMounted(async () => {
  // The provider's redirect lands back here with the outcome in the query:
  // a linked provider, or a closed failure reason. Read, toast, strip.
  const linked = typeof route.query.linked === "string" ? route.query.linked : "";
  const failed = typeof route.query.oauth_error === "string" ? route.query.oauth_error : "";
  if (linked || failed) {
    void router.replace("/account");
    if (linked) toastSuccess(t("account.linked.linked", { provider: providerLabel(linked) }));
    if (failed) toastWarning(t(oauthErrorKey(failed)));
  }
  await load();
});
</script>

<template>
  <div class="ay-account-page">
    <HkSectionCard :title="t('account.linked.title')" :icon="Link2" :loading="loading" padded>
      <p class="muted ay-linked-hint">{{ t("account.linked.hint") }}</p>
      <ul v-if="identities.length || unlinkedProviders.length" class="ay-linked-list">
        <li v-for="identity in identities" :key="identity.provider" class="ay-linked-row">
          <div class="ay-linked-name">
            <HkTag variant="primary">{{ providerLabel(identity.provider) }}</HkTag>
            <span class="muted ay-linked-meta">
              {{ t("account.linked.since", { date: formatDate(identity.created_at) }) }}
            </span>
          </div>
          <HkButton
            variant="ghost"
            size="sm"
            :disabled="busy !== null"
            @click="unlinkTarget = identity"
          >
            <Link2Off :size="14" /> {{ t("account.linked.unlink") }}
          </HkButton>
        </li>
        <li v-for="provider in unlinkedProviders" :key="provider" class="ay-linked-row">
          <div class="ay-linked-name">
            <HkTag>{{ providerLabel(provider) }}</HkTag>
          </div>
          <HkButton size="sm" :disabled="busy !== null" @click="link(provider)">
            <Link2 :size="14" /> {{ t("account.linked.link", { provider: providerLabel(provider) }) }}
          </HkButton>
        </li>
      </ul>
      <p v-else-if="!loading" class="muted">{{ t("account.linked.none") }}</p>
    </HkSectionCard>
    <!-- Unlinking removes a way in (never the password): a destructive
         action is confirmed, the family principle. -->
    <HkConfirmDialog
      :open="unlinkTarget !== null"
      :title="t('account.linked.unlinkTitle', { provider: unlinkTarget ? providerLabel(unlinkTarget.provider) : '' })"
      :message="t('account.linked.unlinkMessage', { provider: unlinkTarget ? providerLabel(unlinkTarget.provider) : '' })"
      :confirm-label="t('account.linked.unlink')"
      :loading="busy !== null && busy === unlinkTarget?.provider"
      @confirm="confirmUnlink"
      @cancel="unlinkTarget = null"
      @update:open="(v: boolean) => { if (!v) unlinkTarget = null; }"
    />
  </div>
</template>

<style scoped>
.ay-account-page { max-width: 860px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
.ay-linked-hint { margin: 0 0 12px; }
.ay-linked-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
.ay-linked-row {
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  padding: 10px 12px; border-radius: 8px;
  background: rgb(var(--color-surface));
  border: 1px solid rgb(var(--color-border) / 60%);
}
.ay-linked-name { display: flex; align-items: center; gap: 10px; min-width: 0; }
.ay-linked-meta { font-size: 0.8rem; }
</style>
