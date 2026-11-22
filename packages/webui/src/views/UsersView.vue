<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { Globe, Save, Users } from "lucide-vue-next";

import {
  HkAdminTablePage,
  HkBadge,
  HkButton,
  HkInput,
  HkSectionCard,
  HkSwitch,
  type BadgeVariant,
  type HkTableSection,
} from "@celestia-island/hikari";

import { rpc } from "../lib/rpc";
import { t } from "../lib/i18n";
import { toastError, toastSuccess } from "../lib/toast";

interface DnsCheck {
  check: string;
  status: string;
  detail: string;
}

interface AccountRow {
  id: string;
  address: string;
  display_name: string;
  quota_bytes: number;
  admin: boolean;
}

interface DomainRow {
  name: string;
  catch_all: string | null;
  enabled: boolean;
}

const adminOk = ref<boolean | null>(null);
const accounts = ref<AccountRow[]>([]);
const domains = ref<DomainRow[]>([]);
const loading = ref(true);
const busy = ref(false);
const stateText = ref("");
const showAdvanced = ref(false);
const dns = ref<DnsCheck[] | null>(null);
const dnsLoading = ref(false);
const dnsError = ref<string | undefined>(undefined);

onMounted(async () => {
  try {
    const who = await rpc.call<{ admin: boolean }>("session.whoami");
    adminOk.value = who.admin;
    if (who.admin) await loadAll();
  } catch (e) {
    adminOk.value = false;
    toastError(e);
  } finally {
    loading.value = false;
  }
});

async function loadAll(): Promise<void> {
  try {
    // The admin read carries the whole desired state; the page slices it
    // into the two rosters it manages.
    const state = await rpc.call<{
      accounts: AccountRow[];
      domains: DomainRow[];
    }>("admin.state.get");
    accounts.value = state.accounts ?? [];
    domains.value = state.domains ?? [];
    stateText.value = JSON.stringify(state, null, 2);
  } catch (e) {
    toastError(e);
  }
}

/** Toggle an account's administrator grant. A role change is not a
 *  credential change, so it rides its own RPC (the whole-state PUT would
 *  demand every password); the grant is read live, so it applies to
 *  sessions already open. */
async function setAdmin(row: AccountRow, next: boolean): Promise<void> {
  busy.value = true;
  try {
    await rpc.call("admin.accounts.setAdmin", { address: row.address, admin: next });
    row.admin = next;
    toastSuccess(t("users.adminSaved"));
  } catch (e) {
    toastError(e);
  } finally {
    busy.value = false;
  }
}

async function saveState(): Promise<void> {
  busy.value = true;
  try {
    const parsed = JSON.parse(stateText.value) as Record<string, unknown>;
    await rpc.call("admin.state.put", parsed);
    toastSuccess(t("admin.saved"));
    await loadAll();
  } catch (e) {
    toastError(e);
  } finally {
    busy.value = false;
  }
}

async function apply(): Promise<void> {
  busy.value = true;
  try {
    const report = await rpc.call<{ reloaded: { service: string; ok: boolean }[] }>("admin.apply");
    const allOk = report.reloaded.every((r) => r.ok);
    if (allOk) toastSuccess(t("admin.applied"));
    else toastSuccess(t("admin.applyPartial"));
  } catch (e) {
    toastError(e);
  } finally {
    busy.value = false;
  }
}

async function runDns(): Promise<void> {
  dnsLoading.value = true;
  dnsError.value = undefined;
  try {
    const report = await rpc.call<{ checks: DnsCheck[] }>("dns.check");
    dns.value = report.checks;
  } catch (e) {
    toastError(e);
    dnsError.value = t("err.adminFailed");
  } finally {
    dnsLoading.value = false;
  }
}

const accountColumns = computed(() => [
  { key: "address", title: t("users.col.address") },
  { key: "display_name", title: t("users.col.name") },
  { key: "quota_bytes", title: t("users.col.quota"), width: "120px", align: "right" as const, copyable: false },
  { key: "admin", title: t("users.col.role"), width: "120px", copyable: false },
]);

const domainColumns = computed(() => [
  { key: "name", title: t("users.col.domain") },
  { key: "catch_all", title: t("users.col.catchAll") },
  { key: "enabled", title: t("users.col.enabled"), width: "100px", copyable: false },
]);

const domainSections = computed<HkTableSection[]>(() => [
  { key: "domains", rows: domains.value },
]);

const dnsColumns = computed(() => [
  { key: "check", title: t("admin.col.check") },
  { key: "status", title: t("admin.col.status"), width: "120px", copyable: false },
  { key: "detail", title: t("admin.col.detail") },
]);

function badgeOf(status: string): BadgeVariant {
  if (status === "pass") return "success";
  if (status === "warn") return "warning";
  return "error";
}

function quotaLabel(bytes: number): string {
  if (!bytes) return t("users.unlimited");
  return `${Math.round(bytes / (1024 * 1024))} MiB`;
}
</script>

<template>
  <div class="users">
    <HkSectionCard v-if="adminOk === false" :title="t('admin.lockedTitle')" padded>
      <p class="muted">{{ t("admin.lockedHint") }}</p>
    </HkSectionCard>

    <template v-else-if="adminOk">
      <HkAdminTablePage
        :title="t('users.accounts')"
        :icon="Users"
        :rows="accounts"
        :columns="accountColumns"
        row-key="address"
        :loading="loading"
        :empty-title="t('users.noAccounts')"
      >
        <template #cell-admin="{ row }">
          <span class="users-role">
            <HkSwitch
              :model-value="row.admin"
              :disabled="busy"
              @update:model-value="(v: boolean) => setAdmin(row, v)"
            />
            <span class="users-role-label">{{ row.admin ? t("users.roleAdmin") : t("users.roleUser") }}</span>
          </span>
        </template>
        <template #cell-quota_bytes="{ row }">
          {{ quotaLabel(Number(row.quota_bytes)) }}
        </template>
        <template #cell-display_name="{ row }">
          {{ row.display_name || "—" }}
        </template>
      </HkAdminTablePage>

      <HkAdminTablePage
        :title="t('users.domains')"
        :icon="Globe"
        :rows="domains"
        :columns="domainColumns"
        :sections="domainSections"
        row-key="name"
        :loading="loading"
        :empty-title="t('users.noDomains')"
      >
        <template #cell-catch_all="{ row }">
          <span class="muted">{{ row.catch_all || "—" }}</span>
        </template>
        <template #cell-enabled="{ row }">
          <HkBadge :variant="row.enabled ? 'success' : 'muted'">
            {{ row.enabled ? t("users.enabled") : t("users.disabled") }}
          </HkBadge>
        </template>
      </HkAdminTablePage>

      <HkSectionCard :title="t('admin.dns')" :icon="Globe" padded>
        <div class="users-dns">
          <HkButton variant="ghost" size="sm" :loading="dnsLoading" @click="runDns">
            {{ t("admin.rerun") }}
          </HkButton>
          <ul v-if="dns" class="users-dns-list">
            <li v-for="check in dns" :key="check.check">
              <HkBadge :variant="badgeOf(check.status)">{{ check.status }}</HkBadge>
              <b>{{ check.check }}</b>
              <span class="muted">{{ check.detail }}</span>
            </li>
          </ul>
          <p v-else-if="dnsError" class="muted">{{ dnsError }}</p>
        </div>
      </HkSectionCard>

      <HkSectionCard :title="t('users.advanced')" :icon="Save" padded>
        <div class="users-advanced-head">
          <p class="muted users-advanced-hint">{{ t("users.advancedHint") }}</p>
          <HkSwitch
            :model-value="showAdvanced"
            @update:model-value="(v: boolean) => { showAdvanced = v; if (v) void loadAll(); }"
          />
        </div>
        <template v-if="showAdvanced">
          <HkInput v-model="stateText" type="textarea" :rows="18" :spellcheck="false" />
          <div class="users-actions">
            <HkButton :disabled="busy" @click="saveState">{{ t("admin.save") }}</HkButton>
            <HkButton variant="ghost" :disabled="busy" @click="apply">{{ t("admin.apply") }}</HkButton>
          </div>
        </template>
      </HkSectionCard>
    </template>
  </div>
</template>

<style scoped>
.users { width: 100%; display: flex; flex-direction: column; gap: 16px; }
.users-dns { display: flex; flex-direction: column; gap: 10px; align-items: flex-start; }
.users-dns-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; font-size: 0.875rem; }
.users-dns-list li { display: flex; gap: 8px; align-items: baseline; }
.users-advanced-head { display: flex; align-items: center; gap: 12px; }
.users-advanced-hint { margin: 0; flex: 1; font-size: 0.85rem; }
.users-actions { display: flex; gap: 10px; margin-top: 12px; }
.users-role { display: inline-flex; align-items: center; gap: 8px; }
.users-role-label { font-size: 0.8rem; opacity: 0.85; }
</style>