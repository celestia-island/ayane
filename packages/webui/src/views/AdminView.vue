<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { Globe, Save } from "lucide-vue-next";

import {
  HkAdminTablePage,
  HkBadge,
  HkButton,
  HkInput,
  HkSectionCard,
  type BadgeVariant,
} from "@celestia-island/hikari";

import { rpc } from "../lib/rpc";
import { t } from "../lib/i18n";
import { toastError, toastSuccess } from "../lib/toast";

interface DnsCheck {
  check: string;
  status: string;
  detail: string;
}

const adminToken = ref("");
const adminOk = ref(false);
const stateText = ref("");
const dns = ref<DnsCheck[] | null>(null);
const dnsLoading = ref(true);
const dnsError = ref<string | undefined>(undefined);
const busy = ref(false);

onMounted(async () => {
  adminToken.value = localStorage.getItem("ayane.admin") || "";
  if (adminToken.value) await adminLogin();
  else dnsLoading.value = false;
});

async function adminLogin(): Promise<void> {
  try {
    await rpc.call("session.adminLogin", { token: adminToken.value });
    localStorage.setItem("ayane.admin", adminToken.value);
    adminOk.value = true;
    await Promise.all([loadState(), runDns()]);
  } catch (e) {
    toastError(e);
  }
}

async function loadState(): Promise<void> {
  const state = await rpc.call<Record<string, unknown>>("admin.state.get");
  stateText.value = JSON.stringify(state, null, 2);
}

async function saveState(): Promise<void> {
  busy.value = true;
  try {
    const parsed = JSON.parse(stateText.value) as Record<string, unknown>;
    await rpc.call("admin.state.put", parsed);
    toastSuccess(t("admin.saved"));
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

const dnsRows = computed(() => dns.value ?? []);
</script>

<template>
  <div class="admin">
    <HkSectionCard v-if="!adminOk" :title="t('admin.unlockTitle')" class="admin-unlock">
      <form @submit.prevent="adminLogin">
        <p class="muted admin-hint">{{ t("admin.unlockHint") }}</p>
        <HkInput v-model="adminToken" type="password" :placeholder="t('admin.token')" />
        <HkButton type="submit" :disabled="!adminToken || busy">
          <Save :size="14" /> {{ t("admin.unlock") }}
        </HkButton>
      </form>
    </HkSectionCard>

    <template v-else>
      <HkAdminTablePage
        :title="t('admin.dns')"
        :icon="Globe"
        :rows="dnsRows"
        :columns="dnsColumns"
        row-key="check"
        :loading="dnsLoading"
        :error="dnsError"
        :empty-title="t('admin.dns')"
      >
        <template #actions>
          <HkButton variant="ghost" size="sm" :disabled="dnsLoading" @click="runDns">
            {{ t("admin.rerun") }}
          </HkButton>
        </template>
        <template #cell-status="{ row }">
          <HkBadge :variant="badgeOf(String(row.status))">{{ String(row.status) }}</HkBadge>
        </template>
        <template #cell-detail="{ row }">
          <span class="muted">{{ String(row.detail) }}</span>
        </template>
      </HkAdminTablePage>

      <HkSectionCard :title="t('admin.state')" :icon="Save">
        <HkInput v-model="stateText" type="textarea" :rows="18" :spellcheck="false" />
        <div class="admin-actions">
          <HkButton :disabled="busy" @click="saveState">{{ t("admin.save") }}</HkButton>
          <HkButton variant="ghost" :disabled="busy" @click="apply">{{ t("admin.apply") }}</HkButton>
        </div>
      </HkSectionCard>
    </template>
  </div>
</template>

<style scoped>
.admin { max-width: 860px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
.admin-unlock form { display: flex; flex-direction: column; gap: 12px; }
.admin-hint { margin: 0; }
.admin-actions { display: flex; gap: 10px; align-items: center; margin-top: 12px; }
</style>
