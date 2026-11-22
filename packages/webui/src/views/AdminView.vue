<script setup lang="ts">
import { onMounted, ref } from "vue";
import { Globe, Save, Rocket } from "lucide-vue-next";

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
const busy = ref(false);

onMounted(async () => {
  adminToken.value = localStorage.getItem("ayane.admin") || "";
  if (adminToken.value) await adminLogin();
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
    toastSuccess(allOk ? t("admin.applied") : t("admin.applyPartial"));
  } catch (e) {
    toastError(e);
  } finally {
    busy.value = false;
  }
}

async function runDns(): Promise<void> {
  try {
    const report = await rpc.call<{ checks: DnsCheck[] }>("dns.check");
    dns.value = report.checks;
  } catch (e) {
    toastError(e);
  }
}
</script>

<template>
  <div class="admin">
    <form v-if="!adminOk" class="hk-card" @submit.prevent="adminLogin">
      <h3>{{ t("admin.unlockTitle") }}</h3>
      <p class="muted">{{ t("admin.unlockHint") }}</p>
      <input v-model="adminToken" class="hk-input" type="password" :placeholder="t('admin.token')" />
      <button class="hk-button" :disabled="!adminToken">{{ t("admin.unlock") }}</button>
    </form>

    <template v-else>
      <div class="hk-card">
        <h3><Globe :size="16" style="vertical-align: -3px" /> {{ t("admin.dns") }}</h3>
        <ul class="dns">
          <li v-for="c in dns || []" :key="c.check">
            <span class="pill" :class="c.status">{{ c.status }}</span>
            <b>{{ c.check }}</b>
            <span class="muted">{{ c.detail }}</span>
          </li>
        </ul>
        <button class="hk-button ghost" @click="runDns">{{ t("admin.rerun") }}</button>
      </div>

      <div class="hk-card">
        <h3><Save :size="16" style="vertical-align: -3px" /> {{ t("admin.state") }}</h3>
        <textarea v-model="stateText" class="hk-input mono" rows="18" spellcheck="false" />
        <div class="hk-row">
          <button class="hk-button" :disabled="busy" @click="saveState">{{ t("admin.save") }}</button>
          <button class="hk-button" :disabled="busy" @click="apply">
            <Rocket :size="14" /> {{ t("admin.apply") }}
          </button>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped lang="scss">
.admin { max-width: 860px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
form { display: flex; flex-direction: column; gap: 10px; }
.dns { list-style: none; margin: 0 0 10px; padding: 0; display: flex; flex-direction: column; gap: 6px;
  li { display: flex; gap: 8px; align-items: baseline; }
}
.pill { font-size: 11px; padding: 2px 8px; border-radius: 999px; min-width: 44px; text-align: center;
  &.pass { background: #1d4028; color: #7ddba0; }
  &.warn { background: #4a3a12; color: #e2b93b; }
  &.fail { background: #4a1d1d; color: #e08181; }
}
.mono { font-family: ui-monospace, monospace; font-size: 12px; }
.ghost { background: transparent; color: #aab3c5; border: 1px solid #2a3345; }
h3 { margin: 0 0 8px; }
</style>