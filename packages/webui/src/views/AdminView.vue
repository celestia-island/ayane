<script setup lang="ts">
import { onMounted, ref } from "vue";
import { Globe, Save, Rocket } from "lucide-vue-next";

import { rpc } from "../lib/rpc";

interface DnsCheck {
  check: string;
  status: string;
  detail: string;
}

const adminToken = ref("");
const adminOk = ref(false);
const stateText = ref("");
const saved = ref("");
const dns = ref<DnsCheck[] | null>(null);
const busy = ref(false);
const error = ref("");

onMounted(async () => {
  adminToken.value = localStorage.getItem("ayane.admin") || "";
  if (adminToken.value) await adminLogin();
});

async function adminLogin(): Promise<void> {
  error.value = "";
  try {
    await rpc.call("session.adminLogin", { token: adminToken.value });
    localStorage.setItem("ayane.admin", adminToken.value);
    adminOk.value = true;
    await Promise.all([loadState(), runDns()]);
  } catch (e) {
    error.value = String(e instanceof Error ? e.message : e);
  }
}

async function loadState(): Promise<void> {
  const state = await rpc.call<Record<string, unknown>>("admin.state.get");
  stateText.value = JSON.stringify(state, null, 2);
}

async function saveState(): Promise<void> {
  busy.value = true;
  saved.value = "";
  error.value = "";
  try {
    const parsed = JSON.parse(stateText.value) as Record<string, unknown>;
    await rpc.call("admin.state.put", parsed);
    saved.value = "已保存（配置未下发）";
  } catch (e) {
    error.value = String(e instanceof Error ? e.message : e);
  } finally {
    busy.value = false;
  }
}

async function apply(): Promise<void> {
  busy.value = true;
  saved.value = "";
  error.value = "";
  try {
    const report = await rpc.call<{ reloaded: { service: string; ok: boolean }[] }>("admin.apply");
    const allOk = report.reloaded.every((r) => r.ok);
    saved.value = allOk ? "已下发并重载 ✓" : "下发完成，但部分守护进程重载失败（见服务端日志）";
  } catch (e) {
    error.value = String(e instanceof Error ? e.message : e);
  } finally {
    busy.value = false;
  }
}

async function runDns(): Promise<void> {
  try {
    const report = await rpc.call<{ checks: DnsCheck[] }>("dns.check");
    dns.value = report.checks;
  } catch (e) {
    error.value = String(e instanceof Error ? e.message : e);
  }
}
</script>

<template>
  <div class="admin">
    <form v-if="!adminOk" class="hk-card" @submit.prevent="adminLogin">
      <h3>管理登录</h3>
      <p class="muted">输入管理 token 解锁配置与 DNS 面板。</p>
      <input v-model="adminToken" class="hk-input" type="password" placeholder="admin token" />
      <p v-if="error" class="danger">{{ error }}</p>
      <button class="hk-button" :disabled="!adminToken">解锁</button>
    </form>

    <template v-else>
      <div class="hk-card">
        <h3><Globe :size="16" style="vertical-align: -3px" /> DNS 体检</h3>
        <ul class="dns">
          <li v-for="c in dns || []" :key="c.check">
            <span class="pill" :class="c.status">{{ c.status }}</span>
            <b>{{ c.check }}</b>
            <span class="muted">{{ c.detail }}</span>
          </li>
        </ul>
        <button class="hk-button ghost" @click="runDns">重新检查</button>
      </div>

      <div class="hk-card">
        <h3><Save :size="16" style="vertical-align: -3px" /> 邮件域配置（JSON）</h3>
        <textarea v-model="stateText" class="hk-input mono" rows="18" spellcheck="false" />
        <p v-if="error" class="danger">{{ error }}</p>
        <p v-if="saved" class="warn">{{ saved }}</p>
        <div class="hk-row">
          <button class="hk-button" :disabled="busy" @click="saveState">保存配置</button>
          <button class="hk-button" :disabled="busy" @click="apply">
            <Rocket :size="14" /> 下发并重载
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