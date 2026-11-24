<script setup lang="ts">
import { onMounted, ref } from "vue";
import { KeyRound, Plug } from "lucide-vue-next";

import { HkButton, HkCheckbox, HkSectionCard } from "@celestia-island/hikari";

import { rpc } from "../lib/rpc";
import { t } from "../lib/i18n";
import { toastError, toastSuccess } from "../lib/toast";

interface McpGet {
  tools: string[];
  hasToken: boolean;
}

/** MCP 工具目录 + 专用 token（旋转后单次展示）。 */
const CATALOG = [
  { name: "state.get", desc: "Read the desired mail state" },
  { name: "state.put", desc: "Replace the desired state" },
  { name: "apply", desc: "Render and reload the engine" },
  { name: "dns.check", desc: "Run the DNS wizard" },
] as const;

const enabled = ref<string[]>([]);
const hasToken = ref(false);
const busy = ref(false);
const loading = ref(true);
const minted = ref<string | null>(null);

async function load(): Promise<void> {
  try {
    const result = await rpc.call<McpGet>("admin.mcp.get");
    enabled.value = result.tools;
    hasToken.value = result.hasToken;
  } catch (e) {
    toastError(e);
  } finally {
    loading.value = false;
  }
}
onMounted(load);

function toggle(name: string, on: boolean): void {
  enabled.value = on
    ? [...enabled.value, name]
    : enabled.value.filter((n) => n !== name);
}

async function save(): Promise<void> {
  busy.value = true;
  try {
    await rpc.call("admin.mcp.put", { tools: enabled.value });
    toastSuccess(t("admin.saved"));
    await load();
  } catch (e) {
    toastError(e);
  } finally {
    busy.value = false;
  }
}

async function rotate(): Promise<void> {
  busy.value = true;
  try {
    const result = await rpc.call<{ token: string | null }>("admin.mcp.put", {
      tools: enabled.value,
      rotateToken: true,
    });
    minted.value = result.token;
    await load();
  } catch (e) {
    toastError(e);
  } finally {
    busy.value = false;
  }
}

function copyToken(): void {
  if (!minted.value) return;
  void navigator.clipboard.writeText(minted.value);
  toastSuccess(t("net.mcp.copied"));
}
</script>

<template>
  <div class="ay-net">
    <HkSectionCard :title="t('net.mcp.tools')" :icon="Plug" :loading="loading" padded>
      <p class="muted ay-mcp-note">{{ t("net.mcp.note") }}</p>
      <div class="ay-mcp-tools">
        <label v-for="tool in CATALOG" :key="tool.name" class="ay-mcp-tool">
          <HkCheckbox
            :model-value="enabled.includes(tool.name)"
            @update:model-value="(v: boolean) => toggle(tool.name, v)"
          >
            {{ tool.name }}
          </HkCheckbox>
          <span class="muted ay-mcp-desc">{{ tool.desc }}</span>
        </label>
      </div>
      <div class="ay-mcp-actions">
        <HkButton :disabled="busy" @click="save">{{ t("admin.save") }}</HkButton>
        <HkButton variant="ghost" :disabled="busy" @click="rotate">
          <KeyRound :size="14" /> {{ hasToken ? t("net.mcp.rotate") : t("net.mcp.mint") }}
        </HkButton>
      </div>
    </HkSectionCard>
    <HkSectionCard v-if="minted" :title="t('net.mcp.tokenTitle')" padded>
      <p class="muted">{{ t("net.mcp.tokenOnce") }}</p>
      <div class="ay-mcp-token-row">
        <code class="ay-mcp-token">{{ minted }}</code>
        <HkButton size="sm" variant="ghost" @click="copyToken">{{ t("net.mcp.copy") }}</HkButton>
      </div>
    </HkSectionCard>
  </div>
</template>

<style scoped>
.ay-net { max-width: 860px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
.ay-mcp-note { margin: 0 0 12px; }
.ay-mcp-tools { display: flex; flex-direction: column; gap: 10px; }
.ay-mcp-tool { display: flex; align-items: center; gap: 12px; }
.ay-mcp-desc { font-size: 0.8rem; }
.ay-mcp-actions { display: flex; gap: 10px; margin-top: 16px; }
.ay-mcp-token-row { display: flex; gap: 10px; align-items: center; }
.ay-mcp-token {
  font-family: var(--font-mono, ui-monospace, monospace);
  font-size: 0.8rem;
  word-break: break-all;
  padding: 8px 10px;
  border-radius: 8px;
  background: rgb(var(--color-surface));
  border: 1px solid rgb(var(--color-border) / 60%);
}
</style>
