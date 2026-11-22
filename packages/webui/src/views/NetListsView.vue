<script setup lang="ts">
import { onMounted, ref } from "vue";
import { ShieldAlert, ShieldCheck } from "lucide-vue-next";

import { HkButton, HkSectionCard, HkTagInput } from "@celestia-island/hikari";

import { rpc } from "../lib/rpc";
import { t } from "../lib/i18n";
import { toastError, toastSuccess } from "../lib/toast";

const allowlist = ref<string[]>([]);
const denylist = ref<string[]>([]);
const loading = ref(true);
const busy = ref(false);

onMounted(async () => {
  try {
    const result = await rpc.call<{ allowlist: string[]; denylist: string[] }>(
      "admin.policy.get",
    );
    allowlist.value = result.allowlist;
    denylist.value = result.denylist;
  } catch (e) {
    toastError(e);
  } finally {
    loading.value = false;
  }
});

async function save(): Promise<void> {
  busy.value = true;
  try {
    await rpc.call("admin.policy.put", {
      allowlist: allowlist.value,
      denylist: denylist.value,
    });
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
    await rpc.call("admin.policy.put", {
      allowlist: allowlist.value,
      denylist: denylist.value,
    });
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
</script>

<template>
  <div class="ay-net">
    <p class="muted ay-lists-hint">{{ t("net.lists.hint") }}</p>
    <HkSectionCard :title="t('net.lists.deny')" :icon="ShieldAlert" :loading="loading" padded>
      <p class="muted ay-lists-note">{{ t("net.lists.denyNote") }}</p>
      <HkTagInput v-model="denylist" :placeholder="t('net.lists.placeholder')" />
    </HkSectionCard>
    <HkSectionCard :title="t('net.lists.allow')" :icon="ShieldCheck" :loading="loading" padded>
      <p class="muted ay-lists-note">{{ t("net.lists.allowNote") }}</p>
      <HkTagInput v-model="allowlist" :placeholder="t('net.lists.placeholder')" />
    </HkSectionCard>
    <div class="ay-lists-actions">
      <HkButton :disabled="busy || loading" @click="save">{{ t("admin.save") }}</HkButton>
      <HkButton variant="ghost" :disabled="busy || loading" @click="apply">
        {{ t("admin.apply") }}
      </HkButton>
    </div>
  </div>
</template>

<style scoped>
.ay-net { max-width: 860px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
.ay-lists-hint { margin: 0; }
.ay-lists-note { margin: 0 0 10px; font-size: 0.85rem; }
.ay-lists-actions { display: flex; gap: 10px; align-items: center; }
</style>
