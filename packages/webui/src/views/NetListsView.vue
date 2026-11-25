<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { AtSign, ShieldAlert, ShieldCheck } from "lucide-vue-next";

import {
  HkButton,
  HkCheckbox,
  HkSectionCard,
  HkTagInput,
} from "@celestia-island/hikari";

import { rpc } from "../lib/rpc";
import { t } from "../lib/i18n";
import { toastError, toastSuccess } from "../lib/toast";

/** The four independent switches the backend stores under `policy.variants`. */
interface AddressVariants {
  inbound_dots: boolean;
  inbound_plus: boolean;
  outbound_dots: boolean;
  outbound_plus: boolean;
}

const allowlist = ref<string[]>([]);
const denylist = ref<string[]>([]);
// Every switch starts off: an old policy that never carried variants renders
// exactly as it did before, and a read that comes back without them keeps it
// that way.
const variants = reactive<AddressVariants>({
  inbound_dots: false,
  inbound_plus: false,
  outbound_dots: false,
  outbound_plus: false,
});
const loading = ref(true);
const busy = ref(false);

/** The four rows, in the reading order the page shows them. */
const switches: {
  key: keyof AddressVariants;
  label: string;
  note: string;
}[] = [
  { key: "inbound_dots", label: "net.lists.inboundDots", note: "net.lists.inboundDotsNote" },
  { key: "inbound_plus", label: "net.lists.inboundPlus", note: "net.lists.inboundPlusNote" },
  { key: "outbound_dots", label: "net.lists.outboundDots", note: "net.lists.outboundDotsNote" },
  { key: "outbound_plus", label: "net.lists.outboundPlus", note: "net.lists.outboundPlusNote" },
];

onMounted(async () => {
  try {
    const result = await rpc.call<{
      allowlist: string[];
      denylist: string[];
      variants?: Partial<AddressVariants>;
    }>("admin.policy.get");
    allowlist.value = result.allowlist;
    denylist.value = result.denylist;
    for (const key of Object.keys(variants) as (keyof AddressVariants)[]) {
      variants[key] = result.variants?.[key] === true;
    }
  } catch (e) {
    toastError(e);
  } finally {
    loading.value = false;
  }
});

function payload(): Record<string, unknown> {
  return {
    allowlist: allowlist.value,
    denylist: denylist.value,
    variants: { ...variants },
  };
}

async function save(): Promise<void> {
  busy.value = true;
  try {
    await rpc.call("admin.policy.put", payload());
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
    await rpc.call("admin.policy.put", payload());
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
    <h2 class="ay-lists-title">{{ t("net.lists.title") }}</h2>
    <p class="muted ay-lists-hint">{{ t("net.lists.hint") }}</p>
    <HkSectionCard :title="t('net.lists.deny')" :icon="ShieldAlert" :loading="loading" padded>
      <p class="muted ay-lists-note">{{ t("net.lists.denyNote") }}</p>
      <HkTagInput v-model="denylist" :placeholder="t('net.lists.placeholder')" />
    </HkSectionCard>
    <HkSectionCard :title="t('net.lists.allow')" :icon="ShieldCheck" :loading="loading" padded>
      <p class="muted ay-lists-note">{{ t("net.lists.allowNote") }}</p>
      <HkTagInput v-model="allowlist" :placeholder="t('net.lists.placeholder')" />
    </HkSectionCard>
    <HkSectionCard :title="t('net.lists.variants')" :icon="AtSign" :loading="loading" padded>
      <p class="muted ay-lists-note">{{ t("net.lists.variantsHint") }}</p>
      <div class="ay-variants">
        <div v-for="row in switches" :key="row.key" class="ay-variant">
          <HkCheckbox v-model="variants[row.key]" :label="t(row.label)" />
          <span class="muted ay-variant-note">{{ t(row.note) }}</span>
        </div>
      </div>
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
.ay-lists-title { margin: 0; font-size: 1.15rem; }
.ay-lists-hint { margin: 0; }
.ay-lists-note { margin: 0 0 10px; font-size: 0.85rem; }
.ay-lists-actions { display: flex; gap: 10px; align-items: center; }
.ay-variants { display: flex; flex-direction: column; gap: 12px; }
.ay-variant { display: flex; flex-direction: column; gap: 2px; }
.ay-variant-note { font-size: 0.85rem; padding-left: 26px; }
</style>
