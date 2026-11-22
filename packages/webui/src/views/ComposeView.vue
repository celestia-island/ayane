<script setup lang="ts">
import { onMounted, ref } from "vue";
import { FileDown, Send } from "lucide-vue-next";
import { useRoute, useRouter } from "vue-router";

import { HkButton, HkInput, HkSectionCard } from "@celestia-island/hikari";

import { rpc } from "../lib/rpc";
import { t } from "../lib/i18n";
import { toastError, toastSuccess } from "../lib/toast";

const route = useRoute();
const router = useRouter();
const to = ref("");
const subject = ref("");
const body = ref("");
const busy = ref(false);
const savingDraft = ref(false);
/** The draft being edited (send retires it; a plain send passes nothing). */
const draftUid = ref<number | null>(null);

onMounted(async () => {
  const draftParam = Number(route.query.draft);
  if (!route.query.draft || !Number.isInteger(draftParam) || draftParam <= 0) return;
  // Continue a draft: the composer fields come back from the parsed draft
  // (X-Ayane-Draft-To carries the recipient exactly as it was typed).
  try {
    const result = await rpc.call<{
      message: { to: string[]; draft_to?: string | null; subject: string | null; text: string | null };
    }>("mail.read", { uid: draftParam, mailbox: "Drafts", markSeen: false });
    to.value = result.message.draft_to ?? result.message.to[0] ?? "";
    subject.value = result.message.subject ?? "";
    body.value = result.message.text ?? "";
    draftUid.value = draftParam;
  } catch (e) {
    toastError(e);
  }
});

async function send(): Promise<void> {
  busy.value = true;
  try {
    await rpc.call("mail.send", {
      to: to.value,
      subject: subject.value,
      body: body.value,
      ...(draftUid.value ? { draftUid: draftUid.value } : {}),
    });
    toastSuccess(t("compose.sent"));
    draftUid.value = null;
    window.setTimeout(() => router.push("/inbox"), 700);
  } catch (e) {
    toastError(e);
  } finally {
    busy.value = false;
  }
}

async function saveDraft(): Promise<void> {
  savingDraft.value = true;
  try {
    await rpc.call("mail.saveDraft", { to: to.value, subject: subject.value, body: body.value });
    toastSuccess(t("compose.draftSaved"));
  } catch (e) {
    toastError(e);
  } finally {
    savingDraft.value = false;
  }
}
</script>

<template>
  <div class="compose">
    <form @submit.prevent="send">
      <HkSectionCard :title="t('compose.button')" padded>
        <div class="compose-fields">
          <HkInput v-model="to" type="email" required :label="t('compose.to')" placeholder="someone@example.com" />
          <HkInput v-model="subject" :label="t('compose.subject')" />
          <HkInput v-model="body" type="textarea" :rows="10" :label="t('compose.body')" />
        </div>
        <div class="compose-actions">
          <HkButton type="submit" :disabled="busy || !to">
            <Send :size="14" /> {{ t("compose.send") }}
          </HkButton>
          <HkButton variant="ghost" :disabled="savingDraft || busy" @click="saveDraft">
            <FileDown :size="14" /> {{ t("compose.saveDraft") }}
          </HkButton>
          <HkButton variant="ghost" type="button" @click="router.push('/inbox')">
            {{ t("compose.cancel") }}
          </HkButton>
        </div>
      </HkSectionCard>
    </form>
  </div>
</template>

<style scoped>
.compose { max-width: 720px; margin: 0 auto; }
.compose-fields { display: flex; flex-direction: column; gap: 12px; }
.compose-actions { display: flex; gap: 10px; align-items: center; margin-top: 16px; }
</style>
