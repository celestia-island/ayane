<script setup lang="ts">
import { ref } from "vue";
import { Send } from "lucide-vue-next";
import { useRouter } from "vue-router";

import { HkButton, HkInput, HkSectionCard } from "@celestia-island/hikari";

import { rpc } from "../lib/rpc";
import { t } from "../lib/i18n";
import { toastError, toastSuccess } from "../lib/toast";

const router = useRouter();
const to = ref("");
const subject = ref("");
const body = ref("");
const busy = ref(false);

async function send(): Promise<void> {
  busy.value = true;
  try {
    await rpc.call("mail.send", { to: to.value, subject: subject.value, body: body.value });
    toastSuccess(t("compose.sent"));
    window.setTimeout(() => router.push("/inbox"), 700);
  } catch (e) {
    toastError(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="compose">
    <form @submit.prevent="send">
      <HkSectionCard :title="t('compose.button')" class="compose-card">
        <div class="compose-fields">
          <HkInput v-model="to" type="email" required :label="t('compose.to')" placeholder="someone@example.com" />
          <HkInput v-model="subject" :label="t('compose.subject')" />
          <HkInput v-model="body" type="textarea" :rows="10" :label="t('compose.body')" />        </div>
        <div class="compose-actions">
          <HkButton type="submit" :disabled="busy || !to">
            <Send :size="14" /> {{ t("compose.send") }}
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
.compose-card { display: flex; }
.compose-fields { display: flex; flex-direction: column; gap: 12px; }
.compose-actions { display: flex; gap: 10px; align-items: center; margin-top: 16px; }
</style>
