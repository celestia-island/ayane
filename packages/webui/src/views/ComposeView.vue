<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";

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
    <form class="hk-card" @submit.prevent="send">
      <label>
        <span>{{ t("compose.to") }}</span>
        <input v-model="to" class="hk-input" type="email" required placeholder="someone@example.com" />
      </label>
      <label>
        <span>{{ t("compose.subject") }}</span>
        <input v-model="subject" class="hk-input" type="text" />
      </label>
      <label>
        <span>{{ t("compose.body") }}</span>
        <textarea v-model="body" class="hk-input" rows="10" />
      </label>
      <div class="hk-row">
        <button class="hk-button" type="submit" :disabled="busy || !to">{{ t("compose.send") }}</button>
        <button class="hk-button ghost" type="button" @click="router.push('/inbox')">{{ t("compose.cancel") }}</button>
      </div>
    </form>
  </div>
</template>

<style scoped lang="scss">
.compose { max-width: 720px; margin: 0 auto; }
form { display: flex; flex-direction: column; gap: 12px;
  label { display: flex; flex-direction: column; gap: 4px; font-size: 13px; color: #aab3c5; }
}
.ghost { background: transparent; color: #aab3c5; border: 1px solid #2a3345; }
</style>