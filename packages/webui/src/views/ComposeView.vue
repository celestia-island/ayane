<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";

import { rpc } from "../lib/rpc";

const router = useRouter();
const to = ref("");
const subject = ref("");
const body = ref("");
const busy = ref(false);
const error = ref("");
const sent = ref(false);

async function send(): Promise<void> {
  busy.value = true;
  error.value = "";
  sent.value = false;
  try {
    await rpc.call("mail.send", { to: to.value, subject: subject.value, body: body.value });
    sent.value = true;
    window.setTimeout(() => router.push("/inbox"), 700);
  } catch (e) {
    error.value = String(e instanceof Error ? e.message : e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="compose">
    <form class="hk-card" @submit.prevent="send">
      <label>
        <span>收件人</span>
        <input v-model="to" class="hk-input" type="email" required placeholder="someone@example.com" />
      </label>
      <label>
        <span>主题</span>
        <input v-model="subject" class="hk-input" type="text" />
      </label>
      <label>
        <span>正文</span>
        <textarea v-model="body" class="hk-input" rows="10" />
      </label>
      <p v-if="error" class="danger">{{ error }}</p>
      <p v-if="sent" class="warn">已提交发送 ✓</p>
      <div class="hk-row">
        <button class="hk-button" type="submit" :disabled="busy || !to">发送</button>
        <button class="hk-button ghost" type="button" @click="router.push('/inbox')">取消</button>
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