<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";

import { rpc, setSessionToken } from "../lib/rpc";

const router = useRouter();
const address = ref("");
const password = ref("");
const busy = ref(false);
const error = ref("");

async function login(): Promise<void> {
  busy.value = true;
  error.value = "";
  try {
    const result = await rpc.call<{ token: string }>("session.login", {
      address: address.value,
      password: password.value,
    });
    setSessionToken(result.token);
    router.push("/inbox");
  } catch (e) {
    error.value = String(e instanceof Error ? e.message : e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="login">
    <form class="hk-card" @submit.prevent="login">
      <h2>ayane 邮箱</h2>
      <label>
        <span>邮箱地址</span>
        <input v-model="address" class="hk-input" type="email" required autocomplete="username" placeholder="you@example.com" />
      </label>
      <label>
        <span>密码</span>
        <input v-model="password" class="hk-input" type="password" required autocomplete="current-password" />
      </label>
      <p v-if="error" class="danger">{{ error }}</p>
      <button class="hk-button" type="submit" :disabled="busy || !address || !password">
        {{ busy ? "登录中…" : "登录" }}
      </button>
    </form>
  </div>
</template>

<style scoped lang="scss">
.login { display: flex; align-items: center; justify-content: center; height: 100%; }
form { width: 320px; display: flex; flex-direction: column; gap: 12px;
  h2 { margin: 0 0 4px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 13px; color: #aab3c5; }
}
</style>