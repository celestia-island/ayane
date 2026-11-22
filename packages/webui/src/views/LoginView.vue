<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";

import { HkLoginFlow, type HkLoginChannel } from "@celestia-island/hikari";

import { rpc, setSessionToken } from "../lib/rpc";

const router = useRouter();
const channel = ref("mail");
const pending = ref(false);
const failure = ref("");

// The family login panel (chest/auth.celestia.world blueprint): one
// credentials channel renders the plain card — no dead segment group.
const channels: HkLoginChannel[] = [
  {
    key: "mail",
    mode: "credentials",
    title: "ayane 邮箱",
    subtitle: "用邮箱账号登录",
    usernameType: "email",
    usernamePlaceholder: "you@example.com",
    usernameAutocomplete: "email",
    // Account + password on the opening card: the mail service has no
    // MFA ladder yet, so the account-first posture would only add a hop.
    passwordField: true,
  },
];

async function submit(_channel: string, username: string, password: string): Promise<void> {
  pending.value = true;
  failure.value = "";
  try {
    const result = await rpc.call<{ token: string }>("session.login", {
      address: username,
      password,
    });
    setSessionToken(result.token);
    router.push("/inbox");
  } catch (e) {
    failure.value = e instanceof Error ? e.message : String(e);
  } finally {
    pending.value = false;
  }
}
</script>

<template>
  <div class="login-page">
    <HkLoginFlow
      v-model="channel"
      :channels="channels"
      step="account"
      :loading="pending"
      logo-src="https://raw.githubusercontent.com/celestia-island/celestia-island.github.io/main/res/logos/ayane.webp"
      @account-submit="submit"
    >
      <template #top>
        <p v-if="failure" class="login-error" role="alert">{{ failure }}</p>
      </template>
    </HkLoginFlow>
  </div>
</template>

<style scoped lang="scss">
.login-page {
  min-height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
}

.login-error {
  margin: 0 0 10px;
  padding: 8px 12px;
  border-radius: 8px;
  background: rgba(224, 82, 82, 0.12);
  border: 1px solid rgba(224, 82, 82, 0.45);
  color: #e08181;
  font-size: 13px;
}
</style>