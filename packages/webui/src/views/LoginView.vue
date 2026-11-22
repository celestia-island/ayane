<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";

import { HkLoginFlow, type HkLoginChannel } from "@celestia-island/hikari";

import { t } from "../lib/i18n";
import { toastError } from "../lib/toast";

import { rpc, setSessionToken } from "../lib/rpc";

const router = useRouter();
const channel = ref("mail");
const pending = ref(false);

// The family login panel (chest/auth.celestia.world blueprint): one
// credentials channel renders the plain card — no dead segment group.
const channels: HkLoginChannel[] = [
  {
    key: "mail",
    mode: "credentials",
    title: t("login.title"),
    subtitle: t("login.subtitle"),
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
  try {
    const result = await rpc.call<{ token: string; display_name: string }>("session.login", {
      address: username,
      password,
    });
    setSessionToken(result.token);
    localStorage.setItem("ayane.displayName", result.display_name || "");
    router.push("/inbox");
  } catch (e) {
    toastError(e);
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
    />
  </div>
</template>

<style scoped lang="scss">
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
}

</style>