<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";

import {
  HkLoginFlow,
  type HkLoginChannel,
  type HkMfaFactor,
} from "@celestia-island/hikari";

import { t } from "../lib/i18n";
import { toastError } from "../lib/toast";

import { rpc, setSessionToken } from "../lib/rpc";

import logoUrl from "../res/ayane.webp";

/** One sign-in channel as the deployment advertises it. */
interface ChannelRow {
  key: string;
  mode: "credentials" | "sso";
  label?: string;
}

const router = useRouter();
const channel = ref("credentials");
/** The identifier collected in stage one — the ladder needs it again. */
const account = ref("");
/** Stage two is open once stage one has an account: the password is proven
 *  there, never on the opening card. */
const verifyOpen = ref(false);
const pending = ref(false);
const rows = ref<ChannelRow[]>([{ key: "credentials", mode: "credentials" }]);

/**
 * The channels this deployment offers. A deployment with no third-party
 * provider configured advertises credentials only, and the panel then
 * renders a plain card with no segment group — an unconfigured provider
 * must never surface as a dead option.
 */
onMounted(async () => {
  try {
    const result = await rpc.call<{ channels: ChannelRow[] }>("session.channels");
    if (result.channels?.length) rows.value = result.channels;
  } catch {
    // The probe is an enhancement, not a gate: credentials always work.
  }
});

const channels = computed<HkLoginChannel[]>(() =>
  rows.value.map((row): HkLoginChannel => {
    if (row.mode === "sso") {
      // A redirect channel renders the standard single-row card; the host
      // builds the URL. No provider is configured yet, so this arm is the
      // seam the OAuth lane will fill in.
      return {
        key: row.key,
        mode: "sso",
        label: row.label ?? row.key,
        icon: undefined,
        buttonLabel: row.label ?? row.key,
      };
    }
    return {
      key: row.key,
      mode: "credentials",
      title: t("login.title"),
      subtitle: t("login.subtitle"),
      usernameType: "email",
      usernamePlaceholder: "you@example.com",
      usernameAutocomplete: "email",
      // Account-first: the opening card collects the mailbox only. The
      // password is a factor, and factors are proven on the verify step.
      passwordField: false,
    };
  }),
);

/** Stage one: the account name. Nothing is proven yet — open the step-up. */
function onAccountSubmit(_channel: string, username: string): void {
  const name = username.trim();
  if (!name) return;
  account.value = name;
  verifyOpen.value = true;
}

/** Stage two: the password, proven against the account from stage one. */
async function onVerify(kind: HkMfaFactor, proof: string): Promise<void> {
  if (kind !== "password") return;
  pending.value = true;
  try {
    const result = await rpc.call<{ token: string; address: string; display_name: string }>(
      "session.login",
      { address: account.value, password: proof },
    );
    setSessionToken(result.token);
    localStorage.setItem("ayane.displayName", result.display_name || "");
    localStorage.setItem("ayane.address", result.address);
    await router.push("/inbox");
  } catch (e) {
    toastError(e);
  } finally {
    pending.value = false;
  }
}

function onVerifyBack(): void {
  verifyOpen.value = false;
}
</script>

<template>
  <div class="login-page">
    <HkLoginFlow
      v-model="channel"
      :channels="channels"
      :step="verifyOpen ? 'verify' : 'account'"
      :loading="pending"
      :initial-username="account"
      :verify-factors="['password']"
      :verify-account-name="account"
      :verify-loading="pending"
      :verify-show-factor-picker="false"
      :logo-src="logoUrl"
      @account-submit="onAccountSubmit"
      @verify="onVerify"
      @verify-back="onVerifyBack"
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