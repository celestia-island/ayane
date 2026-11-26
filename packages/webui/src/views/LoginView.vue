<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import {
  HkAuthHandoff,
  HkLoginFlow,
  hkIsSameOriginPath,
  hkLoginPlanFromDiscovery,
  type HkLoginChannel,
  type HkLoginCredentialsChannel,
  type HkLoginDiscovery,
  type HkLoginSsoChannel,
  type HkMfaFactor,
} from "@celestia-island/hikari";

import { oauthErrorKey, t } from "../lib/i18n";
import { toastError } from "../lib/toast";

import { rpc, setSessionToken } from "../lib/rpc";

import logoUrl from "../res/ayane.webp";

/**
 * The sign-in channels come from the server's login policy (the family
 * contract): the password card, plus one TAB per provider the deployment
 * CONFIGURED. A deployment with no provider renders a plain card — an
 * unconfigured provider must never surface as a dead option. hikari's
 * adapter maps the document to channels; this view enriches the password
 * card with its own copy and turns every provider into its own sso tab
 * (the navigation target needs a server ticket, so the tab carries no
 * href — the click starts the sign-in instead).
 */
const policy = ref<HkLoginDiscovery | null>(null);

const LOCAL_POLICY: HkLoginDiscovery = { version: 1, mode: "local", password: true, methods: [] };

/** The server localises nothing: a provider row is named by its id, here. */
function providerLabel(id: string): string {
  const key = `login.provider.${id}`;
  const label = t(key);
  return label === key ? id : label;
}

/** The segment label of a provider tab: the app copy for a KNOWN
 *  provider, else the family-neutral tab word — a server-carried
 *  provider string never reaches the tab. */
function providerTabLabel(id: string): string {
  const key = `login.provider.${id}`;
  const label = t(key);
  return label === key ? t("login.channel.provider") : label;
}

/** Where the browser asked to land after signing in (a same-origin path). */
const returnTo = computed(() => {
  const raw = route.query.returnTo;
  return typeof raw === "string" && hkIsSameOriginPath(raw) ? raw : "";
});

const router = useRouter();
const route = useRoute();
const channel = ref("credentials");
/** The identifier collected in stage one — the ladder needs it again. */
const account = ref("");
/** Stage two is open once stage one has an account: the password is proven
 *  there, never on the opening card. */
const verifyOpen = ref(false);
const pending = ref(false);
/** The provider row whose sign-in is being started (it stays disabled). */
const starting = ref<string | null>(null);

type Phase = "form" | "completing" | "failed";
/** `completing` and `failed` are the hand-off screens (no form at all). */
const phase = ref<Phase>("form");
const failureText = ref("");

/**
 * Unlock mode: the session exists (a provider proved the identity) but owes
 * the mailbox password. The SAME verify card collects it; nothing is
 * logged in again.
 */
const unlockAddress = ref<string | null>(null);
/** The server-carried landing path of a provider sign-in. */
const providerReturnTo = ref("");

onMounted(async () => {
  // The callback lands here with a one-time handoff code, a closed failure
  // reason, or the unlock marker (the shell sends a locked session back).
  const handoff = route.query.handoff;
  const error = route.query.oauth_error;
  const unlock = route.query.unlock;
  const code = typeof handoff === "string" ? handoff : "";
  const reason = typeof error === "string" ? error : "";
  if (code || reason || unlock !== undefined) {
    // Strip the query after reading it: a handoff code must not survive a
    // refresh, and a failure must not loop.
    void router.replace({ path: "/login", query: returnTo.value ? { returnTo: returnTo.value } : {} });
  }
  if (code) {
    phase.value = "completing";
    await claim(code);
    return;
  }
  if (reason) {
    phase.value = "failed";
    failureText.value = t(oauthErrorKey(reason));
    return;
  }
  if (unlock !== undefined) {
    unlockAddress.value = localStorage.getItem("ayane.address") || "";
    account.value = unlockAddress.value;
    verifyOpen.value = true;
  }
  try {
    policy.value = await rpc.call<HkLoginDiscovery>("session.loginPolicy", { token: null });
  } catch {
    // The probe is an enhancement, not a gate: credentials always work.
    policy.value = LOCAL_POLICY;
  }
});

/**
 * The segment group the family's login pages share: the mailbox card,
 * the family IdP as a PEER lane (Celestia ID is a named TAB, never a row
 * under the mailbox card), and every other configured provider as its
 * OWN sso tab — the alternative-row syntax under the card is gone from
 * the family contract.
 */
const PEER_PROVIDER = "celestia";

const channels = computed<HkLoginChannel[]>(() => {
  const plan = hkLoginPlanFromDiscovery(policy.value ?? LOCAL_POLICY, {
    credentialsKey: "credentials",
  });
  const rows = plan.channels.filter((entry): entry is HkLoginSsoChannel => entry.mode === "sso");
  const peer = rows.find((row) => row.key === PEER_PROVIDER);
  const others = rows.filter((row) => row !== peer);

  const mailbox: HkLoginCredentialsChannel = {
    key: "credentials",
    mode: "credentials",
    label: t("login.channel.mailbox"),
    title: t("login.title"),
    subtitle: t("login.subtitle"),
    usernameType: "email",
    usernamePlaceholder: "you@example.com",
    usernameAutocomplete: "email",
    // Account-first: the opening card collects the mailbox only. The
    // password is a factor, and factors are proven on the verify step.
    passwordField: false,
  };

  // One tab per provider: the peer keeps its named tab, the rest get the
  // row copy on the card button and the app's tab word (or the neutral
  // one) on the segment. No href — the target needs a server ticket, so
  // the click starts the sign-in and navigates. No icon — the wire
  // carries an icon URL, and the row renders vnodes, not strings.
  const list: HkLoginChannel[] = [mailbox];
  if (peer !== undefined) {
    list.push({
      key: peer.key,
      mode: "sso",
      label: t("login.provider.celestia"),
      title: t("login.title"),
      subtitle: t("login.subtitle"),
      icon: undefined,
      buttonLabel: providerLabel(peer.key),
    });
  }
  for (const row of others) {
    list.push({
      key: row.key,
      mode: "sso",
      label: providerTabLabel(row.key),
      title: t("login.title"),
      subtitle: t("login.subtitle"),
      icon: undefined,
      buttonLabel: providerLabel(row.key),
      // While a provider sign-in is starting, every provider tab rests.
      disabled: starting.value !== null,
    });
  }
  return list;
});

// The active segment follows the policy once it arrives (the plan names
// the default channel; it is the password card in every mode ayane serves).
watch(policy, (discovered) => {
  const plan = hkLoginPlanFromDiscovery(discovered ?? LOCAL_POLICY, {
    credentialsKey: "credentials",
  });
  channel.value = plan.defaultChannel ?? "credentials";
});

/** The landing path of a finished sign-in: the server-carried one, else
 *  the page's own `returnTo`, else the inbox — never a foreign address. */
function landingPath(serverCarried?: string | null): string {
  for (const candidate of [serverCarried, returnTo.value]) {
    if (candidate && hkIsSameOriginPath(candidate)) return candidate;
  }
  return "/inbox";
}

/** Remember who is signed in (the shell reads these before it connects). */
function remember(address: string, displayName: string): void {
  localStorage.setItem("ayane.displayName", displayName || "");
  localStorage.setItem("ayane.address", address);
}

/**
 * Redeem the one-time handoff the callback parked. An own-domain mailbox
 * answers `needs_mailbox_password`: the session exists but is locked, and
 * the verify card asks for that password once (kept for the session only).
 */
async function claim(code: string): Promise<void> {
  pending.value = true;
  try {
    const result = await rpc.call<{
      token: string;
      address: string;
      display_name: string;
      needs_mailbox_password: boolean;
      return_to: string | null;
    }>("session.claimHandoff", { code });
    setSessionToken(result.token);
    remember(result.address, result.display_name);
    if (result.needs_mailbox_password) {
      unlockAddress.value = result.address;
      account.value = result.address;
      providerReturnTo.value = result.return_to ?? "";
      verifyOpen.value = true;
      phase.value = "form";
      return;
    }
    await router.push(landingPath(result.return_to));
  } catch (e) {
    phase.value = "failed";
    failureText.value = t("err.handoffInvalid");
    toastError(e);
  } finally {
    pending.value = false;
  }
}

/** A provider tab was picked: ask for a ticket and leave. The tab's
 *  channel key IS the provider id, so every provider tab lands here. */
function onSsoClick(provider: string): void {
  void startProvider(provider);
}

async function startProvider(provider: string): Promise<void> {
  if (starting.value !== null) return;
  starting.value = provider;
  try {
    // `token: null` keeps the client from attaching a stored bearer to a
    // sign-in. The server reads no token here either way:
    // `session.oauthBegin` is always the login purpose; linking is
    // `session.linkIdentity`, from the account page alone.
    const result = await rpc.call<{ href: string }>("session.oauthBegin", {
      provider,
      token: null,
      returnTo: returnTo.value || undefined,
    });
    if (hkIsSameOriginPath(result.href)) {
      window.location.assign(result.href);
      return;
    }
    toastError(new Error("Session.OAuthFailed: the sign-in target is not a same-origin path"));
  } catch (e) {
    toastError(e);
  } finally {
    starting.value = null;
  }
}

/** Stage one: the account name. Nothing is proven yet — open the step-up. */
function onAccountSubmit(_channel: string, username: string): void {
  const name = username.trim();
  if (!name) return;
  account.value = name;
  verifyOpen.value = true;
}

/**
 * Stage two: the password. Either the mailbox password of a fresh sign-in,
 * or — after a provider proved the identity — the one-time password that
 * unlocks the session.
 */
async function onVerify(kind: HkMfaFactor, proof: string): Promise<void> {
  if (kind !== "password") return;
  pending.value = true;
  try {
    if (unlockAddress.value !== null) {
      await rpc.call("session.unlockMailbox", { password: proof });
      await router.push(landingPath(providerReturnTo.value));
      return;
    }
    const result = await rpc.call<{ token: string; address: string; display_name: string }>(
      "session.login",
      { address: account.value, password: proof },
    );
    setSessionToken(result.token);
    remember(result.address, result.display_name);
    await router.push(landingPath());
  } catch (e) {
    toastError(e);
  } finally {
    pending.value = false;
  }
}

function onVerifyBack(): void {
  verifyOpen.value = false;
  // A locked session has nowhere to go back to: the card is the only way
  // forward, so the step stays open.
  if (unlockAddress.value !== null) verifyOpen.value = true;
}

/** The failed screen's one action: back to the sign-in card. */
function onHandoffBack(): void {
  phase.value = "form";
  void router.replace({ path: "/login" });
}
</script>

<template>
  <div class="login-page">
    <HkAuthHandoff v-if="phase === 'completing'" status="completing" :logo-src="logoUrl" />
    <HkAuthHandoff
      v-else-if="phase === 'failed'"
      status="failed"
      :description="failureText"
      :logo-src="logoUrl"
      @back="onHandoffBack"
    />
    <HkLoginFlow
      v-else
      v-model="channel"
      :channels="channels"
      :step="verifyOpen ? 'verify' : 'account'"
      :loading="pending"
      :initial-username="account"
      :verify-factors="['password']"
      :verify-account-name="account"
      :verify-loading="pending"
      :verify-show-factor-picker="false"
      :verify-title="unlockAddress !== null ? t('login.unlock.title') : undefined"
      :verify-subtitle="unlockAddress !== null ? t('login.unlock.subtitle', { name: account }) : undefined"
      :logo-src="logoUrl"
      @account-submit="onAccountSubmit"
      @sso-click="onSsoClick"
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
