<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { LogOut, Mail, Plus, Settings } from "lucide-vue-next";

import { HkStatusBar, HkToast } from "@celestia-island/hikari";

import { t } from "./lib/i18n";
import type { HkConnectionInfo } from "@celestia-island/hikari";

import { rpc, setSessionToken, type ConnectionState } from "./lib/rpc";

const router = useRouter();
const connState = ref<ConnectionState>("connecting");

onMounted(() => {
  rpc.onChange = (state) => {
    connState.value = state;
  };
});

const info: HkConnectionInfo = {
  state: "connected",
  tier: "ws",
  quality: "ok",
  latencyMs: null,
  isLocalhost: location.hostname === "127.0.0.1" || location.hostname === "localhost",
  region: "—",
  retryCount: 0,
  maxRetries: 8,
  asn: null,
  attemptNumber: 0,
  countdown: 0,
};

function logout(): void {
  rpc.call("session.logout").catch(() => undefined);
  setSessionToken(null);
  rpc.close();
  router.push("/login");
}
</script>

<template>
  <div class="app">
    <header class="top">
      <span class="brand" @click="router.push('/inbox')">
        <img class="brand-logo" src="https://raw.githubusercontent.com/celestia-island/celestia-island.github.io/main/res/logos/ayane.webp" alt="" />
        <span class="brand-name">ayane</span>
      </span>
      <nav>
        <button :title="t('nav.inbox')" data-test="nav-inbox" @click="router.push('/inbox')"><Mail :size="16" /></button>
        <button :title="t('nav.compose')" data-test="nav-compose" @click="router.push('/compose')"><Plus :size="16" /></button>
        <button :title="t('nav.admin')" data-test="nav-admin" @click="router.push('/admin')"><Settings :size="16" /></button>
        <button :title="t('nav.logout')" @click="logout"><LogOut :size="16" /></button>
      </nav>
    </header>

    <main class="body">
      <router-view />
    </main>

    <!-- The family footer: connection traffic light bottom-left. -->
    <HkToast />
    <footer class="foot">
      <HkStatusBar
        :state="connState"
        :info="{ ...info, state: connState === 'connected' ? 'connected' : connState === 'reconnecting' ? 'reconnecting' : 'disconnected' }"
        panel-version="0.1.0"
        compact
      />
    </footer>
  </div>
</template>

<style lang="scss">
* { box-sizing: border-box; }

html, body, #app { height: 100%; margin: 0; }

body {
  font-family: "Inter", "Noto Sans SC", system-ui, sans-serif;
  background: #10141c;
  color: #e6e9f0;
}

.app { display: flex; flex-direction: column; height: 100%; }

.top {
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 16px; height: 46px; border-bottom: 1px solid #232a37;
  .brand {
    display: inline-flex; align-items: center; gap: 8px;
    font-weight: 700; letter-spacing: 0.06em; cursor: pointer;
    .brand-logo { width: 22px; height: 22px; }
    .brand-name { color: #e6e9f0; }
  }
  nav { display: flex; gap: 4px;
    button {
      display: inline-flex; align-items: center; justify-content: center;
      width: 32px; height: 32px; border: 0; border-radius: 8px;
      background: transparent; color: #aab3c5; cursor: pointer;
      &:hover { background: #1b2230; color: #fff; }
    }
  }
}

.body { flex: 1; overflow: auto; padding: 16px; }

.foot {
  position: fixed; left: 12px; bottom: 10px; z-index: 30;
}

// shared small primitives (hikari look-alike until the surface grows)
.hk-card {
  background: #161c27; border: 1px solid #232a37; border-radius: 12px;
  padding: 16px;
}

.hk-button {
  display: inline-flex; align-items: center; gap: 6px;
  border: 0; border-radius: 8px; padding: 8px 14px; cursor: pointer;
  background: #2b6cb0; color: #fff; font-weight: 600;
  &:hover { background: #3b7fc4; }
  &[disabled] { opacity: 0.5; cursor: default; }
}

.hk-input, textarea.hk-input {
  width: 100%; padding: 9px 11px; border-radius: 8px;
  border: 1px solid #2a3345; background: #0d1119; color: #e6e9f0;
  font: inherit;
  &:focus { outline: 1px solid #3b7fc4; }
}

.hk-row { display: flex; gap: 10px; align-items: center; }

.warn { color: #e2b93b; }
.danger { color: #e05252; }
.muted { color: #7f8ba1; }
</style>