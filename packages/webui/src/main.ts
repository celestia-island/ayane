import { createApp } from "vue";
import { createRouter, createWebHistory } from "vue-router";

import "@celestia-island/hikari/styles/index.scss";
// The theme engine: emits the --color-* token sheet every hikari component
// reads. Without initTheme() the tokens are undefined and components fall
// back to light defaults (the un-themed gray-card / white-band renders).
import { createErrorReporting, initTheme, setLocale } from "@celestia-island/hikari";

import { locale as appLocale } from "./lib/i18n";

import App from "./App.vue";

initTheme();
// Dark-first SEED: the mail surface reads best dark, but the choice is the
// user's — the theme panel (HkThemePanelContent) owns `hikari-theme-mode`
// from its first change, and this pin must never override it again.
if (!localStorage.getItem("hikari-theme-mode")) {
  localStorage.setItem("hikari-theme-mode", "dark");
}
const bootMode = localStorage.getItem("hikari-theme-mode") ?? "dark";
document.documentElement.setAttribute("data-mode", bootMode);
// hikari's own strings (Sign in / Password / …) follow the locale.
void setLocale(appLocale());

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/login", component: () => import("./views/LoginView.vue") },
    {
      path: "/",
      component: () => import("./layouts/ShellLayout.tsx"),
      children: [
        { path: "", redirect: "/inbox" },
        {
          path: "inbox",
          component: () => import("./views/InboxView.tsx"),
          props: (route) => ({ mailbox: String(route.query.box || "INBOX") }),
        },
        {
          path: "read/:uid",
          component: () => import("./views/ReadView.vue"),
          props: (route) => ({
            // The id is the maildir file name; `Number()` here would turn it
            // into NaN and every open message would 404 against the reader.
            uid: decodeURIComponent(String(route.params.uid)),
            mailbox: String(route.query.box || "INBOX"),
          }),
        },
        { path: "compose", component: () => import("./views/ComposeView.vue") },
        // Linked sign-ins: the one place a provider identity is linked to
        // (or unlinked from) the signed-in mailbox.
        { path: "account", component: () => import("./views/AccountView.vue") },
        { path: "admin", component: () => import("./views/UsersView.vue") },
        { path: "net-cert", component: () => import("./views/NetCertView.tsx") },
        { path: "net-traffic", component: () => import("./views/NetTrafficView.tsx") },
        { path: "net-lists", component: () => import("./views/NetListsView.vue") },
        { path: "net-audit", component: () => import("./views/NetAuditView.tsx") },
        { path: "net-mcp", component: () => import("./views/NetMcpView.vue") },
      ],
    },
  ],
});

router.beforeEach((to) => {
  if (to.path !== "/login" && !localStorage.getItem("ayane.session")) {
    return "/login";
  }
});

const app = createApp(App);
// The family error landing, installed BEFORE mount: on install it reads the
// `hk-server-error` island the server injects into index.html when the
// navigation itself failed (the OAuth callback, a revoked link, a gateway
// 502) and raises the unified card at the real HTTP status; afterwards it
// catches what crashes the running app. Mounting first would paint the
// normal shell and bury the server's verdict.
app.use(createErrorReporting());
app.use(router);
app.mount("#app");