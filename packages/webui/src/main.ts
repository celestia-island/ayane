import { createApp } from "vue";
import { createRouter, createWebHistory } from "vue-router";

// Full hikari stylesheet bundle (the admin chrome styles its components
// render — status bar, auth card, glass header).
import "@celestia-island/hikari/styles/index.scss";
// The theme engine: emits the --color-* token sheet every hikari component
// reads. Without initTheme() the tokens are undefined and components fall
// back to light defaults (the un-themed gray-card / white-band renders).
import { initTheme, setLocale } from "@celestia-island/hikari";

import { locale as appLocale } from "./lib/i18n";

initTheme();
// Dark-first: the mail surface reads best dark, matching the app chrome.
localStorage.setItem("hikari-theme-mode", "dark");
document.documentElement.setAttribute("data-mode", "dark");
initTheme();
// hikari's own strings (Sign in / Password / …) follow the locale.
void setLocale(appLocale());

import App from "./App.vue";
import { rpc } from "./lib/rpc";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", redirect: "/inbox" },
    { path: "/login", component: () => import("./views/LoginView.vue") },
    {
      path: "/inbox",
      component: () => import("./views/InboxView.vue"),
      props: (route) => ({ mailbox: String(route.query.box || "INBOX") }),
    },
    {
      path: "/read/:uid",
      component: () => import("./views/ReadView.vue"),
      props: (route) => ({ uid: Number(route.params.uid), mailbox: String(route.query.box || "INBOX") }),
    },
    { path: "/compose", component: () => import("./views/ComposeView.vue") },
    { path: "/admin", component: () => import("./views/AdminView.vue") },
  ],
});

router.beforeEach((to) => {
  if (to.path !== "/login" && !localStorage.getItem("ayane.session")) {
    return "/login";
  }
});

rpc.connect();

createApp(App).use(router).mount("#app");