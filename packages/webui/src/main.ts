import { createApp } from "vue";
import { createRouter, createWebHistory } from "vue-router";

// Full hikari stylesheet bundle (the admin chrome styles its components
// render — status bar, auth card, glass header) and the family dark mode:
// hikari components are mode-aware and default to light without this.
import "@celestia-island/hikari/styles/index.scss";
document.documentElement.setAttribute("data-mode", "dark");

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