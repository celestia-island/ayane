import { computed, defineComponent, onMounted, ref } from "vue";
import { RouterView, useRoute, useRouter } from "vue-router";
import { LogOut, Mail, PenLine, Settings } from "lucide-vue-next";

import {
  HkAdminHeader,
  HkAdminShell,
  HkMenu,
  HkStatusBar,
  HSidebar,
  type HkConnectionInfo,
  type HkMenuItem,
} from "@celestia-island/hikari";

import { rpc, sessionToken, setSessionToken, type ConnectionState } from "../lib/rpc";
import { t } from "../lib/i18n";

/** The signed-in shell: HkAdminShell + family admin header + sidebar nav +
 * the full footer status bar with version rows (the erp/chest pattern). */
export default defineComponent({
  name: "ShellLayout",
  setup() {
    const route = useRoute();
    const router = useRouter();
    const connState = ref<ConnectionState>("connecting");

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

    const pageTitle = computed(() => {
      if (route.path.startsWith("/compose")) return t("nav.compose");
      if (route.path.startsWith("/read")) return t("nav.inbox");
      if (route.path.startsWith("/admin")) return t("nav.admin");
      return t("nav.inbox");
    });

    const displayName = localStorage.getItem("ayane.displayName") || "";

    const navItems = computed<HkMenuItem[]>(() => [
      { key: "inbox", label: t("nav.inbox"), icon: Mail },
      { key: "compose", label: t("nav.compose"), icon: PenLine },
      { key: "admin", label: t("nav.admin"), icon: Settings },
    ]);

    const activeKey = computed(() => {
      if (route.path.startsWith("/compose")) return "compose";
      if (route.path.startsWith("/admin")) return "admin";
      return "inbox";
    });

    function logout(): void {
      rpc.call("session.logout").catch(() => undefined);
      setSessionToken(null);
      localStorage.removeItem("ayane.displayName");
      rpc.close();
      router.push("/login");
    }

    onMounted(() => {
      // Route guard backstop: no session token = back to login.
      if (!sessionToken()) router.push("/login");
      rpc.onChange = (state) => {
        connState.value = state;
      };
      rpc.connect();
    });

    return () => (
      <HkAdminShell
        sidebarCollapsed={false}
        navTitle="ayane"
        contentKey={route.path}
      >
        {{
          header: () => (
            <HkAdminHeader
              title={pageTitle.value}
              brandSrc="https://raw.githubusercontent.com/celestia-island/celestia-island.github.io/main/res/logos/ayane.webp"
              username={displayName}
              actions={[
                <button
                  key="logout"
                  class="s-logout-btn"
                  title={t("nav.logout")}
                  aria-label={t("nav.logout")}
                  onClick={logout}
                >
                  <LogOut size={16} />
                </button>,
              ]}
            />
          ),
          sidebar: () => (
            <HSidebar>
              {{
                default: () => (
                  <HkMenu
                    variant="sidebar"
                    open={true}
                    title="ayane"
                    items={navItems.value}
                    activeKey={activeKey.value}
                    onSelect={(key: string) => {
                      router.push(key === "inbox" ? "/inbox" : `/${key}`);
                    }}
                  />
                ),
              }}
            </HSidebar>
          ),
          content: () => <RouterView />,
          footer: () => (
            <HkStatusBar
              version="0.1.0"
              connectionStatus={connState.value}
              connectionInfo={{
                ...info,
                state:
                  connState.value === "connected"
                    ? "connected"
                    : connState.value === "reconnecting"
                      ? "reconnecting"
                      : "disconnected",
              }}
            />
          ),
        }}
      </HkAdminShell>
    );
  },
});
