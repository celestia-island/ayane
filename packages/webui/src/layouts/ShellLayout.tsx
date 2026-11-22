import { computed, defineComponent, onMounted, ref } from "vue";
import { RouterView, useRoute, useRouter } from "vue-router";
import { LogOut, Mail, PenLine, Send, Settings } from "lucide-vue-next";

import {
  HkAdminHeader,
  HkAdminShell,
  HkMenu,
  HkPopover,
  HkStatusBar,
  HSidebar,
  setLocale,
  useTheme,
  type HkConnectionInfo,
  type HkMenuItem,
} from "@celestia-island/hikari";

import {
  LOCALES,
  locale as appLocale,
  onLocaleChange,
  setAppLocale,
  t,
  type Locale,
} from "../lib/i18n";
import { onSessionRequired, rpc, sessionToken, setSessionToken, type ConnectionState } from "../lib/rpc";

/** The signed-in shell: HkAdminShell + family admin header (brand menu
 *  top-left with logout, settings popover top-right) + Gmail-style
 *  sidebar (compose button, then mail folders) + the full footer status
 *  bar. Session expiry anywhere in the app returns to the login page. */
export default defineComponent({
  name: "ShellLayout",
  setup() {
    const route = useRoute();
    const router = useRouter();
    const connState = ref<ConnectionState>("connecting");
    const theme = useTheme();

    const brandRef = ref<HTMLElement | null>(null);
    const brandOpen = ref(false);
    const settingsRef = ref<HTMLElement | null>(null);
    const settingsOpen = ref(false);

    const displayName = localStorage.getItem("ayane.displayName") || "";

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
      if (route.path.startsWith("/compose")) return t("compose.button");
      if (route.path.startsWith("/read")) return t("folder.inbox");
      if (route.path.startsWith("/admin")) return t("admin.state");
      return route.query.box === "Sent" ? t("folder.sent") : t("folder.inbox");
    });

    const folders = computed<HkMenuItem[]>(() => [
      { key: "inbox", label: t("folder.inbox"), icon: Mail },
      { key: "sent", label: t("folder.sent"), icon: Send },
    ]);

    const activeKey = computed(() =>
      route.query.box === "Sent" || route.path === "/sent" ? "sent" : "inbox",
    );

    function logout(): void {
      rpc.call("session.logout").catch(() => undefined);
      setSessionToken(null);
      localStorage.removeItem("ayane.displayName");
      rpc.close();
      router.push("/login");
    }

    onSessionRequired.handler = () => {
      setSessionToken(null);
      localStorage.removeItem("ayane.displayName");
      rpc.close();
      router.push("/login");
    };

    const localeNames: Record<Locale, string> = {
      en: "English",
      "zh-Hans": "简体中文",
      "zh-Hant": "繁體中文",
      ja: "日本語",
      ko: "한국어",
      de: "Deutsch",
      fr: "Français",
      es: "Español",
      ru: "Русский",
    };

    function pickLocale(code: string): void {
      setAppLocale(code as Locale);
      void setLocale(code);
    }

    onMounted(() => {
      if (!sessionToken()) {
        router.push("/login");
        return;
      }
      onLocaleChange.handler = (l) => void setLocale(l);
      void setLocale(appLocale());
      rpc.onChange = (state) => {
        connState.value = state;
      };
      rpc.connect();
    });

    return () => (
      <HkAdminShell sidebarCollapsed={false} navTitle="ayane" contentKey={route.path}>
        {{
          header: () => (
            <>
            <HkAdminHeader
              title={pageTitle.value}
              username={displayName}
              logoutLabel={t("menu.logout")}
              onLogout={logout}
              actions={[
                <span key="settings" ref={settingsRef} style="display: inline-flex">
                  <button
                    class="s-logout-btn"
                    title={t("settings.title")}
                    aria-label={t("settings.title")}
                    onClick={() => {
                      settingsOpen.value = !settingsOpen.value;
                    }}
                  >
                    <Settings size={16} />
                  </button>
                </span>,
              ]}
            >
              {{
                brand: () => (
                  <span ref={brandRef} style="display: inline-flex">
                    <button
                      class="s-brand-btn"
                      aria-label="ayane"
                      onClick={() => {
                        brandOpen.value = !brandOpen.value;
                      }}
                    >
                      <img
                        style="width: 26px; height: 26px"
                        src="https://raw.githubusercontent.com/celestia-island/celestia-island.github.io/main/res/logos/ayane.webp"
                        alt=""
                      />
                      <span style="font-weight: 700; letter-spacing: 0.04em">ayane</span>
                    </button>
                  </span>
                ),
              }}
            </HkAdminHeader>
            <HkPopover
              modelValue={brandOpen.value}
              onUpdate:modelValue={(v: boolean) => {
                brandOpen.value = v;
              }}
              anchorRef={brandRef.value}
              placement="bottom-start"
              offset={6}
              title="ayane"
              padding="sm"
            >
              <div style="display: flex; flex-direction: column; gap: 2px; min-width: 180px">
                <div class="s-menu-identity">
                  <small class="s-menu-caption">{t("menu.signedInAs")}</small>
                  <span>{localStorage.getItem("ayane.address") || displayName}</span>
                </div>
                <button class="s-menu-row" onClick={logout}>
                  <LogOut size={14} />
                  {t("menu.logout")}
                </button>
              </div>
            </HkPopover>
            <HkPopover
              modelValue={settingsOpen.value}
              onUpdate:modelValue={(v: boolean) => {
                settingsOpen.value = v;
              }}
              anchorRef={settingsRef.value}
              placement="bottom-end"
              offset={6}
              title={t("settings.title")}
              padding="sm"
            >
              <div style="display: flex; flex-direction: column; gap: 8px; min-width: 180px">
                <small class="s-menu-caption">{t("settings.theme")}</small>
                <div style="display: flex; gap: 6px">
                  <button
                    class={["s-menu-row", theme.effectiveMode.value === "dark" ? "s-menu-row-active" : ""]}
                    onClick={() => theme.setMode("dark")}
                  >
                    {t("settings.dark")}
                  </button>
                  <button
                    class={["s-menu-row", theme.effectiveMode.value === "light" ? "s-menu-row-active" : ""]}
                    onClick={() => theme.setMode("light")}
                  >
                    {t("settings.light")}
                  </button>
                </div>
                <small class="s-menu-caption">{t("settings.language")}</small>
                {LOCALES.map((code) => (
                  <button
                    class={["s-menu-row", appLocale() === code ? "s-menu-row-active" : ""]}
                    onClick={() => pickLocale(code)}
                  >
                    {localeNames[code]}
                  </button>
                ))}
              </div>
            </HkPopover>
            </>
          ),
          sidebar: () => (
            <HSidebar>
              {{
                default: () => (
                  <div style="display: flex; flex-direction: column; gap: 8px; padding: 8px">
                    <button
                      class="s-compose-btn"
                      onClick={() => router.push("/compose")}
                    >
                      <PenLine size={16} />
                      {t("compose.button")}
                    </button>
                    <HkMenu
                      variant="sidebar"
                      open={true}
                      items={folders.value}
                      activeKey={activeKey.value}
                      onSelect={(key: string) => {
                        router.push(key === "sent" ? "/inbox?box=Sent" : "/inbox");
                      }}
                    />
                    <div style="display: flex; flex-direction: column; gap: 2px; padding: 0 6px">
                      <button
                        class="s-manage-btn"
                        onClick={() => router.push("/admin")}
                      >
                        <Settings size={15} />
                        {t("nav.admin")}
                      </button>
                    </div>
                  </div>
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