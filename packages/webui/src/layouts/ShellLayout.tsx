import { computed, defineComponent, onMounted, ref } from "vue";
import { RouterView, useRoute, useRouter } from "vue-router";
import { Mail, PenLine, Send, Settings } from "lucide-vue-next";

import {
  HkAdminHeader,
  HkAdminShell,
  HkIconButton,
  HkMenu,
  HkSettingsDialog,
  HkStatusBar,
  HkThemePanelContent,
  HSidebar,
  setLocale,
  useToast,
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

const LOCALE_LABELS: Record<Locale, string> = {
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

/** The signed-in shell: HkAdminShell + family admin header (identity face:
 *  avatar + account menu with logout) + the sidebar nav (HkMenu) + the
 *  full footer status bar. Settings ride the family HkSettingsDialog
 *  (theme / language / about sections) from the header gear. A stale
 *  session anywhere returns to the login page silently. */
export default defineComponent({
  name: "ShellLayout",
  setup() {
    const route = useRoute();
    const router = useRouter();
    const toast = useToast();
    const connState = ref<ConnectionState>("connecting");
    const settingsOpen = ref(false);
    const settingsSection = ref("theme");

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
      if (route.path.startsWith("/admin")) return t("nav.admin");
      return route.query.box === "Sent" ? t("folder.sent") : t("folder.inbox");
    });

    const navItems = computed<HkMenuItem[]>(() => [
      { key: "compose", label: t("compose.button"), icon: PenLine },
      { key: "inbox", label: t("folder.inbox"), icon: Mail },
      { key: "sent", label: t("folder.sent"), icon: Send },
      { key: "admin", label: t("nav.admin"), icon: Settings },
    ]);

    const activeKey = computed(() => {
      if (route.path.startsWith("/compose")) return "compose";
      if (route.path.startsWith("/admin")) return "admin";
      return route.query.box === "Sent" || route.path === "/sent" ? "sent" : "inbox";
    });

    const sections = computed(() => [
      { key: "theme", label: t("settings.theme") },
      { key: "language", label: t("settings.language") },
      { key: "about", label: t("settings.about") },
    ]);

    function onLocaleSelect(code: string): void {
      setAppLocale(code as Locale);
      void setLocale(code);
    }

    function logout(): void {
      rpc.call("session.logout").catch(() => undefined);
      setSessionToken(null);
      localStorage.removeItem("ayane.displayName");
      localStorage.removeItem("ayane.address");
      rpc.close();
      router.push("/login");
    }

    onSessionRequired.handler = () => {
      setSessionToken(null);
      localStorage.removeItem("ayane.displayName");
      localStorage.removeItem("ayane.address");
      rpc.close();
      router.push("/login");
    };

    onMounted(() => {
      if (!sessionToken()) {
        router.push("/login");
        return;
      }
      onLocaleChange.handler = (l) => void setLocale(l);
      rpc.onChange = (state) => {
        connState.value = state;
      };
      rpc.connect();
    });

    return () => (
      <>
      <HkAdminShell sidebarCollapsed={false} navTitle="ayane" contentKey={route.path}>
        {{
          header: () => (
            <HkAdminHeader
              title={pageTitle.value}
              username={displayName}
              avatarAction="menu"
              avatarMenuLabel={t("menu.account")}
              logoutLabel={t("menu.logout")}
              onLogout={logout}
              actions={[
                <HkIconButton
                  key="settings"
                  variant="ghost"
                  size={32}
                  {...{ title: t("settings.title"), "aria-label": t("settings.title") }}
                  onClick={() => {
                    settingsOpen.value = true;
                  }}
                >
                  <Settings size={16} />
                </HkIconButton>,
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
                      router.push(
                        key === "sent" ? "/inbox?box=Sent" : key === "inbox" ? "/inbox" : `/${key}`,
                      );
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
      <HkSettingsDialog
        modelValue={settingsOpen.value}
        title={t("settings.title")}
        navLabel={t("settings.title")}
        sections={sections.value}
        section={settingsSection.value}
        onUpdate:section={(key: string) => {
          settingsSection.value = key;
        }}
        onUpdate:modelValue={(v: boolean) => {
          settingsOpen.value = v;
        }}
      >
        {{
          theme: () => (
            <div>
              <HkThemePanelContent />
            </div>
          ),
          language: () => (
            <div style="display: flex; flex-direction: column; gap: 6px">
              {LOCALES.map((code) => (
                <button
                  key={code}
                  class={{
                    "s-language-option": true,
                    "s-language-option-active": appLocale() === code,
                  }}
                  onClick={() => onLocaleSelect(code)}
                >
                  {LOCALE_LABELS[code]}
                </button>
              ))}
            </div>
          ),
          about: () => (
            <div style="display: flex; flex-direction: column; gap: 8px">
              <div class="s-about-row">
                <span class="s-about-label">{t("settings.app")}</span>
                <span>ayane</span>
              </div>
              <div class="s-about-row">
                <span class="s-about-label">{t("settings.panel")}</span>
                <span>0.1.0</span>
              </div>
            </div>
          ),
        }}
      </HkSettingsDialog>
      </>
    );
  },
});