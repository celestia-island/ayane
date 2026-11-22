import { computed, defineComponent, onMounted, ref } from "vue";
import { RouterView, useRoute, useRouter } from "vue-router";
import { Mail, PenLine, Send, Settings, SquarePen, Star, Trash2 } from "lucide-vue-next";

import {
  HkAboutBody,
  HkAdminHeader,
  HkAdminShell,
  HkAvatar,
  HkButton,
  HkIconButton,
  HkMenu,
  HkModal,
  HkSelect,
  HkSettingsDialog,
  HkStatusBar,
  HkThemePanelContent,
  HSidebar,
  hkParseIdentity,
  setLocale,
  useToast,
  type HAboutCredit,
  type HAboutLink,
  type HkConnectionInfo,
  type HkMenuItem,
  type HkSettingsSection,
} from "@celestia-island/hikari";

import logoUrl from "../res/ayane.webp";
import {
  LOCALES,
  locale as appLocale,
  onLocaleChange,
  setAppLocale,
  t,
  type Locale,
} from "../lib/i18n";
import { onSessionRequired, rpc, sessionToken, setSessionToken, type ConnectionState } from "../lib/rpc";
import { inboxUnread } from "../lib/mailbox";

/** Build identity baked by vite (package version + <branch>:<hash7>). */
declare const __AYANE_VERSION__: string;

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

/** The trailing `<branch>:<hash>` token marks a development build (the
 *  family's version-line rule): the branch and commit ARE the dev marker.
 *  Trunk stamps (master / main) carry no pill — the parse is hikari's
 *  hkParseIdentity, the same one the status bar consumes. */
const TRUNK_BRANCHES = new Set(["master", "main"]);

function isDevelopmentStamp(versionLine: string): boolean {
  const stamp = versionLine.trim().split(/\s+/).pop();
  const branch = hkParseIdentity(stamp)?.branch;
  return branch !== undefined && !TRUNK_BRANCHES.has(branch);
}

/** The credits sentence: organization first, author second — the same
 *  anatomy chest's about surface renders (accent names, localized runs). */
function aboutCredits(): HAboutCredit[] {
  return [
    { text: t("about.creditsFrom") },
    { name: "Celestia Island", href: "https://celestia.world", face: "accent" },
    { text: t("about.creditsJoiner") },
    { name: t("about.author"), href: "https://github.com/langyo", face: "accent" },
    { text: t("about.creditsRole") },
  ];
}

const ABOUT_LICENSES: HAboutLink[] = [
  { label: "SySL-1.0", href: "https://sysl.celestia.world" },
];

/** The signed-in shell: HkAdminShell + family admin header (identity face:
 *  avatar menu with identity block, language cascade, account window and
 *  logout) + the 224px sidebar nav (HkMenu) + the full footer status bar.
 *  Settings ride the family HkSettingsDialog (language select / theme
 *  panel / the shared HkAboutBody about page) from the header gear. A
 *  stale session anywhere returns to the login page silently. */
export default defineComponent({
  name: "ShellLayout",
  setup() {
    const route = useRoute();
    const router = useRouter();
    const toast = useToast();
    const connState = ref<ConnectionState>("connecting");
    const settingsOpen = ref(false);
    const settingsSection = ref("language");
    /** The hidden file input behind the upload-avatar button. */
    const avatarInput = ref<HTMLInputElement>();

    const displayName = ref(localStorage.getItem("ayane.displayName") || "");
    const address = ref(localStorage.getItem("ayane.address") || "");
    const admin = ref(false);
    const avatarUrl = ref(localStorage.getItem("ayane.avatar") || "");

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
      const box = typeof route.query.box === "string" ? route.query.box : "";
      return t(FOLDER_LABEL[(box.toLowerCase() || "inbox") as keyof typeof FOLDER_LABEL]);
    });

    /** Folder keys are the IMAP names the list route carries (box=…),
     *  except the two pseudo-entries (compose, admin). */
    const FOLDER_KEYS = ["inbox", "starred", "sent", "drafts", "trash"] as const;
    const FOLDER_LABEL: Record<(typeof FOLDER_KEYS)[number], string> = {
      inbox: "folder.inbox",
      starred: "folder.starred",
      sent: "folder.sent",
      drafts: "folder.drafts",
      trash: "folder.trash",
    };

    const navItems = computed<HkMenuItem[]>(() => [
      {
        key: "inbox",
        label: t("folder.inbox"),
        icon: Mail,
        badge: inboxUnread.value > 0 ? String(inboxUnread.value) : undefined,
      },
      { key: "starred", label: t("folder.starred"), icon: Star },
      { key: "sent", label: t("folder.sent"), icon: Send },
      { key: "drafts", label: t("folder.drafts"), icon: SquarePen },
      { key: "trash", label: t("folder.trash"), icon: Trash2 },
      { key: "admin", label: t("nav.admin"), icon: Settings },
    ]);

    /** The chest console's grouped nav: pinned compose, then themed
     *  collapsible sections (all expanded — a table of contents). */
    const navGroups = computed(() => [
      {
        id: "mail",
        label: t("sidebar.group.mail"),
        items: navItems.value.filter((item) => FOLDER_KEYS.includes(item.key as never)),
      },
      {
        id: "system",
        label: t("sidebar.group.system"),
        items: [navItems.value.find((item) => item.key === "admin")!],
      },
    ]);

    const menuItems = computed<HkMenuItem[]>(() => [
      { key: "compose", label: t("compose.button"), icon: PenLine },
      ...navGroups.value.map((group) => ({
        key: `group:${group.id}`,
        label: group.label,
        children: group.items,
      })),
    ]);

    const activeKey = computed(() => {
      if (route.path.startsWith("/compose")) return "compose";
      if (route.path.startsWith("/admin")) return "admin";
      // The route's box parameter IS the folder key (INBOX is the default,
      // and the legacy ?box=Sent spelling reads as the sent folder).
      const box = route.query.box;
      if (typeof box === "string" && FOLDER_KEYS.includes(box as never)) {
        return box === "INBOX" ? "inbox" : (box.toLowerCase() as string);
      }
      return "inbox";
    });

    const sections = computed<HkSettingsSection[]>(() => [
      { key: "language", label: t("settings.language") },
      { key: "theme", label: t("settings.theme") },
      { key: "about", label: t("settings.about") },
    ]);

    const localeOptions = computed(() =>
      LOCALES.map((code) => ({ code, label: LOCALE_LABELS[code] })),
    );

    /** HkSelect's option model ({value,label}) — the header cascade takes
     *  the {code,label} shape, so each surface gets its own mapping. */
    const selectOptions = computed(() =>
      LOCALES.map((code) => ({ value: code, label: LOCALE_LABELS[code] })),
    );

    /** Sidebar key → IMAP mailbox name carried in ?box= (exact server
     *  spelling: INBOX / Starred / Sent / Drafts / Trash). */
    const MAILBOX_OF_KEY: Record<string, string> = {
      inbox: "INBOX",
      starred: "Starred",
      sent: "Sent",
      drafts: "Drafts",
      trash: "Trash",
    };

    function navigate(key: string, close?: () => void): void {
      if (key === "compose" || key === "admin") {
        router.push(`/${key}`);
      } else if (key in MAILBOX_OF_KEY) {
        router.push(key === "inbox" ? "/inbox" : `/inbox?box=${MAILBOX_OF_KEY[key]}`);
      }
      close?.();
    }

    function onLocaleSelect(code: string): void {
      setAppLocale(code as Locale);
      void setLocale(code);
    }

    function clearIdentity(): void {
      localStorage.removeItem("ayane.displayName");
      localStorage.removeItem("ayane.address");
    }

    function logout(): void {
      rpc.call("session.logout").catch(() => undefined);
      setSessionToken(null);
      clearIdentity();
      rpc.close();
      router.push("/login");
    }

    onSessionRequired.handler = () => {
      setSessionToken(null);
      clearIdentity();
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
      // Fresh identity for the header face (localStorage is only the
      // pre-connect fallback): address, display name and the admin badge.
      rpc
        .call<{ address: string; display_name: string; admin: boolean }>("session.whoami")
        .then((who) => {
          address.value = who.address;
          admin.value = who.admin;
          if (who.display_name) {
            displayName.value = who.display_name;
            localStorage.setItem("ayane.displayName", who.display_name);
          }
          localStorage.setItem("ayane.address", who.address);
        })
        .catch(() => undefined);
    });

    /** Pick a local image, cover-crop to 128px and store the data URL.
     *  Client-side only (the server keeps no profile blob yet) — the
     *  note in the account window says so. */
    function onAvatarFile(e: Event): void {
      const input = e.target as HTMLInputElement;
      const file = input.files?.[0];
      input.value = "";
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        const img = new Image();
        img.onload = () => {
          const canvas = document.createElement("canvas");
          canvas.width = 128;
          canvas.height = 128;
          const ctx = canvas.getContext("2d");
          if (!ctx) return;
          const scale = Math.max(128 / img.width, 128 / img.height);
          const w = img.width * scale;
          const h = img.height * scale;
          ctx.drawImage(img, (128 - w) / 2, (128 - h) / 2, w, h);
          avatarUrl.value = canvas.toDataURL("image/jpeg", 0.85);
          localStorage.setItem("ayane.avatar", avatarUrl.value);
        };
        img.src = String(reader.result);
      };
      reader.readAsDataURL(file);
    }

    function removeAvatar(): void {
      avatarUrl.value = "";
      localStorage.removeItem("ayane.avatar");
    }

    const aboutRows = computed(() => {
      const rows: { label: string; value: string; meta?: string }[] = [
        { label: t("settings.panel"), value: __AYANE_VERSION__ },
      ];
      // The branch word is the environment: a non-trunk stamp is a dev
      // build — the pill is the environment word, not a second value.
      if (isDevelopmentStamp(__AYANE_VERSION__)) {
        rows[0].meta = t("about.devBuild");
      }
      return rows;
    });

    return () => (
      <>
        <HkAdminShell sidebarCollapsed={false} navTitle="ayane" contentKey={route.path}>
          {{
            header: () => (
              <HkAdminHeader
                title={pageTitle.value}
                username={displayName.value}
                userEmail={address.value}
                avatarUrl={avatarUrl.value}
                avatarAction="menu"
                avatarMenuLabel={t("menu.account")}
                logoutLabel={t("menu.logout")}
                localeOptions={localeOptions.value}
                currentLocale={appLocale()}
                onLocaleSelect={onLocaleSelect}
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
                v-slots={{
                  "avatar-modal": ({
                    open,
                    onUpdateOpen,
                  }: {
                    open: boolean;
                    onUpdateOpen: (v: boolean) => void;
                  }) => (
                    <HkModal
                      modelValue={open}
                      onUpdate:modelValue={onUpdateOpen}
                      title={t("menu.account")}
                      width="26rem"
                    >
                      <div class="ay-account">
                        <HkAvatar src={avatarUrl.value || undefined} name={displayName.value} size="lg" />
                        <div class="ay-account-rows">
                          <div class="ay-account-row">
                            <span class="ay-account-label">{t("account.displayName")}</span>
                            <span>{displayName.value || "—"}</span>
                          </div>
                          <div class="ay-account-row">
                            <span class="ay-account-label">{t("account.address")}</span>
                            <span class="ay-account-mono">{address.value || "—"}</span>
                          </div>
                          {admin.value && (
                            <div class="ay-account-row">
                              <span class="ay-account-label">{t("menu.account")}</span>
                              <span class="ay-account-badge">{t("account.admin")}</span>
                            </div>
                          )}
                        </div>
                        <div class="ay-account-actions">
                          <input
                            ref={avatarInput}
                            type="file"
                            accept="image/*"
                            style="display: none"
                            onChange={onAvatarFile}
                          />
                          <HkButton
                            variant="ghost"
                            size="sm"
                            onClick={() => avatarInput.value?.click()}
                          >
                            {t("account.uploadAvatar")}
                          </HkButton>
                          {avatarUrl.value && (
                            <HkButton variant="ghost" size="sm" onClick={removeAvatar}>
                              {t("account.removeAvatar")}
                            </HkButton>
                          )}
                        </div>
                        <p class="ay-account-note">{t("account.avatarNote")}</p>
                      </div>
                    </HkModal>
                  ),
                }}
              />
            ),
            sidebar: (shell: { onNavigate?: () => void; inDrawer?: boolean; collapsed?: boolean }) => (
              <HSidebar
                width={shell.inDrawer ? "100%" : "224px"}
                collapsed={shell.collapsed ?? false}
              >
                {{
                  default: () => (
                    <HkMenu
                      variant="sidebar"
                      open={true}
                      defaultExpandGroups
                      title="ayane"
                      items={menuItems.value}
                      activeKey={activeKey.value}
                      onSelect={(key: string) => navigate(key, shell.onNavigate)}
                    />
                  ),
                }}
              </HSidebar>
            ),
            content: () => <RouterView />,
            footer: () => (
              <HkStatusBar
                version={__AYANE_VERSION__}
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
          width="46rem"
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
            language: () => (
              <div class="ay-settings-field">
                <label class="ay-settings-label">{t("settings.uiLanguage")}</label>
                <HkSelect
                  modelValue={appLocale()}
                  onUpdate:modelValue={(v: string) => onLocaleSelect(v)}
                  options={selectOptions.value}
                />
                <p class="ay-settings-hint">{t("settings.languageHint")}</p>
              </div>
            ),
            theme: () => (
              <div class="ay-settings-theme">
                <HkThemePanelContent />
              </div>
            ),
            about: () => (
              <div class="ay-settings-about">
                {/* THE family about body — the same one chest's settings
                 *  pane and about window mount. No decorative backdrop for
                 *  now (that pipeline artwork is chest-specific). */}
                <HkAboutBody
                  appName="ayane"
                  version={__AYANE_VERSION__}
                  logoSrc={logoUrl}
                  tagline={t("about.tagline")}
                  credits={aboutCredits()}
                  licenses={ABOUT_LICENSES}
                  componentVersions={aboutRows.value}
                  copyright="Celestia Island"
                />
              </div>
            ),
          }}
        </HkSettingsDialog>
      </>
    );
  },
});
