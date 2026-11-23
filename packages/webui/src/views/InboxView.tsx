import { computed, defineComponent, onMounted, ref, watch, type VNode } from "vue";

import {
  HkCard,
  HkConfirmDialog,
  HkDateTag,
  HkEmptyState,
  HkIconButton,
  HkMasterDetail,
  HkMenu,
  HkScrollContainer,
  HkTag,
  useConfirm,
  type HkMenuItem,
} from "@celestia-island/hikari";
import { MoreHorizontal } from "lucide-vue-next";

import ReadView from "./ReadView.vue";

import { rpc } from "../lib/rpc";
import { inboxUnread } from "../lib/mailbox";
import { currentIdentity, identityParams } from "../lib/identity";
import { t } from "../lib/i18n";
import { toastError } from "../lib/toast";

/** The exact IMAP names the route may carry (?box=…). */
const FOLDERS = ["INBOX", "Starred", "Sent", "Drafts", "Trash"] as const;
type Folder = (typeof FOLDERS)[number];

/** The list response of mail.list AND mail.listStarred (same shape). */
interface MailboxListing {
  total: number;
  unread?: number;
  messages: EnvelopeRow[];
}

interface EnvelopeRow {
  uid: number;
  mailbox: string;
  from: string | null;
  subject: string | null;
  seen: boolean;
  flagged: boolean;
  preview: string | null;
  date: string | null;
}

type LaneKey = "today" | "yesterday" | "thisWeek" | "earlier";
const LANES: LaneKey[] = ["today", "yesterday", "thisWeek", "earlier"];
const DAY_MS = 86_400_000;

/** The swimlane a message lands in, judged against LOCAL midnights. */
function laneOf(row: EnvelopeRow): LaneKey {
  if (!row.date) return "earlier";
  const at = new Date(row.date).getTime();
  if (Number.isNaN(at)) return "earlier";
  const now = new Date();
  const midnight = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  if (at >= midnight) return "today";
  if (at >= midnight - DAY_MS) return "yesterday";
  if (at >= midnight - 6 * DAY_MS) return "thisWeek";
  return "earlier";
}

/** Today's messages carry the locale time beside the date (the family
 *  date tag's `time` flag) — older rows keep the calendar segments only. */
function isToday(value: string | null): boolean {
  if (!value) return false;
  const at = new Date(value);
  return !Number.isNaN(at.getTime()) && at.toDateString() === new Date().toDateString();
}

/** The standard mail console: HkMasterDetail's flush two-column form —
 *  the roster column (quiet small-caps head + count readout over the
 *  HkTable whose swimlanes are date groups; the column scrolls
 *  internally, the page never does) and the reading region beside it.
 *  Rows navigate on cell-click (HkTable owns no row-click — every data
 *  cell carries the enter click, the family EdgeFleet pattern); the ⋯
 *  column carries read-flag, star, trash and (in Trash) permanent
 *  delete. */
export default defineComponent({
  name: "InboxView",
  props: { mailbox: { type: String, required: true } },
  setup(props) {
    const confirm = useConfirm();
    const rows = ref<EnvelopeRow[]>([]);
    const total = ref(0);
    const loading = ref(true);
    const error = ref<string | undefined>(undefined);
    const rowMenuUid = ref<number | null>(null);
    const rowMenuAnchor = ref<HTMLElement | null>(null);
    /** The purge flow's armed row (the confirm dialog owns the rest). */
    const purgeRow = ref<EnvelopeRow | null>(null);
    const purging = ref(false);
    /** The message open in the detail pane (master-detail, not a route
     *  jump — the roster stays on screen beside it). */
    const selected = ref<EnvelopeRow | null>(null);

    /** The exact server folder the roster is on (route default INBOX). */
    const folder = computed<Folder>(() =>
      (FOLDERS as readonly string[]).includes(props.mailbox)
        ? (props.mailbox as Folder)
        : "INBOX",
    );

    const folderTitle = computed(() => {
      const keys: Record<Folder, string> = {
        INBOX: "folder.inbox",
        Starred: "folder.starred",
        Sent: "folder.sent",
        Drafts: "folder.drafts",
        Trash: "folder.trash",
      };
      return t(keys[folder.value]);
    });

    async function load(): Promise<void> {
      loading.value = true;
      error.value = undefined;
      try {
        const result = await rpc.call<MailboxListing>(
          folder.value === "Starred" ? "mail.listStarred" : "mail.list",
          { mailbox: props.mailbox, limit: 50, ...identityParams() },
        );
        rows.value = result.messages;
        total.value = result.total;
        if (folder.value === "INBOX" && typeof result.unread === "number") {
          inboxUnread.value = result.unread;
        }
      } catch (e) {
        toastError(e);
        error.value = t("err.mailFailed");
      } finally {
        loading.value = false;
      }
    }
    onMounted(load);
    watch(() => props.mailbox, () => void load());
    // Switching the header's mailbox identity swaps the whole roster (and
    // closes the open email — it belongs to the previous identity). This
    // also self-heals the mount race: the first load may run before the
    // identity list resolves, and the watch re-runs once it lands.
    watch(currentIdentity, () => {
      selected.value = null;
      void load();
    });

    function open(row: EnvelopeRow): void {
      selected.value = row;
      // Opening a message marks it read server-side; the row's own dot
      // and the sidebar badge follow.
      if (!row.seen) {
        void rpc
          .call("mail.markSeen", {
            uid: row.uid,
            mailbox: row.mailbox || props.mailbox,
            seen: true,
            ...identityParams(),
          })
          .then(() => {
            refreshUnreadAfterSeen(row, true);
            row.seen = true;
          })
          .catch(() => undefined);
      }
    }

    function closeDetail(): void {
      selected.value = null;
    }

    /** The roster's date lanes (today / yesterday / this week / earlier) —
     *  group headers over the card stack, the family's swimlane order. */
    const sections = computed(() =>
      LANES.map((lane) => ({
        key: lane,
        label: t(`mail.${lane}`),
        rows: rows.value.filter((row) => laneOf(row) === lane),
      })).filter((section) => section.rows.length > 0),
    );

    /** One message = one card (HkCard's surface + hover chrome). The card
     *  IS the enter affordance, so the whole surface drills through while
     *  the ⋯ lane stops its own click; Enter/Space mirror the pointer. */
    const mailCard = (row: EnvelopeRow): VNode => (
      <HkCard
        class={
          "ay-mail-card" + (selected.value?.uid === row.uid ? " ay-mail-card--open" : "")
        }
        padding="md"
        hoverable
      >
        <div
          class="ay-mail-card-enter"
          role="button"
          tabindex={0}
          data-unread={!row.seen || undefined}
          aria-label={`${t("mail.open")}: ${row.subject || t("mail.noSubject")}`}
          onClick={() => open(row)}
          onKeydown={(e: KeyboardEvent) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              open(row);
            }
          }}
        >
        <div class="ay-mail-card-head">
          <span class="ay-mail-dot" aria-hidden="true" data-unread={!row.seen || undefined} />
          <HkTag size="sm" variant={row.seen ? "default" : "primary"}>
            {row.from || t("mail.unknownSender")}
          </HkTag>
          {row.flagged && (
            <span class="ay-mail-star" aria-hidden="true" data-flagged="true" />
          )}
          <span class="ay-mail-card-push" />
          <HkDateTag value={row.date ?? ""} time={isToday(row.date)} />
        </div>
        <div class="ay-mail-card-subject" data-unread={!row.seen || undefined}>
          {row.subject || t("mail.noSubject")}
        </div>
        {row.preview && (
          <div class="ay-mail-card-preview">
            {row.preview}
          </div>
        )}
        </div>
        <span class="ay-mail-card-actions">
          <HkIconButton
            size={24}
            variant="ghost"
            aria-label={t("mail.actions")}
            onClick={(e: MouseEvent) => {
              e.stopPropagation();
              onManage(row, e.currentTarget as HTMLElement);
            }}
          >
            <MoreHorizontal size={14} />
          </HkIconButton>
        </span>
      </HkCard>
    );

    const menuRow = computed(() =>
      rows.value.find((row) => row.uid === rowMenuUid.value) ?? null,
    );

    const rowMenuItems = computed<HkMenuItem[]>(() => {
      const row = menuRow.value;
      if (!row) return [];
      const items: HkMenuItem[] = [
        {
          key: "seen",
          label: row.seen ? t("mail.markUnread") : t("mail.markSeen"),
        },
        {
          key: "star",
          label: row.flagged ? t("mail.unstar") : t("mail.star"),
        },
      ];
      if (row.mailbox !== "Trash") {
        items.push({ key: "trash", label: t("mail.trashMove"), danger: true });
      } else {
        items.push({ key: "purge", label: t("mail.purge"), danger: true });
      }
      return items;
    });

    function refreshUnreadAfterSeen(row: EnvelopeRow, nowSeen: boolean): void {
      if ((row.mailbox || props.mailbox) !== "INBOX") return;
      if (row.seen && !nowSeen) inboxUnread.value += 1;
      if (!row.seen && nowSeen) inboxUnread.value = Math.max(0, inboxUnread.value - 1);
    }

    async function onMenuSelect(key: string): Promise<void> {
      const row = menuRow.value;
      rowMenuUid.value = null;
      if (!row) return;
      try {
        if (key === "seen") {
          const target = !row.seen;
          await rpc.call("mail.markSeen", {
            uid: row.uid,
            mailbox: row.mailbox || props.mailbox,
            seen: target,
            ...identityParams(),
          });
          refreshUnreadAfterSeen(row, target);
          row.seen = target;
        } else if (key === "star") {
          const target = !row.flagged;
          await rpc.call("mail.star", {
            uid: row.uid,
            mailbox: row.mailbox || props.mailbox,
            starred: target,
            ...identityParams(),
          });
          row.flagged = target;
        } else if (key === "trash") {
          await rpc.call("mail.trash", {
            uid: row.uid,
            mailbox: row.mailbox || props.mailbox,
            ...identityParams(),
          });
          rows.value = rows.value.filter((r) => r.uid !== row.uid);
          total.value = Math.max(0, total.value - 1);
        } else if (key === "purge") {
          purgeRow.value = row;
        }
      } catch (e) {
        toastError(e);
      }
    }

    function onManage(row: EnvelopeRow, opener: HTMLElement): void {
      rowMenuAnchor.value = opener;
      rowMenuUid.value = row.uid;
    }

    async function onPurgeConfirm(): Promise<void> {
      const row = purgeRow.value;
      if (!row) return;
      purging.value = true;
      try {
        await rpc.call("mail.purge", {
          uid: row.uid,
          mailbox: row.mailbox || props.mailbox,
          ...identityParams(),
        });
        rows.value = rows.value.filter((r) => r.uid !== row.uid);
        total.value = Math.max(0, total.value - 1);
        purgeRow.value = null;
      } catch (e) {
        toastError(e);
      } finally {
        purging.value = false;
      }
    }

    return () => (
      <>
        <HkMasterDetail
          detailOpen={selected.value !== null}
          detailTitle={selected.value?.subject || t("mail.noSubject")}
          emptyTitle={t("mail.pickOne")}
          emptyDescription={t("mail.pickOneHint")}
          closeLabel={t("mail.closeDetail")}
          listWidth="24rem"
          onClose={closeDetail}
        >
        {{
          list: () => (
            <>
              {/* The roster column's quiet head — the page identity lives
               * in the shell's nav; the column speaks the small-caps
               * voice the family's console sidebars use (wowsp's replay
               * list shape). */}
              <div class="ay-roster-head">
                <h2 class="ay-roster-title">{folderTitle.value}</h2>
                {total.value > 0 && (
                  <span class="ay-roster-count">
                    {t("mail.totalCount").replace("{n}", String(total.value))}
                  </span>
                )}
              </div>
              <HkScrollContainer class="ay-roster-scroll">
                <div class="ay-roster-body">
                  {loading.value ? (
                    <HkEmptyState loading />
                  ) : error.value ? (
                    <HkEmptyState title={error.value} />
                  ) : rows.value.length === 0 ? (
                    <HkEmptyState
                      title={folder.value === "INBOX" ? t("inbox.empty") : folderTitle.value}
                    />
                  ) : (
                    sections.value.map((section) => (
                      <section class="ay-roster-lane" key={section.key}>
                        <h3 class="ay-roster-lane-label">{section.label}</h3>
                        {section.rows.map((row) => mailCard(row))}
                      </section>
                    ))
                  )}
                </div>
              </HkScrollContainer>
            </>
          ),
          detail: () =>
            selected.value ? (
              <ReadView
                uid={selected.value.uid}
                mailbox={selected.value.mailbox || props.mailbox}
                embedded
              />
            ) : null,
        }}
        </HkMasterDetail>
        {/* The roster rows' shared ⋯ menu: one instance per view, anchored
         *  at the pressed trigger (the family useRowMenu shape). */}
        <HkMenu
          open={rowMenuUid.value !== null}
          onUpdate:open={(v: boolean) => {
            if (!v) rowMenuUid.value = null;
          }}
          placement="bottom-end"
          anchorRef={rowMenuAnchor.value}
          title={t("mail.actions")}
          items={rowMenuItems.value}
          onSelect={onMenuSelect}
        />
        {/* Permanently deleting from Trash is destructive behind a confirm
         *  (the family principle: a destructive action is never bare). */}
        <HkConfirmDialog
          open={purgeRow.value !== null}
          title={t("mail.purgeTitle")}
          message={t("mail.purgeMessage")}
          loading={purging.value}
          onConfirm={onPurgeConfirm}
          onCancel={() => {
            purgeRow.value = null;
          }}
          onUpdate:open={(v: boolean) => {
            if (!v) purgeRow.value = null;
          }}
        />
      </>
    );
  },
});
