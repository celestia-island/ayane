import { computed, defineComponent, onMounted, ref, watch, type VNode } from "vue";
import { useRouter } from "vue-router";

import {
  HkAdminTablePage,
  HkCard,
  HkConfirmDialog,
  HkMenu,
  HTable,
  useConfirm,
  type HkMenuItem,
  type HkTableSection,
} from "@celestia-island/hikari";

import { rpc } from "../lib/rpc";
import { inboxUnread } from "../lib/mailbox";
import { locale, t } from "../lib/i18n";
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
  size: number;
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

/** Short date column: time on today's messages, date otherwise (the year
 *  only when it differs from the current one). */
function formatDate(value: string | null): string {
  if (!value) return "—";
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) return "—";
  const now = new Date();
  const sameYear = at.getFullYear() === now.getFullYear();
  const sameDay = at.toDateString() === now.toDateString();
  const localeTag = locale();
  if (sameDay) {
    return new Intl.DateTimeFormat(localeTag, { hour: "2-digit", minute: "2-digit" }).format(at);
  }
  return new Intl.DateTimeFormat(
    localeTag,
    sameYear ? { month: "short", day: "numeric" } : { year: "numeric", month: "short", day: "numeric" },
  ).format(at);
}

/** The standard mail roster: HkAdminTablePage (page header + count readout
 *  + scroll-progress dock) over an HkTable whose swimlanes are date groups.
 *  Rows navigate on cell-click (HkTable owns no row-click — every data
 *  cell carries the enter click, the family EdgeFleet pattern); the ⋯
 *  column carries read-flag, star, trash and (in Trash) permanent delete. */
export default defineComponent({
  name: "InboxView",
  props: { mailbox: { type: String, required: true } },
  setup(props) {
    const router = useRouter();
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
          { mailbox: props.mailbox, limit: 50 },
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

    function open(row: EnvelopeRow): void {
      const box = row.mailbox || props.mailbox;
      void router.push({ path: `/read/${row.uid}`, query: { box } });
    }

    const sections = computed<HkTableSection[]>(() =>
      LANES.map((lane) => ({
        key: lane,
        label: t(`mail.${lane}`),
        rows: rows.value.filter((row) => laneOf(row) === lane),
      })).filter((section) => section.rows.length > 0),
    );

    const columns = computed(() => [
      { key: "from", title: t("mail.col.from") },
      { key: "subject", title: t("mail.col.subject") },
      { key: "date", title: t("mail.col.date"), width: "170px", align: "right" as const, copyable: false },
      { key: "size", title: t("mail.col.size"), width: "76px", align: "right" as const, copyable: false },
    ]);

    /** Every data cell's content carries the enter click — the whole row
     *  navigates while HkTable's copy/menus keep their own semantics. */
    const enterWrap = (row: EnvelopeRow, cell: VNode | string): VNode => (
      <div
        class="ay-mail-row-enter"
        role="button"
        tabindex={0}
        aria-label={`${t("mail.open")}: ${row.subject || t("mail.noSubject")}`}
        onClick={() => open(row)}
        onKeydown={(e: KeyboardEvent) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            open(row);
          }
        }}
      >
        {cell}
      </div>
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
          });
          refreshUnreadAfterSeen(row, target);
          row.seen = target;
        } else if (key === "star") {
          const target = !row.flagged;
          await rpc.call("mail.star", {
            uid: row.uid,
            mailbox: row.mailbox || props.mailbox,
            starred: target,
          });
          row.flagged = target;
        } else if (key === "trash") {
          await rpc.call("mail.trash", {
            uid: row.uid,
            mailbox: row.mailbox || props.mailbox,
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

    function onManage(row: Record<string, unknown>, opener: HTMLElement): void {
      rowMenuAnchor.value = opener;
      rowMenuUid.value = (row as unknown as EnvelopeRow).uid;
    }

    async function onPurgeConfirm(): Promise<void> {
      const row = purgeRow.value;
      if (!row) return;
      purging.value = true;
      try {
        await rpc.call("mail.purge", {
          uid: row.uid,
          mailbox: row.mailbox || props.mailbox,
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
        <HkAdminTablePage
          title={folderTitle.value}
          rows={rows.value}
          columns={columns.value}
          rowKey="uid"
          loading={loading.value}
          error={error.value}
          emptyTitle={folder.value === "INBOX" ? t("inbox.empty") : folderTitle.value}
          total={total.value}
        >
          {{
            body: () => (
              <HkCard padded={false}>
                <HTable
                  columns={columns.value}
                  rows={rows.value}
                  sections={sections.value}
                  rowKey="uid"
                  total={total.value}
                  manageable={true}
                  onManage={onManage}
                >
                  {{
                    "cell-from": ({ row }: { row: EnvelopeRow }) =>
                      enterWrap(row, (
                        <span class="ay-mail-from">
                          <span class="ay-mail-dot" aria-hidden="true" data-unread={!row.seen || undefined} />
                          {row.flagged && (
                            <span class="ay-mail-star" aria-hidden="true" data-flagged="true" />
                          )}
                          <span class="ay-mail-from-text">{row.from || t("mail.unknownSender")}</span>
                        </span>
                      )),
                    "cell-subject": ({ row }: { row: EnvelopeRow }) =>
                      enterWrap(row, (
                        <span class="ay-mail-subject" data-unread={!row.seen || undefined}>
                          {row.subject || t("mail.noSubject")}
                        </span>
                      )),
                    "cell-date": ({ row }: { row: EnvelopeRow }) => enterWrap(row, formatDate(row.date)),
                    "cell-size": ({ row }: { row: EnvelopeRow }) =>
                      enterWrap(row, `${Math.max(1, Math.round(row.size / 1024))}K`),
                  }}
                </HTable>
              </HkCard>
            ),
          }}
        </HkAdminTablePage>
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
