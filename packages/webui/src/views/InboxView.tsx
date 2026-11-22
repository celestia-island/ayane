import { computed, defineComponent, onMounted, ref, watch, type VNode } from "vue";
import { useRouter } from "vue-router";

import {
  HkAdminTablePage,
  HkCard,
  HkMenu,
  HTable,
  type HkMenuItem,
  type HkTableSection,
} from "@celestia-island/hikari";

import { rpc } from "../lib/rpc";
import { locale, t } from "../lib/i18n";
import { toastError } from "../lib/toast";

interface EnvelopeRow {
  uid: number;
  from: string | null;
  subject: string | null;
  seen: boolean;
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
 *  column carries the seen-flag toggle. */
export default defineComponent({
  name: "InboxView",
  props: { mailbox: { type: String, required: true } },
  setup(props) {
    const router = useRouter();
    const rows = ref<EnvelopeRow[]>([]);
    const loading = ref(true);
    const error = ref<string | undefined>(undefined);
    const rowMenuUid = ref<number | null>(null);
    const rowMenuAnchor = ref<HTMLElement | null>(null);

    async function load(): Promise<void> {
      loading.value = true;
      error.value = undefined;
      try {
        const result = await rpc.call<{ messages: EnvelopeRow[] }>("mail.list", {
          mailbox: props.mailbox,
          limit: 50,
        });
        rows.value = result.messages;
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
      void router.push({ path: `/read/${row.uid}`, query: { box: props.mailbox } });
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
        aria-label={t("mail.open")}
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
      return [
        {
          key: "seen",
          label: row.seen ? t("mail.markUnread") : t("mail.markSeen"),
        },
      ];
    });

    async function onMenuSelect(key: string): Promise<void> {
      const row = menuRow.value;
      rowMenuUid.value = null;
      if (key !== "seen" || !row) return;
      const target = !row.seen;
      try {
        await rpc.call("mail.markSeen", {
          uid: row.uid,
          mailbox: props.mailbox,
          seen: target,
        });
        row.seen = target;
      } catch (e) {
        toastError(e);
      }
    }

    function onManage(row: Record<string, unknown>, opener: HTMLElement): void {
      rowMenuAnchor.value = opener;
      rowMenuUid.value = (row as unknown as EnvelopeRow).uid;
    }

    return () => (
      <>
        <HkAdminTablePage
          title={props.mailbox === "Sent" ? t("folder.sent") : t("folder.inbox")}
          rows={rows.value}
          columns={columns.value}
          rowKey="uid"
          loading={loading.value}
          error={error.value}
          emptyTitle={t("inbox.empty")}
        >
          {{
            body: () => (
              <HkCard padded={false}>
                <HTable
                  columns={columns.value}
                  rows={rows.value}
                  sections={sections.value}
                  rowKey="uid"
                  total={rows.value.length}
                  manageable={true}
                  onManage={onManage}
                >
                  {{
                    "cell-from": ({ row }: { row: EnvelopeRow }) =>
                      enterWrap(row, (
                        <span class="ay-mail-from">
                          <span class="ay-mail-dot" aria-hidden="true" data-unread={!row.seen || undefined} />
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
          items={rowMenuItems.value}
          onSelect={onMenuSelect}
        />
      </>
    );
  },
});
