import { computed, defineComponent, onMounted, ref } from "vue";
import { Bot, ScanSearch } from "lucide-vue-next";

import {
  HkAdminTablePage,
  HkBadge,
  HkButton,
  HkSectionCard,
} from "@celestia-island/hikari";

import { rpc } from "../lib/rpc";
import { t } from "../lib/i18n";
import { toastError } from "../lib/toast";

interface AuditHit {
  uid: number;
  subject: string | null;
  from: string | null;
  keyword?: string;
  ai_verdict?: string;
}

interface AuditReport {
  scanned: number;
  flagged: number;
  hits: AuditHit[];
}

/** 审计：关键词命中 + AI（仅 arona）复判的 INBOX 扫描。 */
export default defineComponent({
  name: "NetAuditView",
  setup() {
    const keywords = ref<string[]>([]);
    const aiEnabled = ref(false);
    const aiEndpoint = ref("");
    const loading = ref(true);
    const running = ref(false);
    const report = ref<AuditReport | null>(null);
    const error = ref<string | undefined>(undefined);

    onMounted(async () => {
      try {
        const state = await rpc.call<{ audit?: { keywords?: string[]; ai?: { enabled?: boolean; endpoint?: string } } }>(
          "admin.state.get",
        );
        keywords.value = state.audit?.keywords ?? [];
        aiEnabled.value = state.audit?.ai?.enabled ?? false;
        aiEndpoint.value = state.audit?.ai?.endpoint ?? "";
      } catch (e) {
        toastError(e);
      } finally {
        loading.value = false;
      }
    });

    async function run(): Promise<void> {
      running.value = true;
      error.value = undefined;
      try {
        report.value = await rpc.call<AuditReport>("admin.audit.run", { limit: 20 });
      } catch (e) {
        toastError(e);
        error.value = t("err.adminFailed");
      } finally {
        running.value = false;
      }
    }

    const columns = computed(() => [
      { key: "from", title: t("mail.col.from") },
      { key: "subject", title: t("mail.col.subject") },
      { key: "keyword", title: t("net.audit.keyword"), width: "140px" },
      { key: "ai_verdict", title: "AI" },
    ]);

    return () => (
      <div class="ay-net">
        <HkSectionCard
          title={t("net.audit.config")}
          icon={ScanSearch}
          loading={loading.value}
          padded
        >
          <div class="ay-audit-meta">
            <span>
              {t("net.audit.keywords")}:{" "}
              {keywords.value.length
                ? keywords.value.map((k) => (
                    <HkBadge key={k} variant="muted">
                      {k}
                    </HkBadge>
                  ))
                : t("net.audit.noKeywords")}
            </span>
            <span class="muted">
              {aiEnabled.value
                ? `${t("net.audit.aiOn")} · ${aiEndpoint.value}`
                : t("net.audit.aiOff")}
            </span>
          </div>
          <div class="ay-audit-actions">
            <HkButton loading={running.value} disabled={running.value} onClick={() => void run()}>
              {t("net.audit.run")}
            </HkButton>
          </div>
        </HkSectionCard>
        {report.value && (
          <HkAdminTablePage
            title={t("net.audit.hits")}
            icon={Bot}
            rows={report.value.hits}
            columns={columns.value}
            rowKey="uid"
            error={error.value}
            emptyTitle={t("net.audit.clean")}
            subtitle={t("net.audit.scanSummary", {
              n: report.value.scanned,
              m: report.value.flagged,
            })}
          >
            {{
              "cell-from": ({ row }: { row: AuditHit }) => row.from || "—",
              "cell-subject": ({ row }: { row: AuditHit }) => row.subject || t("mail.noSubject"),
              "cell-keyword": ({ row }: { row: AuditHit }) => (
                <HkBadge variant="warning">{row.keyword ?? "—"}</HkBadge>
              ),
              "cell-ai_verdict": ({ row }: { row: AuditHit }) =>
                row.ai_verdict ? (
                  <span class="muted ay-audit-verdict">{row.ai_verdict}</span>
                ) : (
                  <span class="muted">—</span>
                ),
            }}
          </HkAdminTablePage>
        )}
      </div>
    );
  },
});
