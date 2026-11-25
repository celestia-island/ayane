import { computed, defineComponent, onMounted, ref } from "vue";
import { Globe, ShieldCheck } from "lucide-vue-next";

import {
  HkAdminTablePage,
  HkBadge,
  HkSectionCard,
  type BadgeVariant,
} from "@celestia-island/hikari";

import { rpc } from "../lib/rpc";
import { t } from "../lib/i18n";
import { toastError } from "../lib/toast";

interface DnsCheck {
  check: string;
  status: string;
  detail: string;
}

interface CertStatus {
  subject: string;
  issuer: string;
  not_after: number;
  days_left: number;
}

/** 域名与证书：DNS 体检（dns.check）+ TLS 证书余期（admin.net.cert）。 */
export default defineComponent({
  name: "NetCertView",
  setup() {
    const dns = ref<DnsCheck[]>([]);
    const dnsLoading = ref(true);
    const dnsError = ref<string | undefined>(undefined);
    const cert = ref<CertStatus | null>(null);
    const certError = ref<string | undefined>(undefined);
    const certLoading = ref(true);

    async function loadDns(): Promise<void> {
      dnsLoading.value = true;
      dnsError.value = undefined;
      try {
        const report = await rpc.call<{ checks: DnsCheck[] }>("dns.check");
        dns.value = report.checks;
      } catch (e) {
        toastError(e);
        dnsError.value = t("err.adminFailed");
      } finally {
        dnsLoading.value = false;
      }
    }

    async function loadCert(): Promise<void> {
      certLoading.value = true;
      certError.value = undefined;
      try {
        cert.value = await rpc.call<CertStatus>("admin.net.cert");
      } catch (e) {
        toastError(e);
        certError.value = t("net.certUnavailable");
      } finally {
        certLoading.value = false;
      }
    }

    onMounted(() => {
      void loadDns();
      void loadCert();
    });

    const dnsColumns = computed(() => [
      { key: "check", title: t("admin.col.check") },
      { key: "status", title: t("admin.col.status"), width: "120px", copyable: false },
      { key: "detail", title: t("admin.col.detail") },
    ]);

    function badgeOf(status: string): BadgeVariant {
      if (status === "pass") return "success";
      if (status === "warn") return "warning";
      return "error";
    }

    const certTone = computed<BadgeVariant>(() => {
      const days = cert.value?.days_left ?? -1;
      if (days > 14) return "success";
      if (days > 0) return "warning";
      return "error";
    });

    const certDate = computed(() => {
      if (!cert.value) return "—";
      return new Intl.DateTimeFormat(undefined, { dateStyle: "full" }).format(
        new Date(cert.value.not_after * 1000),
      );
    });

    return () => (
      <div class="ay-net">
        <HkSectionCard
          title={t("net.cert")}
          icon={ShieldCheck}
          error={certError.value}
          loading={certLoading.value}
        >
          {cert.value && (
            <div class="ay-cert">
              <div class="ay-cert-row">
                <span class="ay-cert-label">{t("net.certSubject")}</span>
                <span class="ay-cert-value">{cert.value.subject}</span>
              </div>
              <div class="ay-cert-row">
                <span class="ay-cert-label">{t("net.certIssuer")}</span>
                <span class="ay-cert-value">{cert.value.issuer}</span>
              </div>
              <div class="ay-cert-row">
                <span class="ay-cert-label">{t("net.certExpiry")}</span>
                <span class="ay-cert-value">{certDate.value}</span>
              </div>
              <div class="ay-cert-row">
                <span class="ay-cert-label">{t("net.certDays")}</span>
                <HkBadge variant={certTone.value}>
                  {t("net.certDaysLeft", { n: cert.value.days_left })}
                </HkBadge>
              </div>
            </div>
          )}
        </HkSectionCard>
        <HkAdminTablePage
          title={t("admin.dns")}
          icon={Globe}
          rows={dns.value}
          columns={dnsColumns.value}
          rowKey="check"
          loading={dnsLoading.value}
          error={dnsError.value}
          emptyTitle={t("admin.dns")}
        >
          {{
            actions: () => (
              <span />
            ),
            "cell-status": ({ row }: { row: DnsCheck }) => (
              <HkBadge variant={badgeOf(row.status)}>{row.status}</HkBadge>
            ),
            "cell-detail": ({ row }: { row: DnsCheck }) => (
              <span class="muted">{row.detail}</span>
            ),
          }}
        </HkAdminTablePage>
      </div>
    );
  },
});
