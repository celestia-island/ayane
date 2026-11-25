import { computed, defineComponent, onMounted, ref } from "vue";
import { ArrowDownLeft, ArrowUpRight } from "lucide-vue-next";

import { HkAdminTablePage } from "@celestia-island/hikari";

import { rpc } from "../lib/rpc";
import { t } from "../lib/i18n";
import { toastError } from "../lib/toast";

interface InboundPeer {
  peer: string;
  connects: number;
}

interface OutboundPeer {
  relay: string;
  domains: string[];
  sent: number;
  deferred: number;
  bounced: number;
}

interface TrafficReport {
  inbound: InboundPeer[];
  outbound: OutboundPeer[];
}

const WINDOWS = [
  { key: "24h", label: "24h" },
  { key: "72h", label: "72h" },
  { key: "168h", label: "7d" },
] as const;

/** 流量统计：谁来访问过我们（inbound connect），我们往谁发（outbound relay）。 */
export default defineComponent({
  name: "NetTrafficView",
  setup() {
    const report = ref<TrafficReport>({ inbound: [], outbound: [] });
    const loading = ref(true);
    const error = ref<string | undefined>(undefined);
    const since = ref<string>("72h");

    async function load(): Promise<void> {
      loading.value = true;
      error.value = undefined;
      try {
        report.value = await rpc.call<TrafficReport>("admin.net.traffic", {
          since: since.value,
        });
      } catch (e) {
        toastError(e);
        error.value = t("err.adminFailed");
      } finally {
        loading.value = false;
      }
    }
    onMounted(load);

    const inboundColumns = computed(() => [
      { key: "peer", title: t("net.traffic.peer") },
      { key: "connects", title: t("net.traffic.connects"), width: "120px", align: "right" as const },
    ]);
    const outboundColumns = computed(() => [
      { key: "relay", title: t("net.traffic.relay") },
      { key: "domains", title: t("net.traffic.domains") },
      { key: "sent", title: t("net.traffic.sent"), width: "90px", align: "right" as const, copyable: false },
      { key: "deferred", title: t("net.traffic.deferred"), width: "90px", align: "right" as const, copyable: false },
      { key: "bounced", title: t("net.traffic.bounced"), width: "90px", align: "right" as const, copyable: false },
    ]);

    return () => (
      <div class="ay-net">
        <HkAdminTablePage
          title={t("net.traffic.in")}
          icon={ArrowDownLeft}
          rows={report.value.inbound}
          columns={inboundColumns.value}
          rowKey="peer"
          loading={loading.value}
          error={error.value}
          emptyTitle={t("net.traffic.emptyIn")}
        >
          {{
            actions: () => (
              <div class="ay-traffic-windows">
                {WINDOWS.map((w) => (
                  <button
                    key={w.key}
                    class={{
                      "ay-traffic-window": true,
                      "ay-traffic-window-active": since.value === w.key,
                    }}
                    onClick={() => {
                      since.value = w.key;
                      void load();
                    }}
                  >
                    {w.label}
                  </button>
                ))}
              </div>
            ),
          }}
        </HkAdminTablePage>
        <HkAdminTablePage
          title={t("net.traffic.out")}
          icon={ArrowUpRight}
          rows={report.value.outbound}
          columns={outboundColumns.value}
          rowKey="relay"
          loading={loading.value}
          emptyTitle={t("net.traffic.emptyOut")}
        >
          {{
            "cell-domains": ({ row }: { row: OutboundPeer }) => (
              <span class="muted">{row.domains.join(", ")}</span>
            ),
          }}
        </HkAdminTablePage>
      </div>
    );
  },
});
