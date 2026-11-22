<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { ShieldAlert, FileLock2 } from "lucide-vue-next";

import { rpc } from "../lib/rpc";
import { t } from "../lib/i18n";
import { toastError } from "../lib/toast";

interface AttachmentMeta {
  filename: string;
  content_type: string;
  size: number;
  sha256: string;
}

interface LinkVerdict {
  url: string;
  reasons: string[];
  verdict: string;
}

interface ParsedMessage {
  from: string | null;
  to: string[];
  subject: string | null;
  text: string | null;
  html: string | null;
  attachments: AttachmentMeta[];
}

const props = defineProps<{ uid: number; mailbox: string }>();
const router = useRouter();
const message = ref<ParsedMessage | null>(null);
const links = ref<LinkVerdict[]>([]);
const loading = ref(true);

const suspicious = computed(() => links.value.filter((l) => l.verdict !== "ok"));

onMounted(async () => {
  try {
    const result = await rpc.call<{ message: ParsedMessage; links: LinkVerdict[] }>("mail.read", {
      uid: props.uid,
      mailbox: props.mailbox,
    });
    message.value = result.message;
    links.value = result.links;
  } catch (e) {
    toastError(e);
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <div class="read">
    <button class="hk-button ghost" @click="router.push('/inbox')">← {{ t("read.back") }}</button>
    <p v-if="loading" class="muted">{{ t("inbox.loading") }}</p>
    <template v-else-if="message">
      <h2>{{ message.subject || "(无主题)" }}</h2>
      <p class="muted">{{ message.from }} → {{ message.to.join(", ") }}</p>

      <div v-if="suspicious.length" class="hk-card warn-card">
        <p class="warn"><ShieldAlert :size="16" style="vertical-align: -3px" /> {{ t("read.suspicious", { n: suspicious.length }) }}</p>
        <ul>
          <li v-for="link in suspicious" :key="link.url" :class="link.verdict">
            <code>{{ link.url }}</code>
            <small class="muted"> — {{ link.reasons.join("；") }}</small>
          </li>
        </ul>
      </div>

      <!-- Only ammonia-sanitised HTML from the server, remote references stripped. -->
      <div v-if="message.html" class="body html" v-html="message.html" />
      <pre v-else-if="message.text" class="body">{{ message.text }}</pre>
      <p v-else class="muted body">{{ t("read.noBody") }}</p>

      <div v-if="message.attachments.length" class="hk-card">
        <p class="muted">
          <FileLock2 :size="16" style="vertical-align: -3px" />
          {{ t("read.attachments", { n: message.attachments.length }) }}
        </p>
        <table>
          <thead>
            <tr><th>文件</th><th>类型</th><th>大小</th><th>SHA-256</th></tr>
          </thead>
          <tbody>
            <tr v-for="att in message.attachments" :key="att.sha256">
              <td>{{ att.filename }}</td>
              <td>{{ att.content_type }}</td>
              <td>{{ att.size }} B</td>
              <td><code class="muted">{{ att.sha256 }}</code></td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>

<style scoped lang="scss">
.read { max-width: 860px; margin: 0 auto; display: flex; flex-direction: column; gap: 14px; }
h2 { margin: 0; }
.body { white-space: pre-wrap; background: #161c27; border: 1px solid #232a37; border-radius: 12px; padding: 16px; }
.html { white-space: normal;
  :deep(a) { color: #6cb2ff; }
  :deep(img), :deep(video), :deep(iframe) { display: none; }
}
.warn-card { border-color: #6b5a1e;
  ul { margin: 6px 0 0; padding-left: 18px; }
}
table { width: 100%; border-collapse: collapse; font-size: 13px;
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #232a37; }
  code { font-size: 11px; word-break: break-all; }
}
.ghost { background: transparent; color: #aab3c5; border: 1px solid #2a3345; }
</style>