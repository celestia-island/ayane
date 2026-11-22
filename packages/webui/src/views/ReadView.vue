<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { ArrowLeft, ShieldAlert, FileLock2, SquarePen } from "lucide-vue-next";

import { HkButton, HkSectionCard } from "@celestia-island/hikari";

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
    <div class="read-top">
      <HkButton variant="ghost" size="sm" @click="router.push(props.mailbox === 'Drafts' ? '/inbox?box=Drafts' : '/inbox')">
        <ArrowLeft :size="14" /> {{ t("read.back") }}
      </HkButton>
      <HkButton
        v-if="props.mailbox === 'Drafts'"
        size="sm"
        @click="router.push(`/compose?draft=${props.uid}`)"
      >
        <SquarePen :size="14" /> {{ t("read.continueDraft") }}
      </HkButton>
    </div>
    <p v-if="loading" class="muted">{{ t("inbox.loading") }}</p>
    <template v-else-if="message">
      <h2>{{ message.subject || t("mail.noSubject") }}</h2>
      <p class="muted read-route">{{ message.from }} → {{ message.to.join(", ") }}</p>

      <HkSectionCard
        v-if="suspicious.length"
        :title="t('read.suspicious', { n: suspicious.length })"
        :icon="ShieldAlert"
        level="h3"
      >
        <ul class="read-links">
          <li v-for="link in suspicious" :key="link.url">
            <code>{{ link.url }}</code>
            <small class="muted"> — {{ link.reasons.join("；") }}</small>
          </li>
        </ul>
      </HkSectionCard>

      <!-- Only ammonia-sanitised HTML from the server, remote references stripped. -->
      <div v-if="message.html" class="read-body html" v-html="message.html" />
      <pre v-else-if="message.text" class="read-body">{{ message.text }}</pre>
      <p v-else class="muted read-body">{{ t("read.noBody") }}</p>

      <HkSectionCard
        v-if="message.attachments.length"
        :title="t('read.attachments', { n: message.attachments.length })"
        :icon="FileLock2"
        level="h3"
      >
        <table class="read-attachments">
          <thead>
            <tr><th>{{ t("read.att.file") }}</th><th>{{ t("read.att.type") }}</th><th>{{ t("mail.col.size") }}</th><th>SHA-256</th></tr>
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
      </HkSectionCard>
    </template>
  </div>
</template>

<style scoped>
.read { max-width: 860px; margin: 0 auto; display: flex; flex-direction: column; gap: 14px; }
.read-top { display: flex; gap: 8px; align-items: center; }
.read h2 { margin: 0; font-size: 1.3rem; }
.read-route { margin: 0; font-size: 0.85rem; }
.read-body {
  white-space: pre-wrap;
  /* The HkCard surface grammar (card blend over the page surface). */
  background: color-mix(in srgb, rgb(var(--color-surface)) 70%, transparent);
  border: 1px solid rgb(var(--color-border, 35 42 55) / 60%);
  border-radius: 12px;
  padding: 16px;
}
.read-body.html { white-space: normal; }
.read-body.html :deep(a) { color: rgb(var(--color-primary, 108 178 255)); }
.read-body.html :deep(img),
.read-body.html :deep(video),
.read-body.html :deep(iframe) { display: none; }
.read-links { margin: 0; padding-left: 18px; }
.read-links li { margin-block: 4px; }
.read-attachments { width: 100%; border-collapse: collapse; font-size: 13px; }
.read-attachments th,
.read-attachments td { text-align: left; padding: 6px 8px; border-bottom: 1px solid rgb(var(--color-border, 35 42 55)); }
.read-attachments code { font-size: 11px; word-break: break-all; }
</style>
