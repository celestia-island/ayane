<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { ArrowLeft, ShieldAlert, FileLock2, SquarePen } from "lucide-vue-next";

import { HkButton, HkDateTag, HkSectionCard, HkTag } from "@celestia-island/hikari";

import { rpc } from "../lib/rpc";
import { t } from "../lib/i18n";
import { toastError } from "../lib/toast";
import { identityParams } from "../lib/identity";

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
  cc: string[];
  bcc: string[];
  date: string | null;
  subject: string | null;
  text: string | null;
  html: string | null;
  attachments: AttachmentMeta[];
}

const props = defineProps<{ uid: number; mailbox: string; embedded?: boolean }>();
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
      ...identityParams(),
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
  <div :class="{ read: true, 'read-embedded': props.embedded }">
    <div v-if="!props.embedded" class="read-top">
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
      <div class="read-headers">
        <div class="read-header-row">
          <span class="read-header-label">{{ t("read.from") }}</span>
          <span class="read-header-value">
            <HkTag size="sm">{{ message.from || t("mail.unknownSender") }}</HkTag>
          </span>
        </div>
        <div class="read-header-row">
          <span class="read-header-label">{{ t("read.to") }}</span>
          <span class="read-header-value">
            <HkTag v-for="addr in message.to" :key="addr" size="sm">{{ addr }}</HkTag>
            <span v-if="!message.to.length">—</span>
          </span>
        </div>
        <div v-if="message.cc.length" class="read-header-row">
          <span class="read-header-label">{{ t("read.cc") }}</span>
          <span class="read-header-value">
            <HkTag v-for="addr in message.cc" :key="addr" size="sm" variant="info">{{ addr }}</HkTag>
          </span>
        </div>
        <div v-if="message.bcc.length" class="read-header-row">
          <span class="read-header-label">{{ t("read.bcc") }}</span>
          <span class="read-header-value">
            <HkTag v-for="addr in message.bcc" :key="addr" size="sm" variant="info">{{ addr }}</HkTag>
          </span>
        </div>
        <div v-if="message.date" class="read-header-row">
          <span class="read-header-label">{{ t("read.date") }}</span>
          <span class="read-header-value">
            <HkDateTag :value="message.date" time />
          </span>
        </div>
      </div>
      <hr class="read-divider" />

      <HkSectionCard
        v-if="suspicious.length"
        :title="t('read.suspicious', { n: suspicious.length })"
        :icon="ShieldAlert"
        level="h3"
        padded
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
.read { display: flex; flex-direction: column; gap: 14px; width: 100%; max-width: 860px; margin: 0 auto; }
.read-embedded { max-width: none; }
.read-top { display: flex; gap: 8px; align-items: center; }
.read h2 { margin: 0; font-size: 1.3rem; }
/* The envelope header is a LABEL BLOCK, not a card: the reader already
 * frames the body, and a second outline directly above it reads as one
 * frame too many (field report). No border, no fill — the rows align with
 * the subject above and the body below. */
.read-headers {
  display: flex;
  flex-direction: column;
  gap: 3px;
  padding: 0;
}

.read-header-row {
  display: flex;
  gap: 10px;
  align-items: baseline;
  min-width: 0;
}

.read-header-label {
  flex: none;
  width: 4rem;
  font-size: 0.72rem;
  color: rgb(var(--color-muted));
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.read-header-value {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px;
  min-width: 0;
  font-size: 0.85rem;
  color: rgb(var(--color-text));
  overflow-wrap: anywhere;
}
/* A message body is text, not a panel: no frame, no fill. The envelope
 * above it is separated by a divider instead, so a plain-text mail reads
 * as one column instead of a box inside a box. */
.read-body {
  white-space: pre-wrap;
  padding: 0;
  background: none;
  border: 0;
}

/* The envelope/body divider: one faint rule, the full measure. */
.read-divider {
  margin: 2px 0 4px;
  border: 0;
  border-top: 1px solid var(--border-faint, rgb(var(--color-border) / 12%));
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
