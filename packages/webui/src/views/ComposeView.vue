<script setup lang="ts">
import { onMounted, ref } from "vue";
import { FileDown, Files, Paperclip, Send, X } from "lucide-vue-next";
import { useRoute, useRouter } from "vue-router";

import {
  HkButton,
  HkInput,
  HkMenu,
  HkModal,
  HkSectionCard,
  HkSelect,
  type HkMenuItem,
} from "@celestia-island/hikari";

import { rpc } from "../lib/rpc";
import { t } from "../lib/i18n";
import { toastError, toastSuccess } from "../lib/toast";

interface Identity {
  address: string;
  display_name: string;
  kind: "personal" | "shared";
}

interface Template {
  id: string;
  owner: string;
  name: string;
  subject: string;
  body: string;
}

interface DraftAttachment {
  filename: string;
  content_type: string;
  /** Raw File held client-side until the send. */
  file: File;
}

const route = useRoute();
const router = useRouter();
const from = ref("");
const to = ref("");
const subject = ref("");
const body = ref("");
const busy = ref(false);
const savingDraft = ref(false);
/** The draft being edited (send retires it; a plain send passes nothing). */
const draftUid = ref<number | null>(null);

const identities = ref<Identity[]>([]);
const templates = ref<Template[]>([]);
const attachments = ref<DraftAttachment[]>([]);
const templateMenuOpen = ref(false);
const templateMenuAnchor = ref<HTMLElement | null>(null);
const saveTemplateOpen = ref(false);
const templateName = ref("");

const identityOptions = ref<{ value: string; label: string }[]>([]);

async function loadIdentities(): Promise<void> {
  try {
    const result = await rpc.call<{ identities: Identity[] }>("mail.fromAddresses");
    identities.value = result.identities;
    identityOptions.value = result.identities.map((identity) => ({
      value: identity.address,
      label: `${identity.display_name} <${identity.address}> · ${
        identity.kind === "shared" ? t("compose.fromShared") : t("compose.fromPersonal")
      }`,
    }));
    if (!from.value) from.value = result.identities[0]?.address ?? "";
  } catch (e) {
    toastError(e);
  }
}

async function loadTemplates(): Promise<void> {
  try {
    const result = await rpc.call<{ templates: Template[] }>("mail.templates.list");
    templates.value = result.templates;
  } catch {
    // The template menu simply stays empty — composing must not block.
  }
}

function addFiles(files: FileList | File[]): void {
  for (const file of Array.from(files)) {
    attachments.value.push({
      filename: file.name,
      content_type: file.type || "application/octet-stream",
      file,
    });
  }
}

function onAttachPick(e: Event): void {
  const input = e.target as HTMLInputElement;
  if (input.files) addFiles(input.files);
  input.value = "";
}

function onDrop(e: DragEvent): void {
  if (e.dataTransfer?.files.length) {
    addFiles(e.dataTransfer.files);
    e.preventDefault();
  }
}

function removeAttachment(index: number): void {
  attachments.value.splice(index, 1);
}

function applyTemplate(id: string): void {
  const template = templates.value.find((tpl) => tpl.id === id);
  templateMenuOpen.value = false;
  if (!template) return;
  if (!subject.value) subject.value = template.subject;
  body.value = template.body;
}

async function saveAsTemplate(): Promise<void> {
  if (!templateName.value.trim()) return;
  try {
    await rpc.call("mail.templates.save", {
      name: templateName.value.trim(),
      subject: subject.value,
      body: body.value,
    });
    toastSuccess(t("compose.templateSaved"));
    saveTemplateOpen.value = false;
    templateName.value = "";
    await loadTemplates();
  } catch (e) {
    toastError(e);
  }
}

onMounted(async () => {
  void loadIdentities();
  void loadTemplates();

  const draftParam = Number(route.query.draft);
  if (!route.query.draft || !Number.isInteger(draftParam) || draftParam <= 0) return;
  // Continue a draft: the composer fields come back from the parsed draft
  // (X-Ayane-Draft-To carries the recipient exactly as it was typed).
  try {
    const result = await rpc.call<{
      message: { to: string[]; draft_to?: string | null; subject: string | null; text: string | null };
    }>("mail.read", { uid: draftParam, mailbox: "Drafts", markSeen: false });
    to.value = result.message.draft_to ?? result.message.to[0] ?? "";
    subject.value = result.message.subject ?? "";
    body.value = result.message.text ?? "";
    draftUid.value = draftParam;
  } catch (e) {
    toastError(e);
  }
});

async function send(): Promise<void> {
  busy.value = true;
  try {
    const payload: Record<string, unknown> = {
      to: to.value,
      subject: subject.value,
      body: body.value,
      format: "markdown",
      ...(from.value ? { from: from.value } : {}),
      ...(draftUid.value ? { draftUid: draftUid.value } : {}),
    };
    // Attachments ride base64; each file is read once before the call.
    if (attachments.value.length) {
      const encoded = await Promise.all(
        attachments.value.map(async (attachment) => ({
          filename: attachment.filename,
          content_type: attachment.content_type,
          data: await fileToBase64(attachment.file),
        })),
      );
      payload.attachments = encoded;
    }
    await rpc.call("mail.send", payload);
    toastSuccess(t("compose.sent"));
    draftUid.value = null;
    window.setTimeout(() => router.push("/inbox"), 700);
  } catch (e) {
    toastError(e);
  } finally {
    busy.value = false;
  }
}

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result);
      resolve(result.slice(result.indexOf(",") + 1));
    };
    reader.onerror = () => reject(new Error("read failed"));
    reader.readAsDataURL(file);
  });
}

async function saveDraft(): Promise<void> {
  savingDraft.value = true;
  try {
    await rpc.call("mail.saveDraft", { to: to.value, subject: subject.value, body: body.value });
    toastSuccess(t("compose.draftSaved"));
  } catch (e) {
    toastError(e);
  } finally {
    savingDraft.value = false;
  }
}

</script>

<template>
  <div class="compose" @dragover.prevent @drop="onDrop">
    <HkSectionCard :title="t('compose.button')" padded>
      <div class="compose-fields">
        <HkSelect
          v-model="from"
          :label="t('compose.from')"
          :options="identityOptions"
        />
        <HkInput v-model="to" type="email" required :label="t('compose.to')" placeholder="someone@example.com" />
        <HkInput v-model="subject" :label="t('compose.subject')" />
        <HkInput v-model="body" type="textarea" :rows="12" :label="t('compose.body')" />
      </div>

      <div v-if="attachments.length" class="compose-attachments">
        <span class="muted">{{ t("compose.attachments") }}:</span>
        <span v-for="(att, i) in attachments" :key="att.filename + i" class="compose-attachment">
          <Paperclip :size="12" />
          {{ att.filename }}
          <button class="compose-attachment-x" type="button" @click="removeAttachment(i)">
            <X :size="12" />
          </button>
        </span>
      </div>

      <div class="compose-actions">
        <HkButton type="submit" :disabled="busy || !to" @click="send">
          <Send :size="14" /> {{ t("compose.send") }}
        </HkButton>
        <HkButton variant="ghost" :disabled="savingDraft || busy" @click="saveDraft">
          <FileDown :size="14" /> {{ t("compose.saveDraft") }}
        </HkButton>
        <HkButton
          variant="ghost"
          :ref="(el: unknown) => { if (el && '$el' in (el as object)) templateMenuAnchor = ((el as { $el: HTMLElement }).$el); }"
          @click="templateMenuOpen = !templateMenuOpen"
        >
          <Files :size="14" /> {{ t("compose.templates") }}
        </HkButton>
        <label class="compose-attach">
          <input type="file" multiple @change="onAttachPick" />
          <HkButton variant="ghost" type="button" tabindex="-1" tag="span">
            <Paperclip :size="14" /> {{ t("compose.attachments") }}
          </HkButton>
        </label>
        <HkButton variant="ghost" type="button" @click="router.push('/inbox')">
          {{ t("compose.cancel") }}
        </HkButton>
      </div>
    </HkSectionCard>

    <HkMenu
      :open="templateMenuOpen"
      :anchor-ref="templateMenuAnchor"
      placement="bottom-start"
      :title="t('compose.templates')"
      :items="templates.map((tpl): HkMenuItem => ({ key: tpl.id, label: tpl.name }))"
      @update:open="(v: boolean) => { if (!v) templateMenuOpen = false; }"
      @select="(key: string) => applyTemplate(key)"
    />

    <HkModal
      :model-value="saveTemplateOpen"
      :title="t('compose.saveAsTemplate')"
      width="22rem"
      @update:model-value="(v: boolean) => { saveTemplateOpen = v; }"
    >
      <div class="compose-tpl-form">
        <HkInput v-model="templateName" :label="t('compose.templateName')" />
        <div class="compose-tpl-actions">
          <HkButton size="sm" :disabled="!templateName.trim()" @click="saveAsTemplate">
            {{ t("admin.save") }}
          </HkButton>
        </div>
      </div>
    </HkModal>
  </div>
</template>

<style scoped>
.compose { max-width: 760px; margin: 0 auto; }
.compose-fields { display: flex; flex-direction: column; gap: 12px; }
.compose-attachments { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 12px; }
.compose-attachment {
  display: inline-flex; align-items: center; gap: 4px;
  font-size: 0.8rem; padding: 2px 8px; border-radius: 999px;
  background: rgb(var(--color-surface)); border: 1px solid rgb(var(--color-border) / 60%);
}
.compose-attachment-x { border: 0; background: none; cursor: pointer; display: inline-flex; padding: 0; color: inherit; opacity: 0.6; }
.compose-attachment-x:hover { opacity: 1; }
.compose-actions { display: flex; gap: 10px; align-items: center; margin-top: 16px; flex-wrap: wrap; }
.compose-attach input { display: none; }
.compose-tpl-form { display: flex; flex-direction: column; gap: 12px; }
.compose-tpl-actions { display: flex; justify-content: flex-end; }
</style>
