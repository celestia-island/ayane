<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";

import { rpc } from "../lib/rpc";
import { t } from "../lib/i18n";
import { toastError } from "../lib/toast";

interface EnvelopeRow {
  uid: number;
  from: string | null;
  subject: string | null;
  seen: boolean;
  size: number;
}

const props = defineProps<{ mailbox: string }>();
const router = useRouter();
const messages = ref<EnvelopeRow[]>([]);
const loading = ref(true);

onMounted(async () => {
  try {
    const result = await rpc.call<{ messages: EnvelopeRow[] }>("mail.list", {
      mailbox: props.mailbox,
      limit: 50,
    });
    messages.value = result.messages;
  } catch (e) {
    toastError(e);
  } finally {
    loading.value = false;
  }
});

function open(uid: number): void {
  router.push({ path: `/read/${uid}`, query: { box: props.mailbox } });
}
</script>

<template>
  <div>
    <p v-if="loading" class="muted">{{ t("inbox.loading") }}</p>
    <p v-else-if="messages.length === 0" class="muted">{{ t("inbox.empty") }}</p>
    <ul v-else class="list">
      <li v-for="row in messages" :key="row.uid" :class="{ unread: !row.seen }" @click="open(row.uid)">
        <span class="from">{{ row.from || "(无发件人)" }}</span>
        <span class="subject">{{ row.subject || "(无主题)" }}</span>
        <span class="size muted">{{ Math.max(1, Math.round(row.size / 1024)) }}K</span>
      </li>
    </ul>
  </div>
</template>

<style scoped lang="scss">
.list {
  list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px;
  li {
    display: grid; grid-template-columns: 220px 1fr 48px; gap: 10px;
    padding: 10px 12px; border-radius: 10px; background: #161c27;
    border: 1px solid #232a37; cursor: pointer; align-items: center;
    &:hover { border-color: #3b7fc4; }
    &.unread .subject { font-weight: 700; }
    .from { color: #aab3c5; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .subject { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .size { text-align: right; }
  }
}
</style>