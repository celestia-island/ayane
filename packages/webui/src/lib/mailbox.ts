/** Mailbox state shared across the shell and the list view.
 *
 *  The sidebar's 收件箱 badge must update while the user is INSIDE the
 *  inbox view (read/unread flips, mail arriving), so the count lives in
 *  one module-scope ref that InboxView writes after every load and the
 *  shell's nav reads at render — the same direction chest's nav badges
 *  flow, just with a store small enough to not need pinia.
 */
import { ref } from "vue";

/** Unread count of the INBOX mailbox (IMAP STATUS UNSEEN). */
export const inboxUnread = ref(0);
