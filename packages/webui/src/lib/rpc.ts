/**
 * The JSON-RPC WebSocket client — the family transport, lean edition.
 *
 * Reconnect with capped backoff, one pending-map by request id, the bearer
 * token injected into every call's params, and a reactive connection state
 * the footer status light consumes. Application errors arrive as the
 * family envelope: code -32000 with a `"<Path>: <prose>"` message — the
 * path prefix is the machine channel.
 */

export class RpcError extends Error {
  readonly path: string;
  readonly prose: string;

  constructor(message: string) {
    super(message);
    const idx = message.indexOf(": ");
    this.path = idx > 0 ? message.slice(0, idx) : "Rpc.Unknown";
    this.prose = idx > 0 ? message.slice(idx + 2) : message;
  }
}

export type ConnectionState = "connected" | "connecting" | "reconnecting" | "disconnected";

/** Invoked when the server answers Session.Required — the session is
 *  gone (expired or service restart); the host clears the token and
 *  returns to the login page instead of leaving a dead shell up. */
export const onSessionRequired: { handler: (() => void) | null } = {
  handler: null,
};

type Pending = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: number;
};

const TOKEN_KEY = "ayane.session";

export function sessionToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setSessionToken(token: string | null): void {
  if (token === null) localStorage.removeItem(TOKEN_KEY);
  else localStorage.setItem(TOKEN_KEY, token);
}

export class RpcClient {
  private socket: WebSocket | null = null;
  private pending = new Map<number, Pending>();
  private nextId = 1;
  private retry = 0;
  private wantOpen = true;

  state: ConnectionState = "disconnected";
  onChange: ((state: ConnectionState) => void) | null = null;

  connect(): void {
    this.wantOpen = true;
    this.open();
  }

  close(): void {
    this.wantOpen = false;
    this.socket?.close();
    this.socket = null;
    this.setState("disconnected");
  }

  call<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    const token = sessionToken();
    const merged = token && !("token" in params) ? { ...params, token } : params;
    return new Promise<T>((resolve, reject) => {
      this.send(method, merged, (value) => resolve(value as T), reject);
    });
  }

  private send(
    method: string,
    params: Record<string, unknown>,
    resolve: (value: unknown) => void,
    reject: (error: Error) => void,
  ): void {
    const id = this.nextId++;
    const timer = window.setTimeout(
      () => {
        this.pending.delete(id);
        reject(new RpcError("Rpc.Timeout: no answer in 30s"));
      },
      30_000,
    );
    this.pending.set(id, { resolve, reject, timer });
    const frame = JSON.stringify({ jsonrpc: "2.0", id, method, params });
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(frame);
    } else {
      this.connect();
      const wait = window.setInterval(() => {
        if (this.socket?.readyState === WebSocket.OPEN) {
          window.clearInterval(wait);
          this.socket.send(frame);
        }
      }, 120);
      window.setTimeout(() => window.clearInterval(wait), 15_000);
    }
  }

  private open(): void {
    if (this.socket && this.socket.readyState <= WebSocket.OPEN) return;
    this.setState(this.retry === 0 ? "connecting" : "reconnecting");
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(`${proto}://${location.host}/api/ws`);
    this.socket = socket;
    socket.onopen = () => {
      this.retry = 0;
      this.setState("connected");
    };
    socket.onmessage = (event) => {
      const reply = JSON.parse(event.data as string) as {
        id?: number;
        result?: unknown;
        error?: { code: number; message: string };
      };
      if (reply.id === undefined || reply.id === null) return;
      const pending = this.pending.get(reply.id);
      if (!pending) return;
      this.pending.delete(reply.id);
      window.clearTimeout(pending.timer);
      if (reply.error) {
        const err = new RpcError(reply.error.message);
        if (err.path === "Session.Required") {
          onSessionRequired.handler?.();
        }
        pending.reject(err);
      } else {
        pending.resolve(reply.result);
      }
    };
    socket.onclose = () => {
      this.socket = null;
      for (const pending of this.pending.values()) {
        window.clearTimeout(pending.timer);
        pending.reject(new RpcError("Rpc.Disconnected: the socket went down"));
      }
      this.pending.clear();
      if (this.wantOpen) {
        this.retry += 1;
        this.setState("reconnecting");
        const delay = Math.min(800 * this.retry, 5000);
        window.setTimeout(() => this.wantOpen && this.open(), delay);
      } else {
        this.setState("disconnected");
      }
    };
  }

  private setState(state: ConnectionState): void {
    if (this.state === state) return;
    this.state = state;
    this.onChange?.(state);
  }
}

export const rpc = new RpcClient();