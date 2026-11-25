/// <reference types="vite/client" />
declare module "*.vue" {
  import type { DefineComponent } from "vue";
  const component: DefineComponent<object, object, unknown>;
  export default component;
}

// ScreenOrientation.lock is experimental; hikari's source uses it and the
// workspace lib types do not declare it.
interface ScreenOrientation {
  lock(orientationLock: string): Promise<void>;
}
