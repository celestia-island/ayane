import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import vueSfc from "@vitejs/plugin-vue";
import vueJsx from "@vitejs/plugin-vue-jsx";
import { defineConfig } from "vite";

const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")) as {
  version?: string;
};

/** Build identity: `<version> <branch>:<hash7>` — the family version-line
 *  shape the About card and the status bar render. `unknown` when git is
 *  unavailable; a build must not break over a missing stamp.
 *
 *  `AYANE_BUILD_COMMIT` pins the stamp for a build whose output is
 *  COMMITTED: the tree that produces `dist` cannot know the hash of the
 *  commit that will contain it (baking HEAD in would make every dist carry
 *  its parent's hash — the 6df8ba8/a0d77ae drift), so such a build names
 *  the revision it was made FROM explicitly. An unpinned build (a
 *  developer's local run) keeps stamping HEAD, which is right for output
 *  that is never committed. */
function buildVersion(): string {
  const version = pkg.version ?? "0.0.0";
  const pinned = process.env.AYANE_BUILD_COMMIT?.trim();
  if (pinned) {
    return `${version} ${process.env.AYANE_BUILD_BRANCH?.trim() ?? "master"}:${pinned}`;
  }
  try {
    const branch = execSync("git rev-parse --abbrev-ref HEAD", { encoding: "utf8" }).trim();
    const hash = execSync("git rev-parse --short=7 HEAD", { encoding: "utf8" }).trim();
    return `${version} ${branch}:${hash}`;
  } catch {
    return `${version} unknown`;
  }
}

// Build-only config (family convention: no dev server, no HMR, no proxy —
// rebuilds are driven externally and the dist is embedded into the binary).
export default defineConfig({
  plugins: [vueSfc(), vueJsx()],
  define: {
    __AYANE_VERSION__: JSON.stringify(buildVersion()),
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
  },
  server: { hmr: false },
});
