import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vitest/config";

// The desktop application's user interface. It is built into `dist/`, which
// the Tauri application embeds at compile time: nothing is ever loaded from a
// server (docs/adr/0009-desktop-application.md).
export default defineConfig({
  plugins: [svelte()],
  // Assets are referenced relative to the page, whatever origin the webview
  // serves the embedded files from.
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // WebView2 (Windows) and WebKit (macOS, Linux) of recent systems.
    target: "es2022",
    // No source maps in what ships.
    sourcemap: false,
  },
  test: {
    include: ["src/**/*.test.ts"],
  },
});
