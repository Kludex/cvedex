import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"));
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.toml" },
        miniflare: {
          bindings: {
            CVE_API_URL: "https://cveawg.test",
            CVE_API_ORG: "acme",
            CVE_API_USER: "service@acme.test",
            CVE_API_KEY: "service-key",
            TEST_MIGRATIONS: migrations,
          },
        },
      }),
    ],
    test: {
      setupFiles: ["./test/apply-migrations.ts"],
      coverage: {
        provider: "istanbul",
        include: ["src"],
        thresholds: { 100: true },
      },
    },
  };
});
