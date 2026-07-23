// Flat ESLint config (P10) — wires the `eslint` half of the web per-language gate
// (tsc --noEmit + eslint + vitest). Security logic stays server-side; this only keeps
// the render-only UI honest. `prettier --check` handles formatting; eslint-config-prettier
// switches off rules that would fight it.
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import prettier from "eslint-config-prettier";

export default tseslint.config(
  { ignores: ["dist", "coverage", "node_modules"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2020,
      globals: { ...globals.browser },
    },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
    },
  },
  prettier,
);
