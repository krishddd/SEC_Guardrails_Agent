// Flat ESLint config (P10). NOTE: typescript-eslint pins `typescript <6.1.0` and hard-errors
// on this repo's TypeScript 7 (Dependabot #62), so it is intentionally NOT used — eslint lints
// JS/config only here. The .ts/.tsx sources are covered by `tsc --noEmit` (types) and
// `prettier --check` (style); re-add typescript-eslint once it ships TS 7 support.
import js from "@eslint/js";
import globals from "globals";
import prettier from "eslint-config-prettier";

export default [
  { ignores: ["dist", "coverage", "node_modules", "**/*.ts", "**/*.tsx"] },
  js.configs.recommended,
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: { ...globals.node, ...globals.browser },
    },
  },
  prettier,
];
