// SAST config for the Security page's "supply chain" scan
// (backend/services/supply_chain.py) — deliberately scoped to
// eslint-plugin-security's rules only, not a general code-style lint
// (no project-wide .eslintrc exists, and this isn't the place to add one).
import security from 'eslint-plugin-security'
import tsParser from '@typescript-eslint/parser'

export default [
  {
    files: ['src/**/*.ts', 'src/**/*.tsx'],
    languageOptions: {
      parser: tsParser,
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    plugins: { security },
    rules: {
      ...security.configs.recommended.rules,
    },
  },
]
