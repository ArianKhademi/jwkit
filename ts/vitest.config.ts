import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      reporter: ['text', 'json-summary'],
      // The CI gate. Lines is the figure quoted in the README; the others
      // are held to the same bar so it cannot be met by one easy metric.
      thresholds: { lines: 90, statements: 90, functions: 90, branches: 90 },
    },
  },
})
