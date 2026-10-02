// Conventional Commits, checked in CI (.github/workflows/commit-convention.yml).
module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    // The component goes in the scope, `fix(bootstrap): …`, never as the type.
    'type-enum': [
      2,
      'always',
      ['feat', 'fix', 'perf', 'refactor', 'build', 'docs', 'test', 'ci', 'chore', 'style', 'revert'],
    ],
    // Subjects are truncated wherever they are displayed; the default 100 is the spec's own guidance.
    'header-max-length': [2, 'always', 100],
    // Dependabot always writes a leading capital ("Bump x from a to b") and cannot be told not to.
    // PascalCase and ALL CAPS stay rejected.
    'subject-case': [2, 'never', ['pascal-case', 'upper-case']],
  },
}
