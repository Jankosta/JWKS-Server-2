module.exports = {
  env: {
    node: true,
    es2021: true,
    jest: true,
  },
  extends: 'airbnb-base',
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module',
  },
  rules: {
    'no-underscore-dangle': 'off',
    'no-console': 'off',
    // on Windows Git checkout will typically use CRLF; disable this rule to avoid false positives
    'linebreak-style': 'off',
    // Allow some inconsistent returns and unnamed functions. This avoids invasive
    // refactors in this exercise and keeps the focus on the project requirements.
    'consistent-return': 'off',
    'func-names': 'off',
  },
};
