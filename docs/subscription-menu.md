# Compact subscription menu

The shipped theme contains `umi.js`, not the original Vue source project. The
readable implementation lives in `theme/Xboard/assets/subscription-menu.mjs`.
After changing it, run:

```sh
node scripts/patch-subscription-menu.mjs
node --check theme/Xboard/assets/umi.js
node --test tests/theme/subscription-menu.test.mjs
```

The patch script embeds the helper into the bundle so the existing Blade asset
hash invalidates caches and no additional module request/MIME configuration is
required. It is repeatable and checks the integration anchors when patching an
upstream bundle for the first time. Review the anchors after any theme upgrade.

Each client has import, QR preview and copy icon buttons. Existing platform
filtering and application schemes are retained. All three actions use the same
explicit format URL; authentication and other query parameters are preserved.
General uses `flag=general`. Automatic, General and the HY2-only format have no
dedicated application scheme, so their import buttons are disabled with an
explanatory label. QR protocol filtering keeps the selected format.

Optional browser checks require Playwright, Chrome, and jsQR:

```sh
node tests/theme/subscription-menu.browser.mjs
```

If these dependencies are installed outside this repository, set
`PLAYWRIGHT_MODULE` and `JSQR_MODULE` to their absolute entry-point paths. The
test serves the actual theme locally with fixture API responses, blocks external
requests, decodes QR contents, and checks desktop, narrow, dark, and Android-UA
layouts. It writes screenshots under `/tmp/xboard-subscription-*.png`. It does
not log in to a real account or launch installed proxy applications.
