# Carapax website

The production site is the static HTML, CSS, JavaScript, and SVG in `public/`.
Vercel serves that directory using the `vercel-build` script. No framework or
new runtime dependency is required.

## Recorded scenario explorer

The explorer deliberately displays recorded evaluations instead of claiming
to evaluate user input live. Generate its public JSON from the core with:

```sh
npm run site:fixtures
```

Three inputs demonstrate hostile web content, an authenticated principal's
preference, and that same preference attributed to an untrusted web source.
No API keys or remote inference are used. The browser only fetches the static
scenario file. Fixture hashes are hashes of these public example strings.

## Verify

```sh
npm run site:check
```

This recomputes the fixtures against the core, executes the copyable Node.js
example, and checks local assets and fragment targets. CI runs this gate.
Integration examples live in `public/examples.js`; keep the initial HTML
Node.js example in sync for visitors without JavaScript.

For visual QA, serve `public/` with a local static server. Check desktop and
mobile layouts, all three scenarios, raw results, code-tab keyboard controls,
copy feedback, and native details controls. Reduced motion is respected. Fonts
come from Google Fonts with local fallbacks; application code has no analytics.

## Evidence

The site cites the September 4, 2026 local run of `npm run bench`: 0/30 attack
promotions for Carapax, 25/30 for the naive filter, and 30/30 without a gate.
Heuristic recall was 14/30; benign flags were 1/25, and trusted benign memory
blocks were 0/16. These are a small internal corpus, not an independent audit.
Latency numbers are deliberately omitted because they vary with hardware.
