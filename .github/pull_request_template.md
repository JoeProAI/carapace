## Summary

What this PR changes and why.

## Verify gate

Confirm the checks pass locally (CI runs the same):

- [ ] `npm run typecheck`
- [ ] `npm test`
- [ ] `npm run demo`
- [ ] `npm run redteam`
- [ ] Worker (if touched): `cd worker && npm run typecheck && npm test`

## Project rules

- [ ] No fake data or invented benchmarks. Numbers come from a real run or cited prior work.
- [ ] Strict TypeScript, named exports, no `any`.
- [ ] No em dashes in prose, no emoji.
- [ ] Core library in `src/` stays zero-runtime-deps; model detection lives in the Worker.
- [ ] The promotion gate still decides on provenance; the model verdict only raises the injection signal.

## Notes

Anything reviewers should know (caveats, follow-ups, screenshots).
