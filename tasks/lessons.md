# Lessons — frisk

- **Evidence anchors need unique field paths.** Any `(field_path, offset)` evidence scheme
  requires every path to resolve to exactly ONE string. Dict keys vs. values collided on the
  same path in the leaf walker (§2 review); key leaves now get a `#key` suffix. When adding
  new leaf sources, add them to `test_leaf_walker_field_paths_are_unique`.
- **Schema keywords are leaf noise.** `_walk` yields JSON Schema structural keys (`type`,
  `properties`, `description`) as `#key` leaves. Detectors matching generic words must not
  anchor on schema-keyword leaves (D3/D4: match property names by position, not any leaf).
