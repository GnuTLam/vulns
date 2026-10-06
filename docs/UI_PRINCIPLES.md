# UI principles

VulnS is an operator workspace. Every screen should answer one of three questions: what needs action, what changed, and where the evidence is.

## Hierarchy

1. A compact statistics strip for orientation.
2. Actionable work directly below it (the dashboard's Needs attention queue).
3. Recent records and breakdowns as supporting detail.
4. One primary action per screen; secondary actions stay neutral.
5. A component must support a decision, navigation or data entry, or it is removed.

## Layout and density

- Prefer one bordered container with internal dividers over several adjacent cards.
- Keep controls together and separate from results.
- Tables are for full registries; dashboard summaries use compact lists.
- Keep numbers, statuses and row actions aligned.
- Mobile layouts never scroll horizontally; wide registries scroll inside their own table wrapper.

## Visual language

- Neutral slate surfaces. Dark mode uses graphite, never pure black.
- Blue is reserved for navigation and primary actions; semantic colours are reserved for status and data.
- Flat surfaces: in-page panels are separated by 1 px borders, never shadows. Shadows are only for overlays.
- Corner radius stays between 6 and 8 px.
- Weight 600 only for titles, active navigation and key values. Labels are sentence case.
- No gradients, glow, fake activity indicators or decorative telemetry.

## Information

- Never rely on colour alone. Severity uses one to five bars plus a text label; status uses text plus a dot.
- Charts repeat their values as text.
- Group work by reason: the group heading states the status once, rows only call out exceptions.
- Empty states are explicit. An empty workspace shows a single getting-started panel instead of zeros.
- Amounts in different currencies are never added together.

## Interaction

- Registry rows open the record drawer; links inside rows stay keyboard accessible.
- Destructive actions sit behind a disclosure and a confirmation dialog.
- Client-side validation is a convenience; the server is authoritative.
- Motion is brief and respects `prefers-reduced-motion`.

## Definition of done

A UI change is complete when:

- it removes ambiguity or interaction cost and adds no duplicate control;
- desktop and 375 px mobile layouts have no horizontal overflow in both themes;
- text tokens meet WCAG AA contrast (covered by a test);
- the browser console has no errors and the test suite passes.
