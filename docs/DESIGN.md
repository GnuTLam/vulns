# VulnS design: the casebook

VulnS is one hunter's casebook: every report is a case, every program a file, the money a
ledger. The interface borrows from printed ledgers and engineering notebooks — paper, ink,
pencil rules, figures set in a typewriter face, labels in the margin — and stops there. It is
a tool used every day, so it stays dense, quiet and fast; character comes from type, rules and
a few deliberate marks, never from decoration.

Read with [UI_PRINCIPLES.md](UI_PRINCIPLES.md), which holds the product rules (what a row shows,
how money and drafts are counted). This file holds the visual language.

## Who uses it, and for what

One security researcher, on a laptop most of the day and a phone in between. They open VulnS to

1. see what is waiting on them (drafts to finish, money not received) and on programs (reports
   not answered yet);
2. find a report again — by its platform ID, an endpoint, a parameter, a bug class;
3. write or paste a report and keep it as reusable knowledge;
4. know what they earned, per currency, and what is still owed.

Everything is judged against those four jobs. A screen that does not serve one of them is
reduced or removed.

## Identity

- **Paper and ink.** The page is warm paper (`--paper`); content sits on sheets (`--sheet`) with
  a 1px pencil rule (`--rule`), 4px corners, no shadow. Text is ink (`--ink`), with two lighter
  inks for secondary (`--ink-2`) and tertiary (`--ink-3`) text.
- **Primary action is ink**: a solid near-black button (`.button.primary`). There is one per
  view at most. Links and focus use the accent ink blue (`--accent`).
- **The highlighter** (`--marker`) is the one playful mark: text selection, `<mark>` in search
  hits, the stripe in the logo. Do not use it as a background for whole blocks.
- **Marginal labels.** Section names, table headers and group captions are small mono capitals
  (`.section-label`, `th`): Plex Mono 11–11.5px, uppercase, 0.05–0.06em tracking, `--ink-2/3`.
  Titles of things (a report, a program) are Plex Sans semibold, sentence case.
- **Figures are mono.** IDs, amounts, dates, counts: Plex Mono with tabular figures (`.num`,
  `.mono`, `.mono-cell`, `.date-cell`, `.amount-cell`). Amounts right-aligned in columns.
- **Colour means something or is absent.** Severity hues (`--sev-*`), status dots, money
  received (`--ok`) and owed (`--owed`), danger. Nothing else is coloured: no tinted section
  backgrounds, no gradients, no coloured icons.

## Type scale

| Use | Face | Size / weight |
| --- | --- | --- |
| Page title (`.toolbar h1`) | Sans | 22px / 600, 19px on phones |
| Sheet title, report title in a row | Sans | 14px / 600 |
| Body, controls | Sans | 13–14px / 400–500 |
| Secondary line under a title | Sans | 12px, `--ink-3` |
| Marginal label, table header | Mono caps | 11–11.5px / 500 |
| Figures | Mono | 12–13px; big numbers 20–28px / 500 |
| Report reading text (markdown) | Sans | 15px / 1.65 |

Never bigger than 28px outside the report title. No letter-spaced sans headings.

## Space and shape

- 4px grid. Sheet padding 16px (12px on phones). Gaps between sheets 20px. Page gutter 28px,
  20px under 1000px, 14px under 760px.
- Rows are 44–52px; lists are rows separated by rules, not cards in a grid.
- Radius 4px (sheets, buttons, inputs), 3px (tags, badges). No pill shapes except the status dot.
- Shadow only on things that float: the palette, drawers, dialogs, menus (`--lift`).

## Components (in `css/core.css` — use them, do not restyle them per page)

- Frame: `.page-wrap` (max 1280px), `.page-narrow` (860px reading column), `.toolbar` page head
  with `.crumbs`, `h1`, `p` lede and `.toolbar-actions`.
- Sheets: `.panel` > `.panel-head` (`.section-label` + `.meta`/`a.meta`) + `.panel-body`.
- Controls: `.button` (`.primary`, `.ghost`, `.danger`, `.compact-button`), `.text-action`,
  `.icon-button`, inputs/selects/textareas, `.segments`/`.segment` and `.period-tabs`/`.period-tab`
  (a switch; `.active` or `aria-current="page"` marks the current one).
- Data: `table` / `.registry-table` in `.table-wrap`, `.num-cell`, `.amount-cell`, `.date-cell`.
- Marks: `.severity-label.sev-*` (signal bars + word, tinted tag), `.status.<status>` (dot +
  word; `.outcome-*`, `.is-draft`), `.money` (mono amount + currency code), `.paid-badge`
  (`.is-paid` / `.is-unpaid`), `.tag`, `.bar-row` breakdowns.
- Report rows: `.vuln-list` / `.vuln-list-head` / `.vuln-row` / `.list-group` from the
  `vuln_row` and `vuln_list_head` macros. Same grammar everywhere a list of reports appears.
- Messages: `.alert` (`.danger`, `.success`, `.warning`), `.empty-state`, `.empty-compact`.

Area stylesheets (`css/<area>.css`) lay out their pages with these and add only what is
specific to the page. They use the tokens; they never hard-code a colour or define a new font.

## Layout

The masthead (52px, sticky) carries the wordmark, the six places, search (opens the palette,
Ctrl K) and "New vulnerability". Below 1000px the places move into a drawer. On program pages
the explorer tree sits on the left; below 1180px it becomes a drawer.

Pages choose the layout their job needs:

- **Registries** (vulnerabilities, programs, tags): a page head, one filter row, one sheet with
  the list or table. Filters are a single line; the count lives in the switch.
- **Dashboard**: a working surface. What needs action first and widest; money and the
  breakdown in a narrow right column; a row of key figures on top.
- **Report**: a reading column (860px) with the facts above the text; metadata and tracking
  in a side column on wide screens, under the text on narrow ones.
- **Editor**: the writing area is the page; metadata is secondary and collapsible.

## Motion

Colour and background transitions of 120ms on hover; drawers slide in 160ms. No entrance
animations, no transforms on hover, nothing that delays a click. Respect reduced motion.

## States

Every list has an empty state that says what goes there and offers the action that fills it.
Errors say what happened and what to do. Disabled controls are 50% opacity. Loading is rare
(server-rendered pages); where JS fetches, show text ("Searching…"), not a spinner.

## Do not

- Cards in a grid for things that are rows. Icons as decoration. Emoji.
- Gradients, glass, glows, coloured section backgrounds, drop shadows on sheets.
- New fonts, new colours outside the tokens, pill-shaped buttons, text in all caps outside
  marginal labels.
- Derived ages ("41 days waiting") or numbers the page cannot reconcile with another page.
