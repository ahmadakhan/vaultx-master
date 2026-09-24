# VaultX Frontend Design System

> "Secure Minimalism" — an enterprise-grade visual language for VaultX's
> encrypted cloud storage. Clean surfaces, subtle elevation, precise
> typography, and a professional neutral palette anchored by a single deep-teal
> accent.

---

## 1. Design Philosophy

| Principle | Application |
|---|---|
| **Subtle elevation over borders** | Surfaces use soft shadows (`shadow-sm`/`shadow-md`) rather than thick borders. Borders are reserved as barely-visible dividers (`--border`). |
| **Accent only for actions** | The deep-teal primary is used on interactive elements (buttons, links, active states) — never as decoration. |
| **Typography-driven hierarchy** | Visual weight comes from font size, weight, and letter-spacing, not color. |
| **Consistent iconography** | All icons come from `lucide-react` at 20px with a 1.5px stroke. |
| **Generous whitespace** | 16px base padding, 24px between major sections, 8px baseline grid. |
| **Skeletons, not spinners** | Loading surfaces render `Skeleton` placeholders; no decorative spinners in content areas. |
| **Inline, icon-led errors** | Errors render inline with a small icon and concise message. |

---

## 2. Color System (OKLCH)

All colors are expressed in `oklch()` for perceptually uniform light/dark
switching. The deep-teal accent persists in both themes.

### Core tokens

| Token | Light | Dark |
|---|---|---|
| `--background` | `oklch(0.975 0.002 90)` ~`#FAFAFA` | `oklch(0.12 0 0)` ~`#121212` |
| `--foreground` | `oklch(0.15 0 0)` ~`#111827` | `oklch(0.985 0 0)` ~`#F9FAFB` |
| `--card` / `--surface` | `oklch(1 0 0)` ~`#FFFFFF` | `oklch(0.21 0 0)` ~`#1E1E1E` |
| `--muted` | `oklch(0.97 0 0)` | `oklch(0.23 0 0)` |
| `--muted-foreground` | `oklch(0.556 0 0)` ~`#6B7280` | `oklch(0.708 0 0)` |
| `--border` | `oklch(0.922 0 0)` ~`#E5E7EB` | `oklch(1 0 0 / 8%)` |
| `--input` | `oklch(0.96 0 0)` | `oklch(1 0 0 / 12%)` |
| `--ring` | `oklch(0.43 0.18 196)` | `oklch(0.556 0 0)` |

### Accent

| Token | Value | Hex |
|---|---|---|
| `--primary` | `oklch(0.43 0.18 196)` | `#0D9488` |
| `--primary-foreground` | `oklch(0.985 0 0)` (white) | `#FFFFFF` |
| `--accent` (hover bg, light) | `oklch(0.93 0.18 196)` | teal-100 |
| `--accent` (hover bg, dark) | `oklch(0.32 0.18 196)` | — |

Hover/active teal shades:
- Hover background tint: `bg-primary/10` or `bg-accent/50`
- The primary itself darkens via `hover:bg-primary/90`.

### Status colors (desaturated)

| Token | Value | Hex | Usage |
|---|---|---|---|
| `--success` | `oklch(0.6 0.18 140)` | `#10B981` | success badges, checks |
| `--warning` | `oklch(0.75 0.15 70)` | `#F59E0B` | warnings |
| `--info` | `oklch(0.6 0.2 250)` | `#3B82F6` | informational |
| `--destructive` | `oklch(0.54 0.22 25)` | `#F43F5E` | delete actions, errors |

### File-type accents (desaturated, colorblind-safe)

| Token | Value |
|---|---|
| `--file-pdf` | `oklch(0.54 0.22 25)` (rose) |
| `--file-word` | `oklch(0.58 0.2 230)` (blue) |
| `--file-excel` | `oklch(0.55 0.15 75)` (amber) |
| `--file-image` | `oklch(0.6 0.13 270)` (violet) |
| `--file-video` | `oklch(0.58 0.17 260)` (indigo) |
| `--file-audio` | `oklch(0.62 0.18 320)` (pink) |
| `--file-archive` | `oklch(0.58 0.17 60)` (amber) |
| `--file-code` | `oklch(0.6 0.14 80)` (amber) |
| `--file-text` | `oklch(0.6 0 0)` (neutral) |
| `--file-markdown` | `oklch(0.6 0.04 240)` (slate) |

All file icons use `lucide-react` glyphs colored via these tokens — no bright,
saturated colors.

---

## 3. Typography

Primary font: **Geist Sans** (`--font-geist-sans`, loaded in `app/layout.tsx`).
Monospace: **Geist Mono** for technical metadata / key material.

| Name | Size | Weight | Tracking | Use |
|---|---|---|---|---|
| `text-xs` | 12px | 500 | normal | tertiary / captions |
| `text-sm` | 14px | 400 | normal | primary body |
| `text-base` | 16px | 400 | normal | input fields |
| `text-lg` | 18px | 600 | normal | card titles / section bodies |
| `text-xl` | 20px | 600 | normal | table headers |
| `text-2xl` | 24px | 600 | `-0.01em` | page headings |
| `text-3xl` | 28px | 600 | `-0.01em` | H1 / display |

Semantic utility classes (defined in `app/globals.css`):

| Class | Style |
|---|---|
| `.vaultx-display` | `text-3xl font-semibold tracking-[-0.01em]` |
| `.vaultx-heading` | `text-2xl font-semibold tracking-[-0.01em]` |
| `.vaultx-subheading` | `text-lg font-semibold` |
| `.vaultx-label` | `text-sm font-medium` |
| `.vaultx-caption` | `text-xs font-medium uppercase tracking-[0.05em]` |
| `.vaultx-body` | `text-sm leading-[1.5]` |
| `.vaultx-secondary` | `text-sm text-muted-foreground leading-[1.5]` |
| `.vaultx-tertiary` | `text-xs text-muted-foreground` |

### Line height & letter-spacing
- Body text: `line-height 1.5`
- Headings: `line-height 1.3`, `letter-spacing -0.01em`
- All-caps section labels: `letter-spacing +0.05em`

---

## 4. Spacing & Elevation

- **Baseline grid**: 8px base, multiples of 4 (4, 8, 12, 16, 24, 32).
- **Component padding**: 16px standard, 12px for compact elements.
- **Section gaps**: 24px between major sections, 16px between sub-sections.
- **List item height**: minimum 48px touch target (12px vertical padding).
- **Container max-width**: 1200px (`--container-max`), 1140px for forms (`--container-form`).

### Corner radius

| Token | Value | Use |
|---|---|---|
| `--radius-sm` | 6px | small badges, inputs |
| `--radius-md` | 8px | cards, buttons, inputs |
| `--radius-lg` | 12px | large containers, modals |
| `--radius-xl` | 12px | sheets, upload zone |

### Elevation (shadows)

| Token | Light | Dark |
|---|---|---|
| `--shadow-xs` | `0 1px 2px 0 rgb(0 0 0 / 0.03)` | `0 1px 2px 0 rgb(0 0 0 / 0.15)` |
| `--shadow-sm` | `0 1px 2px 0 rgb(0 0 0 / 0.04)` | `0 1px 2px 0 rgb(0 0 0 / 0.2)` |
| `--shadow-md` | `0 2px 4px -1px rgb(0 0 0 / 0.06)` | `0 2px 4px -1px rgb(0 0 0 / 0.25)` |
| `--shadow-lg` | `0 4px 12px 0 rgb(0 0 0 / 0.08)` | `0 4px 12px 0 rgb(0 0 0 / 0.32)` |
| `--shadow-xl` | `0 8px 20px 0 rgb(0 0 0 / 0.1)` | `0 8px 20px 0 rgb(0 0 0 / 0.38)` |

---

## 5. Component Guidelines

### Buttons (`components/ui/button.tsx`)
Three-tier hierarchy, all with hover/focus/active states and `transition-all duration-150`:

| Variant | Style | Use |
|---|---|---|
| `default` | Solid deep-teal fill, `shadow-xs hover:shadow-sm` | primary actions |
| `outline` | Border + transparent bg, hover `bg-accent` | secondary actions |
| `secondary` | `bg-secondary`, hover tint | alternative actions |
| `ghost` | Text only, hover `bg-accent/50` | tertiary / icon buttons |
| `link` | Underline | inline links |

Sizes: `sm` (h-8), `default` (h-9), `lg` (h-10), `icon` (36px).

### Cards (`components/ui/card.tsx`)
`bg-card` with `border border-border shadow-sm rounded-lg`. Lifted on hover
via `hover:shadow-md`. Card titles use the `text-lg font-semibold` scale.

### Input (`components/ui/input.tsx`)
`h-10`, `rounded-md`, `border border-input`, focus ring = primary teal
(`focus-visible:ring-ring/50`). Icons placed via `absolute left-3`.

### Badges (`components/ui/badge.tsx`)
Variants: `default` (primary), `secondary`, `destructive`, `success`,
`warning`, `outline`. Rounded `md`, `text-xs font-medium`.

### Dialog (`components/ui/dialog.tsx`)
`shadow-xl`, `rounded-lg`, `border-border`. Close button in top-right with
ring offset.

### Dropdown Menu (`components/ui/dropdown-menu.tsx`)
Arrow-less, `rounded-md`, `shadow-md`, `border-border`. Items use
`focus:bg-accent/50`.

### Tooltip (`components/ui/tooltip.tsx`)
Lightweight, dependency-free (no `@radix-ui/react-tooltip`). Hover/focus
controlled via context; content renders `absolute` relative to a positioned
wrapper. Used in the collapsed sidebar.

### Skeleton (`components/ui/skeleton.tsx`)
`bg-muted animate-pulse rounded-md` — used for loading file lists and audit
tables, never a spinner.

---

## 6. UI States

### Loading
- File listings render `<FileListSkeleton />` (shimmer rows or grid cards).
- Audit logs render a table-shaped skeleton.
- Auth check renders a centered "Checking session…" with a pulsing dot.

### Empty
`<EmptyState />` — centered SVG icon, short title, supporting description,
and a primary CTA. Used for: no files, shared-with-me empty, trash empty,
logs empty.

### Error
`<ErrorState />` — inline icon (`AlertCircle` in a `bg-destructive/10`
circle), short title, message, and a "Try Again" button. Used for fetch
failures. The upload modal also shows per-file error badges.

### Populated
File grid/list with hover elevation, type-specific icons, and a shared
"Shared" badge. Three-dot context menu per file (Details, Download, Share,
Delete).

---

## 7. Dashboard Layout

### Header (`components/dashboard-layout.tsx`)
- **Left**: VaultX logo + name (deep-teal vault icon).
- **Center**: global search, `placeholder="Search Vault"` with a hidden
  `⌘K` keyboard hint visible on `sm`+ screens.
- **Right**: theme toggle (`SunMoon`) → user dropdown (avatar, Profile,
  Theme, Settings, Logout).

### Sidebar (`components/sidebar.tsx`)
- Collapsible (`w-64` / `w-14`) with a collapse toggle.
- Prominent **Upload File** CTA at the top.
- Navigation: **My Vault**, **Shared with Me**, **Trash**, **Audit Logs**.
- Active section highlighted with an accent teal **left border** and
  `bg-accent/60`.
- Collapsed icons show a **tooltip** on hover.
- Account / Settings / Logout at the bottom.

### Main content (`components/file-manager.tsx`)
- Top bar: section title, **Sort** select, item count, view toggle
  (`ViewToggle`), and **Upload** button (primary).
- Content area switches between `FileGrid`, `FileList`, `EmptyState`,
  `ErrorState`, and `FileListSkeleton`.
- `FileDetailModal` opens on row/click for metadata + activity timeline.
- `ShareModal` and `UploadModal` render as overlays.

---

## 8. Responsive Behavior (mobile-first)

| Breakpoint | Behavior |
|---|---|
| **< 640px (sm)** | Header collapses logo+name, search keeps compact width, search hint hidden. Sidebar collapses to icon-only (`w-14`) automatically on narrow screens. Grid → 2 columns. |
| **640px – 1024px (md)** | Grid → 3–4 columns. Header search hint visible. |
| **1024px – 1280px (lg)** | Grid → 4–5 columns. |
| **≥ 1280px (xl)** | Grid → 6 columns. Main content capped at `--container-max`. |

Forms cap at `--container-form` (1140px). All interactive elements respect a
minimum 48px touch target.

---

## 9. Iconography

- Library: `lucide-react@^0.542`
- Standard size: **20px**, stroke-width: **1.5**
- File-type glyphs use desaturated tokens (never bright Tailwind colors).
- Action icons (`Search`, `UploadCloud`, `Share2`, `Trash2`, `Eye`,
  `Download`, `SunMoon`, `LogOut`, …) are imported directly as components.

---

## 10. Motion

All transitions use the design tokens `--transition` (150ms) and
`--transition-slow` (250ms). No flashy animations:
- Hover elevation: `transition-shadow`
- Theme color changes: `transition-colors`
- Skeleton shimmer: `animate-pulse`
- Upload spinners: minimal `animate-spin` on status dots only

---

## 11. File Architecture

```
frontend/
├── app/
│   ├── globals.css          # design tokens + base typography + utilities
│   ├── layout.tsx           # fonts, theme provider
│   ├── page.tsx             # login route (centered card)
│   └── dashboard/
│       └── page.tsx         # auth guard + FileManager
├── components/
│   ├── file-manager.tsx      # orchestrator (crypto + state)
│   ├── dashboard-layout.tsx  # top header
│   ├── sidebar.tsx           # collapsible nav + upload CTA
│   ├── file-grid.tsx         # grid view + card + context menu
│   ├── file-list.tsx         # list view + row + context menu
│   ├── file-icon.tsx         # shared type-specific icon component
│   ├── file-skeleton.tsx     # loading skeletons
│   ├── file-detail-modal.tsx # metadata + activity timeline
│   ├── upload-modal.tsx      # encrypted upload wizard
│   ├── share-modal.tsx       # RSA key share management
│   ├── empty-state.tsx       # empty states
│   ├── error-state.tsx       # inline error states
│   ├── view-toggle.tsx       # grid/list radio toggle
│   ├── sort-select.tsx       # sort + applySort helper
│   ├── logs.tsx              # audit trail
│   └── trash.tsx             # trashed files
├── components/ui/            # shadcn-style primitives
│   ├── button.tsx, card.tsx, input.tsx, badge.tsx
│   ├── dialog.tsx, dropdown-menu.tsx, select.tsx
│   ├── avatar.tsx, checkbox.tsx, switch.tsx
│   ├── label.tsx, progress.tsx, separator.tsx
│   ├── skeleton.tsx, tooltip.tsx   # new
│   └── ...
├── lib/
│   ├── types.ts              # shared FileItem / RawFile types
│   ├── api.ts
│   └── crypto/               # AES / RSA / key derivation
└── hooks/useAuth.ts
```

---

## 12. Usage Notes

- The design system is expressed entirely through **CSS custom properties**
  in `app/globals.css`. Tailwind's `@theme inline` block maps these to
  color utilities (`bg-primary`, `text-muted-foreground`, `shadow-sm`, …), so
  existing shadcn component APIs need no breaking changes.
- Dark mode is opt-in via the `class="dark"` toggle in the header (powered by
  `next-themes`). All tokens have light/dark definitions.
- To keep the accent trustworthy, reserve `--primary` (deep teal) for
  **actions and active states only**; use `--muted` and `--muted-foreground`
  for passive surfaces.
