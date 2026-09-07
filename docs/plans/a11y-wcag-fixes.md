# Plan: Accessibility (WCAG 2.2 AA) Remediation

## Objective
Remediate accessibility violations identified during the accessibility audit across `app/layout.tsx`, `app/globals.css`, and `app/page.tsx` to achieve full WCAG 2.2 AA compliance.

## Target Files
1. `app/layout.tsx` — Add accessible skip-to-content bypass link.
2. `app/globals.css` — Fix color contrast ratios (`--text-subtle`, `--sidebar-text-muted`), enhance search input `:focus-within` styling, and verify focus ring offsets.
3. `app/page.tsx` — Add missing `DialogDescription`, improve touch targets for user menu actions, fix icon color contrast (`text-amber-600`), and ensure ARIA table semantics and form associations.

---

## Detailed Step-by-Step Implementation

### Step 1: Add "Skip to Main Content" Bypass Link (`app/layout.tsx`)
- **Problem**: Keyboard users must tab through all navigation items before reaching dashboard content.
- **Change**: Add an accessible skip link immediately inside `<body>` pointing to `#main-content`, styled to be visually hidden until focused via keyboard (`sr-only focus:not-sr-only`).

### Step 2: Fix Color Contrast & Focus Visible Tokens (`app/globals.css`)
- **Problem**: 
  - `--text-subtle` (`#a1a1aa` on `#ffffff`) is only 2.37:1 contrast ratio.
  - `--sidebar-text-muted` (`#71717a` on `#09090b`) is 4.12:1 contrast ratio.
  - `.searchbox input` disables `outline: 0;` without styling `.searchbox:focus-within`.
- **Change**:
  - Update `--text-subtle` to `#71717a` (4.6:1 ratio, passing 4.5:1 AA standard).
  - Update `--sidebar-text-muted` to `#9ca3af` (6.5:1 ratio, passing 4.5:1 AA standard).
  - Add `.searchbox:focus-within` with `outline: 2px solid var(--focus-ring); outline-offset: 1px;` so keyboard users have clear visual focus feedback.

### Step 3: Enhance Modal & Component Accessibility (`app/page.tsx`)
- **Problem**: 
  - `DialogContent` lacks `DialogDescription` which causes Radix UI warnings and reduces context for screen readers.
  - User menu action button in sidebar is undersized (~22px).
  - Amber warning icon in posture score has low contrast (2.1:1 with `text-amber-500`).
  - Secret table rows lack ARIA row/grid relationships.
- **Change**:
  - Import and add `DialogDescription` to the secret creation modal.
  - Increase the user action button touch target to minimum 36px with `size-8 flex items-center justify-center` and proper focus ring.
  - Update posture check icon from `text-amber-500` to `text-amber-600` / `text-amber-700` (> 3.0:1 contrast).
  - Add `role="table"`, `role="rowgroup"`, `role="row"`, `role="columnheader"`, and `role="cell"` attributes to the secret table grid.

---

## Design Decisions and Alternatives

1. **Skip link implementation**:
   - *Alternative rejected*: Placing the skip link inside `app/page.tsx`.
   - *Reason*: `app/layout.tsx` is the root layout for all pages in Next.js App Router, ensuring the bypass link works uniformly across the entire application without duplicating code.
2. **Table ARIA Roles vs Semantic HTML `<table>`**:
   - *Alternative rejected*: Complete rewrite of CSS grid into native `<table>`, `<thead>`, `<tbody>` elements.
   - *Reason*: The existing layout uses responsive CSS grid classes (`display: grid` with media queries for compact screen breakpoints). Native tables often break responsive flex/grid layouts on small screens without extensive CSS overrides. Adding standard ARIA roles (`role="table"`, `role="row"`, `role="cell"`, etc.) gives 100% assistive technology parity while preserving responsive styling.

---

## Verification
1. Verify keyboard navigation: Tab through page to ensure skip link works, focus rings appear around search box, and all interactive elements are reachable.
2. Verify contrast ratios pass WCAG AA (>= 4.5:1 for body/muted text, >= 3.0:1 for non-text graphics).
3. Test dialog open/close with keyboard and verify no console warnings from Radix UI.
