# UI Quality and Accessibility Cleanup Plan

## Overview
Perform a focused accessibility (a11y), responsive touch-target, design token, keyboard navigation, and logical spacing cleanup on `app/page.tsx` and `app/globals.css`, strictly preserving the minimalist monochrome UI.

## Scope of Changes

### 1. Form Accessibility (`app/page.tsx`)
- Add explicit `id` and `htmlFor` bindings to all form fields in the Add/Create Secret modal (`secret-key`, `secret-value`, `secret-path`).
- Add accessible labels / `aria-label` to the search input (`search-secrets`).

### 2. Icon-Only Buttons & Semantic Accessibility (`app/page.tsx`)
- Ensure all interactive buttons have `type="button"` unless explicitly submitting forms.
- Add descriptive `aria-label` and `aria-pressed` to the reveal/hide button (e.g., `aria-label={isRevealed ? \`Hide \${s.key} value\` : \`Reveal \${s.key} value\`}`).
- Add descriptive `aria-label` to the copy button (`aria-label={\`Copy \${s.key} to clipboard\`}`).
- Add descriptive `aria-label` to dropdown menu triggers (`aria-label={\`More options for \${s.key}\`}`).
- Add `aria-hidden="true"` to decorative Lucide icons inside labelled controls.
- Maintain strict secret masking: no secret values exposed in `aria-label`, toast notifications, or logs.

### 3. Design Tokens, Colors & Nested Radii (`app/globals.css`)
- Replace hardcoded hex colors (`#ffffff`, `#09090b`, `#27272a`, `#18181b`, `#3f3f46`, `#a1a1aa`, `#71717a`, `#e4e4e7`, etc.) with semantic CSS variables (`--surface`, `--surface-muted`, `--surface-hover`, `--text-main`, `--text-muted`, `--border`, `--focus-ring`).
- Introduce structured radius tokens (`--radius-sm: 4px`, `--radius-md: 6px`, `--radius-lg: 8px`). Ensure `inner = outer - padding` geometry for nested elements like `brand-mark` inside `sidebar`.
- Add global `:focus-visible` styling using `outline: 2px solid var(--focus-ring, var(--text-main))` and `outline-offset: 2px`.
- Add `@media (prefers-reduced-motion: reduce)` rules for motion accessibility.

### 4. Row-Action Touch Targets & Control Heights (`app/globals.css`, `app/page.tsx`)
- Standardize `.searchbox`, tabs, and toolbar buttons to `36px` (`h-9`).
- Increase row action button touch targets to `36px × 36px` desktop and `40px` on mobile using logical properties (`inline-size`, `block-size`, `min-inline-size`, `min-block-size`) while keeping icons centered at 14–16px.
- Use logical spacing properties (`margin-inline-start`, `margin-inline-end`, `padding-inline-start`, `padding-inline-end`) and replace physical `mr-1.5` with `me-1.5`.

## Verification Steps
1. Run `npx tsc --noEmit` to verify type safety.
2. Run `npm run build` or dev server verification.
3. Test keyboard focus, screen reader attributes, and touch-target sizing.
