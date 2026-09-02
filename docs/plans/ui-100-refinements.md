# UI 100/100 Refinement Plan

## Objective
Address the three remaining quality gaps to achieve 100/100 on the UI design score while preserving the minimalist monochrome visual identity and full accessibility compliance.

## Target Fixes

### 1. Dedicated Filtered & Empty States (`app/page.tsx`, `app/globals.css`)
- Import `SearchX` from `lucide-react`.
- When `secrets.length === 0`: render initial zero-state prompting to create the first secret.
- When `secrets.length > 0 && filtered.length === 0`: render filtered empty state with `role="status"`, `aria-live="polite"`, a `SearchX` icon, explanatory text, and a "Clear filter" button resetting `query` to `""`.
- Add clean, restrained `.empty-state` CSS tokens and rules to `app/globals.css`.

### 2. Subtle Card Elevation Layering (`app/globals.css`)
- Define `--shadow-card: 0 1px 2px 0 rgb(0 0 0 / 0.04)` in `:root`.
- Apply `box-shadow: var(--shadow-card)` to `.panel` and `.stats article`.
- Keep nested elements free of redundant shadow stacking.

### 3. Normalize Badge Variants & Remove Legacy Classes (`app/page.tsx`, `app/globals.css`)
- Replace legacy `.badge.good` / `.badge.bad` in `FeaturePage` with standardized `<Badge variant="...">` components.
- Standardize badge dimensions (height 22px, font-size 11px, weight 500, radius `var(--radius-sm)`).
- Remove obsolete `.badge.good` / `.badge.bad` CSS rules.

## Verification
- Run `npm run lint` and `npm test`.
- Verify responsive layout, keyboard interactions, and run `/ui-score`.
