# Minimal UI Redesign Plan

## Objective
Transform the AegisVault user interface from a crowded, colorful design into a clean, minimal, distraction-free security dashboard (inspired by Linear and modern Cloudflare/Vercel dashboards).

## Key Design Decisions & Alternatives

1. **Color Palette: Neutral Monochrome vs Multi-color Accent System**
   - *Choice*: Clean slate/zinc monochrome palette with subtle semantic indicators (subtle emerald for active/healthy, subtle amber for warning, clean neutral borders).
   - *Alternative Considered*: Keeping vibrant gradients and bright purple/cyan/amber icons.
   - *Why Rejected*: High saturation and colorful badges create visual noise and distract from critical security data.

2. **Typography & Layout Spacing: Compact Cramped vs Structured Breathing Room**
   - *Choice*: Clean standard typography scale (13px/14px body, refined 12px metadata, clear tabular monospace for keys/hashes), with 24px-32px padding and crisp 1px neutral borders.
   - *Alternative Considered*: Dense micro-fonts (8px-10px) with heavy nested panels.
   - *Why Rejected*: Dense micro-fonts make auditing and inspecting secrets harder to scan and read quickly.

3. **Sidebar & Navigation: Clean Unified Minimalist Sidebar**
   - *Choice*: Subtle dark zinc (`#0f172a` / `#111827`) or sleek neutral dark sidebar with subtle hover highlights, clear icon-label pairings, and neat category grouping.
   - *Alternative Considered*: Loud multi-color badges and avatar gradients.
   - *Why Rejected*: A minimalist sidebar keeps focus squarely on the content and operational actions.

## Files to Modify
1. `app/globals.css`:
   - Replace complex gradients and micro-font styles with a minimalist design token system (clean grays, subtle borders, refined card states, clean secret tables).
2. `app/page.tsx`:
   - Refactor page layout, overview cards, and secret tables into clean, minimal components with clear hierarchy, smooth search filtering, reveal/copy toggles, and unified modals.

## Verification Plan
1. Ensure the development server compiles without errors (`curl -I http://localhost:5173`).
2. Test responsive layout and navigation across tabs (Overview, Secrets, Certificates, KMS, Access, Audit logs).
3. Test secret creation, reveal, copy-to-clipboard, and environment switching.
