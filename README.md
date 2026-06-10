# Secura

Secura is a dark, editorial cybersecurity publication built as a static multi-page site.

## Pages

- `index.html` - homepage with category filters and placeholder cards
- `threat-report-emotet.html` - reusable long-form article template
- `dashboard.html` - archive page with category filters
- `about.html` - mission, scope, and disclaimer

## Design Direction

- Black-first visual system with layered near-black surfaces
- Editorial typography using `Inter` for body copy and `Space Grotesk` for headings
- Minimal cyan and emerald accents used only for emphasis
- Simple content structure with no fabricated case studies

## Interactions

- Dark theme toggle between `Black` and `Graphite`
- Search overlay triggered from navigation or `/`
- Sticky mobile-friendly navigation
- Category filters for `CTF Walkthrough` and `Malware Analysis`
- Sticky article table of contents with active section highlighting
- Copy buttons for code blocks and table values
- Search and CSV export for the article table

## Files

- `styles-new.css` - shared design system and responsive layout
- `app.js` - theme, search, navigation, TOC, copy, and IOC tooling

## Usage

Open `index.html` in a browser to explore the site locally.
