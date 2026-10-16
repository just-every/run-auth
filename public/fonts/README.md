# Fonts

Wix Madefor Display (headings) and Wix Madefor Text (body and UI) are
self-hosted under the SIL Open Font License 1.1 in `wix-madefor/LICENSE.txt`.
The Latin and Latin Extended variable WOFF2 subsets (weights 400 to 800) come
from Fontsource's `@fontsource-variable/wix-madefor-display` and
`@fontsource-variable/wix-madefor-text` 5.3.0; upstream:
https://github.com/wix/wixmadefor.

The documents link `/fonts/fonts.css` once and preload only the Latin Text
file (`src/base/font-head.ts`). Do not import this CSS from a component. Body
text uses `--font-body`, headings `--font-heading`; controls inherit them. The
run site and the `--rer-*` theme (`public/rer-theme.css`) name the same faces.
