# PWA icons

`icon.svg` is the source-of-truth brand mark. The PNG variants referenced by
`manifest.webmanifest` (`icon-192.png`, `icon-512.png`) are not committed and
must be generated locally before a production build.

## Generate the PNG icons

Pick one of the following workflows. Output should live next to this README at
`frontend/public/icons/icon-192.png` and `frontend/public/icons/icon-512.png`.

### Option 1: `svg-to-png-cli` (no install)

```bash
cd frontend/public/icons
npx svg-to-png-cli icon.svg -o icon-192.png -w 192 -h 192
npx svg-to-png-cli icon.svg -o icon-512.png -w 512 -h 512
```

### Option 2: `sharp` (Node)

```bash
npx --yes sharp-cli -i icon.svg -o icon-192.png resize 192 192
npx --yes sharp-cli -i icon.svg -o icon-512.png resize 512 512
```

### Option 3: ImageMagick / rsvg

```bash
rsvg-convert -w 192 -h 192 icon.svg > icon-192.png
rsvg-convert -w 512 -h 512 icon.svg > icon-512.png
# or
magick convert -background none -resize 192x192 icon.svg icon-192.png
magick convert -background none -resize 512x512 icon.svg icon-512.png
```

### Option 4: Manual export

Open `icon.svg` in Figma, Sketch, or Affinity Designer and export 192x192 and
512x512 PNGs with a transparent or `#0a0a0a` background.

## Why no PNG checked in

PWA icons are binary build artifacts. We avoid committing them so the brand
asset stays in sync with `icon.svg` and small tweaks do not pollute git
history. The Apple touch icon link in `index.html` and the `manifest.webmanifest`
both expect these files to exist at deploy time.
