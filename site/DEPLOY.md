# Deploying the WebRecon landing page on Vercel

This folder is a single static `index.html` — no build step.

1. Push this repo to GitHub.
2. On https://vercel.com → **Add New… → Project → Import** your repo.
3. In the project settings set **Root Directory = `site`**.
4. Framework preset: **Other** (it's plain static). Deploy.

The **Download for Windows** button links to
`…/releases/latest/download/webrecon.exe`, which always serves the newest
release's exe. So **publish a GitHub Release first** (push a `v*` tag — the
`.github/workflows/release.yml` workflow builds `webrecon.exe` and attaches it
automatically), otherwise the button 404s until a release exists.
