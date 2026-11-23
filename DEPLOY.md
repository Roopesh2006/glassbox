# GlassBox — 5-Minute Publish & Go-Viral Deployment Guide

Follow these 4 steps in order to publish GlassBox cleanly to GitHub + PyPI and launch for maximum star velocity.

---

## Step 1 — Unzip & Test Locally (30 Seconds)

```bash
unzip glassbox.zip
cd glassbox
pip install -e .
python3 -m unittest discover -s tests -v
glassbox demo
```

All 10 tests should pass with 0 warnings.

---

## Step 2 — Push to GitHub (1 Minute)

Run the bundled publisher script (handles `git init`, commit, public repo creation, and adding all 20 high-discovery GitHub Topics):

```bash
chmod +x push-to-github.sh
./push-to-github.sh
```

Then in your new GitHub repo's **Settings → General → Social Preview**:
- Upload `assets/social-preview.png` (1280×640 dark terminal preview ready to go).

---

## Step 3 — Publish `glassbox-firewall` to PyPI So Users Can Run `uvx glassbox-firewall demo` (2 Minutes)

Zero-friction `uvx` / `pip install` install is one of the biggest multipliers for GitHub star conversion. This repo already includes `.github/workflows/release.yml` configured for PyPI Trusted Publishing:

1. Create a free account at [pypi.org](https://pypi.org) (enable 2FA).
2. Go to **PyPI → Your Account → Publishing → Add a new pending publisher**:
   - PyPI Project Name: `glassbox-firewall`
   - Owner: `<your-github-username>`
   - Repository name: `glassbox`
   - Workflow name: `release.yml`
3. Push the release tag from your terminal:
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```
4. GitHub Actions automatically runs all 10 tests, builds the wheel, and publishes `glassbox-firewall` to PyPI. Anyone in the world can now run `uvx glassbox-firewall demo` in one command!

---

## Step 4 — Execute the 24-Hour Coordinated Viral Launch

Open [LAUNCH_PLAYBOOK.md](LAUNCH_PLAYBOOK.md) for the exact:
1. **40-second demo video script** (record with Screen Studio / OBS / asciinema; 3-second hook showing `SHADOW_SIMULATE` catching `.env` exfiltration in `0.04ms`, zero logo sting, burned-in captions).
2. **Tuesday–Thursday 8:30 AM ET launch schedule** (compress Show HN + X native video + `r/ClaudeCode` + `r/LocalLLaMA` + `r/programming` into one 24-hour window to cross the 80+ stars/day GitHub Trending threshold).
3. **Copy-paste Show HN title & first comment, X thread, and problem-framed Reddit posts.**
4. **5 `good first issue` tickets** to open right after publishing so contributors immediately engage.
