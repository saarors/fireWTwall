@echo off
cd /d C:\Users\Saar\fireWTwall
git add -A
git commit -m "Add Bun package support" -m "" -m "- Add bunfig.toml with Bun configuration" -m "- Update nodejs/package.json to include Bun runtime and scripts" -m "- Add docs/nodejs/bun.md with complete Bun documentation" -m "- Update README.md with Bun badges and installation instructions" -m "- Update docs/index.md to reference Bun support" -m "- Update docs/nodejs/installation.md with Bun installation instructions" -m "" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
git push
