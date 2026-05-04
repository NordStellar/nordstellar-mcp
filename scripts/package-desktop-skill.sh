#!/usr/bin/env bash
set -euo pipefail

# Packages the individual skills/ directories into a single ZIP suitable for
# Claude Desktop (Settings > Skills > Import).
#
# Output: dist/nordstellar.zip
#
# Structure inside the ZIP:
#   nordstellar/
#   ├── SKILL.md          (generated from nordstellar-general + reference links)
#   └── references/
#       ├── attack-surface-management.md
#       ├── dark-web-search.md
#       ├── domain-squatting.md
#       └── malware-infection-analysis.md

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILLS_DIR="$REPO_ROOT/skills"
DIST_DIR="$REPO_ROOT/dist"
BUILD_DIR="$DIST_DIR/.build/nordstellar"

MAIN_SKILL="nordstellar-general"
REFERENCE_SKILLS=(
  "attack-surface-management"
  "dark-web-search"
  "domain-squatting"
  "malware-infection-analysis"
)

DESCRIPTION="NordStellar threat intelligence via MCP: leaked data, attack surface, dark web, domain squatting, and malware analysis."

strip_frontmatter() {
  # Remove YAML frontmatter (everything between the first two --- lines)
  awk 'BEGIN{fm=0} /^---$/{fm++; next} fm>=2{print}' "$1"
}

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/references"

# --- Main SKILL.md ---
{
  cat <<EOF
---
name: nordstellar
description: "${DESCRIPTION}"
---
EOF

  strip_frontmatter "$SKILLS_DIR/$MAIN_SKILL/SKILL.md"

  cat <<'EOF'

---

## Additional references

For deeper coverage of each domain, Claude will load these automatically when relevant:

- [Attack Surface Management](references/attack-surface-management.md) — scans, templates, facets, search filters, activity logs
- [Dark Web Search](references/dark-web-search.md) — Lucene syntax, tag filtering, recursive investigation strategy
- [Domain Squatting](references/domain-squatting.md) — permutation forensics, WHOIS, AI analysis, case workflow, events feed
- [Malware Infection Analysis](references/malware-infection-analysis.md) — stealer log drill-down, cookie/session risk, reporting template
EOF
} > "$BUILD_DIR/SKILL.md"

# --- Reference files (strip frontmatter from each) ---
for skill in "${REFERENCE_SKILLS[@]}"; do
  strip_frontmatter "$SKILLS_DIR/$skill/SKILL.md" > "$BUILD_DIR/references/$skill.md"
done

# --- Create ZIP ---
mkdir -p "$DIST_DIR"
rm -f "$DIST_DIR/nordstellar.zip"
(cd "$DIST_DIR/.build" && zip -r "../nordstellar.zip" nordstellar/)

# Cleanup build artifacts
rm -rf "$DIST_DIR/.build"

echo ""
echo "✓ dist/nordstellar.zip created"
echo "  Import in Claude Desktop → Settings > Skills > + > Upload a skill"
