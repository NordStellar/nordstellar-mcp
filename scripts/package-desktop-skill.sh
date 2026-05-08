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
#       └── *.md          (one file per non-main skill, frontmatter stripped)

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILLS_DIR="$REPO_ROOT/skills"
DIST_DIR="$REPO_ROOT/dist"
BUILD_DIR="$DIST_DIR/.build/nordstellar"

MAIN_SKILL="nordstellar-general"

DESCRIPTION="NordStellar threat intelligence via MCP: leaked data, attack surface, dark web, domain squatting, malware analysis, compliance and audit workflows, and related investigations."

strip_frontmatter() {
  # Remove YAML frontmatter (everything between the first two --- lines)
  awk 'BEGIN{fm=0} /^---$/{fm++; next} fm>=2{print}' "$1"
}

reference_title() {
  # Prefer the first Markdown H1 in the body (after frontmatter).
  local md="$1"
  local slug="$2"
  local t
  t="$(strip_frontmatter "$md" | grep -m1 '^# ' | sed 's/^# //')"
  if [[ -n "${t// /}" ]]; then
    printf '%s' "$t"
    return
  fi
  # Fallback: slug words → Title Case (portable; no bash 4 substring ops)
  echo "$slug" | tr '-' ' ' | awk '{for(i=1;i<=NF;i++){$i=toupper(substr($i,1,1)) substr($i,2)} print}'
}

# All skill dirs except the main hub that contain SKILL.md (sorted).
REFERENCE_SKILLS=()
while IFS= read -r _dir; do
  [[ -f "$_dir/SKILL.md" ]] || continue
  REFERENCE_SKILLS+=("$(basename "$_dir")")
done < <(find "$SKILLS_DIR" -mindepth 1 -maxdepth 1 -type d ! -name "$MAIN_SKILL" | LC_ALL=C sort)

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

EOF
  for skill in "${REFERENCE_SKILLS[@]}"; do
    md="$SKILLS_DIR/$skill/SKILL.md"
    title="$(reference_title "$md" "$skill")"
    printf -- '- [%s](references/%s.md)\n' "$title" "$skill"
  done
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
