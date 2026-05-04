---
name: dark-web-search
version: 1.2.0
description: "NordStellar dark web search via GraphQL: ad-hoc search across forums, Telegram, ransomware blogs, and marketplaces."
metadata:
  nordstellar:
    category: "threat-intelligence"
    requires:
      tools: ["graphql_query", "search_types", "get_type_definition"]
---

# NordStellar — Dark Web Search

Search scraped dark web content via the NordStellar GraphQL API across four source types: forum threads, Telegram channel messages, ransomware group posts, and marketplace listings.

## Agent expectations (volume, coverage, and narrowing)

This API rewards **iteration**, not a single perfect query. Posts use slang, typos, leet, alternate brand spellings, and different languages; the same incident may appear only in **one** forum, **one** channel, or **one** timeframe. You must run **many** searches—across **all four** endpoints, with **multiple query variants** (aliases, handles, domains, threat keywords), and often with **`searchContentsTags`**, **`postedAt` / `scrapedAt`**, and **Lucene field** filters—to approximate complete coverage. Treat “I ran one search” as **incomplete**: it is **easy to miss** relevant rows because you only paginated the first page, used wording the author did not use, skipped a source type, or hit the **`totalCount` ceiling**.

**When results are too many** (`totalCount` in the thousands, or stuck at **10000**): the string is usually **too broad**. Narrow systematically—add required clauses (`AND`, `+terms`), combine subject with threat signals (stealer, ransomware, RDP, etc.), restrict the date range, add GraphQL **`searchContentsTags`**, scope to **`content:`** vs **`title:`**, or use endpoint-specific fields (**`site_domain_name`**, **`channel_name`**). Split one vague query into **several tighter queries** (per alias, per source, or per threat angle) instead of trying to “read” an enormous hit set.

Follow **Recursive Investigation Strategy** below; it is the operational pattern for systematic coverage.

## PREREQUISITE

All dark web queries require a `projectId`. Call `projectsV2` first to get one:

```graphql
query {
  projectsV2(take: 10) {
    items { id name }
  }
}
```

## Ad-hoc Search Queries

There are four search queries — one per source type. All share the same input shape and `skip`/`take` pagination (max 100 per page).

| Query | Source | Unique response fields |
|-------|--------|------------------------|
| `forumsSearchContents` | Dark web forum threads | `threadName`, `threadPost`, `forumName`, `forumSection`, `screenshotIdentifier` |
| `telegramSearchContents` | Telegram channel messages | `messageHeadline`, `messageContent`, `channelName` |
| `ransomwareSearchContents` | Ransomware group blogs | `messageHeadline`, `messageContent`, `aiDescription`, `victimInformation` |
| `marketplacesSearchContents` | Dark web marketplaces | `messageHeadline`, `marketplaceContent`, `price`, `marketplaceType`, `domainName`, `screenshotIdentifier` |

### Input shape (same for all four)

```graphql
input ListForumsSearchContentsInput {
  projectId: UUID!                         # required
  query: String!                           # Lucene query string
  searchContentsTags: [SearchContentsTag!]! # [] to search all tags, or filter by tag enum values
  scrapedAt: DateRangeInput                # optional: { from: DateTime, to: DateTime }
  postedAt: DateRangeInput                 # optional: { from: DateTime, to: DateTime }
  highlightParameters: HighlightParametersInput # optional: { preTags: ["<em>"], postTags: ["</em>"] }
}
```

### Forum search example

```graphql
query($listForumsSearchContentsInput: ListForumsSearchContentsInput!, $skip: Int, $take: Int) {
  forumsSearchContents(listForumsSearchContentsInput: $listForumsSearchContentsInput, skip: $skip, take: $take) {
    totalCount
    pageInfo { hasNextPage }
    items {
      id
      threadName
      author
      forumName
      forumSection
      threadPost
      postedAt
      scrapedAt
      url
      tags
      screenshotIdentifier
    }
  }
}
```

Variables:
```json
{
  "listForumsSearchContentsInput": {
    "projectId": "<projectId>",
    "query": "\"acme.com\" OR \"Acme Corp\"",
    "searchContentsTags": []
  },
  "skip": 0,
  "take": 20
}
```

### Telegram search example

```graphql
query($listTelegramSearchContentsInput: ListTelegramSearchContentsInput!, $skip: Int, $take: Int) {
  telegramSearchContents(listTelegramSearchContentsInput: $listTelegramSearchContentsInput, skip: $skip, take: $take) {
    totalCount
    pageInfo { hasNextPage }
    items {
      id
      messageHeadline
      channelName
      author
      messageContent
      postedAt
      url
      tags
    }
  }
}
```

### Ransomware search example

```graphql
query($listRansomwareSearchContentsInput: ListRansomwareSearchContentsInput!, $skip: Int, $take: Int) {
  ransomwareSearchContents(listRansomwareSearchContentsInput: $listRansomwareSearchContentsInput, skip: $skip, take: $take) {
    totalCount
    pageInfo { hasNextPage }
    items {
      id
      messageHeadline
      author
      aiDescription
      postedAt
      url
      tags
      victimInformation {
        companyName
        website
        industry
        country { name }
        companySize
        revenueRange
        addressLocation
      }
    }
  }
}
```

### Marketplace search example

```graphql
query($listMarketplacesSearchContentsInput: ListMarketplacesSearchContentsInput!, $skip: Int, $take: Int) {
  marketplacesSearchContents(listMarketplacesSearchContentsInput: $listMarketplacesSearchContentsInput, skip: $skip, take: $take) {
    totalCount
    pageInfo { hasNextPage }
    items {
      id
      messageHeadline
      price
      marketplaceType
      author
      domainName
      marketplaceContent
      postedAt
      url
      tags
      screenshotIdentifier
    }
  }
}
```

## Tag Filtering with `searchContentsTags`

Tags are a **GraphQL enum** (`SearchContentsTag`) — they are defined in the schema, not stored in the database, so there is no runtime API call to list them. To always get the current full list, call:

```
get_type_definition(type_name: "SearchContentsTag")
```

Pass `[]` to search across all content regardless of tag. Pass one or more tag values to restrict results to that content category.

**Full tag reference** (call `get_type_definition` for the authoritative list):

| Tag | What it covers |
|-----|----------------|
| `COMBO_LIST` | Username/password credential lists |
| `DATABASE` | Leaked database dumps |
| `STEALER_MALWARE_LOGS` | Infostealer / malware log exports |
| `CREDIT_CARDS` | Stolen payment card data |
| `MALWARE` | Malware samples, builders, or discussion |
| `EXPLOIT` | Exploits, PoCs, vulnerability discussion |
| `RANSOMWARE` | Ransomware incidents and victim posts |
| `ACCOUNT_TAKE_OVER` | ATO attacks, credential stuffing |
| `SOURCE_CODE` | Leaked proprietary source code |
| `LIVE_ACCESS` | Active access for sale (RDP, shells, VPN, SMTP) |
| `PHISHING` | Phishing kits, campaigns, infrastructure |
| `SOFTWARE` | Software piracy, cracking, keygens |
| `CRYPTO` | Cryptocurrency theft or scams |
| `BOTNET` | Botnet infrastructure or logs |
| `PROXY` | Proxy / anonymisation services |
| `DRUGS` | Drug market listings |
| `WEAPONS` | Weapons listings |
| `FRAUD` | Financial fraud tools and services |
| `IDENTITY_DOCUMENTS` | Stolen IDs, passports, DL |
| `SSN_LIST` | Social Security Number lists |
| `EMAIL_LIST` | Bulk email / contact lists |
| `IP_LIST` | IP lists (proxies, scanners) |
| `COOKIES` | Stolen browser cookie exports |
| `CONFIGURATION_FILES` | Leaked config files |
| `ANDROID_PACKAGE` | Android APKs (malicious or pirated) |
| `TOP200_CF` … `TOP1000000_CF` | Cloudflare top-N domain signal (the target domain ranks in the top N globally) |
| `OTHER` | Uncategorised content |

**Tag filtering examples:**

```json
// All content (no filter)
{ "searchContentsTags": [] }

// Only credential leaks
{ "searchContentsTags": ["COMBO_LIST", "DATABASE", "STEALER_MALWARE_LOGS"] }

// Only access sales
{ "searchContentsTags": ["LIVE_ACCESS"] }

// Software piracy only
{ "searchContentsTags": ["SOFTWARE"] }

// High-value targets (Cloudflare top 5000 domains, any threat type)
{ "searchContentsTags": ["TOP5000_CF"] }
```

## Query String Syntax

The `query` field accepts **Lucene query syntax** (Elasticsearch classic query string behavior). Never pass prose — always build explicit terms, phrases, and field filters.

### Indexed fields (per API — important)

Each search endpoint indexes **different field names**. Using a field that does not exist on that index returns a GraphQL error: **`Invalid Lucene query.`** with extension code **`INVALID_LUCENE_QUERY`** (the entire search call fails).

| Field | `forumsSearchContents` | `telegramSearchContents` | `ransomwareSearchContents` | `marketplacesSearchContents` |
|-------|------------------------|---------------------------|----------------------------|------------------------------|
| `content` | yes | yes | yes | yes |
| `title` | yes | yes | yes | yes |
| `author_name` | yes | yes | yes | yes |
| `tags` | yes | yes | yes | yes |
| `site_domain_name` | yes (forum / paste host) | **no** — invalid | **no** — invalid | yes (listing domain) |
| `channel_name` | **no** — invalid | yes (Telegram channel) | **no** — invalid | **no** — invalid |

**What each field searches (conceptually):**

| Lucene field | Meaning |
|--------------|--------|
| `content` | Main body text: forum `threadPost`, Telegram `messageContent`, ransomware blog / victim narrative text, marketplace listing body (`marketplaceContent`). Use for raw mentions, IOCs, and long-form discussion. |
| `title` | Short headline / title line: forum `threadName`, Telegram `messageHeadline`, ransomware `messageHeadline`, marketplace `messageHeadline`. Use when the subject is likely only in the subject line. |
| `author_name` | Poster or seller handle (maps to `author` in API responses where present). Use to follow a specific actor across queries. |
| `tags` | Classification labels stored in the search index (values align with **`SearchContentsTag`** — uppercase, e.g. `tags:MALWARE`). Distinct from GraphQL `searchContentsTags`, which is a separate filter on the request. |
| `site_domain_name` | Host / site where the content was scraped **(forums and marketplaces only)** — e.g. forum or market onion / domain. Not valid for Telegram or ransomware search. |
| `channel_name` | Telegram channel identifier / name field in the index **(Telegram only)**. Not valid for forums, ransomware, or marketplaces. |

Unscoped terms (no `field:` prefix) search the index’s **default combined text** (typically body + headline + author + tags, depending on backend mapping). Use explicit `content:` or `title:` when you need to **force** where matching should occur.

**Practical use:**

- **Forums / marketplaces:** narrow by host with `site_domain_name:` plus a token or wildcard fragment (e.g. a market hostname substring). Prefer mid‑pattern wildcards (`*onion*`) over a bare leading `*` on the whole term; behaviour matches classic Lucene wildcard rules.
- **Telegram:** narrow to a channel with `channel_name:ChannelName` (combine with `content:` / `title:` for topic terms).
- **Ransomware:** victim domains and company names live in the general text index — use `content:`, `title:`, or unscoped terms; there is **no** `site_domain_name` / `channel_name` on this index.
- **When unsure:** omit the field prefix to search the default combined fields, or use `content:` to force the body/text index only.

### totalCount ceiling and “too many results”

`totalCount` is **capped at 10000**. If you see exactly **10000**, the true number of matches may be larger—you cannot tell how much larger from this field alone.

Interpret volume:

- **Hundreds to low thousands** — still noisy; plan extra narrowing or more pages if the topic is narrow.
- **Near or at 10000** — query is **too loose** for safe review; **do not** treat “first page only” as a survey of the set.

**Narrow aggressively** until `totalCount` drops to a level you can paginate through or reason about:

1. Add **conjunctive** terms: `AND`, `+must terms`, parentheses so OR‑lists do not widen too far.
2. Add **time bounds**: `postedAt` / `scrapedAt` on the input when you have a plausible window.
3. Add **GraphQL `searchContentsTags`** when the threat category is known (e.g. stealer logs vs. access sales).
4. Use **Lucene fields**: `content:` vs `title:`; on Telegram use `channel_name:` for a known channel; on forums/marketplaces use `site_domain_name:` for a known host.
5. **Split** one broad string into several queries (per brand alias, per actor handle, per keyword cluster) instead of one mega‑OR.

Use **narrower** queries when you need to **compare** two strategies (only sub‑cap counts are comparable).

### Phrase search
Wrap multi-word terms in double quotes. This is the single most important construct — always use it for company names, domains, and specific terms:

```
"acme corp"
"acme.com"
"data breach"
```

### Boolean operators
Operators must be **uppercase** (`AND`, `OR`, `NOT`). Lowercase `and` / `or` are **not** Boolean operators — they are searched as **words**, which can explode noise and push `totalCount` to the 10000 ceiling.

```
"acme.com" OR "acmecorp.com" OR "acme corp"

"acme.com" AND (breach OR leak OR dump OR credentials)

"acme.com" AND NOT "press release"
```

### Required terms (`+`)

Lucene **`+term`** means “must appear”. Use it for strict conjunctive matching when you want more control than implicit AND between simple tokens:

```
+nordvpn +breach
+content:credentials +"company name"
```

### Grouping
Use parentheses to control operator precedence. `AND` does not bind tighter than `OR` automatically — always group explicitly:

```
# Without grouping — ambiguous:
"acme" OR "acmecorp" AND breach

# With grouping — explicit:
("acme" OR "acmecorp") AND (breach OR leak OR dump)
```

### Wildcards
`*` matches zero or more characters. `?` matches exactly one character. **Leading** `*` on a token is usually invalid in classic Lucene wildcard rules; prefer mid‑pattern wildcards (`*onion*`, `nord*`) or field‑scoped queries.

```
acme*          # matches acme, acmecorp, acme123
nordvp?        # matches nordvpn, nordvpm
channel_name:* # valid on Telegram only — see **Indexed fields** table above
site_domain_name:*onion*  # valid on forums/marketplaces — scope to onion domains
```

Avoid putting `*` **inside** a quoted phrase; build separate wildcard terms or use field + unquoted wildcard instead.

### Special character escaping
Escape these characters with a backslash when they appear literally in a search term:
`+ - = & | > < ! ( ) { } [ ] ^ " ~ * ? : \ /`

```
# Searching for a domain with a dot — dot is safe unescaped in most positions,
# but quote the whole phrase to be safe:
"acme.com"

# Searching for an email address:
"user\@acme.com"
```

### Tags in Lucene (`tags:`) vs GraphQL `searchContentsTags`

The Lucene field **`tags:`** takes values aligned with the **`SearchContentsTag`** enum (uppercase, e.g. `tags:MALWARE`, `tags:LIVE_ACCESS`). Values that are **not** valid enum labels behave like a non‑existent tag — you typically get **0 hits**, not a validation error.

GraphQL input **`searchContentsTags`** applies a **separate** document filter at query time. Combine both when you need “enum‑accurate tag in the index **and** a restricted category filter”.

Non‑enum words like `tags:critical` will not work unless `critical` is a real tag value (it is not in `SearchContentsTag`).

### Fuzzy and proximity (supported syntax)

These parse successfully on the backend; usefulness depends on how the text was tokenised:

- **Fuzzy:** `nordvpn~2` (edit distance on the preceding term)
- **Phrase slop:** `"data breach"~3` (words may be farther apart in the phrase match)

Use sparingly — they widen recall and can flood results (especially near the `totalCount` cap).

### Invalid queries

Malformed syntax or **wrong field for that API** → search field is `null` and `errors[]` contains `INVALID_LUCENE_QUERY`. Fix the string and retry — there is no partial result.

### Building effective queries

**Start broad, then narrow.** Do not over-constrain the first query — dark web authors do not write like PR teams:

```
# Too narrow (will miss most real content):
"Acme Corporation Data Breach 2025 Leaked Employee Records"

# Too broad (returns noise):
breach

# Right level — brand + threat signal:
("acme.com" OR "Acme Corp") AND (breach OR leak OR dump OR credentials OR database)
```

**Use vendor/brand names, not product names.** Dark web posts rarely use formal product or bundle names:

```
# Unlikely to appear verbatim on dark web:
"Complete Access Bundle subscription"

# What actors actually write:
"Slate Digital" AND (crack OR keygen OR R2R OR patch)
```

**Combine multiple aliases and typos:**

```
("nordvpn" OR "nordsec" OR "nord vpn" OR "nordvpn.com")
```

**Threat-type query patterns:**

```
# Credential exposure
("acme.com" OR "Acme Corp") AND (leak OR breach OR dump OR combolist OR "combo list" OR credentials OR password)

# Ransomware victim lookup
("Acme Corp" OR "acme.com" OR "acmecorp.com")

# Access sale (initial access broker)
("acme.com" OR "Acme Corp") AND (RDP OR VPN OR shell OR access OR "remote desktop")

# Stealer logs
("acme.com" OR "Acme Corp") AND (stealer OR infostealer OR redline OR raccoon OR vidar OR lumma)

# Threat actor tracking
"threat_actor_handle"

# Software piracy
"VendorName" AND (crack OR cracked OR keygen OR R2R OR patch OR serial OR bypass)
```

## Pagination

Results use `skip`/`take` (max 100 per page). Always check `totalCount` and `pageInfo.hasNextPage`:

```json
{ "skip": 0,  "take": 20 }   // page 1
{ "skip": 20, "take": 20 }   // page 2
{ "skip": 40, "take": 20 }   // page 3
```

Paginate whenever `pageInfo.hasNextPage` is `true` or `totalCount` exceeds `skip + take`. Relevant findings are frequently not in the first page.

## Recursive Investigation Strategy

A single query is rarely sufficient to claim coverage (see **Agent expectations**). Use this loop:

### Round 1 — Cast wide across all sources

Run the same broad query across all four sources. Use `searchContentsTags: []`:

```
forumsSearchContents      → query: ("target.com" OR "Target Corp")
telegramSearchContents    → query: ("target.com" OR "Target Corp")
ransomwareSearchContents  → query: ("target.com" OR "Target Corp")
marketplacesSearchContents → query: ("target.com" OR "Target Corp")
```

Note `totalCount` for each. Sources with zero results can be deprioritised. Sources with hundreds of results need pagination and refinement.

### Round 2 — Extract identifiers and re-query

From Round 1 results, extract:
- **`author`** names / handles that appear repeatedly
- **`forumName`** / `channelName` with high concentrations of relevant posts
- **`tags`** that appear on matching results (use these to narrow `searchContentsTags`)
- **Domains**, company names, aliases mentioned in post content

Feed each extracted identifier back as a new targeted query:

```
# Author seen repeatedly in Round 1 forum results
forumsSearchContents  → query: "threat_actor_handle"
telegramSearchContents → query: "threat_actor_handle"

# Forum with many hits — find more from that same forum
forumsSearchContents  → query: ("target.com") + narrow by forumName if possible

# Tags from results reveal content category — filter on them
forumsSearchContents  → query: "target.com", searchContentsTags: ["DATABASE", "COMBO_LIST"]
```

### Round 3 — Refine with threat context

With the picture from Rounds 1–2, run targeted queries combining the original subject with specific threat terminology you've now observed:

```
# If Round 1/2 showed stealer log references
forumsSearchContents → query: ("target.com") AND (redline OR lumma OR vidar OR stealer OR infostealer)

# If a specific threat actor was identified
forumsSearchContents → query: "confirmed_actor_handle" AND ("target.com" OR "target corp")
telegramSearchContents → query: "confirmed_actor_handle"

# If a specific breach date was observed — narrow the time window
postedAt: { from: "2025-01-01T00:00:00Z", to: "2025-06-30T23:59:59Z" }
```

### Round 4 — Exhaust pagination on high-value results

For any query where `totalCount` is significantly higher than what you've seen, paginate through all pages before concluding. A `totalCount` of 500 with only 20 results reviewed is not a complete investigation.

### Stop condition

Stop when:
- No new actor names, forum names, domains, or aliases emerge from a round
- All high-`totalCount` result sets have been paginated through
- All four sources have been queried with the final refined terms

**Source characteristics:**

| Use case | Best source |
|----------|-------------|
| Software piracy, cracked tools | Forums |
| Credential dumps, combo lists | Forums + Telegram |
| Threat actor communications, data drops | Telegram |
| Corporate victim identification | Ransomware |
| Stolen card data, stealer logs, RDP/VPN access sales | Marketplace |

## Monitoring Rules (Pre-configured Alerts)

In addition to ad-hoc searches, NordStellar supports persistent monitoring rules that continuously scan dark web sources for a saved search filter.

```graphql
# List monitoring rules for a project
query {
  darkWebMonitoringRules(projectId: "<projectId>", skip: 0, take: 20) {
    totalCount
    items {
      id
      name
      description
      sourceTypes
      lastDetectedAt
      darkWebMonitoringSearchFilter { name query tags }
    }
  }
}
```

### Listing hits from monitoring (alerts)

Ad-hoc search APIs (`forumsSearchContents`, etc.) are separate from **monitoring hits**. Alert rows are project **event projections**. List them with `eventsProjectionsV2` and `EventProjectionType`:

- `DARK_WEB_FORUM_POST`
- `DARK_WEB_TELEGRAM_POST`
- `DARK_WEB_RANSOMWARE_POST`
- `DARK_WEB_MARKETPLACE_POST`

```graphql
query DarkWebForumAlerts($projectId: UUID!) {
  eventsProjectionsV2(
    projectId: $projectId
    skip: 0
    take: 20
    where: { type: { eq: DARK_WEB_FORUM_POST }, isResolved: { eq: false } }
    order: [{ createdAt: DESC }]
  ) {
    totalCount
    items {
      id
      entityId
      type
      assetValue
      riskLevel
      isResolved
      createdAt
      eventCreatedAt
    }
  }
}
```

Use `entityId` from each item with the detail query for that source:

- `darkWebForumPost(darkWebForumPostId: $entityId)` — fields include `forumTitle`, `forumName`, `content`, `author`, `postedAt`, `query`, `tags`, `riskLevel`, `screenshotIdentifier`
- `darkWebTelegramPost(darkWebTelegramPostId: $entityId)` — `title`, `channelName`, `content`, …
- `darkWebRansomwarePost(darkWebRansomwarePostId: $entityId)` — `title`, `content`, victim fields on the post type, …
- `darkWebMarketplacePost(darkWebMarketplacePostId: $entityId)` — `title`, `content`, `price`, `siteDomainName`, …

Repeat the `eventsProjectionsV2` pattern with the other `EventProjectionType` values for Telegram, ransomware, and marketplace.
