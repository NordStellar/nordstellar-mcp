---

name: asset-dark-web-research
version: 1.0.0
description: "NordStellar asset-driven dark web research via GraphQL: inventory project assets, collapse emails/subdomains/IPs into efficient Lucene search terms, search forums, Telegram, ransomware blogs, and marketplaces in iterative rounds, and use subagents or graphql_batch for coverage."
metadata:
  nordstellar:
    category: "threat-intelligence"
    requires:
  tools: ["graphql_query", "graphql_batch", "search_types", "get_type_definition"]

---

# NordStellar - Asset-Driven Dark Web Research

Use this skill when the user asks to research dark web mentions for all assets in a NordStellar project, build an asset-based threat intelligence report, or look for leaks, access sales, ransomware, marketplace listings, Telegram/forum mentions, or credential exposure across a project's domains, emails, IPs, and brands.

This workflow is intentionally iterative. Do not search every email address one by one unless there are only a few high-value accounts. Collapse assets into efficient search groups, run many targeted searches across all four dark web sources, inspect the results, extract new terms, and loop until no new useful leads appear.

## Ground Rules

- Start with `projectsV2` and select the correct `projectId`.
- Use `skip` / `take`; max `take` is `100`.
- Do not use GraphQL aliases.
- Use `search_types` / `get_type_definition` before adding unfamiliar fields or filters.
- Prefer `graphql_batch` for the same operation across many query strings.
- For large investigations, use subagents if available: one per source type, asset cluster, or threat angle. Give each subagent the project ID, query set, pagination rules, and required output shape.
- Treat one broad search as incomplete. Search all four sources, paginate high-value result sets, and run refinement rounds.

## Step 1: Project and Asset Inventory

```graphql
query {
  projectsV2(take: 20, skip: 0) {
    totalCount
    items { id name }
  }
}
```

Then get asset counts and the current search tag enum:

```graphql
query AssetResearchSetup($projectId: UUID!) {
  assetProjectionsCounts(projectId: $projectId) {
    approvedAssetsCount
    monitoredAssetsCount
    unmonitoredAssetsCount
  }
  searchContentsTags(projectId: $projectId)
}
```

List the asset inventory with dark web monitoring fields:

```graphql
query AssetInventory($projectId: UUID!, $skip: Int!, $take: Int!) {
  assetsProjections(
    projectId: $projectId
    skip: $skip
    take: $take
    where: { isDeleted: { eq: false }, status: { eq: ACCEPTED } }
    order: [{ assetType: ASC }, { assetValue: ASC }]
  ) {
    totalCount
    pageInfo { hasNextPage }
    items {
      assetId
      assetType
      assetSubtype
      assetValue
      parentAssets
      orphanedParents
      darkWebMonitoringMonitoringStatus
      darkWebMonitoringSearchInTypes
      darkWebMonitoringSearchFilter
      darkWebMonitoringLastDetectedAt
    }
  }
}
```

Helpful inventory shortcuts:

```graphql
query AssetParents($projectId: UUID!) {
  assetProjectionsParentAssets(input: { projectId: $projectId })
  assetProjectionsOrphanedParentAssets(input: { projectId: $projectId })
}
```

Use `watchList` / `assetGroupWatchList` to prioritize assets that already have leaked-data exposure:

```graphql
query ExposureWatchlist($projectId: UUID!) {
  watchList(projectId: $projectId, skip: 0, take: 50, order: [{ dataBreachesCount: DESC }]) {
    totalCount
    items {
      riskLevel
      dataBreachesCount
      leakedCredentialsCount
      malwareInfectionsCount
      dataPointsCount
      lastPublishedAt
      asset { value type }
    }
  }
  assetGroupWatchList(projectId: $projectId, skip: 0, take: 50, order: [{ dataBreachesCount: DESC }]) {
    totalCount
    items {
      riskLevel
      affectedEmployeesCount
      dataBreachesCount
      leakedCredentialsCount
      malwareInfectionsCount
      dataPointsCount
      lastPublishedAt
      assetGroup { value type domainType }
    }
  }
}
```

## Step 2: Collapse Assets into Search Groups

Build a search plan before querying DDW:

- Domains: use registrable/root domains and important brand domains first, for example `"example.com"` instead of every `*.example.com`.
- Emails: group by domain and parent asset. Search `"example.com"` or `content:"example.com"` before individual `"user\@example.com"` queries. Search individual emails only for executives, admins, service accounts, or if domain-level results indicate credential exposure.
- Subdomains: only search specific subdomains when they are high-value (`admin`, `vpn`, `sso`, `mail`, `git`, `jira`, `grafana`, `argocd`, `api`, `staging`, `dev`) or when a broad domain search returns too much noise.
- IPs: search IP addresses in small batches only when they are stable, owned, or tied to exposed services. IP mentions are usually weaker than domains.
- Brand aliases: infer from project name and major domains. Include official names, product names, merged spellings, spaced spellings, common typos, and old brands.
- Existing monitoring filters: reuse useful `darkWebMonitoringSearchFilter` strings from assets and `darkWebMonitoringRules`.

Good first query shapes:

```text
("example.com" OR "example.io" OR "Example Corp")
("example.com" OR "example.io") AND (leak OR breach OR dump OR database OR credentials OR password OR combolist OR "combo list")
("example.com" OR "example.io") AND (stealer OR infostealer OR redline OR raccoon OR vidar OR lumma)
("example.com" OR "example.io") AND (RDP OR VPN OR shell OR access OR "remote desktop" OR smtp OR ftp)
```

When a project has many domains, chunk OR groups by theme instead of one giant query:

- Primary brands and apex domains.
- Login/account/payment/support domains.
- Internal/admin/dev/staging subdomains.
- Employee email domains.
- IP/service exposure terms.
- Product or company aliases.

## Step 3: Search All Four DDW Sources

Run the same query set across all four endpoints. Use `searchContentsTags: []` for broad discovery, then rerun with focused tags.

Forums:

```graphql
query ForumSearch($projectId: UUID!, $query: String!, $tags: [SearchContentsTag!]!, $skip: Int!, $take: Int!) {
  forumsSearchContents(
    skip: $skip
    take: $take
    listForumsSearchContentsInput: { projectId: $projectId, query: $query, searchContentsTags: $tags }
  ) {
    totalCount
    pageInfo { hasNextPage }
    items { id threadName author forumName forumSection postedAt scrapedAt url tags threadPost }
  }
}
```

Telegram:

```graphql
query TelegramSearch($projectId: UUID!, $query: String!, $tags: [SearchContentsTag!]!, $skip: Int!, $take: Int!) {
  telegramSearchContents(
    skip: $skip
    take: $take
    listTelegramSearchContentsInput: { projectId: $projectId, query: $query, searchContentsTags: $tags }
  ) {
    totalCount
    pageInfo { hasNextPage }
    items { id messageHeadline channelName author postedAt scrapedAt url tags messageContent }
  }
}
```

Ransomware:

```graphql
query RansomwareSearch($projectId: UUID!, $query: String!, $tags: [SearchContentsTag!]!, $skip: Int!, $take: Int!) {
  ransomwareSearchContents(
    skip: $skip
    take: $take
    listRansomwareSearchContentsInput: { projectId: $projectId, query: $query, searchContentsTags: $tags }
  ) {
    totalCount
    pageInfo { hasNextPage }
    items {
      id
      messageHeadline
      author
      postedAt
      scrapedAt
      url
      tags
      aiDescription
      messageContent
      victimInformation { companyName website industry country { name iso2 } companyType companySize revenueRange }
    }
  }
}
```

Marketplaces:

```graphql
query MarketplaceSearch($projectId: UUID!, $query: String!, $tags: [SearchContentsTag!]!, $skip: Int!, $take: Int!) {
  marketplacesSearchContents(
    skip: $skip
    take: $take
    listMarketplacesSearchContentsInput: { projectId: $projectId, query: $query, searchContentsTags: $tags }
  ) {
    totalCount
    pageInfo { hasNextPage }
    items { id messageHeadline author domainName subdomainUrl marketplaceType price postedAt scrapedAt url tags marketplaceContent }
  }
}
```

Use focused tag sets:

- Credential exposure: `["COMBO_LIST", "DATABASE", "EMAIL_LIST", "STEALER_MALWARE_LOGS", "COOKIES"]`
- Access sales: `["LIVE_ACCESS", "FTP", "SMTP", "ACCOUNT_TAKE_OVER"]`
- Malware and exploit context: `["MALWARE", "BOTNET", "EXPLOIT", "CONFIGURATION_FILES"]`
- Ransomware: `["RANSOMWARE"]`
- Source/code leaks: `["SOURCE_CODE", "CODES", "CONFIGURATION_FILES"]`

## Step 4: Parallelize the Loop

Use one of these patterns:

- `graphql_batch`: same endpoint, many variable sets. Best for testing many Lucene strings on forums or Telegram.
- Subagent per source: one agent handles forums, one Telegram, one ransomware, one marketplaces. Each returns counts, paginated findings, top authors/channels/sites, and suggested refinements.
- Subagent per asset cluster: one agent handles primary domains, one email domains, one high-value subdomains, one IP/service assets.
- Subagent per threat angle: credentials, stealer logs, access sales, ransomware, source/config leaks.

Subagent prompt template:

```text
Use NordStellar MCP only. Project ID: <projectId>.
Search <source or asset cluster> with these Lucene queries: <queries>.
For each query, run take 20 first, record totalCount/hasNextPage, paginate high-value sets up to the useful limit, extract repeated authors/channels/forums/sites/tags/domains, and propose the next query round.
Return only: source, query, tags, totalCount, pages reviewed, relevant hits with IDs/URLs/dates, extracted pivots, and recommended refinements.
```

## Step 5: Refine Until Coverage Is Good

Round 1: Broad asset presence

- Run grouped domains and brand aliases across all four sources with `searchContentsTags: []`.
- Record `totalCount`, `hasNextPage`, source, tags, authors/channels/forums/marketplaces, and dates.

Round 2: Threat-angle searches

- Credentials: domain group plus leak/breach/dump/credentials/password/combo terms.
- Stealer logs: domain group plus stealer family names.
- Access sales: domain group plus VPN/RDP/shell/access/smtp/ftp.
- Ransomware: brand and domain group, usually broad rather than heavily tagged.
- Source/config: domain group plus source code/config/env/git/token/key terms.

Round 3: Pivot from results

- Search repeated `author` handles across forums, Telegram, and marketplaces.
- Search `forumName`, `channelName`, marketplace host, and source-specific terms when supported by the DDW search skill.
- Search newly observed domains, typos, product names, paste titles, breach names, or actor names.
- Add `postedAt` or `scrapedAt` date windows when an incident timeframe emerges.

Round 4: Exhaust high-value pages

- Paginate any relevant result set where `hasNextPage` is true.
- If `totalCount` is huge or capped at `10000`, narrow before paginating blindly.
- Stop only when new rounds stop producing new pivots and all relevant high-count sets have been narrowed or paginated.

## Monitoring Rules and Alert Hits

List saved monitoring filters and rules:

```graphql
query MonitoringRules($projectId: UUID!) {
  darkWebMonitoringRules(projectId: $projectId, skip: 0, take: 100) {
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
  darkWebMonitoringSearchFilters(projectId: $projectId, first: 100) {
    nodes { id name query tags }
  }
}
```

List dark web monitoring events by source:

```graphql
query DarkWebEvents($projectId: UUID!, $type: EventProjectionType!, $skip: Int!, $take: Int!) {
  eventsProjectionsV2(
    projectId: $projectId
    skip: $skip
    take: $take
    where: { type: { eq: $type }, isResolved: { eq: false } }
    order: [{ createdAt: DESC }]
  ) {
    totalCount
    pageInfo { hasNextPage }
    items { id entityId type assetValue riskLevel isResolved eventCreatedAt createdAt name tags }
  }
}
```

Use `entityId` with the detail query matching `type`:

- `DARK_WEB_FORUM_POST` -> `darkWebForumPost(darkWebForumPostId: $entityId)`
- `DARK_WEB_TELEGRAM_POST` -> `darkWebTelegramPost(darkWebTelegramPostId: $entityId)`
- `DARK_WEB_RANSOMWARE_POST` -> `darkWebRansomwarePost(darkWebRansomwarePostId: $entityId)`
- `DARK_WEB_MARKETPLACE_POST` -> `darkWebMarketplacePost(darkWebMarketplacePostId: $entityId)`

## Output Shape

Use this structure unless the user asks otherwise:

1. Scope: project, asset counts, source coverage, date of investigation, and important limitations.
2. Search strategy: asset groups used, Lucene query families, tags, source endpoints, pages reviewed, and subagent/batch split.
3. Findings: confirmed relevant mentions first, grouped by credential exposure, access sale, stealer/malware, ransomware, marketplace, source/config, and generic brand mention.
4. Pivots explored: authors, channels, forums, marketplaces, domains, tags, dates, and follow-up queries.
5. Negative coverage: important asset groups and source types searched with no relevant hits.
6. Recommendations: remediation or monitoring actions tied to the evidence.
7. Appendix: raw query log with endpoint, query, tags, `totalCount`, pages reviewed, and notable IDs/URLs.

