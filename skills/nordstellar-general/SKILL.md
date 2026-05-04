---
name: nordstellar
description: |
  Use this skill for ANY task involving NordStellar's threat intelligence platform via MCP. Triggers on:
  - Leaked data / credential / breach investigations ("find leaked credentials", "check for breaches", "stealer logs", "combo lists", "malware infections", "data breach report")
  - Attack surface management ("attack surface scan", "vulnerabilities", "open ports", "web applications", "SSL certs", "DNS issues", "network services", "ASM report")
  - Dark web search and monitoring ("dark web", "forum posts", "Telegram channels", "ransomware", "marketplace listings", "threat intel search", "DDW report")
  - Domain squatting / typosquatting ("domain permutations", "squatting", "look-alike domains", "brand protection", "phishing domains", "squatting report")
  - Any NordStellar project review, investigation, or report generation
  Always use this skill before writing GraphQL queries or producing NordStellar deliverables.
---
 
# NordStellar Skill
 
NordStellar is Nord Security's threat intelligence platform. Use the MCP `graphql_query` tool directly with the queries below — no scripts needed.
 
---
 
## Setup: Always do first
 
Get a project ID before running any domain queries:
 
```graphql
query { projectsV2(take: 20) { items { id name } } }
```
 
Store the relevant `projectId` (UUID) for all subsequent queries.
 
---
 
## Key Rules & Gotchas
 
- **Pagination**: Use `skip`/`take` (not `first`/`after`). Max `take: 100`.
- **Filters**: `where: { isResolved: { eq: false } }` for unresolved items only.
- **Risk levels**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` (uppercase in filters).
- **No aliases**: MCP does not support GraphQL aliases.
- **Two-step detail**: List to get IDs → fetch detail by ID.
- **Search input wrapper**: DDW search queries use a named input object (e.g. `listForumsSearchContentsInput`).
- **Tag shapes**: DDW search hits use `tags` as `[SearchContentsTag!]!` (enum values, no nested fields). Leaked-data asset occurrences use `tags { value }`. Dark-web monitoring hits use `eventsProjectionsV2` + `darkWebForumPost` / `darkWebTelegramPost` / `darkWebRansomwarePost` / `darkWebMarketplacePost` with each row’s `entityId`.
---
 
## Leaked Data Intelligence
 
### General Overview
Stats + top exposed assets. Run first for any leaked data report.
```graphql
query Overview($projectId: UUID!) {
  generalData(projectId: $projectId) {
    dataBreachesCount
    malwareInfectionsCount
    leakedCredentialsCount
    affectedEmployeesCount
  }
  assetTopUnresolvedAssetOccurrencesStatistics(projectId: $projectId) {
    assetIdentifier
    total
    high { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
    medium { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
    low { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
    informational { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
  }
}
```
Variables: `{ "projectId": "..." }`
 
### Data Breaches
Assets found in known breach dumps.
```graphql
query DataBreaches($projectId: UUID!) {
  dataBreachesAssetsOccurrences(
    projectId: $projectId take: 50 skip: 0
    where: { isResolved: { eq: false } }
    order: [{ riskLevel: DESC }, { createdAt: DESC }]
  ) {
    items {
      id assetId occurrenceId riskLevel isResolved dataPointsCount dataPoints createdAt
      asset { value type }
      occurrence { id origin type occurredAt publishedAt }
      tags { value }
    }
    totalCount
  }
}
```
 
### Breach Detail (by occurrenceId)
```graphql
query BreachDetail($occurrenceId: UUID!, $projectId: UUID!) {
  dataBreachOccurrenceDetails(occurrenceId: $occurrenceId, projectId: $projectId) {
    id
    dataKeys
    description
    dataBreachOccurrenceType
    origin
    type
    occurredAt
    publishedAt
  }
}
```
 
### Leaked Credentials
Combo lists associated with monitored assets.
```graphql
query LeakedCreds($projectId: UUID!) {
  leakedCredentialsAssetsOccurrencesV1(
    projectId: $projectId take: 50 skip: 0
    where: { isResolved: { eq: false } }
    order: [{ riskLevel: DESC }, { createdAt: DESC }]
  ) {
    items {
      id assetId occurrenceId riskLevel isResolved urls createdAt
      asset { value type }
      occurrence { id origin type occurredAt publishedAt }
      tags { value }
    }
    totalCount
  }
}
```
 
### Malware / Stealer Infections
Infostealer infections affecting monitored assets.
```graphql
query MalwareInfections($projectId: UUID!) {
  malwareInfectionsAssetsOccurrences(
    projectId: $projectId take: 50 skip: 0
    where: { isResolved: { eq: false } }
    order: [{ riskLevel: DESC }, { createdAt: DESC }]
  ) {
    items {
      id assetId occurrenceId riskLevel isResolved
      corporateCredentialsCount corporateCookiesCount credentialsCount cookiesCount autoFillsCount filesCount creditCardsCount
      createdAt
      asset { value type }
      occurrence { id origin type occurredAt publishedAt }
      tags { value }
    }
    totalCount
  }
}
```
 
### Malware Detail (by assetOccurrenceId)
```graphql
query MalwareDetail($assetOccurrenceId: UUID!) {
  malwareInfectionAssetOccurrenceV2(
    assetOccurrenceId: $assetOccurrenceId
    revealNonCorporateData: false
    revealSensitiveData: false
  ) {
    id riskLevel
    asset { value type }
    occurrence { id origin type occurredAt publishedAt }
  }
}
```
 
---
 
## Attack Surface Management (ASM)
 
### Vulnerability Counts
Always run first to frame scope.
```graphql
query VulnCounts($projectId: UUID!) {
  attackSurfaceVulnerabilitiesCounts(projectId: $projectId) {
    totalCount
    resolvedCount
    unresolvedCount
    criticalUnresolvedCount
    highUnresolvedCount
    mediumUnresolvedCount
    lowUnresolvedCount
    infoUnresolvedCount
  }
}
```
 
### All Vulnerabilities
```graphql
query Vulnerabilities($projectId: UUID!) {
  attackSurfaceVulnerabilities(
    projectId: $projectId take: 100 skip: 0
    where: { isResolved: { eq: false } }
    order: [{ riskLevel: DESC }, { createdAt: DESC }]
  ) {
    items { id assetId assetValue title sourceType type riskLevel tags isResolved createdAt }
    totalCount
  }
}
```
Filter by risk: `where: { isResolved: { eq: false }, riskLevel: { eq: CRITICAL } }`
Filter by source: `where: { isResolved: { eq: false }, sourceType: { eq: WEB_APPLICATION } }` (`WEB_APPLICATION`, `NETWORK_SERVICE`, `DNS`)
 
### Vulnerability Detail (by sourceType)
```graphql
# Web application
query WebVulnDetail($id: UUID!) {
  webApplicationAttackSurfaceVulnerability(attackSurfaceVulnerabilityId: $id) {
    id title riskLevel description impactDescription remediationInstructions
    sourceType type assetValue port
    evidenceUrl evidenceHttpRequest evidenceHttpResponse evidenceHost evidencePort evidenceScheme
    commonVulnerabilitiesAndExposuresId
    commonVulnerabilityScoringSystem3Score
  }
}
 
# Network service
query NetVulnDetail($id: UUID!) {
  networkServiceAttackSurfaceVulnerability(attackSurfaceVulnerabilityId: $id) {
    id title riskLevel description impactDescription remediationInstructions
    sourceType type assetValue
    networkServiceName protocol product version isActive port
    evidenceUrl evidenceHttpRequest evidenceHttpResponse
    commonVulnerabilitiesAndExposuresId
    commonVulnerabilityScoringSystem3Score
  }
}
 
# DNS
query DnsVulnDetail($id: UUID!) {
  dnsAttackSurfaceVulnerability(attackSurfaceVulnerabilityId: $id) {
    id title riskLevel description impactDescription remediationInstructions
    sourceType type assetValue
    evidenceUrl evidenceData evidenceHttpRequest
    commonVulnerabilitiesAndExposuresId
  }
}
```
 
### Domains
DNS health, SPF/DMARC state.
```graphql
query Domains($projectId: UUID!) {
  attackSurfaceDomains(
    projectId: $projectId take: 100 skip: 0
    order: [{ unresolvedDnsVulnerabilitiesCount: DESC }]
  ) {
    items { id value spoofingRiskLevel spfState dmarcState unresolvedDnsVulnerabilitiesCount lastDiscoveredAtDnsScan dnsRecordCounts { type count } }
    totalCount
  }
}
```
 
### IP Addresses
```graphql
query IPs($projectId: UUID!) {
  attackSurfaceIps(
    projectId: $projectId take: 100 skip: 0
    order: [{ unresolvedNetworkServicesVulnerabilitiesCount: DESC }]
  ) {
    items {
      id
      value
      domains
      networkServices
      provider
      geolocationCountry
      geolocationCountryCode
      autonomousSystemNumber
      unresolvedNetworkServicesVulnerabilitiesCount
      lastDiscoveredAtNetworkServicesScan
    }
    totalCount
  }
}
```
 
### Web Applications
```graphql
query WebApps($projectId: UUID!) {
  webApplicationProjections(
    projectId: $projectId take: 100 skip: 0
    order: [{ unresolvedVulnerabilitiesCount: DESC }]
  ) {
    items {
      webApplicationId
      assetId
      assetValue
      port
      responseStatusCode
      cNames
      ipAddresses
      technologies
      unresolvedVulnerabilitiesCount
      hasScreenshot
      lastDiscoveredAt
    }
    totalCount
  }
}
```
 
### Network Services / Open Ports
```graphql
query NetworkServices($projectId: UUID!) {
  networkServiceProjections(
    projectId: $projectId take: 100 skip: 0
    order: [{ unresolvedVulnerabilitiesCount: DESC }]
  ) {
    items {
      networkServiceId
      projectId
      ipId
      name
      product
      ip
      port
      version
      isActive
      domains
      unresolvedVulnerabilitiesCount
      lastDiscoveredAt
    }
    totalCount
  }
}
```
 
### SSL Certificates
```graphql
query SSLCerts($projectId: UUID!) {
  attackSurfaceSslCertificates(
    projectId: $projectId take: 100 skip: 0
    order: [{ validTo: DESC }]
  ) {
    items {
      id
      subject
      subjectAlternativeNames
      issuer
      validTo
      isValid
      targetsCount
      webApplicationsCount
      networkServicesCount
      lastDiscoveredAt
    }
    totalCount
  }
}
```
 
### Target Assets (scope)
```graphql
query TargetAssets($projectId: UUID!) {
  attackSurfaceTargetAssets(projectId: $projectId take: 100 skip: 0) {
    items { id value type }
    totalCount
  }
}
```
 
---
 
## Dark Web (DDW)
 
Two modes: **search** (ad-hoc keyword search) vs **monitoring** (rule hits as event projections). Use search for investigations; use `eventsProjectionsV2` filtered by `DARK_WEB_*` types for alert triage, then `darkWebForumPost` / `darkWebTelegramPost` / `darkWebRansomwarePost` / `darkWebMarketplacePost` with `entityId` for full content.
 
### Forum Search
```graphql
query ForumSearch($projectId: UUID!, $query: String!) {
  forumsSearchContents(
    take: 20 skip: 0
    listForumsSearchContentsInput: { projectId: $projectId, query: $query, searchContentsTags: [] }
  ) {
    items { id threadName author forumName forumSection postedAt scrapedAt threadPost url tags screenshotIdentifier }
    totalCount
  }
}
```
Variables: `{ "projectId": "...", "query": "target keyword" }`
 
### Telegram Search
```graphql
query TelegramSearch($projectId: UUID!, $query: String!) {
  telegramSearchContents(
    take: 20 skip: 0
    listTelegramSearchContentsInput: { projectId: $projectId, query: $query, searchContentsTags: [] }
  ) {
    items { id messageHeadline channelName author postedAt scrapedAt messageContent url tags }
    totalCount
  }
}
```
 
### Ransomware Search
```graphql
query RansomwareSearch($projectId: UUID!, $query: String!) {
  ransomwareSearchContents(
    take: 20 skip: 0
    listRansomwareSearchContentsInput: { projectId: $projectId, query: $query, searchContentsTags: [] }
  ) {
    items {
      id messageHeadline author postedAt scrapedAt messageContent url aiDescription
      victimInformation {
        companyName
        website
        industry
        country { name iso2 }
        companyType
        companySize
        revenueRange
        addressLocation
      }
      tags
    }
    totalCount
  }
}
```
 
### Marketplace Search
```graphql
query MarketplaceSearch($projectId: UUID!, $query: String!) {
  marketplacesSearchContents(
    take: 20 skip: 0
    listMarketplacesSearchContentsInput: { projectId: $projectId, query: $query, searchContentsTags: [] }
  ) {
    items { id messageHeadline price marketplaceType marketplaceContent author domainName subdomainUrl url postedAt scrapedAt tags screenshotIdentifier }
    totalCount
  }
}
```
 
### Monitoring (rule hits)

List unresolved dark-web alert rows via `eventsProjectionsV2` and `EventProjectionType` (`DARK_WEB_FORUM_POST`, `DARK_WEB_TELEGRAM_POST`, `DARK_WEB_RANSOMWARE_POST`, `DARK_WEB_MARKETPLACE_POST`). Each item’s `entityId` is the ID for the matching detail query: `darkWebForumPost(darkWebForumPostId:)`, `darkWebTelegramPost`, `darkWebRansomwarePost`, or `darkWebMarketplacePost`.

```graphql
query DarkWebForumAlerts($projectId: UUID!) {
  eventsProjectionsV2(
    projectId: $projectId take: 50 skip: 0
    where: { type: { eq: DARK_WEB_FORUM_POST }, isResolved: { eq: false } }
    order: [{ createdAt: DESC }]
  ) {
    items { id entityId type assetValue riskLevel isResolved createdAt eventCreatedAt }
    totalCount
  }
}
```

Repeat with `DARK_WEB_TELEGRAM_POST`, `DARK_WEB_RANSOMWARE_POST`, and `DARK_WEB_MARKETPLACE_POST` for other sources.

### Search tags API

`searchContentsTags` returns the `SearchContentsTag` enum values allowed in `searchContentsTags` on search inputs:

```graphql
query Tags($projectId: UUID!) {
  searchContentsTags(projectId: $projectId)
}
```

Use the returned enum strings in `searchContentsTags: [...]`. You can also confirm via `get_type_definition(type_name: "SearchContentsTag")`.
 
---
 
## Domain Squatting
 
### Squatting Overview / Counts
Always start here.
```graphql
query SquattingOverview($projectId: UUID!) {
  domainSquattingCounts(projectId: $projectId) {
    totalEventsCount
    highRiskEventsPerThirtyDaysCount
    eventsPerThirtyDaysCount
    countsPerPermutationType { key value }
  }
}
```
 
### Domain Permutations List
```graphql
query Permutations($projectId: UUID!) {
  domainPermutationsProjections(
    projectId: $projectId take: 100 skip: 0
    where: { isResolved: { eq: false } }
    order: [{ riskLevel: DESC }, { detectionDate: DESC }]
  ) {
    items {
      id domainPermutationId originalDomain detectedDomain permutationType
      nameServers mailServers riskLevel similarityScore visualSimilarity detectionDate isResolved resolvedAt
      ips { address countryCodeIso countryName }
    }
    totalCount
  }
}
```
Filter by domain: `where: { isResolved: { eq: false }, originalDomain: { eq: "example.com" } }`
Filter by risk: `where: { isResolved: { eq: false }, riskLevel: { in: [CRITICAL, HIGH] } }`
 
### Permutation Detail (by domainPermutationId)
```graphql
query PermutationDetail($domainPermutationId: UUID!) {
  domainPermutation(domainPermutationId: $domainPermutationId) {
    originalDomain
    domain
    permutationType
    riskLevel
    detectedAt
    nameServers
    mailServers
    geoIps { address countryName countryCodeIso2 }
    screenshotKey
  }
}
```
 
### Permutation Events (monitoring alerts)
```graphql
query PermutationEvents($projectId: UUID!) {
  eventsProjectionsV2(
    projectId: $projectId take: 50 skip: 0
    where: { type: { eq: DOMAIN_PERMUTATION }, isResolved: { eq: false } }
    order: [{ createdAt: DESC }]
  ) {
    items { id entityId type riskLevel isResolved createdAt assetValue }
    totalCount
  }
}
```
 
### Metadata Queries (for filtering/analysis)
```graphql
query OriginalDomains($projectId: UUID!) { domainPermutationsOriginalDomains(projectId: $projectId) }
query DetectedDomains($projectId: UUID!) { domainPermutationsDetectedDomains(projectId: $projectId) }
query PermutationTypes($projectId: UUID!) { domainPermutationsPermutationTypes(projectId: $projectId) }
```
 
**Permutation type reference:** `homoglyph`, `typo`, `hyphenation`, `subdomain`, `tld-swap`, `addition`, `omission`, `transposition`, `repetition`, `bitsquatting`, `vowel-swap`
 
