---
name: attack-surface-management
version: 1.2.0
description: "NordStellar attack surface management (ASM) via GraphQL: vulnerabilities, scans, DNS/domains, IPs, web apps, network services, technologies, SSL certs, target assets, search filters, activity history, templates, and facet helpers."
metadata:
  nordstellar:
    category: "attack-surface"
    requires:
      tools: ["graphql_query", "graphql_batch", "search_types", "get_type_definition"]
---

# NordStellar — Attack Surface Management (ASM)

Query scanned external attack surface: vulnerabilities by type (web, network, DNS), infrastructure inventory, and certificate posture. Use the MCP `graphql_query` tool with the queries below. For the same operation across many `projectId` values (no aliases), use `graphql_batch` with `variables_list`.

## PREREQUISITE

All ASM queries require a `projectId`. Call `projectsV2` first:

```graphql
query {
  projectsV2(take: 20) {
    items { id name }
  }
}
```

## Rules (ASM)

- **Pagination**: `skip` / `take`, max `take: 100`.
- **Unresolved findings**: `where: { isResolved: { eq: false } }` on vulnerability lists.
- **Risk levels** (filters on `RiskLevel`): `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL` (uppercase). The aggregate field for informational open issues is `infoUnresolvedCount` — filter with `riskLevel: { eq: INFORMATIONAL }`, not `INFO`.
- **No GraphQL aliases** in MCP queries. That includes field aliases (`myName: attackSurfaceVulnerabilities`); the API responds with `ALIAS_NOT_ALLOWED`. Run separate operations instead of aliasing multiple branches in one document.
- **Two-step flow**: list vulnerabilities → use list item `id` as `attackSurfaceVulnerabilityId` on the detail query that matches `sourceType` (`WEB_APPLICATION`, `NETWORK_SERVICE`, `DNS`). Detail types expose flat evidence fields and `remediationInstructions` (not a nested `details` object).
- **Null counts**: `attackSurfaceVulnerabilitiesCounts` may be `null` when the project has no ASM capability, no data yet, or the caller lacks access. It can also be `null` while **inventory** queries still return rows (for example domains or target assets) but `attackSurfaceVulnerabilities { totalCount }` is zero — treat counts as unavailable and rely on list `totalCount` plus inventory queries to understand state.

## Vulnerability counts

Run first to frame scope.

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

## All vulnerabilities

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

**Narrow by scope** (optional arguments on `attackSurfaceVulnerabilities`, same pagination): `attackSurfaceScanId`, `attackSurfaceScanExecutionId`, `webApplicationId`, `networkServiceId`. Use these after you have IDs from scan projections or asset listings.

## Vulnerability detail (by source type)

Use the list query’s `id` as `attackSurfaceVulnerabilityId`. Run **one** of the following — it must match the row’s `sourceType`. (Keep each query as its own MCP request.)

**Web application** (`WEB_APPLICATION`):

```graphql
query WebVulnDetail($id: UUID!) {
  webApplicationAttackSurfaceVulnerability(attackSurfaceVulnerabilityId: $id) {
    id title riskLevel description impactDescription remediationInstructions
    sourceType type assetValue port
    evidenceUrl evidenceHttpRequest evidenceHttpResponse evidenceHost evidencePort evidenceScheme
    commonVulnerabilitiesAndExposuresId
    commonVulnerabilityScoringSystem3Score
  }
}
```

**Network service** (`NETWORK_SERVICE`):

```graphql
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
```

**DNS** (`DNS`):

```graphql
query DnsVulnDetail($id: UUID!) {
  dnsAttackSurfaceVulnerability(attackSurfaceVulnerabilityId: $id) {
    id title riskLevel description impactDescription remediationInstructions
    sourceType type assetValue
    evidenceUrl evidenceData evidenceHttpRequest
    commonVulnerabilitiesAndExposuresId
    commonVulnerabilityScoringSystem3Score
  }
}
```

## Vulnerability activity (triage / audit)

```graphql
query VulnActivity($attackSurfaceVulnerabilityId: UUID!) {
  attackSurfaceVulnerabilityEventActivityLogProjections(
    attackSurfaceVulnerabilityId: $attackSurfaceVulnerabilityId
  ) {
    id type content actorUsername actorEmail previousStatus currentStatus createdAt
  }
}
```

## Scans (configuration and per-scan counts)

List configured scans for a project:

```graphql
query Scans($projectId: UUID!) {
  attackSurfaceScanProjections(projectId: $projectId take: 100 skip: 0) {
    items {
      attackSurfaceScanId name type unresolvedVulnerabilitiesCount
      lastExecutionStartedAt lastExecutionStatus
    }
    totalCount
  }
}
```

Unresolved **critical/high** counts for one scan (`attackSurfaceScanId` from the list above):

```graphql
query ScanVulnCounts($attackSurfaceScanId: UUID!) {
  attackSurfaceScanVulnerabilitiesCounts(attackSurfaceScanId: $attackSurfaceScanId) {
    criticalUnresolvedCount
    highUnresolvedCount
  }
}
```

**Scan configuration and run history** (`attackSurfaceScanId` from the list above):

```graphql
query ScanDetail($attackSurfaceScanId: UUID!) {
  attackSurfaceScanProjection(attackSurfaceScanId: $attackSurfaceScanId) {
    name type scanAllDomains scanAllIps cronSchedule selectedTemplatesCount unresolvedVulnerabilitiesCount
    lastExecutionStartedAt lastExecutionStatus lastExecutionDuration
  }
  attackSurfaceScanExecutionProjections(
    attackSurfaceScanId: $attackSurfaceScanId take: 20 skip: 0
    order: [{ createdAt: DESC }]
  ) {
    items {
      attackSurfaceScanExecutionId status duration isTriggeredManually createdAt
    }
    totalCount
  }
}
```

Use `attackSurfaceScanExecutionId` from this list with `attackSurfaceVulnerabilities(..., attackSurfaceScanExecutionId: ...)` when you need findings from a specific run.

## Scan templates (global)

Catalog of template IDs and names (no `projectId`; use IDs when creating or editing scans elsewhere in the API):

```graphql
query ScanTemplates {
  attackSurfaceScanTemplates {
    id name scanType
  }
}
```

`scanType` is typically `APPLICATION`, `NETWORK`, or `DNS` — aligned with scan `type` on `attackSurfaceScanProjections`.

## Search and text filters

- **`attackSurfaceIps`**: `searchFilter` (value, domains, services, provider, country, ASN). Optional: `domainsIds`, `networkServicesNames`.
- **`webApplicationProjections`**: `searchFilter` (domains, CNAMEs, IPs, ports, statuses, technologies, vuln counts). Optional: `addresses` for exact CNAME/IP match.
- **`networkServiceProjections`**: `searchFilter` (names, products, domains, IPs, ports, versions, statuses, vuln counts). Optional: `domainsIds`.

Example (web apps matching a hostname fragment):

```graphql
query WebAppsSearch($projectId: UUID!) {
  webApplicationProjections(
    projectId: $projectId take: 100 skip: 0
    searchFilter: "example.com"
  ) {
    items { webApplicationId assetValue port unresolvedVulnerabilitiesCount }
    totalCount
  }
}
```

## Domains

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

**Single domain (full DNS records)** — `domainId` is the list row `id`. On `dnsRecords`, use `dnsRecordType` (not `type`):

```graphql
query OneDomain($domainId: UUID!) {
  attackSurfaceDomain(domainId: $domainId) {
    id value lastDiscoveredAtDnsScan
    dnsRecords { id dnsRecordType value }
    dnsMetadata { spfState dmarcState spoofingRiskLevel }
  }
}
```

## IP addresses

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

**Single IP** — `id` is the IP row `id` from `attackSurfaceIps`:

```graphql
query OneIp($id: UUID!) {
  attackSurfaceIp(id: $id) {
    id value lastDiscoveredAtNetworkServicesScan
    metadata {
      provider autonomousSystemNumber autonomousSystemOrganization geolocationCountry geolocationCountryCode
    }
    domains { id value }
    networkServices { id name port product protocol version isActive }
  }
}
```

**IP facets** (small payloads — good for filter UI or summaries):

```graphql
query IpFacets($projectId: UUID!) {
  attackSurfaceIpsProviders(projectId: $projectId)
  attackSurfaceIpsCountries(projectId: $projectId) { country countryCode }
  attackSurfaceIpsDomains(projectId: $projectId) { id value }
}
```

## Web applications

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

## Network services / open ports

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

## Detected technologies

Stack fingerprints aggregated across the project. Optional narrow scope: pass `webApplicationId` or `networkServiceId`.

```graphql
query Technologies($projectId: UUID!) {
  technologies(projectId: $projectId take: 100 skip: 0 order: [{ targetsCount: DESC }]) {
    items { id name version categories commonPlatformEnumeration targetsCount }
    totalCount
  }
}
```

## SSL certificates

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

## Target assets (scope)

```graphql
query TargetAssets($projectId: UUID!) {
  attackSurfaceTargetAssets(projectId: $projectId take: 100 skip: 0) {
    items { id value type }
    totalCount
  }
}
```

## Helpers (assignees, distinct assets)

- **`attackSurfaceVulnerabilitiesAssets`**: returns `[String!]!` of all asset values tied to vulnerabilities — often **thousands of entries**; avoid pulling it unless you need the full distinct set.
- **`attackSurfaceVulnerabilitiesAssignees`**: current assignees on vulns; fields are `userId`, `username`, `email` only.
- **`attackSurfaceVulnerabilitiesAssignableUsers`**: project users eligible for assignment; `userId`, `username`, `email`.

```graphql
query VulnHelpers($projectId: UUID!) {
  attackSurfaceVulnerabilitiesAssignees(projectId: $projectId) { userId username email }
  attackSurfaceVulnerabilitiesAssignableUsers(projectId: $projectId) { userId username email }
}
```

## Write operations

Mutations for ASM exist (assign/unassign users, change status, resolve, comments, create/update/delete scans, start scan, organizational consents). This skill focuses on **reads**; use `search_types` with keywords like `AttackSurface`, `ResolveAttackSurface`, `AssignUserToAttackSurface` and `get_type_definition` on the matching `*Input` type, or the general NordStellar skill for mutation patterns.

Variables for any `$projectId` query: `{ "projectId": "<uuid>" }`
