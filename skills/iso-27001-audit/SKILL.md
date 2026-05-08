---

name: iso-27001-audit
version: 1.0.0
description: "NordStellar audit workflow for ISO/IEC 27001:2022 evidence collection: map MCP data to Annex A controls for asset inventory, threat intelligence, event handling, vulnerability management, monitoring, network exposure, TLS/DNS posture, dark web exposure, malware infections, leaked credentials, and domain-squatting risk."
metadata:
  nordstellar:
    category: "audit-compliance"
    framework: "ISO/IEC 27001:2022"
    requires:
  tools: ["graphql_query", "graphql_batch", "search_types", "get_type_definition"]

---

# NordStellar - ISO 27001 Audit Evidence

Use this skill when the user asks for ISO 27001 audit support, Annex A evidence, certification readiness, control coverage, Statement of Applicability evidence, security audit findings, or compliance reporting based on NordStellar data.

NordStellar does **not** prove ISO 27001 compliance by itself. It provides technical evidence for selected controls: monitored assets, external attack surface, vulnerabilities, scan freshness, event workflow, threat intelligence, leaked data, malware infection exposure, dark web monitoring, domain-squatting risks, DNS/email security, and certificate/TLS posture. Always separate **observed evidence** from **auditor conclusion** and **manual evidence required**.

## Realistic Audit Coverage

Set expectations early. NordStellar can usually cover **technical evidence for roughly 10-15 ISO/IEC 27001:2022 Annex A controls**, mostly in the threat intelligence, asset inventory, monitoring, event handling, vulnerability management, network security, cryptography, and application security areas. That is a meaningful evidence package, but it is **not a complete ISO 27001 audit**.

**Default completeness score: 18/100.** This score reflects realistic ISO 27001 audit coverage from NordStellar data alone: useful evidence for selected Annex A technical controls, but little to no direct evidence for ISMS clauses 4-10, governance, risk methodology, internal processes, HR, physical security, supplier contracts, management review, or continual improvement. Raise the score only when the user supplies external/manual audit evidence; lower it when modules are disabled, scans are stale, or assets are unmonitored.

What NordStellar can cover well:

- Current external asset and monitoring scope: domains, IPs, emails, web apps, network services, certificates, monitored/unmonitored assets.
- External technical risk posture: unresolved vulnerabilities, DNS/email spoofing controls, exposed services, web technologies, TLS/certificate posture, scan status, and remediation evidence.
- External threat and exposure evidence: dark web mentions, monitoring rules, leaked credentials, data breach occurrences, malware/stealer infections, domain-squatting and phishing-like infrastructure.
- Event workflow signals: event status, assignee, risk, creation/resolution timestamps, activity logs, and unresolved-age metrics.

What NordStellar can only partially cover:

- Incident response effectiveness: it can show detected events and workflow state, but not full incident records, RCA quality, tabletop exercises, or post-incident reviews.
- Vulnerability management process: it can show findings and remediation state, but not SLA policy approval, exception/risk acceptance records, patch deployment tickets, or management review.
- Asset management: it can show monitored external assets, but not complete internal inventories, data classification, ownership records, lifecycle approvals, or CMDB reconciliation.
- Logging and monitoring: it can show NordStellar event/activity logs and monitoring rules, but not SIEM coverage, endpoint logs, cloud audit logs, retention policy, or alert tuning.
- Supplier/cloud assurance: it can reveal providers, ASNs, technologies, and hosting countries, but vendor ISO/SOC attestations, DPAs, subprocessors, and contracts must come from external evidence.

What NordStellar cannot realistically cover:

- ISO clauses 4-10, ISMS governance, leadership, context, objectives, internal audits, management review, and continual improvement.
- HR, legal, procurement, physical security, access review, backup, business continuity, secure SDLC governance, training, awareness, and policy approval controls.
- Any control requiring internal procedures, interviews, tickets, screenshots from internal systems, signed approvals, contractual documents, or auditor sampling outside NordStellar.

When communicating to users, say: "NordStellar can provide strong technical evidence for selected Annex A controls and identify audit-relevant gaps, but a complete ISO 27001 audit still requires governance, process, contractual, HR, physical, and internal system evidence from outside NordStellar."

## Ground Rules

- Start with `projectsV2` and select the relevant `projectId`.
- Use `skip` / `take`; max `take` is `100`.
- Do not use GraphQL aliases.
- Use `graphql_batch` for the same query across multiple projects.
- Use `search_types` and `get_type_definition` before adding unfamiliar fields or filters.
- Do not claim control conformity when NordStellar only provides partial evidence. Mark missing policy, ownership, risk acceptance, procedure, ticketing, training, contract, and internal-control proof as manual evidence.
- For sensitive leaked-data results, report counts, categories, and remediation needs by default. Do not expose raw passwords, cookie values, or personal data unless the user explicitly needs it and has authority.

## ISO 27001 Control Coverage

Strong NordStellar evidence:

- `A.5.7 Threat intelligence`: dark web search, ransomware/forum/Telegram/marketplace monitoring, tags, saved rules, last detected dates.
- `A.5.9 Inventory of information and other associated assets`: project assets, accepted target assets, monitored/unmonitored counts, asset types, parent assets.
- `A.5.25 Assessment and decision on information security events`: event risk, type, status, assignee, age, unresolved counts.
- `A.5.26 Response to information security incidents`: resolution counts, status changes, assignees, activity logs, comments where present.
- `A.8.8 Management of technical vulnerabilities`: ASM vulnerability counts, detailed CVE/misconfiguration evidence, remediation instructions, scan history.
- `A.8.15 Logging`: limited evidence only from NordStellar event activity logs, not internal application/system logs.
- `A.8.16 Monitoring activities`: dark web monitoring rules, event feeds, ASM scan execution freshness.
- `A.8.20 Network security`: exposed IPs, ports, protocols, providers, countries, ASNs, network services.
- `A.8.21 Security of network services`: service products/versions, active state, TLS on services, unresolved network vulnerabilities.
- `A.8.24 Use of cryptography`: SSL certificate validity, issuers, expiry, SANs, TLS grade/protocol/cipher evidence from web/service detail.
- `A.8.26 Application security requirements`: web application exposure, technologies, headers, TLS, unresolved web vulnerabilities.
- `A.8.9 Configuration management`: partial evidence from DNS, SPF/DMARC, headers, TLS, technologies, exposed debug/admin surfaces.

Weak or manual-only evidence:

- Governance clauses, risk methodology, SoA ownership, HR controls, supplier contracts, physical security, internal access control, backup, secure SDLC process, change management, and business continuity cannot be proven from NordStellar MCP alone.
- Cloud/data-center certification claims require vendor trust-center, SOC/ISO certificates, DPAs, subprocessors, or internal approved-vendor records outside NordStellar.

## Required First Query

```graphql
query {
  projectsV2(take: 20, skip: 0) {
    totalCount
    items { id name summary isBillable createdAt updatedAt }
  }
  organization { id name }
}
```

## Audit Overview

Run this first to size the evidence set and identify enabled modules. `attackSurfaceVulnerabilitiesCounts` or `generalData` can be `null` for projects without that module/data or without caller access.

```graphql
query IsoAuditOverview($projectId: UUID!) {
  assetProjectionsCounts(projectId: $projectId) {
    approvedAssetsCount
    monitoredAssetsCount
    unmonitoredAssetsCount
    countsPerAssetType { key value }
  }
  generalData(projectId: $projectId) {
    dataBreachesCount
    malwareInfectionsCount
    leakedCredentialsCount
    affectedEmployeesCount
  }
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
  domainSquattingCounts(projectId: $projectId) {
    totalEventsCount
    highRiskEventsPerThirtyDaysCount
    eventsPerThirtyDaysCount
    countsPerPermutationType { key value }
  }
  eventsDaysUnresolvedAverages(projectId: $projectId) {
    criticalEventsDaysUnresolvedAverage
    highEventsDaysUnresolvedAverage
    mediumEventsDaysUnresolvedAverage
    lowEventsDaysUnresolvedAverage
  }
}
```

For all projects, run the same operation through `graphql_batch` with one `{ "projectId": "..." }` object per project.

## Asset Inventory Evidence

Supports `A.5.9` and scoping for all other controls.

```graphql
query AssetInventory($projectId: UUID!, $skip: Int!, $take: Int!) {
  assetsProjections(
    projectId: $projectId
    skip: $skip
    take: $take
    where: { isDeleted: { eq: false } }
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
      source
      status
      leakedDataManagementMonitoringStatus
      isLeakedDataManagementMonitoringStatusSuccessful
      domainSquattingMonitoringStatus
      isDomainSquattingMonitoringStatusSuccessful
      darkWebMonitoringMonitoringStatus
      isDarkWebMonitoringMonitoringStatusSuccessful
      darkWebMonitoringSearchInTypes
      darkWebMonitoringSearchFilter
      darkWebMonitoringLastDetectedAt
      createdAt
    }
  }
  attackSurfaceTargetAssets(projectId: $projectId, take: 100, skip: 0) {
    totalCount
    items { id value type }
  }
}
```

Audit checks:

- Accepted/approved assets exist for the reviewed scope.
- Unmonitored or failed-monitoring assets are listed as coverage gaps.
- Asset parents/orphans are reconciled with the customer's asset inventory or SoA scope.

## Threat Intelligence Evidence

Supports `A.5.7`, `A.8.16`, and incident detection evidence.

```graphql
query ThreatIntelSetup($projectId: UUID!) {
  searchContentsTags(projectId: $projectId)
  darkWebMonitoringRules(projectId: $projectId, take: 100, skip: 0) {
    totalCount
    items {
      id
      name
      description
      sourceTypes
      lastDetectedAt
      createdAt
      darkWebMonitoringSearchFilter { id name query tags createdAt updatedAt }
    }
  }
}
```

Run ad-hoc searches across all four sources for the customer's legal name, brand names, apex domains, product names, high-value login/payment/support domains, and known aliases. Start broad with `searchContentsTags: []`, then narrow with tags such as `COMBO_LIST`, `DATABASE`, `STEALER_MALWARE_LOGS`, `COOKIES`, `LIVE_ACCESS`, `RANSOMWARE`, `PHISHING`, `EXPLOIT`, `SOURCE_CODE`, and `CONFIGURATION_FILES`.

```graphql
query DarkWebSearch($projectId: UUID!, $query: String!, $tags: [SearchContentsTag!]!, $skip: Int!, $take: Int!) {
  forumsSearchContents(skip: $skip, take: $take, listForumsSearchContentsInput: { projectId: $projectId, query: $query, searchContentsTags: $tags }) {
    totalCount
    pageInfo { hasNextPage }
    items { id threadName author forumName forumSection postedAt scrapedAt url tags }
  }
  telegramSearchContents(skip: $skip, take: $take, listTelegramSearchContentsInput: { projectId: $projectId, query: $query, searchContentsTags: $tags }) {
    totalCount
    pageInfo { hasNextPage }
    items { id messageHeadline channelName author postedAt scrapedAt url tags }
  }
  ransomwareSearchContents(skip: $skip, take: $take, listRansomwareSearchContentsInput: { projectId: $projectId, query: $query, searchContentsTags: $tags }) {
    totalCount
    pageInfo { hasNextPage }
    items { id messageHeadline author postedAt scrapedAt url tags victimInformation { companyName website industry country { name iso2 } } }
  }
  marketplacesSearchContents(skip: $skip, take: $take, listMarketplacesSearchContentsInput: { projectId: $projectId, query: $query, searchContentsTags: $tags }) {
    totalCount
    pageInfo { hasNextPage }
    items { id messageHeadline marketplaceType price author postedAt scrapedAt url tags }
  }
}
```

## Event Workflow Evidence

Supports `A.5.25`, `A.5.26`, `A.8.15` (limited), and `A.8.16`.

```graphql
query EventWorkflow($projectId: UUID!, $fromDate: DateTime!) {
  eventsProjectionsV2(
    projectId: $projectId
    take: 100
    skip: 0
    where: { isResolved: { eq: false } }
    order: [{ riskLevel: DESC }, { createdAt: DESC }]
  ) {
    totalCount
    pageInfo { hasNextPage }
    items {
      id
      entityId
      type
      assetValue
      riskLevel
      isResolved
      status
      assigneeEmail
      eventCreatedAt
      createdAt
      resolvedAt
      tags
    }
  }
  eventsAssignees(projectId: $projectId) { userId username email }
  eventsCounts(input: { projectId: $projectId, fromDate: $fromDate }) {
    key
    value { totalCount unresolvedCount }
  }
  eventsResolutionCounts(input: { projectId: $projectId, fromDate: $fromDate }) {
    type
    newUnresolved { criticalEventsCount highEventsCount mediumEventsCount lowEventsCount infoEventsCount }
    newTotal { criticalEventsCount highEventsCount mediumEventsCount lowEventsCount infoEventsCount }
    resolved { criticalEventsCount highEventsCount mediumEventsCount lowEventsCount infoEventsCount }
  }
}
```

For activity logs, use the event row's `type` and `entityId` with the matching query:

```graphql
query ActivityLogs($attackSurfaceVulnerabilityId: UUID!, $domainPermutationId: UUID!, $assetOccurrenceId: UUID!) {
  attackSurfaceVulnerabilityEventActivityLogProjections(attackSurfaceVulnerabilityId: $attackSurfaceVulnerabilityId) {
    id actorEmail actorType assigneeEmail previousStatus currentStatus type content createdAt updatedAt isDeleted
  }
  domainPermutationEventActivityLogProjections(domainPermutationId: $domainPermutationId) {
    id actorEmail actorType assigneeEmail previousStatus currentStatus type content createdAt updatedAt isDeleted
  }
  assetOccurrenceEventActivityLogProjections(assetOccurrenceId: $assetOccurrenceId) {
    id actorEmail actorType assigneeEmail previousStatus currentStatus type content createdAt updatedAt isDeleted
  }
}
```

Run only the relevant branch if you have one ID. Dark-web events have source-specific activity-log queries: `darkWebForumPostEventActivityLogProjections`, `darkWebTelegramPostEventActivityLogProjections`, `darkWebRansomwarePostEventActivityLogProjections`, and `darkWebMarketplacePostEventActivityLogProjections`.

## Vulnerability and ASM Evidence

Supports `A.8.8`, `A.8.16`, `A.8.20`, `A.8.21`, `A.8.24`, `A.8.26`, and partial `A.8.9`.

```graphql
query AsmAuditEvidence($projectId: UUID!) {
  attackSurfaceScanProjections(projectId: $projectId, take: 100, skip: 0, order: [{ createdAt: DESC }]) {
    totalCount
    items {
      attackSurfaceScanId
      name
      type
      cronSchedule
      scanAllIps
      scanAllDomains
      ipsCount
      domainsCount
      useAllTemplates
      selectedTemplatesCount
      unresolvedVulnerabilitiesCount
      lastExecutionStartedAt
      lastExecutionStatus
      createdAt
    }
  }
  attackSurfaceVulnerabilities(
    projectId: $projectId
    take: 100
    skip: 0
    where: { isResolved: { eq: false }, riskLevel: { in: [CRITICAL, HIGH, MEDIUM] } }
    order: [{ riskLevel: DESC }, { createdAt: DESC }]
  ) {
    totalCount
    pageInfo { hasNextPage }
    items { id assetValue title sourceType type riskLevel tags isResolved status assigneeEmail createdAt }
  }
  webApplicationProjections(projectId: $projectId, take: 100, skip: 0, order: [{ unresolvedVulnerabilitiesCount: DESC }]) {
    totalCount
    items { webApplicationId assetValue port responseStatusCode technologies ipAddresses cNames unresolvedVulnerabilitiesCount hasScreenshot lastDiscoveredAt }
  }
  networkServiceProjections(projectId: $projectId, take: 100, skip: 0, order: [{ unresolvedVulnerabilitiesCount: DESC }]) {
    totalCount
    items { networkServiceId ip name product version port isActive domains unresolvedVulnerabilitiesCount lastDiscoveredAt }
  }
  attackSurfaceIps(projectId: $projectId, take: 100, skip: 0, order: [{ unresolvedNetworkServicesVulnerabilitiesCount: DESC }]) {
    totalCount
    items { id value domains networkServices provider geolocationCountry geolocationCountryCode autonomousSystemNumber unresolvedNetworkServicesVulnerabilitiesCount lastDiscoveredAtNetworkServicesScan }
  }
}
```

Fetch details before making audit findings:

```graphql
query WebVulnerabilityDetail($id: UUID!) {
  webApplicationAttackSurfaceVulnerability(attackSurfaceVulnerabilityId: $id) {
    id title riskLevel description impactDescription remediationInstructions
    sourceType type assetValue port tags references
    commonVulnerabilitiesAndExposuresId commonWeaknessEnumerationIds
    commonVulnerabilityScoringSystem3Score commonVulnerabilityScoringSystemVector
    evidenceUrl evidenceHost evidencePort evidenceScheme evidenceHttpRequest evidenceHttpResponse evidenceData evidenceExtractedData
  }
}
```

Use `networkServiceAttackSurfaceVulnerability` for `NETWORK_SERVICE` rows and `dnsAttackSurfaceVulnerability` for `DNS` rows. Request the same evidence/remediation/CVE fields available on those detail types.

## DNS, Email Security, and Cryptography

Supports `A.8.24`, `A.8.20`, `A.8.21`, partial `A.8.9`, and phishing/spoofing evidence related to `A.5.7`.

```graphql
query DnsAndCertificateEvidence($projectId: UUID!) {
  attackSurfaceDomains(projectId: $projectId, take: 100, skip: 0, order: [{ unresolvedDnsVulnerabilitiesCount: DESC }]) {
    totalCount
    items {
      id
      value
      spoofingRiskLevel
      spfState
      dmarcState
      unresolvedDnsVulnerabilitiesCount
      lastDiscoveredAtDnsScan
      dnsRecordCounts { type count }
    }
  }
  attackSurfaceSslCertificates(projectId: $projectId, take: 100, skip: 0, order: [{ validTo: ASC }]) {
    totalCount
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
  }
}
```

For stronger crypto evidence, fetch `webApplication(webApplicationId:)` or `networkService(id:)` details and inspect `sslDetails` for TLS grade, HSTS, protocols, and cipher suites, plus `sslCertificate(sslCertificateId:)` for key/signature/expiry/revocation fields where available.

## Leaked Data and Malware Evidence

Supports `A.5.7`, `A.5.25`, `A.5.26`, and credential/session compromise signals relevant to access-control audits.

```graphql
query ExposureEvidence($projectId: UUID!) {
  assetTopUnresolvedAssetOccurrencesStatistics(projectId: $projectId) {
    assetIdentifier
    total
    high { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
    medium { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
    low { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
    informational { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
  }
  dataBreachesAssetsOccurrences(projectId: $projectId, take: 100, skip: 0, where: { isResolved: { eq: false } }, order: [{ riskLevel: DESC }, { createdAt: DESC }]) {
    totalCount
    items { id assetId occurrenceId riskLevel isResolved status assigneeEmail dataPointsCount dataPoints createdAt asset { value type } occurrence { id origin type occurredAt publishedAt } tags { value } }
  }
  leakedCredentialsAssetsOccurrencesV1(projectId: $projectId, take: 100, skip: 0, where: { isResolved: { eq: false } }, order: [{ riskLevel: DESC }, { createdAt: DESC }]) {
    totalCount
    items { id assetId occurrenceId riskLevel isResolved status assigneeEmail urls createdAt asset { value type } occurrence { id origin type occurredAt publishedAt } tags { value } }
  }
  malwareInfectionsAssetsOccurrences(projectId: $projectId, take: 100, skip: 0, where: { isResolved: { eq: false } }, order: [{ riskLevel: DESC }, { createdAt: DESC }]) {
    totalCount
    items {
      id assetId occurrenceId riskLevel isResolved status assigneeEmail
      corporateCredentialsCount corporateCookiesCount credentialsCount cookiesCount autoFillsCount filesCount creditCardsCount
      createdAt
      asset { value type }
      occurrence { id origin type occurredAt publishedAt }
      tags { value }
    }
  }
}
```

If you need detail for one malware finding, use `malwareInfectionAssetOccurrenceV2(assetOccurrenceId:, revealNonCorporateData: false, revealSensitiveData: false)` first. Only set reveal flags to `true` when explicitly authorized.

## Domain Squatting Evidence

Supports `A.5.7`, phishing/brand abuse monitoring, incident triage, and external attack-surface risks.

```graphql
query DomainSquattingEvidence($projectId: UUID!) {
  domainPermutationsOriginalDomains(projectId: $projectId)
  domainPermutationsPermutationTypes(projectId: $projectId)
  domainPermutationsProjections(
    projectId: $projectId
    take: 100
    skip: 0
    where: { isResolved: { eq: false } }
    order: [{ riskLevel: DESC }, { detectionDate: DESC }]
  ) {
    totalCount
    pageInfo { hasNextPage }
    items {
      id
      domainPermutationId
      originalDomain
      detectedDomain
      permutationType
      riskLevel
      similarityScore
      visualSimilarity
      detectionDate
      isResolved
      status
      assigneeEmail
      nameServers
      mailServers
      ips { address countryCodeIso countryName }
    }
  }
}
```

## Audit Output Shape

Use this structure unless the user asks otherwise:

1. Scope and evidence basis: project, dates, modules queried, pagination limits, and freshness of scans/events.
2. Control coverage matrix: ISO control, NordStellar evidence used, coverage level (`strong`, `partial`, `none`), gaps/manual evidence.
3. Key audit observations: unresolved critical/high risks, stale scans, unmonitored assets, missing assignees/statuses, excessive unresolved age, spoofing/DNS gaps, certificate/TLS issues, leaked credentials/malware, dark web/domain-squatting alerts.
4. Findings: control reference, evidence, risk, impact, recommended remediation, owner/assignee if present, and whether evidence is suitable for audit sampling.
5. Manual evidence required: SoA entries, policies/procedures, risk acceptance records, tickets, incident reports, vendor certificates, contracts/DPAs, access reviews, backup/BCP evidence, internal logs.
6. Appendix: GraphQL query log, result counts, sampled IDs, pages reviewed, and data that was intentionally not revealed.

## Audit Judgment Rules

- `Compliant` requires NordStellar evidence plus appropriate manual evidence. Do not mark compliant from NordStellar data alone.
- `Partially evidenced` means NordStellar supports the control objective but cannot prove governance or process execution.
- `Gap` means NordStellar shows missing/failed/stale monitoring, unresolved high-risk exposure, no scan evidence, no triage/assignment, or no relevant data where the control expects it.
- `Not covered by NordStellar` means the control is outside MCP data; list the evidence the auditor should request.
- Always include evidence freshness: scan `lastExecutionStartedAt`, asset/issue `createdAt`, event `eventCreatedAt`, certificate `lastDiscoveredAt`, and dark web `postedAt`/`scrapedAt`/`lastDetectedAt`.

