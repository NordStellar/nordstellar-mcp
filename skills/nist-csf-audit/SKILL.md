---

name: nist-csf-audit
version: 1.0.0
description: "NordStellar audit workflow for NIST Cybersecurity Framework 2.0 evidence collection: map MCP data to Govern, Identify, Protect, Detect, Respond, and Recover outcomes for asset inventory, threat intelligence, vulnerability management, monitoring, event workflow, external exposure, DNS/TLS posture, leaked data, malware infections, and domain-squatting risk."
metadata:
  nordstellar:
    category: "audit-compliance"
    framework: "NIST Cybersecurity Framework 2.0"
    requires:
  tools: ["graphql_query", "graphql_batch", "search_types", "get_type_definition"]

---

# NordStellar - NIST CSF Audit Evidence

Use this skill when the user asks for NIST CSF, NIST Cybersecurity Framework, CSF 2.0 profile evidence, current/target profile support, cybersecurity maturity evidence, or a NIST-aligned security posture review using NordStellar data.

NordStellar does **not** prove NIST CSF implementation by itself. It provides external technical evidence that supports selected CSF 2.0 outcomes, mostly in `Identify`, `Protect`, `Detect`, and `Respond`. `Govern` and `Recover` are mostly manual evidence areas.

## Realistic Coverage

NordStellar can usually provide strong evidence for **external asset inventory, threat intelligence, vulnerability management, monitoring, detection, and response workflow outcomes**. It can identify gaps for a NIST CSF profile, but it cannot complete an enterprise CSF assessment alone.

**Default completeness score: 30/100.** NIST CSF is outcome-oriented, so NordStellar can cover a useful portion of `Identify`, `Detect`, and parts of `Protect`/`Respond` from external technical evidence. The score remains conservative because `Govern`, `Recover`, internal protection controls, policy execution, enterprise risk management, and resilience evidence require non-NordStellar sources. Raise it only for a narrow external-threat profile; lower it for enterprise-wide CSF maturity assessments.

Covered well:

- `ID.AM` asset management: monitored domains, IPs, emails, web apps, network services, certificates, asset status, and target scope.
- `ID.RA` risk assessment: unresolved vulnerabilities, exposure counts, leaked data, malware infections, domain squatting, dark web mentions.
- `PR.PS` and `PR.IR` partial platform/infrastructure protection: DNS, SPF/DMARC, TLS, exposed ports, technologies, and configuration findings.
- `DE.CM` continuous monitoring: dark web rules, event feeds, scan execution status, detection timestamps.
- `DE.AE` adverse event analysis: event types, risk levels, tags, affected assets, unresolved age.
- `RS.AN` and `RS.MI` partial response evidence: status, assignment, activity logs, remediation state, resolution counts.

Partial only:

- Governance outcomes need risk appetite, roles, policies, legal obligations, management oversight, and metrics outside NordStellar.
- Protect outcomes need internal access control, training, endpoint, backup, data protection, and secure configuration evidence outside NordStellar.
- Recover outcomes need business continuity, restore tests, communication plans, and lessons learned outside NordStellar.

Communicate this limit: "NordStellar gives strong external technical evidence for parts of a NIST CSF profile, but a complete CSF assessment still needs governance, internal systems, policy, recovery, supplier, and process evidence."

## Ground Rules

- Start with `projectsV2` and select the relevant `projectId`.
- Use `skip` / `take`; max `take` is `100`.
- Do not use GraphQL aliases.
- Use `graphql_batch` for the same operation across many projects.
- Use `search_types` / `get_type_definition` before adding unfamiliar fields.
- Report coverage as `strong`, `partial`, `gap`, or `not covered by NordStellar`.
- Treat raw passwords, cookies, and personal data as sensitive; report counts and categories unless explicitly authorized.

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

## CSF Function Mapping

- `Govern (GV)`: weak evidence. NordStellar can support risk reporting and supplier/technology discovery, but governance is mostly manual.
- `Identify (ID)`: strong for external asset inventory, attack surface, threat exposure, vulnerability context, and current risk.
- `Protect (PR)`: partial for technical hardening evidence: DNS/email controls, TLS, exposed services, web headers/technologies, and vulnerabilities.
- `Detect (DE)`: strong for NordStellar detections: dark web monitoring, leaked credentials, malware infections, domain permutations, ASM findings, event feed.
- `Respond (RS)`: partial for triage workflow: assignees, statuses, resolved/unresolved counts, activity logs.
- `Recover (RC)`: not covered except indirect remediation/resolution signals.

## Overview Query

```graphql
query NistCsfOverview($projectId: UUID!) {
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
    totalCount resolvedCount unresolvedCount
    criticalUnresolvedCount highUnresolvedCount mediumUnresolvedCount lowUnresolvedCount infoUnresolvedCount
  }
  domainSquattingCounts(projectId: $projectId) {
    totalEventsCount highRiskEventsPerThirtyDaysCount eventsPerThirtyDaysCount
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

## Asset and Attack Surface Evidence

Supports `ID.AM`, `ID.RA`, `PR.PS`, `PR.IR`, and `DE.CM`.

```graphql
query NistCsfAssetAndAsm($projectId: UUID!) {
  assetsProjections(projectId: $projectId, take: 100, skip: 0, where: { isDeleted: { eq: false } }) {
    totalCount
    pageInfo { hasNextPage }
    items {
      assetId assetType assetSubtype assetValue parentAssets orphanedParents source status
      leakedDataManagementMonitoringStatus isLeakedDataManagementMonitoringStatusSuccessful
      domainSquattingMonitoringStatus isDomainSquattingMonitoringStatusSuccessful
      darkWebMonitoringMonitoringStatus isDarkWebMonitoringMonitoringStatusSuccessful
      darkWebMonitoringSearchInTypes darkWebMonitoringSearchFilter darkWebMonitoringLastDetectedAt
      createdAt
    }
  }
  attackSurfaceScanProjections(projectId: $projectId, take: 100, skip: 0, order: [{ createdAt: DESC }]) {
    totalCount
    items { attackSurfaceScanId name type cronSchedule scanAllIps scanAllDomains useAllTemplates unresolvedVulnerabilitiesCount lastExecutionStartedAt lastExecutionStatus createdAt }
  }
  attackSurfaceVulnerabilities(projectId: $projectId, take: 100, skip: 0, where: { isResolved: { eq: false }, riskLevel: { in: [CRITICAL, HIGH, MEDIUM] } }, order: [{ riskLevel: DESC }, { createdAt: DESC }]) {
    totalCount
    pageInfo { hasNextPage }
    items { id assetValue title sourceType type riskLevel tags isResolved status assigneeEmail createdAt }
  }
}
```

## Detect and Respond Evidence

Supports `DE.CM`, `DE.AE`, `RS.AN`, and partial `RS.MI`.

```graphql
query NistCsfDetectRespond($projectId: UUID!, $fromDate: DateTime!) {
  darkWebMonitoringRules(projectId: $projectId, take: 100, skip: 0) {
    totalCount
    items { id name description sourceTypes lastDetectedAt createdAt darkWebMonitoringSearchFilter { id name query tags createdAt updatedAt } }
  }
  eventsProjectionsV2(projectId: $projectId, take: 100, skip: 0, where: { isResolved: { eq: false } }, order: [{ riskLevel: DESC }, { createdAt: DESC }]) {
    totalCount
    pageInfo { hasNextPage }
    items { id entityId type assetValue riskLevel isResolved status assigneeEmail eventCreatedAt createdAt resolvedAt tags }
  }
  eventsResolutionCounts(input: { projectId: $projectId, fromDate: $fromDate }) {
    type
    newUnresolved { criticalEventsCount highEventsCount mediumEventsCount lowEventsCount infoEventsCount }
    newTotal { criticalEventsCount highEventsCount mediumEventsCount lowEventsCount infoEventsCount }
    resolved { criticalEventsCount highEventsCount mediumEventsCount lowEventsCount infoEventsCount }
  }
}
```

## Exposure Evidence

Supports `ID.RA`, `DE.CM`, and response prioritization.

```graphql
query NistCsfExposure($projectId: UUID!) {
  assetTopUnresolvedAssetOccurrencesStatistics(projectId: $projectId) {
    assetIdentifier total
    high { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
    medium { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
    low { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
    informational { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
  }
  leakedCredentialsAssetsOccurrencesV1(projectId: $projectId, take: 100, skip: 0, where: { isResolved: { eq: false } }, order: [{ riskLevel: DESC }, { createdAt: DESC }]) {
    totalCount
    items { id riskLevel isResolved status assigneeEmail urls createdAt asset { value type } occurrence { id origin type occurredAt publishedAt } tags { value } }
  }
  malwareInfectionsAssetsOccurrences(projectId: $projectId, take: 100, skip: 0, where: { isResolved: { eq: false } }, order: [{ riskLevel: DESC }, { createdAt: DESC }]) {
    totalCount
    items { id riskLevel isResolved status assigneeEmail corporateCredentialsCount corporateCookiesCount credentialsCount cookiesCount createdAt asset { value type } occurrence { id origin type occurredAt publishedAt } tags { value } }
  }
}
```

## Output Shape

Use this structure:

1. Scope and profile context: project, current/target profile if supplied, evidence date, pages reviewed, and data freshness.
2. Function summary: `Govern`, `Identify`, `Protect`, `Detect`, `Respond`, `Recover` with coverage level and NordStellar evidence.
3. Key gaps: unmonitored assets, stale scans, unresolved critical/high findings, unresolved event age, missing assignees, DNS/TLS weaknesses, leaked credentials, malware infections, domain squatting, dark web alerts.
4. Profile evidence matrix: CSF category/outcome, evidence query, result summary, manual evidence needed.
5. Manual evidence required: policies, roles, risk appetite, internal inventories, access reviews, endpoint/SIEM evidence, backup/recovery tests, supplier due diligence.
6. Appendix: query log, counts, sampled IDs, pagination, and sensitive data not revealed.

