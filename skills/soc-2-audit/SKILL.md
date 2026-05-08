---

name: soc-2-audit
version: 1.0.0
description: "NordStellar audit workflow for SOC 2 Trust Services Criteria evidence collection: map MCP data to Security common criteria and partial Availability, Confidentiality, Processing Integrity, and Privacy evidence for external asset inventory, vulnerability management, monitoring, incident/event workflow, network exposure, TLS/DNS posture, leaked data, malware infections, dark web monitoring, and supplier exposure."
metadata:
  nordstellar:
    category: "audit-compliance"
    framework: "SOC 2 Trust Services Criteria"
    requires:
  tools: ["graphql_query", "graphql_batch", "search_types", "get_type_definition"]

---

# NordStellar - SOC 2 Audit Evidence

Use this skill when the user asks for SOC 2 evidence, Trust Services Criteria, Security common criteria, SOC 2 readiness, SOC 2 Type I/Type II support, or security control evidence from NordStellar data.

NordStellar does **not** prove SOC 2 compliance by itself. It provides technical and monitoring evidence mostly for the `Security` category and selected points of focus around vulnerability management, monitoring, incident detection, and logical/perimeter security. It cannot prove control design/operation over the full audit period without policies, tickets, interviews, internal logs, access reviews, vendor records, and management evidence.

## Realistic Coverage

NordStellar can realistically support **SOC 2 Security common criteria evidence for technical monitoring and external risk**, but it is not enough for a SOC 2 report. For Type II, NordStellar evidence must be tied to the audit period and complemented by operating evidence from the organization's systems.

**Default completeness score: 20/100.** NordStellar can contribute useful technical evidence for SOC 2 Security monitoring, vulnerability management, external perimeter, threat exposure, and incident triage. It cannot prove control design or operation across the audit period without control narratives, tickets, internal logs, access reviews, change records, vendor records, and management evidence. Raise the score only for Security-only readiness focused on external risk; lower it for Type II reports or additional TSC categories.

Covered well:

- Security monitoring: dark web monitoring rules, event feed, event risk/status, unresolved/resolved metrics.
- Vulnerability management: ASM scans, vulnerabilities, CVEs/misconfigurations, remediation evidence, scan freshness.
- External perimeter: IPs, web apps, network services, ports, DNS, TLS/certificates, technologies.
- Threat/exposure management: leaked credentials, data breaches, malware/stealer infections, domain squatting, ransomware/forum/Telegram/marketplace mentions.
- Incident workflow signals: assignees, status, activity logs, timestamps, resolution counts.

Partial only:

- Availability: exposed infrastructure and certificate expiry can signal risks, but not uptime, capacity, DR, backup, or SLA operation.
- Confidentiality/Privacy: leaked data and exposure findings can signal risk, but not data classification, retention, access approvals, privacy notices, or DSR workflows.
- Processing Integrity: mostly not covered except web app/security defects that may affect integrity.
- Vendor management: provider/technology visibility exists, but contracts, SOC reports, DPAs, and subprocessor evidence are external.

Tell users: "NordStellar is useful SOC 2 evidence for security monitoring, vulnerability management, external perimeter, and incident triage, but a SOC 2 audit still requires control narratives and operating evidence from internal systems across the audit period."

## Ground Rules

- Start with `projectsV2` and select `projectId`.
- Ask whether the scope is Type I or Type II and what audit period applies. Use `fromDate` aligned to the period.
- Use `skip` / `take`; max `take` is `100`.
- Do not use GraphQL aliases.
- Use `graphql_batch` for cross-project or repeated-period evidence.
- Use `search_types` / `get_type_definition` before unfamiliar fields.
- Keep SOC 2 conclusions conservative: `supports evidence`, `partial`, `gap`, or `manual evidence required`.
- Do not reveal raw passwords/cookies without explicit authorization.

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

## TSC Mapping

- `Security`: strong for external monitoring, vulnerabilities, event detection, perimeter exposure, threat intelligence.
- `Availability`: partial for certificate expiry, infrastructure exposure, stale scans, unresolved critical/high service risks.
- `Confidentiality`: partial for leaked data, credentials, dark web exposure, and data breach signals.
- `Processing Integrity`: weak, except vulnerability evidence affecting application integrity.
- `Privacy`: weak to partial, only where leaked PII/data breach evidence exists.

## Overview Query

```graphql
query Soc2Overview($projectId: UUID!) {
  assetProjectionsCounts(projectId: $projectId) {
    approvedAssetsCount monitoredAssetsCount unmonitoredAssetsCount
    countsPerAssetType { key value }
  }
  generalData(projectId: $projectId) {
    dataBreachesCount malwareInfectionsCount leakedCredentialsCount affectedEmployeesCount
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
    criticalEventsDaysUnresolvedAverage highEventsDaysUnresolvedAverage mediumEventsDaysUnresolvedAverage lowEventsDaysUnresolvedAverage
  }
}
```

## Security Monitoring and Incident Evidence

```graphql
query Soc2Monitoring($projectId: UUID!, $fromDate: DateTime!) {
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
  eventsAssignees(projectId: $projectId) { userId username email }
}
```

Use source-specific activity log queries for samples: `attackSurfaceVulnerabilityEventActivityLogProjections`, `assetOccurrenceEventActivityLogProjections`, `domainPermutationEventActivityLogProjections`, and dark-web post activity-log queries.

## Vulnerability Management Evidence

```graphql
query Soc2VulnerabilityManagement($projectId: UUID!) {
  attackSurfaceScanProjections(projectId: $projectId, take: 100, skip: 0, order: [{ createdAt: DESC }]) {
    totalCount
    items { attackSurfaceScanId name type cronSchedule scanAllIps scanAllDomains useAllTemplates unresolvedVulnerabilitiesCount lastExecutionStartedAt lastExecutionStatus createdAt }
  }
  attackSurfaceVulnerabilities(projectId: $projectId, take: 100, skip: 0, where: { isResolved: { eq: false } }, order: [{ riskLevel: DESC }, { createdAt: DESC }]) {
    totalCount
    pageInfo { hasNextPage }
    items { id assetValue title sourceType type riskLevel tags isResolved status assigneeEmail createdAt }
  }
}
```

For audit samples, fetch detail with `webApplicationAttackSurfaceVulnerability`, `networkServiceAttackSurfaceVulnerability`, or `dnsAttackSurfaceVulnerability` and include description, impact, remediation, CVE/CVSS, evidence URL/request/response/data.

## External Perimeter and Availability Signals

```graphql
query Soc2Perimeter($projectId: UUID!) {
  webApplicationProjections(projectId: $projectId, take: 100, skip: 0, order: [{ unresolvedVulnerabilitiesCount: DESC }]) {
    totalCount
    items { webApplicationId assetValue port responseStatusCode technologies ipAddresses cNames unresolvedVulnerabilitiesCount hasScreenshot lastDiscoveredAt }
  }
  networkServiceProjections(projectId: $projectId, take: 100, skip: 0, order: [{ unresolvedVulnerabilitiesCount: DESC }]) {
    totalCount
    items { networkServiceId ip name product version port isActive domains unresolvedVulnerabilitiesCount lastDiscoveredAt }
  }
  attackSurfaceSslCertificates(projectId: $projectId, take: 100, skip: 0, order: [{ validTo: ASC }]) {
    totalCount
    items { id subject subjectAlternativeNames issuer validTo isValid targetsCount webApplicationsCount networkServicesCount lastDiscoveredAt }
  }
  attackSurfaceDomains(projectId: $projectId, take: 100, skip: 0, order: [{ unresolvedDnsVulnerabilitiesCount: DESC }]) {
    totalCount
    items { id value spoofingRiskLevel spfState dmarcState unresolvedDnsVulnerabilitiesCount lastDiscoveredAtDnsScan dnsRecordCounts { type count } }
  }
}
```

## Confidentiality, Privacy, and Threat Exposure

```graphql
query Soc2Exposure($projectId: UUID!) {
  assetTopUnresolvedAssetOccurrencesStatistics(projectId: $projectId) {
    assetIdentifier total
    high { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
    medium { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
    low { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
    informational { total dataBreachesCount leakedCredentialsCount malwareInfectionsCount }
  }
  dataBreachesAssetsOccurrences(projectId: $projectId, take: 100, skip: 0, where: { isResolved: { eq: false } }, order: [{ riskLevel: DESC }, { createdAt: DESC }]) {
    totalCount
    items { id riskLevel isResolved status assigneeEmail dataPointsCount dataPoints createdAt asset { value type } occurrence { id origin type occurredAt publishedAt } tags { value } }
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

1. Scope: SOC 2 type, audit period, TSC categories, project, evidence date, scan/event freshness.
2. TSC evidence matrix: category, criterion/control objective, NordStellar evidence, coverage level, period evidence, manual evidence needed.
3. Security findings: vulnerabilities, monitoring gaps, unresolved events, lack of assignees, DNS/TLS weaknesses, leaked credentials, malware, domain squatting, dark web alerts.
4. Availability/confidentiality/privacy implications: only where NordStellar evidence supports them.
5. Manual evidence required: policies, control narratives, tickets, access reviews, SIEM/EDR logs, change records, incident reports, vendor SOC reports, DPAs, backup/DR evidence, management review.
6. Appendix: query log, sampled IDs, pagination, and sensitive data handling.

