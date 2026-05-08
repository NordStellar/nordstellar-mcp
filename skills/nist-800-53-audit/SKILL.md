---

name: nist-800-53-audit
version: 1.0.0
description: "NordStellar audit workflow for NIST SP 800-53 Rev. 5 evidence collection: map MCP data to RA, CA, SI, IR, AU, CM, SC, AC, and SR control families for external asset inventory, vulnerability scanning, continuous monitoring, incident/event workflow, audit/activity records, network exposure, DNS/TLS posture, leaked data, malware infections, and third-party exposure."
metadata:
  nordstellar:
    category: "audit-compliance"
    framework: "NIST SP 800-53 Rev. 5"
    requires:
  tools: ["graphql_query", "graphql_batch", "search_types", "get_type_definition"]

---

# NordStellar - NIST 800-53 Audit Evidence

Use this skill when the user asks for NIST SP 800-53, 800-53 Rev. 5, FedRAMP-like evidence support, control family evidence, technical control sampling, vulnerability monitoring, or continuous monitoring evidence from NordStellar data.

NordStellar does **not** prove NIST 800-53 compliance by itself. It provides external technical and workflow evidence for selected controls, especially `RA`, `CA`, `SI`, `IR`, `AU`, `CM`, `SC`, and limited `SR`. It cannot prove control implementation statements, SSP narratives, authorizations, policies, internal logging, access control, or operational procedures alone.

## Realistic Coverage

NordStellar can realistically support evidence collection for **roughly 15-25 technical controls or control enhancements**, depending on project modules and scan freshness. This is useful for audit sampling and continuous monitoring, but it is not a complete 800-53 assessment.

**Default completeness score: 15/100.** NordStellar is useful for selected external monitoring, vulnerability, incident/event, boundary, and configuration evidence, but NIST 800-53 is a broad catalog covering many governance, access, audit, contingency, personnel, physical, privacy, and system lifecycle controls that are outside NordStellar. Raise the score only for a narrow RA/CA/SI/IR/SC technical evidence package; lower it for full SSP, FedRAMP, or authorization assessments.

Covered well:

- `RA-5 Vulnerability Monitoring and Scanning`: ASM scan configuration, last scan status, unresolved vulnerability counts, CVE/misconfiguration details, remediation instructions.
- `CA-7 Continuous Monitoring`: event feed, scan history, monitoring rules, open/resolved metrics.
- `SI-2 Flaw Remediation`: unresolved findings, resolution status, activity logs, assignees, vulnerability detail and remediation evidence.
- `IR-4 Incident Handling` and `IR-5 Incident Monitoring`: detected events, triage state, assignees, risk, age, resolution counts.
- `AU-2/AU-6` partial: NordStellar activity logs and event records, not system-wide audit logs.
- `CM-6` partial: DNS, SPF/DMARC, TLS, headers, exposed services, technologies, and configuration findings.
- `SC-7/SC-8/SC-13` partial: boundary exposure, network services, TLS/certificate evidence, DNS/email security.
- `SR` partial: providers, ASNs, hosting countries, detected third-party technology exposure.

Not covered or manual:

- Access control (`AC`) beyond leaked credential signals; no internal IAM review.
- Full audit/accountability (`AU`) logging policies, retention, SIEM evidence, or internal log review.
- SSP, POA&M governance, authorization decisions, risk acceptance, policy approvals, training, physical/environmental, contingency planning, and personnel controls.

Tell users: "NordStellar is strong for external continuous monitoring and vulnerability evidence under NIST 800-53, but the assessment still requires SSP/POA&M, policy, authorization, internal logging, IAM, incident records, and operational evidence outside NordStellar."

## Ground Rules

- Start with `projectsV2` and select the relevant `projectId`.
- Use `skip` / `take`; max `take` is `100`.
- Do not use GraphQL aliases.
- Use `graphql_batch` for cross-project evidence.
- Use `search_types` / `get_type_definition` before unfamiliar fields.
- Map evidence to control families cautiously; mark coverage as `strong`, `partial`, `gap`, or `manual`.
- Do not reveal raw passwords or cookie values unless explicitly authorized.

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

## Control Family Mapping

- `RA`: strong for vulnerability scanning, threat exposure, leaked data, malware, dark web, domain-squatting risk.
- `CA`: partial to strong for continuous monitoring evidence; weak for authorization/governance.
- `SI`: strong for technical flaw detection; partial for remediation process proof.
- `IR`: partial for incident/event workflow; needs incident tickets, analysis, communications, lessons learned.
- `AU`: partial for NordStellar activity records only.
- `CM`: partial for external configuration posture and misconfigurations.
- `SC`: partial for boundary, network service, DNS, TLS/certificate evidence.
- `AC`: weak; leaked credential evidence can indicate access-control risk but not IAM control operation.
- `SR`: partial supplier/technology/provider visibility; needs vendor assurance outside NordStellar.

## Overview Query

```graphql
query Nist80053Overview($projectId: UUID!) {
  assetProjectionsCounts(projectId: $projectId) {
    approvedAssetsCount monitoredAssetsCount unmonitoredAssetsCount
    countsPerAssetType { key value }
  }
  attackSurfaceVulnerabilitiesCounts(projectId: $projectId) {
    totalCount resolvedCount unresolvedCount
    criticalUnresolvedCount highUnresolvedCount mediumUnresolvedCount lowUnresolvedCount infoUnresolvedCount
  }
  generalData(projectId: $projectId) {
    dataBreachesCount malwareInfectionsCount leakedCredentialsCount affectedEmployeesCount
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

## RA-5, CA-7, SI-2 Evidence

```graphql
query VulnerabilityMonitoring($projectId: UUID!) {
  attackSurfaceScanProjections(projectId: $projectId, take: 100, skip: 0, order: [{ createdAt: DESC }]) {
    totalCount
    items {
      attackSurfaceScanId name type cronSchedule scanAllIps scanAllDomains
      useAllTemplates selectedTemplatesCount unresolvedVulnerabilitiesCount
      lastExecutionStartedAt lastExecutionStatus createdAt
    }
  }
  attackSurfaceVulnerabilities(projectId: $projectId, take: 100, skip: 0, where: { isResolved: { eq: false } }, order: [{ riskLevel: DESC }, { createdAt: DESC }]) {
    totalCount
    pageInfo { hasNextPage }
    items { id assetValue title sourceType type riskLevel tags isResolved status assigneeEmail createdAt }
  }
  webApplicationProjections(projectId: $projectId, take: 100, skip: 0, order: [{ unresolvedVulnerabilitiesCount: DESC }]) {
    totalCount
    items { webApplicationId assetValue port responseStatusCode technologies unresolvedVulnerabilitiesCount hasScreenshot lastDiscoveredAt }
  }
  networkServiceProjections(projectId: $projectId, take: 100, skip: 0, order: [{ unresolvedVulnerabilitiesCount: DESC }]) {
    totalCount
    items { networkServiceId ip name product version port isActive domains unresolvedVulnerabilitiesCount lastDiscoveredAt }
  }
}
```

Fetch details for sampled findings before writing audit observations:

```graphql
query WebVulnerabilityDetail($id: UUID!) {
  webApplicationAttackSurfaceVulnerability(attackSurfaceVulnerabilityId: $id) {
    id title riskLevel description impactDescription remediationInstructions
    sourceType type assetValue port tags references
    commonVulnerabilitiesAndExposuresId commonWeaknessEnumerationIds commonVulnerabilityScoringSystem3Score
    evidenceUrl evidenceHost evidencePort evidenceScheme evidenceHttpRequest evidenceHttpResponse evidenceData evidenceExtractedData
  }
}
```

Use `networkServiceAttackSurfaceVulnerability` for `NETWORK_SERVICE` and `dnsAttackSurfaceVulnerability` for `DNS`.

## IR, AU, and Continuous Monitoring Evidence

```graphql
query EventMonitoring($projectId: UUID!, $fromDate: DateTime!) {
  eventsProjectionsV2(projectId: $projectId, take: 100, skip: 0, where: { isResolved: { eq: false } }, order: [{ riskLevel: DESC }, { createdAt: DESC }]) {
    totalCount
    pageInfo { hasNextPage }
    items { id entityId type assetValue riskLevel isResolved status assigneeEmail eventCreatedAt createdAt resolvedAt tags }
  }
  eventsAssignees(projectId: $projectId) { userId username email }
  eventsResolutionCounts(input: { projectId: $projectId, fromDate: $fromDate }) {
    type
    newUnresolved { criticalEventsCount highEventsCount mediumEventsCount lowEventsCount infoEventsCount }
    newTotal { criticalEventsCount highEventsCount mediumEventsCount lowEventsCount infoEventsCount }
    resolved { criticalEventsCount highEventsCount mediumEventsCount lowEventsCount infoEventsCount }
  }
  darkWebMonitoringRules(projectId: $projectId, take: 100, skip: 0) {
    totalCount
    items { id name description sourceTypes lastDetectedAt createdAt darkWebMonitoringSearchFilter { id name query tags } }
  }
}
```

For sampled event workflow, use the `entityId` with the matching activity-log query:

```graphql
query ActivityLogSample($attackSurfaceVulnerabilityId: UUID!) {
  attackSurfaceVulnerabilityEventActivityLogProjections(attackSurfaceVulnerabilityId: $attackSurfaceVulnerabilityId) {
    id actorEmail actorType assigneeEmail previousStatus currentStatus type content createdAt updatedAt isDeleted
  }
}
```

## CM, SC, and SR Evidence

```graphql
query BoundaryConfigurationEvidence($projectId: UUID!) {
  attackSurfaceIps(projectId: $projectId, take: 100, skip: 0, order: [{ unresolvedNetworkServicesVulnerabilitiesCount: DESC }]) {
    totalCount
    items { id value domains networkServices provider geolocationCountry geolocationCountryCode autonomousSystemNumber unresolvedNetworkServicesVulnerabilitiesCount lastDiscoveredAtNetworkServicesScan }
  }
  attackSurfaceDomains(projectId: $projectId, take: 100, skip: 0, order: [{ unresolvedDnsVulnerabilitiesCount: DESC }]) {
    totalCount
    items { id value spoofingRiskLevel spfState dmarcState unresolvedDnsVulnerabilitiesCount lastDiscoveredAtDnsScan dnsRecordCounts { type count } }
  }
  attackSurfaceSslCertificates(projectId: $projectId, take: 100, skip: 0, order: [{ validTo: ASC }]) {
    totalCount
    items { id subject subjectAlternativeNames issuer validTo isValid targetsCount webApplicationsCount networkServicesCount lastDiscoveredAt }
  }
  technologies(projectId: $projectId, take: 100, skip: 0, order: [{ targetsCount: DESC }]) {
    totalCount
    items { id name version categories commonPlatformEnumeration targetsCount }
  }
}
```

## Threat and Credential Exposure Evidence

```graphql
query ThreatExposure($projectId: UUID!) {
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

1. Scope: project, system boundary assumptions, dates, modules queried, scan freshness, and sampling limits.
2. Control family matrix: family/control, NordStellar evidence, coverage level, gaps, and manual evidence required.
3. Technical findings: unresolved vulnerabilities, stale scans, exposed services, DNS/TLS issues, leaked credentials, malware, domain squatting, dark web alerts.
4. Continuous monitoring and response: open/resolved metrics, unresolved age, assignees, activity logs, and event types.
5. Manual evidence request list: SSP, POA&M, policies, risk acceptance, tickets, SIEM logs, IAM reviews, incident records, supplier attestations.
6. Appendix: query log, sampled IDs, pagination, and sensitive data handling.

