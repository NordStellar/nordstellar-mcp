---

name: cis-controls-audit
version: 1.0.0
description: "NordStellar audit workflow for CIS Controls v8/v8.1 evidence collection: map MCP data to inventory, vulnerability management, audit log management, email/web browser protections, malware defenses, network infrastructure management, network monitoring, service provider management, penetration testing signals, and incident response evidence."
metadata:
  nordstellar:
    category: "audit-compliance"
    framework: "CIS Controls v8"
    requires:
  tools: ["graphql_query", "graphql_batch", "search_types", "get_type_definition"]

---

# NordStellar - CIS Controls Audit Evidence

Use this skill when the user asks for CIS Controls, CIS v8, CIS v8.1, implementation group evidence, security control assessment, or prioritized hardening evidence using NordStellar data.

NordStellar does **not** prove CIS Controls implementation by itself. It provides strong external evidence for asset inventory, vulnerability management, network exposure, monitoring, malware/leaked credential exposure, DNS/TLS posture, and incident/event workflow. It cannot prove endpoint configuration, internal logging, secure baselines, account management, awareness training, backup, or SDLC process.

## Realistic Coverage

NordStellar can realistically support **6-9 of the 18 CIS Controls** with meaningful technical evidence, mostly as external attack-surface and threat-intelligence evidence. It can support audit sampling for several safeguards, but cannot complete a CIS assessment alone.

**Default completeness score: 25/100.** CIS Controls include several technical safeguards that align with NordStellar external inventory, vulnerability management, exposure, monitoring, malware/leaked-credential, and incident evidence. The score remains conservative because endpoint inventory, internal software inventory, secure baselines, account/access controls, backups, awareness, internal logging, and SDLC safeguards require other systems. Raise it only for external exposure-focused CIS reviews; lower it for full Implementation Group assessments.

Covered well:

- `Control 1 Inventory and Control of Enterprise Assets`: external domains, IPs, emails, web apps, network services, certificates, monitored/unmonitored scope.
- `Control 7 Continuous Vulnerability Management`: ASM scans, unresolved vulnerabilities, CVE/misconfiguration detail, remediation guidance, scan freshness.
- `Control 13 Network Monitoring and Defense`: NordStellar event feed, dark web monitoring, detected external security events, unresolved/resolved metrics.
- `Control 17 Incident Response Management`: partial event triage evidence, assignees, statuses, activity logs, resolution counts.
- `Control 18 Penetration Testing`: partial external findings and scan evidence, but not a replacement for formal penetration tests.

Partial only:

- `Control 2 Software Assets`: web technologies and CPEs only, not full installed software inventory.
- `Control 4 Secure Configuration`: DNS, TLS, headers, exposed services only, not endpoint/cloud baseline configuration.
- `Control 9 Email and Web Browser Protections`: SPF/DMARC/spoofing and web app exposure only.
- `Control 10 Malware Defenses`: infostealer infection evidence only, not endpoint AV/EDR control operation.
- `Control 15 Service Provider Management`: providers, ASNs, countries, and technologies only; contracts and assurance are manual.

Not covered:

- Full account management, access control, data protection, backups, security awareness, endpoint logs, wireless, application SDLC, and internal network controls.

Tell users: "NordStellar can evidence external inventory, vulnerability, exposure, and monitoring portions of CIS Controls, but a full CIS assessment needs endpoint, identity, backup, logging, awareness, SDLC, and internal process evidence."

## Ground Rules

- Start with `projectsV2` and choose `projectId`.
- Use `skip` / `take`; max `take` is `100`.
- Do not use GraphQL aliases.
- Use `graphql_batch` for repeated project or query scans.
- Use `search_types` / `get_type_definition` before unfamiliar fields.
- State whether each CIS Control is `strong`, `partial`, `gap`, or `not covered`.
- Do not reveal raw passwords/cookies without explicit authorization.

## Required First Query

```graphql
query {
  projectsV2(take: 20, skip: 0) {
    totalCount
    items { id name summary isBillable createdAt updatedAt }
  }
}
```

## Control Mapping

- `CIS 1`: strong for external enterprise asset inventory.
- `CIS 2`: partial for detected web/network technologies.
- `CIS 4`: partial for DNS, TLS, headers, ports, exposed services, web configuration findings.
- `CIS 7`: strong for external vulnerability management.
- `CIS 9`: partial for DNS/email spoofing, SPF/DMARC, web app security posture.
- `CIS 10`: partial for malware/stealer infection exposure.
- `CIS 13`: partial to strong for NordStellar monitoring outputs, not SIEM.
- `CIS 15`: partial provider/supplier visibility.
- `CIS 17`: partial incident/event workflow.
- `CIS 18`: partial external scanning evidence; not a formal pentest.

## Overview and Inventory

```graphql
query CisOverview($projectId: UUID!) {
  assetProjectionsCounts(projectId: $projectId) {
    approvedAssetsCount monitoredAssetsCount unmonitoredAssetsCount
    countsPerAssetType { key value }
  }
  assetsProjections(projectId: $projectId, take: 100, skip: 0, where: { isDeleted: { eq: false } }, order: [{ assetType: ASC }, { assetValue: ASC }]) {
    totalCount
    pageInfo { hasNextPage }
    items {
      assetId assetType assetSubtype assetValue parentAssets orphanedParents source status
      leakedDataManagementMonitoringStatus isLeakedDataManagementMonitoringStatusSuccessful
      domainSquattingMonitoringStatus isDomainSquattingMonitoringStatusSuccessful
      darkWebMonitoringMonitoringStatus isDarkWebMonitoringMonitoringStatusSuccessful
      createdAt
    }
  }
  attackSurfaceTargetAssets(projectId: $projectId, take: 100, skip: 0) {
    totalCount
    items { id value type }
  }
}
```

## Vulnerability Management

```graphql
query CisVulnerabilityManagement($projectId: UUID!) {
  attackSurfaceVulnerabilitiesCounts(projectId: $projectId) {
    totalCount resolvedCount unresolvedCount
    criticalUnresolvedCount highUnresolvedCount mediumUnresolvedCount lowUnresolvedCount infoUnresolvedCount
  }
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

Fetch details for audit samples using `webApplicationAttackSurfaceVulnerability`, `networkServiceAttackSurfaceVulnerability`, or `dnsAttackSurfaceVulnerability` based on `sourceType`.

## Network, Configuration, and Software Evidence

```graphql
query CisExposureAndConfiguration($projectId: UUID!) {
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
  technologies(projectId: $projectId, take: 100, skip: 0, order: [{ targetsCount: DESC }]) {
    totalCount
    items { id name version categories commonPlatformEnumeration targetsCount }
  }
}
```

## Email, DNS, TLS, and Certificate Evidence

```graphql
query CisDnsTls($projectId: UUID!) {
  attackSurfaceDomains(projectId: $projectId, take: 100, skip: 0, order: [{ unresolvedDnsVulnerabilitiesCount: DESC }]) {
    totalCount
    items { id value spoofingRiskLevel spfState dmarcState unresolvedDnsVulnerabilitiesCount lastDiscoveredAtDnsScan dnsRecordCounts { type count } }
  }
  attackSurfaceSslCertificates(projectId: $projectId, take: 100, skip: 0, order: [{ validTo: ASC }]) {
    totalCount
    items { id subject subjectAlternativeNames issuer validTo isValid targetsCount webApplicationsCount networkServicesCount lastDiscoveredAt }
  }
}
```

## Monitoring, Malware, and Incident Evidence

```graphql
query CisMonitoringAndResponse($projectId: UUID!, $fromDate: DateTime!) {
  darkWebMonitoringRules(projectId: $projectId, take: 100, skip: 0) {
    totalCount
    items { id name description sourceTypes lastDetectedAt createdAt darkWebMonitoringSearchFilter { id name query tags } }
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
  malwareInfectionsAssetsOccurrences(projectId: $projectId, take: 100, skip: 0, where: { isResolved: { eq: false } }, order: [{ riskLevel: DESC }, { createdAt: DESC }]) {
    totalCount
    items { id riskLevel isResolved status assigneeEmail corporateCredentialsCount corporateCookiesCount credentialsCount cookiesCount createdAt asset { value type } occurrence { id origin type occurredAt publishedAt } tags { value } }
  }
}
```

## Domain Squatting and Leaked Credential Evidence

```graphql
query CisThreatExposure($projectId: UUID!) {
  domainPermutationsProjections(projectId: $projectId, take: 100, skip: 0, where: { isResolved: { eq: false } }, order: [{ riskLevel: DESC }, { detectionDate: DESC }]) {
    totalCount
    pageInfo { hasNextPage }
    items { id domainPermutationId originalDomain detectedDomain permutationType riskLevel similarityScore visualSimilarity detectionDate isResolved status assigneeEmail nameServers mailServers ips { address countryCodeIso countryName } }
  }
  leakedCredentialsAssetsOccurrencesV1(projectId: $projectId, take: 100, skip: 0, where: { isResolved: { eq: false } }, order: [{ riskLevel: DESC }, { createdAt: DESC }]) {
    totalCount
    items { id riskLevel isResolved status assigneeEmail urls createdAt asset { value type } occurrence { id origin type occurredAt publishedAt } tags { value } }
  }
}
```

## Output Shape

Use this structure:

1. Scope: project, CIS version, implementation group if supplied, evidence date, scan freshness, pagination.
2. Control coverage table: CIS Control, NordStellar evidence, coverage level, gaps, manual evidence.
3. Findings: inventory gaps, unmonitored assets, unresolved vulnerabilities, exposed ports/services, DNS/TLS weaknesses, malware/leaked credentials, domain squatting, monitoring gaps.
4. Safeguard evidence: sampled GraphQL rows and IDs tied to relevant safeguards.
5. Manual evidence required: endpoint inventory, software inventory, secure baselines, accounts/access, data recovery, SIEM/logging, awareness, SDLC, service-provider management, penetration-test reports.
6. Appendix: query log, counts, pages reviewed, and sensitive data not revealed.

