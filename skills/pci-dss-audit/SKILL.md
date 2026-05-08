---

name: pci-dss-audit
version: 1.0.0
description: "NordStellar audit workflow for PCI DSS v4.0.1 evidence collection: map MCP data to requirements for network security, secure configurations, vulnerability management, external scanning, monitoring, incident response, payment-page/web exposure signals, DNS/TLS posture, leaked credential exposure, malware infections, and service-provider visibility."
metadata:
  nordstellar:
    category: "audit-compliance"
    framework: "PCI DSS v4.0.1"
    requires:
  tools: ["graphql_query", "graphql_batch", "search_types", "get_type_definition"]

---

# NordStellar - PCI DSS Audit Evidence

Use this skill when the user asks for PCI DSS, cardholder data environment (CDE) external evidence, ASV-like scan support, payment web exposure, vulnerability management, external network review, or PCI readiness using NordStellar data.

NordStellar does **not** prove PCI DSS compliance by itself and is not a substitute for a QSA assessment or approved scanning vendor process. It provides external technical evidence for in-scope or potentially in-scope assets: public IPs, web apps, ports, vulnerabilities, DNS/TLS, certificate posture, technologies, leaked credentials, malware infection exposure, dark web mentions, and event workflow.

## Realistic Coverage

NordStellar can realistically support **technical evidence for parts of PCI DSS Requirements 1, 2, 6, 10, 11, and 12**, depending on whether the user has identified the CDE and payment-page scope. It cannot determine PCI scope by itself.

**Default completeness score: 15/100.** NordStellar can support external technical evidence for PCI-relevant assets, especially vulnerability scanning, web/network exposure, DNS/TLS posture, leaked credentials, malware exposure, and event workflow. The score is low because PCI depends heavily on confirmed CDE scope, segmentation, ASV/QSA evidence, internal controls, access/MFA, logging, FIM, anti-malware, policies, and service-provider documentation outside NordStellar. Raise it only for a narrow external scan/readiness review with confirmed scope.

Covered well:

- Requirement 11 partial: external vulnerability scanning evidence, open findings, scan freshness, web/network/DNS vulnerability details.
- Requirement 6 partial: web application vulnerabilities, vulnerable technologies/CVEs, remediation guidance.
- Requirement 1 and 2 partial: external network services, public ports, providers, DNS/TLS, configuration exposures.
- Requirement 10 partial: NordStellar event/activity logs only, not CDE audit logs.
- Requirement 12 partial: incident/event workflow signals and risk reporting.
- Payment-page risk signals: web apps, technologies, scripts/headers only when payment pages are identifiable; not full PCI 11.6 script-change monitoring.

Partial or not covered:

- CDE segmentation, firewall rule review, internal network diagrams, secure configuration baselines, account/MFA controls, encryption key management, internal audit logs, file integrity monitoring, anti-malware operation, penetration tests, policies, training, service-provider contracts, and ASV attestation are outside NordStellar.
- NordStellar can reveal leaked credentials or malware infections affecting corporate assets, but it cannot prove PCI access-control compliance.

Tell users: "NordStellar can support PCI external technical evidence and find likely PCI-relevant gaps, but PCI compliance still requires CDE scoping, QSA/ASV evidence, internal controls, policies, segmentation, access, logging, and service-provider documentation."

## Ground Rules

- Start with `projectsV2` and choose `projectId`.
- Ask the user for CDE scope, payment domains, payment pages, CDE IPs, and third-party payment providers. If unknown, treat findings as **potentially PCI-relevant**, not confirmed in-scope.
- Use `skip` / `take`; max `take` is `100`.
- Do not use GraphQL aliases.
- Use `graphql_batch` for repeated hostname/IP/payment-page searches.
- Use `search_types` / `get_type_definition` before unfamiliar fields.
- Do not call NordStellar an ASV scan unless the organization has an ASV process validating it.
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

## PCI Requirement Mapping

- `Req. 1 Network Security Controls`: partial external ports, services, IPs, domains, providers, countries.
- `Req. 2 Secure Configurations`: partial DNS/TLS/header/technology/exposed-service evidence.
- `Req. 5 Malware`: partial infostealer/malware infection exposure, not endpoint malware control.
- `Req. 6 Secure Systems and Software`: partial web/network vulnerability and technology evidence.
- `Req. 8 Access`: weak leaked credential signal only; no IAM/MFA proof.
- `Req. 10 Logging`: weak NordStellar activity/event logs only.
- `Req. 11 Testing Security`: strong external scan/vulnerability evidence; formal ASV/pentest evidence manual.
- `Req. 12 Program Management`: partial risk/event reporting; policy/process manual.

## Scope and Overview

```graphql
query PciOverview($projectId: UUID!) {
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
  eventsDaysUnresolvedAverages(projectId: $projectId) {
    criticalEventsDaysUnresolvedAverage highEventsDaysUnresolvedAverage mediumEventsDaysUnresolvedAverage lowEventsDaysUnresolvedAverage
  }
}
```

## External Network and CDE Candidate Evidence

Use `searchFilter` to focus on known CDE IPs, payment domains, checkout hosts, or provider names.

```graphql
query PciNetworkExposure($projectId: UUID!, $searchFilter: String) {
  attackSurfaceIps(projectId: $projectId, take: 100, skip: 0, searchFilter: $searchFilter, order: [{ unresolvedNetworkServicesVulnerabilitiesCount: DESC }]) {
    totalCount
    items { id value domains networkServices provider geolocationCountry geolocationCountryCode autonomousSystemNumber unresolvedNetworkServicesVulnerabilitiesCount lastDiscoveredAtNetworkServicesScan }
  }
  networkServiceProjections(projectId: $projectId, take: 100, skip: 0, searchFilter: $searchFilter, order: [{ unresolvedVulnerabilitiesCount: DESC }]) {
    totalCount
    items { networkServiceId ip name product version port isActive domains unresolvedVulnerabilitiesCount lastDiscoveredAt }
  }
}
```

Flag any non-HTTP(S), admin, database, debug, remote access, or unknown services on candidate CDE assets. Confirm scope manually.

## Vulnerability and Scan Evidence

```graphql
query PciVulnerabilityEvidence($projectId: UUID!) {
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

Fetch details for samples before recommending PCI remediation:

```graphql
query PciWebVulnerabilityDetail($id: UUID!) {
  webApplicationAttackSurfaceVulnerability(attackSurfaceVulnerabilityId: $id) {
    id title riskLevel description impactDescription remediationInstructions
    sourceType type assetValue port tags references
    commonVulnerabilitiesAndExposuresId commonWeaknessEnumerationIds commonVulnerabilityScoringSystem3Score commonVulnerabilityScoringSystemVector
    evidenceUrl evidenceHost evidencePort evidenceScheme evidenceHttpRequest evidenceHttpResponse evidenceData evidenceExtractedData
  }
}
```

Use `networkServiceAttackSurfaceVulnerability` and `dnsAttackSurfaceVulnerability` for non-web rows.

## Payment Web App, DNS, and TLS Evidence

```graphql
query PciWebDnsTls($projectId: UUID!, $searchFilter: String) {
  webApplicationProjections(projectId: $projectId, take: 100, skip: 0, searchFilter: $searchFilter, order: [{ unresolvedVulnerabilitiesCount: DESC }]) {
    totalCount
    items { webApplicationId assetValue port responseStatusCode technologies ipAddresses cNames unresolvedVulnerabilitiesCount hasScreenshot lastDiscoveredAt }
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

For likely payment pages, fetch `webApplication(webApplicationId:)` detail to inspect response headers, TLS details, CNAMEs, IPs, technologies, certificates, and screenshots availability. NordStellar does not prove PCI payment-page script authorization or integrity by itself.

## Credential, Malware, and Dark Web Exposure

```graphql
query PciThreatExposure($projectId: UUID!) {
  darkWebMonitoringRules(projectId: $projectId, take: 100, skip: 0) {
    totalCount
    items { id name description sourceTypes lastDetectedAt createdAt darkWebMonitoringSearchFilter { id name query tags } }
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

## Event and Remediation Workflow

```graphql
query PciEventWorkflow($projectId: UUID!, $fromDate: DateTime!) {
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

## Output Shape

Use this structure:

1. Scope: project, known/assumed CDE and payment assets, PCI version, evidence date, scan freshness, and scope uncertainty.
2. Requirement coverage matrix: PCI requirement, NordStellar evidence, coverage level, in-scope confidence, manual evidence required.
3. Potential PCI findings: unresolved critical/high/medium vulnerabilities, exposed risky ports, stale/failed scans, weak DNS/TLS, certificate expiry, payment web app issues, leaked credentials, malware infections.
4. CDE scope questions: assets needing user confirmation, unknown providers, suspicious payment/checkout domains, third-party payment flows.
5. Manual evidence required: ASV scans, QSA decisions, segmentation tests, firewall rules, secure baselines, access/MFA reviews, CDE logs, FIM, anti-malware, PCI policies, training, service-provider attestations.
6. Appendix: query log, sampled IDs, pages reviewed, sensitive data not revealed.

