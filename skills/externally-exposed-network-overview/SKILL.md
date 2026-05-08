---
name: externally-exposed-network-overview
version: 1.0.0
description: "NordStellar ASM workflow for externally exposed network overviews: internet-facing IPs, providers, countries, ASNs, open ports, network services, web apps, DNS posture, SSL certificates, technologies, and unresolved exposure risks."
metadata:
  nordstellar:
    category: "attack-surface"
    requires:
      tools: ["graphql_query", "graphql_batch", "search_types", "get_type_definition"]
---

# NordStellar — Externally Exposed Network Overview

Use this skill when the user asks for an external network overview, exposed infrastructure inventory, open-port summary, perimeter exposure report, internet-facing services review, or ASM-based infrastructure map.

## Ground Rules

- Start with `projectsV2` and select the relevant `projectId`.
- Use `skip` / `take`; max `take` is `100`.
- Do not use GraphQL aliases.
- Run several focused queries. A single vulnerability list is not a network overview.
- Treat `attackSurfaceVulnerabilitiesCounts` as optional; it can be `null` while inventory queries still return data.
- Prefer inventory first, risk second: IPs, services, web apps, domains, certificates, technologies, then unresolved vulnerabilities.
- Use `search_types` / `get_type_definition` when adding filters or unfamiliar fields.

## Required First Query

```graphql
query {
  projectsV2(take: 20) {
    items { id name }
    totalCount
  }
}
```

## Coverage Snapshot

Run this to understand what ASM data exists for the project before drawing conclusions.

```graphql
query ExposureCoverage($projectId: UUID!) {
  attackSurfaceTargetAssets(projectId: $projectId, take: 1, skip: 0) { totalCount }
  attackSurfaceIps(projectId: $projectId, take: 1, skip: 0) { totalCount }
  networkServiceProjections(projectId: $projectId, take: 1, skip: 0) { totalCount }
  webApplicationProjections(projectId: $projectId, take: 1, skip: 0) { totalCount }
  attackSurfaceDomains(projectId: $projectId, take: 1, skip: 0) { totalCount }
  attackSurfaceSslCertificates(projectId: $projectId, take: 1, skip: 0) { totalCount }
  technologies(projectId: $projectId, take: 1, skip: 0) { totalCount }
  attackSurfaceVulnerabilities(projectId: $projectId, take: 1, skip: 0, where: { isResolved: { eq: false } }) { totalCount }
  attackSurfaceScanProjections(projectId: $projectId, take: 20, skip: 0) {
    items { attackSurfaceScanId name type unresolvedVulnerabilitiesCount lastExecutionStartedAt lastExecutionStatus }
    totalCount
  }
}
```

Use `graphql_batch` with the same query when comparing multiple projects.

## Network Inventory

### IPs and Provider Geography

```graphql
query ExposedIps($projectId: UUID!) {
  attackSurfaceIps(
    projectId: $projectId
    take: 100
    skip: 0
    order: [{ unresolvedNetworkServicesVulnerabilitiesCount: DESC }]
  ) {
    totalCount
    items {
      id
      value
      provider
      geolocationCountry
      geolocationCountryCode
      autonomousSystemNumber
      domains
      networkServices
      unresolvedNetworkServicesVulnerabilitiesCount
      lastDiscoveredAtNetworkServicesScan
    }
  }
}
```

### Facets for Grouping

```graphql
query ExposureFacets($projectId: UUID!) {
  attackSurfaceIpsProviders(projectId: $projectId)
  attackSurfaceIpsCountries(projectId: $projectId) { country countryCode }
  networkServicesNames(projectId: $projectId)
  networkServicesProducts(projectId: $projectId)
  networkServicesPorts(projectId: $projectId)
  webApplicationsTechnologies(projectId: $projectId)
  technologiesCategories(projectId: $projectId)
}
```

Use facets to summarize exposure by provider, country, ASN, service name, product, and port.

### Open Services

```graphql
query NetworkServices($projectId: UUID!) {
  networkServiceProjections(
    projectId: $projectId
    take: 100
    skip: 0
    order: [{ unresolvedVulnerabilitiesCount: DESC }]
  ) {
    totalCount
    items {
      networkServiceId
      ipId
      ip
      port
      name
      product
      version
      isActive
      domains
      unresolvedVulnerabilitiesCount
      lastDiscoveredAt
    }
  }
}
```

Search examples:

```graphql
query NetworkServiceSearch($projectId: UUID!) {
  networkServiceProjections(projectId: $projectId, take: 100, skip: 0, searchFilter: "8443") {
    totalCount
    items { networkServiceId ip port name product version domains unresolvedVulnerabilitiesCount }
  }
}
```

```graphql
query IpSearch($projectId: UUID!) {
  attackSurfaceIps(projectId: $projectId, take: 100, skip: 0, searchFilter: "provider-or-country-or-asn") {
    totalCount
    items { id value provider geolocationCountry autonomousSystemNumber networkServices domains }
  }
}
```

## Web, DNS, Certificates, and Technologies

```graphql
query WebDnsCertTech($projectId: UUID!) {
  webApplicationProjections(
    projectId: $projectId
    take: 100
    skip: 0
    order: [{ unresolvedVulnerabilitiesCount: DESC }]
  ) {
    totalCount
    items {
      webApplicationId
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
  }
  attackSurfaceDomains(
    projectId: $projectId
    take: 100
    skip: 0
    order: [{ unresolvedDnsVulnerabilitiesCount: DESC }]
  ) {
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
  attackSurfaceSslCertificates(
    projectId: $projectId
    take: 100
    skip: 0
    order: [{ validTo: ASC }]
  ) {
    totalCount
    items {
      id
      subject
      issuer
      validTo
      isValid
      targetsCount
      webApplicationsCount
      networkServicesCount
      subjectAlternativeNames
      lastDiscoveredAt
    }
  }
  technologies(projectId: $projectId, take: 100, skip: 0, order: [{ targetsCount: DESC }]) {
    totalCount
    items { id name version categories commonPlatformEnumeration targetsCount }
  }
}
```

For a specific web app, nested IPs only expose `id`, `value`, and `provider`; do not request ASN or country there.

```graphql
query WebApplicationDetail($webApplicationId: UUID!) {
  webApplication(webApplicationId: $webApplicationId) {
    id assetId port responseStatusCode hasScreenshot lastDiscoveredAt cNames
    ips { id value provider }
    sslDetails { id grade isHstsEnabled hstsMaxAge supportedProtocols cipherSuites }
    asset { id value status ownedBy }
    technologies { name version categories commonPlatformEnumeration }
    sslCertificates { id subject issuer validTo isValid subjectAlternativeNames }
  }
}
```

## Risk Queries

Use these after inventory to highlight risky exposure.

```graphql
query HighRiskExposure($projectId: UUID!) {
  attackSurfaceVulnerabilitiesCounts(projectId: $projectId) {
    totalCount
    unresolvedCount
    criticalUnresolvedCount
    highUnresolvedCount
    mediumUnresolvedCount
    lowUnresolvedCount
    infoUnresolvedCount
  }
  attackSurfaceVulnerabilities(
    projectId: $projectId
    take: 100
    skip: 0
    where: { isResolved: { eq: false }, riskLevel: { in: [CRITICAL, HIGH] } }
    order: [{ riskLevel: DESC }, { createdAt: DESC }]
  ) {
    totalCount
    items { id assetValue title sourceType type riskLevel tags createdAt }
  }
}
```

Fetch details by `sourceType`:

```graphql
query NetworkVulnerabilityDetail($id: UUID!) {
  networkServiceAttackSurfaceVulnerability(attackSurfaceVulnerabilityId: $id) {
    id title riskLevel description impactDescription remediationInstructions
    assetValue networkServiceName protocol product version isActive port
    commonVulnerabilitiesAndExposuresId commonVulnerabilityScoringSystem3Score
  }
}
```

```graphql
query WebVulnerabilityDetail($id: UUID!) {
  webApplicationAttackSurfaceVulnerability(attackSurfaceVulnerabilityId: $id) {
    id title riskLevel description impactDescription remediationInstructions
    assetValue port evidenceUrl evidenceHost evidencePort evidenceScheme
    commonVulnerabilitiesAndExposuresId commonVulnerabilityScoringSystem3Score
  }
}
```

```graphql
query DnsVulnerabilityDetail($id: UUID!) {
  dnsAttackSurfaceVulnerability(attackSurfaceVulnerabilityId: $id) {
    id title riskLevel description impactDescription remediationInstructions
    assetValue evidenceData commonVulnerabilitiesAndExposuresId commonVulnerabilityScoringSystem3Score
  }
}
```

## Analysis Checklist

- Count total target assets, IPs, domains, web apps, network services, certificates, technologies, and unresolved findings.
- Group IPs by provider, country, ASN, associated domains, and scan freshness.
- Group network services by port, service name, product/version, active state, and unresolved vulnerability count.
- Highlight unusual or sensitive internet-facing services: SSH, RDP, VNC, databases, admin panels, debug endpoints, Kubernetes, Elasticsearch, Redis, SMB, FTP, mail admin, or high-numbered custom ports.
- Separate public web exposure from raw network exposure. A `443` web app with WAF/CDN is different from an exposed database or debug service.
- Review DNS spoofing posture for domains: `spoofingRiskLevel`, `spfState`, `dmarcState`, and unresolved DNS vulnerabilities.
- Review certificate posture: invalid certificates, near-expiry `validTo`, broad SANs, self-signed/revoked/expired details from `sslCertificate` when needed.
- Mention stale scans or missing scan data. Use `lastExecutionStartedAt`, `lastExecutionStatus`, and `lastDiscoveredAt*` fields.

## Output Shape

Use this structure unless the user asks for another format:

1. Executive summary: one paragraph with total exposure and top risks.
2. Exposure inventory: IPs, countries, providers, ASNs, domains, web apps, services, certificates, technologies.
3. High-risk exposure: critical/high unresolved findings and risky ports/services.
4. Notable concentrations: providers, geographies, products, technologies, or domains with many findings.
5. Data quality: scan freshness, empty datasets, missing counts, and pagination limits.
6. Recommended next steps: concrete actions tied to the observed assets.
