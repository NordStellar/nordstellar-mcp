---
name: web-application-review
version: 1.0.0
description: "NordStellar ASM workflow for reviewing externally exposed web applications: hosts, ports, status codes, CNAMEs, IPs, technologies, response headers, screenshots, TLS posture, certificates, unresolved vulnerabilities, CVEs, and remediation evidence."
metadata:
  nordstellar:
    category: "attack-surface"
    requires:
      tools: ["graphql_query", "graphql_batch", "search_types", "get_type_definition"]
---

# NordStellar — Web Application Review

Use this skill when the user asks for a web application review, website exposure assessment, external app security review, web app inventory, web technology review, TLS/header review, or a vulnerability-focused assessment of internet-facing web apps.

## Ground Rules

- Start with `projectsV2` and select the relevant `projectId`.
- Use `skip` / `take`; max `take` is `100`.
- Do not use GraphQL aliases.
- Review inventory before findings: web apps, technologies, headers/TLS/certificates, then unresolved vulnerabilities.
- Use `searchFilter` for hostnames, technologies, CNAMEs, IPs, ports, status codes, and vulnerability counts.
- Use `search_types` / `get_type_definition` before adding unfamiliar filters or fields.
- Fetch details for important apps. List rows do not include response headers, response body, TLS details, or full certificate data.

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

```graphql
query WebReviewCoverage($projectId: UUID!) {
  webApplicationProjections(projectId: $projectId, take: 1, skip: 0) { totalCount }
  technologies(projectId: $projectId, take: 1, skip: 0) { totalCount }
  attackSurfaceSslCertificates(projectId: $projectId, take: 1, skip: 0) { totalCount }
  attackSurfaceVulnerabilities(
    projectId: $projectId
    take: 1
    skip: 0
    where: { isResolved: { eq: false }, sourceType: { eq: WEB_APPLICATION } }
  ) { totalCount }
  attackSurfaceScanProjections(projectId: $projectId, take: 20, skip: 0) {
    totalCount
    items { attackSurfaceScanId name type unresolvedVulnerabilitiesCount lastExecutionStartedAt lastExecutionStatus }
  }
}
```

Flag empty or stale application scan data. Use scan `type: APPLICATION` and `lastExecutionStatus` when judging evidence freshness.

## Web App Inventory

```graphql
query WebApplications($projectId: UUID!) {
  webApplicationProjections(
    projectId: $projectId
    take: 100
    skip: 0
    order: [{ unresolvedVulnerabilitiesCount: DESC }]
  ) {
    totalCount
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
  }
}
```

Search examples:

```graphql
query WebApplicationSearch($projectId: UUID!, $searchFilter: String!) {
  webApplicationProjections(projectId: $projectId, take: 100, skip: 0, searchFilter: $searchFilter) {
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
      lastDiscoveredAt
    }
  }
}
```

Useful `searchFilter` values: hostname fragment, CNAME, IP, port (`"443"`), status code (`"404"`), technology (`"WordPress"`), or vulnerability count text.

For exact filtering, use `where`:

```graphql
query WebApplicationsFiltered($projectId: UUID!) {
  webApplicationProjections(
    projectId: $projectId
    take: 100
    skip: 0
    where: {
      port: { eq: 443 }
      unresolvedVulnerabilitiesCount: { gt: 0 }
    }
    order: [{ unresolvedVulnerabilitiesCount: DESC }]
  ) {
    totalCount
    items { webApplicationId assetValue port responseStatusCode technologies unresolvedVulnerabilitiesCount }
  }
}
```

## Technologies

```graphql
query WebTechnologies($projectId: UUID!) {
  webApplicationsTechnologies(projectId: $projectId)
  technologiesCategories(projectId: $projectId)
  technologies(projectId: $projectId, take: 100, skip: 0, order: [{ targetsCount: DESC }]) {
    totalCount
    items {
      id
      name
      version
      categories
      commonPlatformEnumeration
      targetsCount
    }
  }
}
```

Review deprecated runtimes, CMS/plugin exposure, old frameworks, uncommon products, analytics/tagging exposure, CDN/WAF coverage, and CPEs that map to known vulnerabilities.

## Detail Review

Use `webApplicationId` from the inventory query.

```graphql
query WebApplicationDetail($webApplicationId: UUID!) {
  webApplication(webApplicationId: $webApplicationId) {
    id
    assetId
    port
    responseStatusCode
    hasScreenshot
    lastDiscoveredAt
    cNames
    responseHeadersKeyValuePairs { key value }
    ips { id value provider }
    sslDetails {
      id
      grade
      isHstsEnabled
      hstsMaxAge
      supportedProtocols
      cipherSuites
    }
    asset { id value status ownedBy }
    technologies { name version categories commonPlatformEnumeration }
    sslCertificates {
      id
      subject
      issuer
      validTo
      isValid
      subjectAlternativeNames
    }
  }
}
```

Important schema notes:

- `webApplication.ips` exposes only `id`, `value`, and `provider`; do not request ASN or country there.
- `sslDetails` exposes TLS posture fields such as `grade`, `isHstsEnabled`, `hstsMaxAge`, `supportedProtocols`, and `cipherSuites`; certificate validity is on `sslCertificates`.
- `asset` exposes `id`, `value`, `status`, and `ownedBy`; it does not expose `type`.

## TLS and Certificates

```graphql
query WebCertificates($projectId: UUID!) {
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
}
```

For full certificate details:

```graphql
query CertificateDetail($sslCertificateId: UUID!) {
  sslCertificate(sslCertificateId: $sslCertificateId) {
    id
    subject
    issuer
    validFrom
    validTo
    publicKeySize
    publicKeyAlgorithm
    signatureAlgorithm
    subjectAlternativeNames
    isSelfSigned
    isRevoked
    isExpired
    isValid
    sha256Fingerprint
    webApplications { id port asset { value } }
  }
}
```

Review invalid, expired, near-expiry, revoked, self-signed, weak-key, broad SAN, and hostname-mismatch indicators. Use `sslDetails` from the web app detail for HSTS, TLS protocol, and cipher evidence.

## Web Vulnerabilities

```graphql
query WebVulnerabilities($projectId: UUID!) {
  attackSurfaceVulnerabilities(
    projectId: $projectId
    take: 100
    skip: 0
    where: { isResolved: { eq: false }, sourceType: { eq: WEB_APPLICATION } }
    order: [{ riskLevel: DESC }, { createdAt: DESC }]
  ) {
    totalCount
    items {
      id
      assetId
      assetValue
      title
      sourceType
      type
      riskLevel
      tags
      isResolved
      createdAt
    }
  }
}
```

Filter high-impact web issues:

```graphql
query HighRiskWebVulnerabilities($projectId: UUID!) {
  attackSurfaceVulnerabilities(
    projectId: $projectId
    take: 100
    skip: 0
    where: {
      isResolved: { eq: false }
      sourceType: { eq: WEB_APPLICATION }
      riskLevel: { in: [CRITICAL, HIGH] }
    }
    order: [{ riskLevel: DESC }, { createdAt: DESC }]
  ) {
    totalCount
    items { id assetValue title type riskLevel tags createdAt }
  }
}
```

Fetch details before recommending remediation:

```graphql
query WebVulnerabilityDetail($id: UUID!) {
  webApplicationAttackSurfaceVulnerability(attackSurfaceVulnerabilityId: $id) {
    id
    title
    riskLevel
    description
    impactDescription
    remediationInstructions
    references
    assetValue
    port
    type
    tags
    commonVulnerabilitiesAndExposuresId
    commonWeaknessEnumerationIds
    commonVulnerabilityScoringSystem3Score
    commonVulnerabilityScoringSystemVector
    exploitPredictionScoringSystemScore
    evidenceUrl
    evidenceHost
    evidencePort
    evidenceScheme
    evidenceHttpRequest
    evidenceHttpResponse
    evidenceData
    evidenceExtractedData
  }
}
```

## Review Checklist

- Prioritize apps with unresolved critical/high findings, unusual ports, 5xx/4xx status codes, no screenshot where one is expected, or stale `lastDiscoveredAt`.
- Review app ownership and scope using `asset.status` and `asset.ownedBy`.
- Identify sensitive exposed names: admin, debug, staging, test, local, internal, auth, payment, dashboard, API, metrics, pprof, kube, grafana, elastic, redis, or db.
- Check response headers for HSTS, CSP, cookies, server disclosure, `X-Powered-By`, cache headers, and framework-specific leakage.
- Check TLS posture: grade, HSTS, supported protocols, cipher suites, certificate validity, expiration, issuer, SANs, and broad wildcard use.
- Review technologies for vulnerable or outdated frameworks, CMS, plugins, runtimes, web servers, cloud/CDN coverage, and CPE-backed products.
- Correlate vulnerabilities with detail evidence before writing remediation. The list title alone is not enough.
- Note pagination limits and whether only the first 100 rows were reviewed.

## Output Shape

Use this structure unless the user asks for another format:

1. Executive summary: total web apps, top risk themes, and evidence freshness.
2. Inventory: notable hosts, ports, status codes, CNAME/IP exposure, technologies, and certificates.
3. High-risk findings: critical/high unresolved vulnerabilities with evidence and remediation.
4. Configuration review: headers, TLS/HSTS, certificate posture, technologies, and exposed sensitive app names.
5. Data gaps: missing scans, stale data, pagination not exhausted, or fields unavailable from ASM.
6. Recommended actions: prioritized fixes tied to specific hosts and vulnerability IDs.
