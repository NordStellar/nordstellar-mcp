---
name: data-center-compliance-review
version: 1.1.0
description: "NordStellar ASM workflow for data center and hosting compliance reviews: providers, ASNs, countries, internet-facing services, certificates, DNS posture, scan freshness, and policy evidence—plus mandatory open-web research for vendor and organizational compliance claims. Use for data residency, vendor hosting, SOC 2, ISO 27001, PCI, GDPR, and internal infrastructure compliance checks."
metadata:
  nordstellar:
    category: "attack-surface"
    requires:
      tools: ["graphql_query", "graphql_batch", "search_types", "get_type_definition"]
---

# NordStellar — Data Center Compliance Review

Use this skill when the user asks whether externally exposed infrastructure complies with data center, hosting provider, data residency, cloud/vendor, SOC 2, ISO 27001, PCI DSS, GDPR, or internal infrastructure policy requirements.

This skill uses NordStellar ASM data as the evidence source for what is exposed. **After** you have an ASM footprint, you **must** use open-web search (web search, `WebSearch`, or equivalent) to research compliance-relevant facts ASM cannot prove: provider and cloud vendor certifications, trust centers, subprocessors, region/data-residency documentation, sanctioned or restricted jurisdictions, and (where applicable) the **customer or parent organization’s** public security and compliance attestations. Treat search-backed claims as **public narrative and due-diligence pointers**, not a substitute for restricted audit reports (SOC under NDA, customer DPAs, internal allow-lists).

If the runtime has **no** search or network access, state that limitation explicitly in the deliverable and expand **needs-manual-evidence** and **unknown** sections accordingly—do not skip the intent of this step silently.

## Ground Rules

- Start with `projectsV2` and select the relevant `projectId`.
- Ask which compliance standard or policy to evaluate if the user did not specify one.
- Do not claim compliance from ASM data alone. ASM can show exposure, location, provider, service, certificate, DNS, technology, and scan evidence; it cannot prove contractual controls or audit certification by itself.
- **Always** run external web research for this skill after the ASM inventory is built (see **Mandatory open-web research**). Technical misconfigurations from ASM (e.g. DNS, TLS, exposed services) remain findings even when vendors publish strong trust pages; organization-level certifications do not automatically scope to every hostname in the project.
- Use `skip` / `take`; max `take` is `100`.
- Do not use GraphQL aliases.
- Use `search_types` / `get_type_definition` before adding unfamiliar filters or fields.

## Required First Query

```graphql
query {
  projectsV2(take: 20) {
    items { id name }
    totalCount
  }
}
```

## Review Workflow

1. Establish the policy: allowed countries, approved providers, required certificates, forbidden exposed services, required DNS/email controls, scan freshness SLA, and remediation severity thresholds.
2. Build the external hosting inventory from ASM: IPs, providers, ASNs, countries, domains, services, web apps, certificates, technologies, scans, and unresolved findings.
3. **Mandatory open-web research:** run targeted searches (see **External Search Guidance**) for the customer/parent brand (if inferable from assets), **each distinct `attackSurfaceIpsProviders` / enriched provider name**, major cloud/CDN/email processors seen in technologies or products, and any country/region tied to the stated policy. Prefer official trust centers, compliance program pages, and DPA/subprocessor documentation; note where only marketing claims exist.
4. Compare ASM evidence against the policy. Cross-check **non-compliant** and **unknown** hosting rows against what public sources say about vendor posture; keep contractual scope gaps in **needs-manual-evidence**.
5. Report compliant, non-compliant, unknown, and needs-manual-evidence items separately. In the output, always include **External verification** with queries run, URLs or page titles consulted, and explicit gaps (e.g. provider with no public ISO/SOC reference found).

## Coverage and Scan Freshness

```graphql
query ComplianceCoverage($projectId: UUID!) {
  attackSurfaceTargetAssets(projectId: $projectId, take: 1, skip: 0) { totalCount }
  attackSurfaceIps(projectId: $projectId, take: 1, skip: 0) { totalCount }
  networkServiceProjections(projectId: $projectId, take: 1, skip: 0) { totalCount }
  webApplicationProjections(projectId: $projectId, take: 1, skip: 0) { totalCount }
  attackSurfaceDomains(projectId: $projectId, take: 1, skip: 0) { totalCount }
  attackSurfaceSslCertificates(projectId: $projectId, take: 1, skip: 0) { totalCount }
  technologies(projectId: $projectId, take: 1, skip: 0) { totalCount }
  attackSurfaceVulnerabilities(projectId: $projectId, take: 1, skip: 0, where: { isResolved: { eq: false } }) { totalCount }
  attackSurfaceScanProjections(projectId: $projectId, take: 20, skip: 0) {
    totalCount
    items {
      attackSurfaceScanId
      name
      type
      unresolvedVulnerabilitiesCount
      lastExecutionStartedAt
      lastExecutionStatus
    }
  }
}
```

Flag stale, failed, or missing scan evidence. Compliance conclusions should include the age of ASM evidence.

## Provider, ASN, and Location Evidence

```graphql
query DataCenterFootprint($projectId: UUID!) {
  attackSurfaceIpsProviders(projectId: $projectId)
  attackSurfaceIpsCountries(projectId: $projectId) { country countryCode }
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

Use `searchFilter` to focus on a provider, country, ASN, IP fragment, service name, or domain:

```graphql
query DataCenterSearch($projectId: UUID!, $searchFilter: String!) {
  attackSurfaceIps(projectId: $projectId, take: 100, skip: 0, searchFilter: $searchFilter) {
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
    }
  }
}
```

For a specific IP:

```graphql
query IpDetail($id: UUID!) {
  attackSurfaceIp(id: $id) {
    id
    value
    lastDiscoveredAtNetworkServicesScan
    metadata {
      provider
      autonomousSystemNumber
      autonomousSystemOrganization
      geolocationCountry
      geolocationCountryCode
    }
    domains { id value }
    networkServices { id name port product protocol version isActive }
  }
}
```

## Internet-Facing Services

```graphql
query HostingServices($projectId: UUID!) {
  networkServicesNames(projectId: $projectId)
  networkServicesProducts(projectId: $projectId)
  networkServicesPorts(projectId: $projectId)
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

Use this to evaluate policy rules such as "only 80/443 may be public", "no database ports exposed", "no admin/debug services exposed", or "all public services must map to approved domains."

For a specific service:

```graphql
query NetworkServiceDetail($id: UUID!) {
  networkService(id: $id) {
    id
    name
    port
    protocol
    product
    version
    banner
    commonPlatformEnumerations
    state
    isActive
    lastDiscoveredAt
    ip { value }
    sslDetails { id grade isHstsEnabled hstsMaxAge supportedProtocols cipherSuites }
    sslCertificates { id subject issuer validTo isValid subjectAlternativeNames }
  }
}
```

## Web Applications, Technologies, and Headers

```graphql
query WebCompliance($projectId: UUID!) {
  webApplicationsTechnologies(projectId: $projectId)
  technologiesCategories(projectId: $projectId)
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
  technologies(projectId: $projectId, take: 100, skip: 0, order: [{ targetsCount: DESC }]) {
    totalCount
    items { id name version categories commonPlatformEnumeration targetsCount }
  }
}
```

For a specific web app:

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
    sslDetails { id grade isHstsEnabled hstsMaxAge supportedProtocols cipherSuites }
    asset { id value status ownedBy }
    technologies { name version categories commonPlatformEnumeration }
    sslCertificates { id subject issuer validTo isValid subjectAlternativeNames }
  }
}
```

Use response headers and technology versions for control checks such as HSTS, unsupported runtime exposure, deprecated CMS/plugin usage, missing security headers, or assets not owned by the organization.

## Certificates and DNS Controls

```graphql
query CertAndDnsCompliance($projectId: UUID!) {
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
    networkServices { id name port ip { value } }
  }
}
```

For full DNS records:

```graphql
query DomainDetail($domainId: UUID!) {
  attackSurfaceDomain(domainId: $domainId) {
    id
    value
    lastDiscoveredAtDnsScan
    dnsRecords { id dnsRecordType value }
    dnsMetadata { spfState dmarcState spoofingRiskLevel }
  }
}
```

## Unresolved Compliance Risks

```graphql
query ComplianceFindings($projectId: UUID!) {
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
    where: { isResolved: { eq: false }, riskLevel: { in: [CRITICAL, HIGH, MEDIUM] } }
    order: [{ riskLevel: DESC }, { createdAt: DESC }]
  ) {
    totalCount
    items { id assetValue title sourceType type riskLevel tags createdAt }
  }
}
```

Use detail queries from the ASM skill for `WEB_APPLICATION`, `NETWORK_SERVICE`, and `DNS` findings before making remediation recommendations.

## External Search Guidance

**Do this on every run** (unless search is impossible in the environment—then document why).

Minimum search set (adapt to the footprint; batch queries to avoid redundant calls):

- **Customer / brand** (from prominent domains or project name) + `SOC 2`, `ISO 27001`, `trust center`, `security`, `subprocessor`, or `DPA` (when the engagement is org-level compliance).
- **Each unique hosting/co-location provider string from ASM** (e.g. M247, Clouvider, Hetzner, Hostinger, Latitude) + `ISO 27001`, `SOC 2`, `GDPR`, `trust center`.
- **Hyperscaler and CDN** identifiers (e.g. Amazon/AWS, Cloudflare, Google Cloud, Microsoft Azure) + `compliance`, `SOC`, `ISO`; cite vendor compliance hubs (e.g. AWS Artifact, Cloudflare Trust Hub) from results.
- **Email / API processors** appearing as providers or technologies (e.g. SendGrid, Mailgun, Twilio) + `SOC 2`, `trust center`.
- **Autonomous system organization names** only when policy requires ASN-level proof or enrichment is ambiguous; pair with provider name searches.
- **Policy-specific geography:** country or region codes from ASM + `data residency`, `region`, `data center locations`, `sanctions` (when the user’s policy invokes residency or geo restrictions).

Also search when materially relevant:

- Certificate issuer CA + trust / compliance stance if certificate or chain posture drives the engagement.
- Public documentation for cloud/CDN services detected in technologies or CNAMEs.

Prefer official trust centers, certification pages, regulatory filings, cloud region docs, and customer-approved vendor lists. Distinguish: **(a)** ASM technical findings, **(b)** vendor public compliance narrative, **(c)** contractual evidence the customer must supply. Mark marketing-only or unverifiable claims as **needs manual evidence** (SOC reports, DPAs, subprocessor registers).

## Evaluation Checklist

- Open-web research: trust-center and certification narrative captured for footprint providers and relevant cloud/CDN/processor services; gaps called out explicitly.
- Approved providers: each `provider` and `autonomousSystemOrganization` is approved or explained.
- Approved countries/regions: each `geolocationCountryCode` is allowed for the workload and data class.
- Approved ASNs: unexpected ASNs are investigated, especially shared hosting, residential, or unmanaged providers.
- Service exposure: public ports and services match policy; admin/debug/database/internal services are flagged.
- Domain ownership: exposed services map to accepted assets and expected domains.
- Web controls: HSTS, TLS grade/protocols, security headers, technology versions, and response status are reviewed for important web apps.
- Certificate controls: validity, expiry, SAN scope, self-signed/revoked/expired status, key/signature algorithms, and target mapping are reviewed.
- DNS/email controls: SPF and DMARC states meet policy; spoofing risks are remediated or accepted.
- Vulnerability posture: critical/high/medium unresolved issues are summarized by asset and control area.
- Scan evidence: last scan time and status support the review window.

## Output Shape

Use this structure unless the user asks otherwise:

1. Scope and standard: project, policy/standard, evidence date, and data limitations.
2. Hosting footprint: providers, ASNs, countries, IPs, domains, and service counts.
3. Compliance assessment: compliant, non-compliant, unknown, and needs-manual-evidence items.
4. Findings: prioritized issues with asset, evidence, policy impact, and remediation.
5. External verification (required): queries run, official sources (URLs or titles) consulted, provider-by-provider summary, and remaining evidence gaps; if search was unavailable, say so here.
6. Appendix: scan freshness, pagination notes, and notable raw ASM counts.
