---
name: company-compliance-review
version: 1.0.0
description: "Orchestrates a full NordStellar compliance review for a company or selected project by delegating to existing framework and evidence skills: ISO 27001, NIST CSF, NIST 800-53, CIS Controls, SOC 2, PCI DSS, ASM, dark web, malware, domain squatting, web application, network exposure, and data-center compliance."
metadata:
  nordstellar:
    category: "audit-compliance"
    requires:
      tools: ["graphql_query", "graphql_batch", "search_types", "get_type_definition"]
---

# NordStellar - Company Compliance Review

Use this skill when the user asks for a full compliance review, company-wide security compliance assessment, project compliance report, multi-standard audit, certification readiness review, or a broad NordStellar evidence package for a company or selected project.

This is an **orchestration skill**. Keep it short in use: do not copy all GraphQL queries here. Load and follow the existing focused skills below, then synthesize their outputs.

## Realistic Scope

NordStellar can provide a strong external technical evidence package: assets, attack surface, vulnerabilities, DNS/TLS, exposed services, dark web monitoring, leaked credentials, malware infections, domain-squatting, event workflow, and scan freshness.

**Default completeness score: 20/100.** For a full company or multi-standard compliance review, NordStellar data alone covers only the external technical evidence layer. The score should stay conservative because full compliance reviews depend on governance, policy, process, internal system, HR, legal, supplier, access, logging, backup, BCP, and management evidence outside NordStellar. Raise it only when the requested review is explicitly limited to external technical exposure.

NordStellar cannot complete a full compliance audit alone. Always state that governance, policies, risk acceptance, interviews, tickets, internal logs, IAM/access reviews, endpoint evidence, supplier contracts, DPAs, training, physical security, backup/BCP, and management review evidence must come from outside NordStellar.

## Required Child Skills

Always load the general skill first:

- `nordstellar-general`

Load framework skills based on the requested standards:

- `iso-27001-audit` for ISO/IEC 27001.
- `nist-csf-audit` for NIST Cybersecurity Framework 2.0.
- `nist-800-53-audit` for NIST SP 800-53 / FedRAMP-like evidence.
- `cis-controls-audit` for CIS Controls v8/v8.1.
- `soc-2-audit` for SOC 2 Trust Services Criteria.
- `pci-dss-audit` for PCI DSS v4.0.1 or payment/CDE reviews.

Load evidence-domain skills for every full review unless clearly out of scope:

- `attack-surface-management`
- `externally-exposed-network-overview`
- `web-application-review`
- `data-center-compliance-review`
- `asset-dark-web-research`
- `dark-web-search`
- `malware-infection-analysis`
- `domain-squatting`

## Delegation Requirement

Use subagents or any available delegated task tool for broad reviews. Do not run the whole review as one serial investigation if delegation is available.

Minimum parallel workstreams:

- **Scope and inventory**: projects, company/project selection, asset counts, monitored/unmonitored assets, target assets.
- **ASM and vulnerability posture**: scans, vulnerabilities, web apps, network services, IPs, DNS, TLS/certificates.
- **Threat intelligence and leaked data**: dark web monitoring/search, data breaches, leaked credentials, malware infections.
- **Brand and phishing exposure**: domain squatting, DNS spoofing, SPF/DMARC, suspicious permutations.
- **Framework mapping**: one subagent per requested framework, using the relevant framework skill.
- **Supplier/data-center exposure**: providers, ASNs, countries, cloud/CDN/email processors, public compliance claims when web search is available.

Subagent prompt template:

```text
Use NordStellar MCP and the <skill-name> skill. Project/company scope: <scope>.
Collect evidence for <workstream/framework>. Use pagination, no GraphQL aliases, and include query names, counts, sampled IDs, evidence freshness, key findings, gaps, and manual evidence required.
Return concise structured findings only: scope, queries run, counts, top risks, coverage/gaps, manual evidence, and recommended next steps.
```

If subagents/delegation are unavailable, simulate the same workstreams sequentially and clearly say delegation was unavailable.

## Workflow

1. Clarify scope: company or project, project IDs, standards, audit period, report depth, and whether sensitive data may be revealed.
2. Run `projectsV2`; select the relevant project(s). Use `graphql_batch` for multi-project reviews.
3. Load the relevant child skills and assign workstreams to subagents.
4. Require each workstream to return counts, freshness, sampled IDs, high-risk findings, gaps, and manual evidence required.
5. Deduplicate findings across workstreams: one risk can map to many standards, but should appear once in the executive findings.
6. Build a cross-standard control matrix. Use the framework skills for exact coverage language and limitations.
7. Separate observed NordStellar evidence, inferred audit risk, and manual evidence requests.

## Synthesis Rules

- Do not mark a company compliant from NordStellar data alone.
- Use `strong`, `partial`, `gap`, or `not covered by NordStellar` as coverage levels.
- Include evidence freshness: scan times, event dates, detection dates, certificate discovery/expiry, and dark web posted/scraped times.
- Highlight missing coverage: disabled modules, unmonitored assets, stale/failed scans, pagination not exhausted, null module counts, missing assignees, and unresolved high-risk events.
- Treat unresolved critical/high vulnerabilities, active leaked credentials, malware infections with corporate credentials/cookies, spoofable domains, expiring/invalid certs, and high-risk domain permutations as priority audit findings.
- Keep raw sensitive data out of the report unless explicitly authorized.

## Output Shape

Use this structure unless the user asks otherwise:

1. Executive summary: scope, standards, evidence date, overall posture, top risks, and key limits.
2. Project/company coverage: projects reviewed, assets, monitoring status, modules available, scan freshness.
3. Cross-standard matrix: standard/control area, NordStellar evidence, coverage level, gaps, manual evidence required.
4. Priority findings: one finding per issue with affected assets, evidence, mapped standards, risk, remediation, owner/assignee if present.
5. Domain reports: attack surface, web apps, network exposure, DNS/TLS, threat intelligence, leaked data/malware, domain squatting, supplier/data-center exposure.
6. Manual evidence request list: grouped by governance, risk, IAM, logging/SIEM, endpoint, incident response, supplier, BCP/backup, HR/training, legal/privacy.
7. Appendix: subagent outputs summarized, query log, counts, sampled IDs, pagination notes, and sensitive data handling.
