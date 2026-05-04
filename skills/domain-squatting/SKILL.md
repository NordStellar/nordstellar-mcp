---
name: domain-squatting
version: 1.0.0
description: "NordStellar domain squatting (typosquat / look-alike brand abuse) via GraphQL: permutation inventory, WHOIS and redirect chains, content and visual similarity, AI threat classification, unified events, and case workflow."
metadata:
  nordstellar:
    category: "brand-protection"
    requires:
      tools: ["graphql_query", "graphql_batch", "search_types", "get_type_definition"]
---

# NordStellar — Domain Squatting (brand / typosquat detection)

NordStellar continuously generates **permutations** of domains you monitor (the “original” or **seed** domains), checks whether those permutations are **registered or active**, and enriches hits with DNS, HTTP/SMTP fingerprints, **redirect chains**, **WHOIS**, **content and perceptual-hash-style similarity**, and an **AI analysis** layer (threat labels, evidence bullets, recommendations).

Typical abuse patterns you will see in data: **phishing**, **affiliate fraud** (redirects into the real brand with tracking parameters), **parking / resale**, **dormant or suspicious infrastructure** (off-brand registrars, nameservers, or hosting), and **homoglyph / bitsquat / insertion / omission** style look-alikes.

Use the MCP **`graphql_query`** tool with the operations below. For the **same** logical query across **many** `projectId` values without GraphQL aliases, use **`graphql_batch`** with `variables_list` (aliases are forbidden server-side).

## Agent expectations

- **Start broad, then narrow.** Run `domainSquattingCounts`, then a modest `domainPermutationsProjections` page, then **facet** queries only when you need filter dropdown values. Some facet endpoints return **hundreds of strings** (IPs, nameserver hostnames)—do not assume you should fetch them all into the model context.
- **Correlate IDs deliberately.** The projection list row has both `id` (projection row id) and `domainPermutationId` (entity id). Detail queries, activity logs, assignments, and resolve mutations use **`domainPermutationId`**. The unified event feed uses **`eventProjection.id`** for the event row; `entityId` on `DOMAIN_PERMUTATION` events is **not** interchangeable with `domainPermutationId`—drill down with `domainPermutation` using the id from the permutation list when you need full enrichment.
- **Iterate on risk and similarity.** High `riskLevel` does not always pair with high `visualSimilarity` (dictionary permutations can be critical while looking unlike the brand visually). Use `similarityScore`, `visualSimilarity`, and AI `threatAnalysis` / `threats` together.
- **Separate workflow enums.** Permutation rows expose `status: DomainPermutationEventStatus` (`OPEN`, `UNDER_INVESTIGATION`, …). Rows in `eventsProjectionsV2` expose `status: EventStatus` for the **event** workflow. Both can be true at once; they are different objects.

## PREREQUISITE

All project-scoped queries need `projectId` (UUID). Discover projects with:

```graphql
query {
  projectsV2(take: 20) {
    items { id name }
  }
}
```

## Platform rules (MCP / NordStellar GraphQL)

- **No field aliases** — the API returns `ALIAS_NOT_ALLOWED` (this applies to multi-branch alias labels like `a: domainSquattingCounts`).
- Pagination: `take` ≤ **100** on `domainPermutationsProjections` and `eventsProjectionsV2`.
- Sorting: `order: [{ field: DESC }]` arrays; `DESC` / `ASC` / `DESC_NULL_LAST` as supported on each sort input (`get_type_definition` on `DomainPermutationProjectionSortInput` / `EventProjectionSortInput` when unsure).
- If a filter field fails validation, inspect the filter input type (e.g. `DomainPermutationProjectionFilterInput`) via **`get_type_definition`**.

---

## 1) Monitoring posture on assets (optional)

For **domain** assets, `assetsProjections` exposes whether domain-squatting monitoring is healthy for that row:

```graphql
query AssetSquattingMonitoring($projectId: UUID!) {
  assetsProjections(
    projectId: $projectId
    take: 50
    skip: 0
    where: { assetType: { eq: DOMAIN }, assetValue: { eq: "example.com" } }
  ) {
    totalCount
    items {
      assetValue
      domainSquattingMonitoringStatus
      isDomainSquattingMonitoringStatusSuccessful
    }
  }
}
```

Use this when troubleshooting “why no new permutations” or inconsistent coverage across seeds.

---

## 2) Overview metrics

Always fetch this first for executive framing and cadence:

```graphql
query DomainSquattingOverview($projectId: UUID!) {
  domainSquattingCounts(projectId: $projectId) {
    totalEventsCount
    highRiskEventsPerThirtyDaysCount
    eventsPerThirtyDaysCount
    countsPerPermutationType {
      key
      value
    }
  }
}
```

**Interpreting `countsPerPermutationType`:** keys are **API strings** (see reference below). Counts can be **non-zero while** `eventsPerThirtyDaysCount` is zero—totals are historical inventory-style counts; the 30-day fields measure recent activity.

---

## 3) Primary inventory — `domainPermutationsProjections`

List look-alike findings with DNS, assignment, and similarity scaffolding:

```graphql
query DomainPermutationsList($projectId: UUID!) {
  domainPermutationsProjections(
    projectId: $projectId
    take: 100
    skip: 0
    where: { isResolved: { eq: false } }
    order: [{ riskLevel: DESC }, { detectionDate: DESC }]
  ) {
    totalCount
    items {
      id
      domainPermutationId
      projectId
      originalDomain
      detectedDomain
      permutationType
      riskLevel
      similarityScore
      visualSimilarity
      detectionDate
      isResolved
      resolvedAt
      status
      assignee
      assigneeEmail
      assigneeUserId
      assigneeType
      nameServers
      mailServers
      ips {
        address
        countryCodeIso
        countryName
      }
    }
  }
}
```

### Focused filters (compose inside `where`)

- **Original seed:** `originalDomain: { eq: "brand.com" }`
- **Detected hostname:** `detectedDomain: { contains: "badsite" }`
- **Risk:** `riskLevel: { in: [CRITICAL, HIGH] }` or `{ eq: CRITICAL }`
- **Permutation class:** `permutationType: { eq: "homoglyph" }` (string must match API — see reference)
- **Workflow:** `status: { eq: OPEN }` or `{ in: [OPEN, UNDER_INVESTIGATION] }`
- **Visual similarity:** `visualSimilarity: { gte: 90 }` (also supports `gt`, `lte`, … via `FloatOperationFilterInput`)
- **Content similarity score:** `similarityScore: { gte: 80 }`
- **IP country (via nested filter):** `ips: { some: { countryCodeIso: { eq: "DE" } } }`

**Pagination:** use `skip` / `take` with `totalCount`. `pageInfo.hasNextPage` is available on the segment for cursor-style awareness.

---

## 4) Facet helpers (for filters, dashboards, and pivoting)

These return **arrays of strings** (sometimes very large). Prefer **constraining** list queries over downloading full facet lists unless you truly need exhaustive values.

```graphql
query DomainSquattingFacets($projectId: UUID!) {
  domainPermutationsOriginalDomains(projectId: $projectId)
  domainPermutationsPermutationTypes(projectId: $projectId)
  domainPermutationsIpAddresses(projectId: $projectId)
  domainPermutationsDetectedDomains(projectId: $projectId)
  domainPermutationsNameServerProviders(projectId: $projectId)
  domainPermutationsMailServerProviders(projectId: $projectId)
}
```

Practical usage:

- `domainPermutationsOriginalDomains` — enumerate **seed** brands/domains with findings.
- `domainPermutationsPermutationTypes` — exact variant strings the backend uses (use these in `permutationType` filters).
- IP / NS / MX provider lists — pivot when hunting **shared infrastructure** across many permutations.

Assignees currently in use:

```graphql
query DomainSquattingAssignees($projectId: UUID!) {
  domainPermutationsAssignees(projectId: $projectId) {
    userId
    username
    email
  }
}
```

Users eligible to be **assigned** (for `assignUserToDomainPermutation`):

```graphql
query DomainSquattingAssignableUsers($projectId: UUID!) {
  domainPermutationsAssignableUsers(projectId: $projectId) {
    userId
    username
    email
  }
}
```

---

## 5) Forensics — `domainPermutation` detail

Use **`domainPermutationId`** from the projection list (not the projection row `id`):

```graphql
query DomainPermutationDetail($domainPermutationId: UUID!) {
  domainPermutation(domainPermutationId: $domainPermutationId) {
    domainPermutationId
    projectId
    originalDomainId
    originalDomain
    domain
    permutationType
    riskLevel
    screenshotKey
    detectedAt
    isResolved
    status
    assignee
    assigneeEmail
    assigneeUserId
    assigneeType
    domainPermutationTaskId
    nameServers
    mailServers
    geoIps {
      address
      countryName
      countryCodeIso2
    }
    whois {
      name
      organization
      registrar
      contacts
      registrationDate
      expirationDate
    }
    serviceBanners {
      http
      smtp
    }
    threatAnalysis {
      contentSimilarity
      visualSimilarity
    }
    redirects {
      url
      statusCode
    }
    aiAnalysis {
      threats {
        type
        confidence
        evidences
        severity
      }
      recommendations {
        action
        rationale
      }
    }
  }
}
```

### Reading the enrichment fields

- **`redirects`:** ordered HTTP-level trail; affiliate fraud often shows **302/307** hops to third-party IPs or trackers before landing on the legitimate brand site. Treat query-string parameters as **evidence**, not secrets to propagate.
- **`threatAnalysis`:** numeric **content** and **visual** similarity (nullable floats).
- **`aiAnalysis.threats`:** `type` is a **machine label** (e.g. threat classes such as affiliate fraud or suspicious infrastructure—exact strings vary). `evidences` is a list of human-readable bullets. `severity` uses `RiskLevel`.
- **`aiAnalysis.recommendations`:** `action` + `rationale` (there is **no** `title` / `description` pair on this type—do not copy outdated examples from informal docs).
- **`screenshotKey`:** opaque storage key for the product UI—do not invent download URLs.

---

## 6) Unified security feed — `DOMAIN_PERMUTATION` events

Surface permutations alongside other threats for SOC-style triage:

```graphql
query DomainPermutationEvents($projectId: UUID!) {
  eventsProjectionsV2(
    projectId: $projectId
    take: 100
    skip: 0
    where: { type: { eq: DOMAIN_PERMUTATION }, isResolved: { eq: false } }
    order: [{ createdAt: DESC }]
  ) {
    totalCount
    items {
      id
      entityId
      type
      assetValue
      domain
      name
      tags
      riskLevel
      isResolved
      status
      assignee
      eventCreatedAt
      createdAt
    }
  }
}
```

**Mapping hints:**

- **`name`** — commonly the **detected** permutation hostname (verify per row).
- **`assetValue` / `domain`** — frequently the **monitored seed** domain context.
- **`tags`** — comma-separated style feature flags (examples observed in production data include permutation class cues and infrastructure labels such as `DORMANT_INFRASTRUCTURE`; treat as opaque strings unless you confirm meanings in your tenant).

Drill into a single event envelope:

```graphql
query OneDomainPermutationEvent($eventProjectionId: UUID!) {
  eventProjection(eventProjectionId: $eventProjectionId) {
    id
    entityId
    type
    name
    assetValue
    domain
    tags
    riskLevel
    status
    isResolved
    assignee
    eventCreatedAt
  }
}
```

---

## 7) Activity log (case history)

```graphql
query DomainPermutationActivity($domainPermutationId: UUID!) {
  domainPermutationEventActivityLogProjections(
    domainPermutationId: $domainPermutationId
  ) {
    id
    type
    content
    actorUsername
    actorEmail
    actorType
    assigneeUsername
    assigneeEmail
    previousStatus
    currentStatus
    createdAt
  }
}
```

Rows may be system-generated (e.g. `EVENT_CREATED`) with null actor fields.

---

## 8) Case management mutations

Always confirm payload shapes with `get_type_definition` before selecting fields.

### Resolve / reopen

```graphql
mutation ResolveDomainPermutation($id: UUID!, $isResolved: Boolean!) {
  updateDomainPermutationIsResolved(input: { id: $id, isResolved: $isResolved }) {
    id
    isResolved
  }
}
```

`id` is the **`domainPermutationId`**.

### Workflow status (`DomainPermutationEventStatus`)

```graphql
mutation ChangeDomainPermutationStatus(
  $domainPermutationId: UUID!
  $status: DomainPermutationEventStatus!
) {
  changeDomainPermutationStatus(
    input: { domainPermutationId: $domainPermutationId, status: $status }
  ) {
    domainPermutationId
    status
  }
}
```

Enum values: `OPEN`, `UNDER_INVESTIGATION`, `REMEDIATION`, `DUPLICATE`, `FALSE_POSITIVE`, `WONT_FIX`, `RESOLVED`, `TAKEDOWN`.

### Assignment

```graphql
mutation AssignDomainPermutation(
  $domainPermutationId: UUID!
  $userId: UUID!
) {
  assignUserToDomainPermutation(
    input: { domainPermutationId: $domainPermutationId, userId: $userId }
  ) {
    domainPermutationId
  }
}
```

```graphql
mutation UnassignDomainPermutation($domainPermutationId: UUID!) {
  unassignUserFromDomainPermutation(input: { domainPermutationId: $domainPermutationId }) {
    domainPermutationId
  }
}
```

Use `domainPermutationsAssignableUsers` to source `userId` values.

### Comments

```graphql
mutation CommentOnDomainPermutation($domainPermutationId: UUID!, $content: String!) {
  addCommentToDomainPermutation(
    input: { domainPermutationId: $domainPermutationId, content: $content }
  ) {
    commentId
  }
}
```

Pair with `editCommentForDomainPermutation` / `deleteCommentFromDomainPermutation` when maintaining investigation notes.

---

## 9) Organization consent (governance)

Domain squatting features require organization-level consent (`Organization.hasDomainSquattingConsent` in the schema). Admins grant it with:

```graphql
mutation GiveDomainSquattingConsent($organizationId: UUID!) {
  giveOrganizationDomainSquattingConsent(
    input: { organizationId: $organizationId }
  ) {
    hasDomainSquattingConsent
    id
  }
}
```

If counts and lists stay empty across seeds that should be monitored, verify entitlement / consent and whether seeds are present as monitored **domain** assets.

---

## 10) Notification routing

Email / Slack / Teams / webhook notification rules can include `DOMAIN_PERMUTATION` in `eventTypes` (`NotificationEventType` enum) when configuring `UpdateEmailNotificationSettingsVNextInput` (and related notification mutations). Use this when helping users wire alerts specifically for squatting findings.

---

## Reference — permutation `permutationType` strings

The backend returns **string** labels (not a GraphQL enum). You will commonly see:

| `permutationType` | Typical meaning |
|-------------------|-----------------|
| `homoglyph` | Visually confusable character swaps (unicode homoglyphs) |
| `bitsquatting` | Bit-flip style neighboring hostnames |
| `omission` / `insertion` / `transposition` | Character deleted, inserted, or swapped |
| `replacement` | Substitutions / keyboard-adjacent style edits (API wording) |
| `vowel-swap` | Vowel alterations |
| `tld-swap` | Alternate TLD or ccTLD on the same second-level label |
| `dictionary` | Dictionary-style or wordlist expansions / compounds |
| `transposition` | Adjacent character order swaps |

**Exact coverage varies by tenant data** — call `domainPermutationsPermutationTypes` instead of hard-coding.

---

## Reference — risk and workflow

- **Risk (`RiskLevel`):** `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- **Permutation workflow (`DomainPermutationEventStatus`):** see mutation section above.
- **Event workflow (`EventStatus` on `EventProjection`):** distinct enum for unified feed rows — inspect `EventStatus` via `get_type_definition` when filtering events.

---

## Investigation playbooks (condensed)

1. **Volume triage:** `domainSquattingCounts` → sliced `domainPermutationsProjections` (`riskLevel` in `CRITICAL,HIGH`, `isResolved: false`).
2. **Single-brand incident:** filter `originalDomain`, sort by `detectionDate DESC`, open top rows in `domainPermutation`.
3. **Affiliate fraud hunt:** detail query focusing on `redirects` + AI threats mentioning fraud; correlate registrars in `whois` vs legitimate brand infrastructure.
4. **Visual phishing:** `visualSimilarity` / `threatAnalysis.visualSimilarity` high, plus `screenshotKey` present—pair with `redirects` and `serviceBanners`.
5. **Infrastructure clustering:** pick a **nameserver** or **IP** from a bad row → search list `where` with `ips: { some: { address: { eq: \"x.x.x.x\" } } }` or constrain `nameServers` / facet provider lists.
6. **Feed-driven SOC:** `eventsProjectionsV2` with `DOMAIN_PERMUTATION`, pivot to `domainPermutation` for enrichment.

---

## Operational pitfalls

- **Assuming `entityId` equals `domainPermutationId`:** false; always keep the projection’s `domainPermutationId` as the forensic key.
- **Fetching full `domainPermutationsIpAddresses` on large tenants:** can return **hundreds** of entries—expensive for context windows.
- **Outdated GraphQL examples** showing `aiAnalysis { threats { title description } }` — schema uses `type/confidence/evidences/severity` and `recommendations { action rationale }`.
- **Using GraphQL aliases** to compare multiple projects in one document—use separate operations or `graphql_batch`.
