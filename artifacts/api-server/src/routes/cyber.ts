import { Router, type IRouter } from "express";
import OpenAI from "openai";
import { and, desc, eq } from "drizzle-orm";
import {
  AnalyzeIncidentBody,
  AnalyzeIncidentResponse,
  GenerateLearningQuizBody,
  GenerateLearningQuizResponse,
  GetAttackParams,
  GetAttackResponse,
  GetDashboardSummaryResponse,
  GetIncidentParams,
  GetIncidentResponse,
  ListAttacksResponse,
  ListIncidentsQueryParams,
  ListIncidentsResponse,
  ListLearningLessonsResponse,
  SendAnalystMessageBody,
  SendAnalystMessageResponse,
} from "@workspace/api-zod";
import { db, incidentsTable } from "@workspace/db";

const router: IRouter = Router();
const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
  : null;

type AnalysisDetails = {
  entryPoint: string;
  attackVector: string;
  assessment: string;
  timeline: Array<{ time: string; event: string; detail: string }>;
  evidence: string[];
  indicators: string[];
  rootCause: string;
  potentialImpact: string;
  immediateActions: string[];
  investigationActions: string[];
  preventionActions: string[];
  attackFlow: Array<{ id: string; label: string; type: string }>;
};

type PublicIncident = {
  id: string;
  title: string;
  attackType: string;
  riskLevel: string;
  confidence: number;
  status: string;
  affectedAsset: string;
  createdAt: string;
};

type PublicAnalysis = PublicIncident & AnalysisDetails;

const attacks: Array<{
  slug: string;
  name: string;
  shortDescription: string;
  category: string;
  severity: string;
  icon: string;
  whatItIs: string;
  howItHappens: string;
  stages: string[];
  detection: string[];
  indicators: string[];
  impact: string;
  mitigation: string[];
  prevention: string[];
}> = [
  {
    slug: "phishing",
    name: "Phishing",
    shortDescription: "Deceptive messages designed to make people reveal information or take unsafe actions.",
    category: "Social engineering",
    severity: "High",
    icon: "mail-warning",
    whatItIs: "Phishing uses a convincing email, message, or website to manipulate a person into sharing credentials, opening a file, or approving an action.",
    howItHappens: "An attacker impersonates a trusted sender and creates urgency. The message usually leads to a lookalike login page or an attachment.",
    stages: ["Impersonate trusted sender", "Create urgency", "Deliver link or attachment", "Capture input", "Use access or sell credentials"],
    detection: ["Check sender domain and reply-to address", "Inspect links before opening", "Correlate message delivery with sign-in events"],
    indicators: ["Lookalike domains", "Unexpected MFA prompts", "Urgent password reset language", "New mailbox forwarding rules"],
    impact: "Credential compromise, malware delivery, financial loss, or unauthorized access to cloud resources.",
    mitigation: ["Reset exposed credentials", "Revoke sessions and tokens", "Preserve the message and headers", "Search for related messages"],
    prevention: ["Phishing-resistant MFA", "Email authentication and filtering", "Security awareness training", "Conditional access policies"],
  },
  {
    slug: "spear-phishing",
    name: "Spear Phishing",
    shortDescription: "Highly targeted social engineering built around a specific person, team, or business process.",
    category: "Social engineering",
    severity: "Critical",
    icon: "target",
    whatItIs: "Spear phishing is a tailored phishing campaign that uses personal or organizational context to appear unusually credible.",
    howItHappens: "Attackers research a target, impersonate an executive or partner, and ask for credentials, payments, or sensitive files.",
    stages: ["Research target", "Build trust", "Make a targeted request", "Capture access or data"],
    detection: ["Verify unusual requests out of band", "Review email authentication", "Look for new OAuth grants or forwarding rules"],
    indicators: ["Executive impersonation", "New external reply-to domains", "Requests that bypass normal process"],
    impact: "Business email compromise, data loss, fraud, and high-value account takeover.",
    mitigation: ["Pause the requested transaction", "Reset and revoke access", "Notify affected stakeholders", "Review mailbox activity"],
    prevention: ["Payment approval controls", "Phishing-resistant MFA", "Executive impersonation monitoring"],
  },
  {
    slug: "ransomware",
    name: "Ransomware",
    shortDescription: "Malware that disrupts availability by encrypting or exfiltrating data for extortion.",
    category: "Malware",
    severity: "Critical",
    icon: "lock-keyhole",
    whatItIs: "Ransomware is an extortion attack that can encrypt systems, steal data, or both.",
    howItHappens: "Initial access may come from phishing, exposed services, stolen credentials, or a vulnerable endpoint. Attackers then expand access before disruption.",
    stages: ["Initial access", "Privilege escalation", "Lateral movement", "Data theft", "Encryption or disruption"],
    detection: ["Monitor abnormal file changes", "Alert on privilege and remote access anomalies", "Isolate affected endpoints quickly"],
    indicators: ["Mass file renames", "Shadow copy deletion", "Unusual admin tools", "Large outbound transfers"],
    impact: "Extended outage, data loss, recovery costs, regulatory exposure, and reputational harm.",
    mitigation: ["Isolate affected systems", "Protect backups", "Preserve volatile evidence", "Activate incident response plan"],
    prevention: ["Offline tested backups", "Least privilege", "Network segmentation", "Endpoint detection and response"],
  },
  {
    slug: "brute-force",
    name: "Brute Force",
    shortDescription: "Repeatedly trying credentials or keys until one succeeds.",
    category: "Credential attacks",
    severity: "High",
    icon: "key-round",
    whatItIs: "A brute-force attack guesses passwords or authentication secrets through repeated attempts.",
    howItHappens: "An attacker automates many guesses against a login or service, often rotating sources to avoid basic blocking.",
    stages: ["Choose target", "Generate guesses", "Send repeated attempts", "Exploit successful login"],
    detection: ["Track failed attempts by account and source", "Alert on password spray patterns", "Correlate success after failures"],
    indicators: ["Repeated failures", "Distributed source IPs", "Sign-in success after a burst of failures"],
    impact: "Account takeover, lockouts, and unauthorized access to connected resources.",
    mitigation: ["Block or rate-limit sources", "Reset credentials", "Revoke sessions", "Review successful access"],
    prevention: ["MFA", "Strong password policy", "Rate limiting", "Risk-based sign-in controls"],
  },
  {
    slug: "credential-stuffing",
    name: "Credential Stuffing",
    shortDescription: "Reusing credentials leaked from another service to access a new account.",
    category: "Credential attacks",
    severity: "High",
    icon: "fingerprint",
    whatItIs: "Credential stuffing exploits password reuse rather than guessing a password from scratch.",
    howItHappens: "Automated tools test username and password pairs from a breach against another login surface.",
    stages: ["Acquire breached pairs", "Test at scale", "Identify valid accounts", "Access and monetize"],
    detection: ["Compare sign-ins with known breach patterns", "Detect automation and impossible travel", "Watch for password reset spikes"],
    indicators: ["Many accounts targeted from rotating sources", "Valid login after few failures", "New device or geography"],
    impact: "Account takeover, fraud, and access to reused corporate credentials.",
    mitigation: ["Force reset affected accounts", "Revoke sessions", "Review account activity", "Notify users"],
    prevention: ["Unique passwords", "Passwordless or MFA", "Breached-password screening", "Bot detection"],
  },
  {
    slug: "malware",
    name: "Malware",
    shortDescription: "Software intentionally designed to disrupt, damage, spy on, or gain access to systems.",
    category: "Endpoint",
    severity: "High",
    icon: "bug",
    whatItIs: "Malware is a broad category covering malicious programs such as trojans, spyware, worms, and loaders.",
    howItHappens: "It can arrive through a malicious file, drive-by download, compromised software, or another compromised account.",
    stages: ["Delivery", "Execution", "Persistence", "Command and control", "Impact"],
    detection: ["Use endpoint telemetry", "Monitor new persistence mechanisms", "Inspect DNS and process anomalies"],
    indicators: ["Unexpected processes", "Unsigned binaries", "Suspicious scheduled tasks", "Outbound connections to rare domains"],
    impact: "Data theft, credential theft, disruption, and a foothold for further compromise.",
    mitigation: ["Isolate endpoint", "Collect forensic artifacts", "Remove persistence", "Reset exposed secrets"],
    prevention: ["Endpoint protection", "Application allowlisting", "Patch management", "Least privilege"],
  },
  {
    slug: "ddos",
    name: "DDoS",
    shortDescription: "Overwhelming a service with traffic or requests so legitimate users cannot reach it.",
    category: "Availability",
    severity: "High",
    icon: "traffic-cone",
    whatItIs: "Distributed denial of service attacks use many sources to exhaust bandwidth, connections, or application capacity.",
    howItHappens: "Attackers coordinate traffic from compromised devices or rented infrastructure against a public service.",
    stages: ["Select target", "Generate traffic", "Exhaust capacity", "Adapt to controls"],
    detection: ["Baseline traffic and request rates", "Monitor edge saturation", "Compare geographic and protocol patterns"],
    indicators: ["Sharp traffic spike", "Many similar requests", "Unusual protocol mix", "High error rates"],
    impact: "Service outage, customer disruption, and increased infrastructure cost.",
    mitigation: ["Engage DDoS protection", "Rate-limit abusive traffic", "Scale and filter at the edge", "Preserve attack telemetry"],
    prevention: ["Capacity planning", "CDN and scrubbing service", "Resilient architecture", "Runbook exercises"],
  },
  {
    slug: "sql-injection",
    name: "SQL Injection",
    shortDescription: "Manipulating unsafe database queries through untrusted application input.",
    category: "Application",
    severity: "Critical",
    icon: "database-zap",
    whatItIs: "SQL injection occurs when an application combines untrusted input with database commands without safe parameterization.",
    howItHappens: "A crafted request changes the meaning of a query, potentially exposing or modifying data.",
    stages: ["Find input surface", "Probe behavior", "Alter query meaning", "Read or change data"],
    detection: ["Review WAF and application logs", "Watch for database errors", "Correlate unusual query patterns"],
    indicators: ["Repeated syntax-like input", "Unexpected database errors", "Large or unusual result sets"],
    impact: "Data exposure, data modification, authentication bypass, or service disruption.",
    mitigation: ["Patch the affected code", "Rotate exposed secrets", "Review database access", "Preserve logs"],
    prevention: ["Parameterized queries", "Input validation", "Least-privilege database roles", "Security testing"],
  },
  {
    slug: "man-in-the-middle",
    name: "Man-in-the-Middle",
    shortDescription: "Intercepting or altering communications between two parties.",
    category: "Network",
    severity: "High",
    icon: "waypoints",
    whatItIs: "A man-in-the-middle attack places an attacker between communicating systems to observe or manipulate traffic.",
    howItHappens: "Attackers may abuse unsafe networks, compromised certificates, rogue access points, or routing weaknesses.",
    stages: ["Position between parties", "Intercept traffic", "Read or alter data", "Maintain access"],
    detection: ["Inspect certificate warnings", "Monitor network changes", "Compare device and gateway behavior"],
    indicators: ["Unexpected certificate", "Rogue Wi-Fi", "ARP or DNS anomalies", "Session integrity warnings"],
    impact: "Credential theft, data manipulation, and loss of communication confidentiality.",
    mitigation: ["Terminate sessions", "Move to trusted network", "Rotate credentials", "Investigate certificates"],
    prevention: ["TLS validation", "Secure Wi-Fi", "Network segmentation", "Device trust controls"],
  },
  {
    slug: "insider-threat",
    name: "Insider Threat",
    shortDescription: "Harm caused by someone with legitimate access, intentionally or accidentally.",
    category: "Identity and data",
    severity: "High",
    icon: "user-round-alert",
    whatItIs: "An insider threat involves misuse of authorized access, whether through malicious intent, negligence, or a compromised employee account.",
    howItHappens: "A user accesses more data than their role requires, exports it, or creates risky sharing paths.",
    stages: ["Obtain or retain access", "Access sensitive resource", "Move or share data", "Avoid attention"],
    detection: ["Use access and data-loss telemetry", "Compare activity with role and baseline", "Review offboarding controls"],
    indicators: ["Bulk downloads", "Unusual access time", "New sharing links", "Access after role change"],
    impact: "Data loss, fraud, privacy incidents, and reputational damage.",
    mitigation: ["Preserve evidence", "Limit access carefully", "Coordinate with HR and legal", "Review affected data"],
    prevention: ["Least privilege", "Joiner-mover-leaver controls", "Data classification", "Separation of duties"],
  },
];

const lessons = [
  { id: "phishing-basics", title: "Phishing, without the jargon", description: "Learn how deceptive messages create pressure and how to verify them safely.", level: "Beginner", duration: "8 min", topic: "Phishing" },
  { id: "read-an-alert", title: "How to read a security alert", description: "Turn an alert into a small set of questions about evidence, scope, and impact.", level: "Beginner", duration: "12 min", topic: "Incident response" },
  { id: "mfa-explained", title: "Why MFA changes the game", description: "Understand which second factors meaningfully reduce account takeover risk.", level: "Beginner", duration: "7 min", topic: "Identity security" },
  { id: "attack-chain", title: "Following an attack chain", description: "Practice connecting entry point, evidence, and defensive next steps.", level: "Intermediate", duration: "15 min", topic: "Threat analysis" },
];

const seededAnalyses: PublicAnalysis[] = [
  {
    id: "inc-1001",
    title: "Unusual sign-in after credential exposure",
    attackType: "Phishing → Credential compromise",
    riskLevel: "CRITICAL",
    confidence: 91,
    status: "Investigating",
    affectedAsset: "Employee account",
    createdAt: "2026-09-05T10:12:00.000Z",
    entryPoint: "Phishing email",
    attackVector: "Malicious link to a lookalike login page",
    assessment: "Potential attack detected. The sequence is consistent with credential compromise, but confirm mailbox and identity-provider evidence before declaring the incident contained.",
    timeline: [
      { time: "10:02 AM", event: "Suspicious email received", detail: "Message impersonated an internal file-sharing notification." },
      { time: "10:05 AM", event: "Malicious link clicked", detail: "Link resolved to a lookalike sign-in page." },
      { time: "10:07 AM", event: "Credentials potentially exposed", detail: "The user submitted credentials before closing the page." },
      { time: "10:12 AM", event: "Suspicious login detected", detail: "Successful sign-in from an unusual geography." },
    ],
    evidence: ["Lookalike sender domain", "Malicious URL", "Successful login after unusual activity", "New device fingerprint"],
    indicators: ["185.73.221.19", "login-sharepoint-secure.com", "Impossible travel pattern"],
    rootCause: "Compromised user credentials due to a targeted phishing message.",
    potentialImpact: "Unauthorized mailbox access and possible access to connected cloud resources.",
    immediateActions: ["Disable or suspend the account", "Reset credentials", "Revoke active sessions and tokens"],
    investigationActions: ["Review identity-provider and mailbox logs", "Search the IP and domain across the tenant", "Check for forwarding rules and OAuth grants"],
    preventionActions: ["Enable phishing-resistant MFA", "Improve email filtering", "Add sign-in risk policies", "Run targeted security awareness training"],
    attackFlow: [
      { id: "n1", label: "Phishing email", type: "source" },
      { id: "n2", label: "Malicious link", type: "vector" },
      { id: "n3", label: "Fake login page", type: "vector" },
      { id: "n4", label: "Credentials exposed", type: "impact" },
      { id: "n5", label: "Unauthorized login", type: "impact" },
    ],
  },
  {
    id: "inc-1002",
    title: "Password spray against finance accounts",
    attackType: "Brute force / password spray",
    riskLevel: "HIGH",
    confidence: 84,
    status: "Contained",
    affectedAsset: "Finance identity group",
    createdAt: "2026-09-04T16:42:00.000Z",
    entryPoint: "Public identity provider",
    attackVector: "Distributed authentication attempts",
    assessment: "Potential attack detected. The distributed failures and one successful login warrant review of the successful session and password reuse.",
    timeline: [
      { time: "4:12 PM", event: "Failure burst began", detail: "Several finance accounts were targeted from rotating sources." },
      { time: "4:24 PM", event: "Conditional access challenged", detail: "Risk controls blocked most attempts." },
      { time: "4:42 PM", event: "Incident contained", detail: "Sessions were revoked and affected accounts reset." },
    ],
    evidence: ["Repeated failures across accounts", "Rotating source addresses", "One success from a new device"],
    indicators: ["Distributed source IP set", "New device fingerprint", "Authentication failures across a role group"],
    rootCause: "Likely password reuse combined with insufficient step-up authentication.",
    potentialImpact: "Unauthorized access to finance workflows if the successful session was valid.",
    immediateActions: ["Revoke active sessions", "Reset affected credentials", "Require step-up verification"],
    investigationActions: ["Review the successful session", "Compare passwords against breach screening", "Search for other targeted groups"],
    preventionActions: ["Require MFA for all finance access", "Add password spray detection", "Enforce unique passwords"],
    attackFlow: [
      { id: "n1", label: "Leaked password pairs", type: "source" },
      { id: "n2", label: "Distributed login attempts", type: "vector" },
      { id: "n3", label: "New device sign-in", type: "impact" },
      { id: "n4", label: "Session revoked", type: "response" },
    ],
  },
  {
    id: "inc-1003",
    title: "Suspicious outbound transfer from endpoint",
    attackType: "Malware / data exfiltration",
    riskLevel: "MEDIUM",
    confidence: 68,
    status: "Monitoring",
    affectedAsset: "Design workstation",
    createdAt: "2026-09-03T08:17:00.000Z",
    entryPoint: "Downloaded document",
    attackVector: "Unknown executable with outbound connection",
    assessment: "Insufficient evidence to confirm. The endpoint behavior is unusual, but the executable and destination need validation before attributing malicious intent.",
    timeline: [
      { time: "8:01 AM", event: "Document downloaded", detail: "Download originated from an external file-sharing domain." },
      { time: "8:09 AM", event: "New process observed", detail: "Unsigned process launched from a temporary directory." },
      { time: "8:17 AM", event: "Outbound connection flagged", detail: "Endpoint protection recorded a rare destination." },
    ],
    evidence: ["Unsigned process", "Temporary-directory execution", "Rare outbound destination"],
    indicators: ["Unknown SHA-256 pending triage", "Rare destination domain", "Temporary directory process"],
    rootCause: "Not confirmed; possible unsafe download or software installation.",
    potentialImpact: "Credential theft or data access if the process is malicious.",
    immediateActions: ["Isolate the endpoint if behavior continues", "Capture process and network telemetry", "Ask the user to preserve the source file"],
    investigationActions: ["Submit the file for sandbox analysis", "Review parent process and command line", "Search for the hash across endpoints"],
    preventionActions: ["Block untrusted executable downloads", "Improve endpoint application control", "Review browser download policies"],
    attackFlow: [
      { id: "n1", label: "External download", type: "source" },
      { id: "n2", label: "Unsigned process", type: "vector" },
      { id: "n3", label: "Rare outbound connection", type: "impact" },
      { id: "n4", label: "Triage pending", type: "response" },
    ],
  },
];

function analysisToRow(analysis: PublicAnalysis) {
  const { entryPoint, attackVector, assessment, timeline, evidence, indicators, rootCause, potentialImpact, immediateActions, investigationActions, preventionActions, attackFlow, ...incident } = analysis;
  return {
    id: incident.id,
    title: incident.title,
    sourceContent: assessment,
    attackType: incident.attackType,
    riskLevel: incident.riskLevel,
    confidence: incident.confidence,
    status: incident.status,
    affectedAsset: incident.affectedAsset,
    analysis: { entryPoint, attackVector, assessment, timeline, evidence, indicators, rootCause, potentialImpact, immediateActions, investigationActions, preventionActions, attackFlow },
  };
}

function rowToAnalysis(row: typeof incidentsTable.$inferSelect): PublicAnalysis {
  const details = row.analysis as unknown as AnalysisDetails;
  return {
    id: row.id,
    title: row.title,
    attackType: row.attackType,
    riskLevel: row.riskLevel,
    confidence: row.confidence,
    status: row.status,
    affectedAsset: row.affectedAsset,
    createdAt: row.createdAt.toISOString(),
    ...details,
  };
}

async function ensureSeedData() {
  const existing = await db.select({ id: incidentsTable.id }).from(incidentsTable).limit(1);
  if (existing.length === 0) {
    await db.insert(incidentsTable).values(seededAnalyses.map(analysisToRow));
  }
}

function publicIncident(analysis: PublicAnalysis): PublicIncident {
  return {
    id: analysis.id,
    title: analysis.title,
    attackType: analysis.attackType,
    riskLevel: analysis.riskLevel,
    confidence: analysis.confidence,
    status: analysis.status,
    affectedAsset: analysis.affectedAsset,
    createdAt: analysis.createdAt,
  };
}

function normalizeJson(content: string) {
  const trimmed = content.trim().replace(/^```json\s*/i, "").replace(/```$/i, "").trim();
  return JSON.parse(trimmed) as Record<string, unknown>;
}

function fallbackAnalysis(content: string): PublicAnalysis {
  const lower = content.toLowerCase();
  const looksLikePhishing = /phish|malicious link|fake login|suspicious email/.test(lower);
  const looksLikeLogin = /login|sign-?in|password|credential/.test(lower);
  const looksLikeRansomware = /ransom|encrypt|locked files/.test(lower);
  const attackType = looksLikeRansomware
    ? "Potential ransomware activity"
    : looksLikePhishing && looksLikeLogin
      ? "Potential phishing → credential compromise"
      : looksLikeLogin
        ? "Potential credential attack"
        : "Potential security incident";
  const riskLevel = looksLikeRansomware ? "CRITICAL" : looksLikePhishing || looksLikeLogin ? "HIGH" : "MEDIUM";
  const now = new Date().toISOString();
  return {
    id: `inc-${crypto.randomUUID().slice(0, 8)}`,
    title: looksLikePhishing ? "Suspicious phishing-linked activity" : "New incident submitted for triage",
    attackType,
    riskLevel,
    confidence: looksLikePhishing || looksLikeLogin ? 76 : 54,
    status: "Investigating",
    affectedAsset: "Asset not yet confirmed",
    createdAt: now,
    entryPoint: looksLikePhishing ? "Suspicious message or link" : "Not yet confirmed",
    attackVector: looksLikePhishing ? "Social engineering" : "Insufficient evidence to confirm",
    assessment: "Potential attack detected. This is an initial triage based on the submitted description; confirm with logs, identity, endpoint, and network evidence.",
    timeline: [{ time: "Now", event: "Incident submitted", detail: "The description was queued for defensive triage." }],
    evidence: [content.slice(0, 180)],
    indicators: ["No normalized indicators extracted yet"],
    rootCause: "Not confirmed. Collect identity, endpoint, and network evidence before assigning root cause.",
    potentialImpact: "Impact cannot be confirmed until scope and affected assets are validated.",
    immediateActions: ["Preserve relevant logs and messages", "Confirm affected identity or asset", "Revoke access only when evidence supports exposure"],
    investigationActions: ["Review authentication and endpoint telemetry", "Check timestamps, sources, and related alerts", "Search for the same indicators across the environment"],
    preventionActions: ["Enable appropriate MFA and alerting", "Reduce unnecessary access", "Document the confirmed attack path and control gap"],
    attackFlow: [
      { id: "n1", label: "Reported signal", type: "source" },
      { id: "n2", label: "Evidence collection", type: "response" },
      { id: "n3", label: "Scope validation", type: "response" },
    ],
  };
}

async function analyzeWithModel(content: string): Promise<PublicAnalysis> {
  if (!openai) return fallbackAnalysis(content);
  try {
    const response = await openai.chat.completions.create({
      model: "gpt-5.2",
      max_completion_tokens: 8192,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content: `You are a defensive cybersecurity analyst. Analyze the supplied incident description or log without claiming certainty. Use "Potential attack detected" or "Insufficient evidence to confirm" when evidence is incomplete. Never provide instructions for unauthorized access, credential theft, malware deployment, persistence, or evasion. Return only valid JSON with this exact shape: {"title":string,"attackType":string,"riskLevel":"CRITICAL"|"HIGH"|"MEDIUM"|"LOW","confidence":number,"status":string,"affectedAsset":string,"entryPoint":string,"attackVector":string,"assessment":string,"timeline":[{"time":string,"event":string,"detail":string}],"evidence":[string],"indicators":[string],"rootCause":string,"potentialImpact":string,"immediateActions":[string],"investigationActions":[string],"preventionActions":[string],"attackFlow":[{"id":string,"label":string,"type":string}]}. Keep actions defensive and practical.`,
        },
        { role: "user", content },
      ],
    });
    const parsed = normalizeJson(response.choices[0]?.message?.content ?? "");
    const fallback = fallbackAnalysis(content);
    return {
      ...fallback,
      ...parsed,
      id: `inc-${crypto.randomUUID().slice(0, 8)}`,
      createdAt: new Date().toISOString(),
      confidence: Math.max(0, Math.min(100, Number(parsed.confidence ?? fallback.confidence))),
    } as PublicAnalysis;
  } catch {
    return fallbackAnalysis(content);
  }
}

function fallbackAnalystAnswer(message: string) {
  const lower = message.toLowerCase();
  const topic = /ransom/.test(lower) ? "ransomware" : /brute|credential/.test(lower) ? "credential attacks" : /phish/.test(lower) ? "phishing" : "the security question";
  return {
    id: `msg-${crypto.randomUUID().slice(0, 8)}`,
    answer: `Here is a defensive overview of ${topic}. Start by validating the signal with timestamps, affected identities or assets, and the smallest set of corroborating logs. Avoid assuming compromise until the evidence lines up.`,
    sections: [
      { title: "What to look for", content: "Correlate the alert with identity, endpoint, email, and network telemetry. Pay attention to unusual geography, new devices, privilege changes, rare processes, and unexpected data movement." },
      { title: "Defensive actions", content: "Preserve evidence, contain only the affected scope, revoke exposed sessions or secrets when appropriate, and document what was confirmed versus what remains a hypothesis." },
      { title: "Prevention", content: "Use strong MFA, least privilege, tested recovery plans, patching, security awareness, and monitoring tuned to the normal baseline." },
    ],
    safetyNote: "CyberShield AI is for defensive analysis, incident response, and security education. It will not provide instructions for unauthorized access or evasion.",
  };
}

async function answerWithModel(message: string) {
  if (!openai) return fallbackAnalystAnswer(message);
  try {
    const response = await openai.chat.completions.create({
      model: "gpt-5.2",
      max_completion_tokens: 8192,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content: `You are CyberShield AI, a defensive cybersecurity analyst. Answer in simple language. Do not provide instructions that facilitate unauthorized access, credential theft, malware deployment, persistence, or evasion. Keep recommendations focused on detection, analysis, mitigation, response, and prevention. Never claim an attack definitely occurred without evidence. Return JSON with {"answer":string,"sections":[{"title":string,"content":string}],"safetyNote":string}.`,
        },
        { role: "user", content: message },
      ],
    });
    const parsed = normalizeJson(response.choices[0]?.message?.content ?? "");
    return { id: `msg-${crypto.randomUUID().slice(0, 8)}`, ...parsed };
  } catch {
    return fallbackAnalystAnswer(message);
  }
}

router.get("/dashboard/summary", async (req, res) => {
  try {
    await ensureSeedData();
    const rows = await db.select().from(incidentsTable).orderBy(desc(incidentsTable.createdAt));
    const analyses = rows.map(rowToAnalysis);
    const byType = new Map<string, number>();
    const bySeverity = new Map<string, number>();
    for (const item of analyses) {
      byType.set(item.attackType, (byType.get(item.attackType) ?? 0) + 1);
      bySeverity.set(item.riskLevel, (bySeverity.get(item.riskLevel) ?? 0) + 1);
    }
    const data = GetDashboardSummaryResponse.parse({
      totalIncidents: analyses.length,
      criticalIncidents: analyses.filter((item) => item.riskLevel === "CRITICAL").length,
      highRiskIncidents: analyses.filter((item) => item.riskLevel === "HIGH").length,
      analyzedAttacks: analyses.length,
      resolvedIncidents: analyses.filter((item) => item.status === "Contained" || item.status === "Resolved").length,
      incidentsOverTime: [
        { label: "Mon", value: Math.max(1, analyses.length - 2) },
        { label: "Tue", value: Math.max(2, analyses.length - 1) },
        { label: "Wed", value: Math.max(1, analyses.length - 1) },
        { label: "Thu", value: analyses.length },
        { label: "Fri", value: Math.max(2, analyses.length - 1) },
        { label: "Sat", value: analyses.length + 1 },
        { label: "Sun", value: analyses.length },
      ],
      attackTypes: [...byType.entries()].map(([label, value], index) => ({ label, value, color: ["#54d6bd", "#ffbd6b", "#f17272", "#8ea7ff"][index % 4] })),
      severityDistribution: [...bySeverity.entries()].map(([label, value], index) => ({ label, value, color: ["#f17272", "#ffbd6b", "#54d6bd", "#8ea7ff"][index % 4] })),
      recentActivity: analyses.slice(0, 4).map((item) => ({
        id: item.id,
        title: item.title,
        description: `${item.attackType} · ${item.affectedAsset}`,
        time: new Date(item.createdAt).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" }),
        severity: item.riskLevel,
      })),
    });
    res.json(data);
  } catch (error) {
    req.log.error({ error }, "Failed to build dashboard summary");
    res.status(500).json({ error: "Unable to load dashboard summary" });
  }
});

router.get("/incidents", async (req, res) => {
  try {
    await ensureSeedData();
    const query = ListIncidentsQueryParams.parse(req.query);
    const rows = await db.select().from(incidentsTable).orderBy(desc(incidentsTable.createdAt)).limit(query.limit ?? 20);
    const filtered = query.status ? rows.filter((row) => row.status === query.status) : rows;
    res.json(ListIncidentsResponse.parse(filtered.map((row) => publicIncident(rowToAnalysis(row)))));
  } catch (error) {
    req.log.error({ error }, "Failed to list incidents");
    res.status(500).json({ error: "Unable to load incidents" });
  }
});

router.post("/incidents", async (req, res) => {
  try {
    const input = AnalyzeIncidentBody.parse(req.body);
    const analysis = await analyzeWithModel(input.content);
    await db.insert(incidentsTable).values(analysisToRow(analysis));
    res.status(201).json(AnalyzeIncidentResponse.parse(analysis));
  } catch (error) {
    req.log.error({ error }, "Failed to analyze incident");
    res.status(400).json({ error: "Unable to analyze this incident" });
  }
});

router.get("/incidents/:id", async (req, res) => {
  try {
    const { id } = GetIncidentParams.parse(req.params);
    const [row] = await db.select().from(incidentsTable).where(eq(incidentsTable.id, id)).limit(1);
    if (!row) return res.status(404).json({ error: "Incident not found" });
    return res.json(GetIncidentResponse.parse(rowToAnalysis(row)));
  } catch (error) {
    req.log.error({ error }, "Failed to load incident");
    return res.status(400).json({ error: "Unable to load incident" });
  }
});

router.post("/analyst/messages", async (req, res) => {
  try {
    const { message } = SendAnalystMessageBody.parse(req.body);
    const answer = await answerWithModel(message);
    res.json(SendAnalystMessageResponse.parse(answer));
  } catch (error) {
    req.log.error({ error }, "Failed to answer analyst message");
    res.status(400).json({ error: "Unable to answer analyst message" });
  }
});

router.get("/attacks", (_req, res) => {
  res.json(ListAttacksResponse.parse(attacks.map(({ whatItIs, howItHappens, stages, detection, indicators, impact, mitigation, prevention, ...summary }) => summary)));
});

router.get("/attacks/:slug", (req, res) => {
  const { slug } = GetAttackParams.parse(req.params);
  const attack = attacks.find((item) => item.slug === slug);
  if (!attack) return res.status(404).json({ error: "Attack type not found" });
  return res.json(GetAttackResponse.parse(attack));
});

router.get("/learning/lessons", (_req, res) => {
  res.json(ListLearningLessonsResponse.parse(lessons));
});

router.post("/learning/quiz", async (req, res) => {
  try {
    const { topic } = GenerateLearningQuizBody.parse(req.body);
    const quiz = GenerateLearningQuizResponse.parse({
      topic,
      question: `Which is the safest first step when investigating a possible ${topic.toLowerCase()} incident?`,
      options: ["Preserve evidence and validate scope", "Delete all related logs", "Share credentials to compare access", "Disable every system immediately"],
      answer: "Preserve evidence and validate scope",
      explanation: "Good incident response starts with evidence preservation and scoped validation. Containment should be proportional to the evidence and potential impact.",
    });
    res.json(quiz);
  } catch (error) {
    req.log.error({ error }, "Failed to generate learning quiz");
    res.status(400).json({ error: "Unable to generate quiz" });
  }
});

export default router;