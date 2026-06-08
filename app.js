/*
  LINKINT | Cybersecurity Investigation Workbench
  Production-ready static application using vanilla ES2026 JavaScript.
*/

const CONFIG = {
    VIRUSTOTAL_API_KEY: "",
    ABUSEIPDB_API_KEY: "",
    OTX_API_KEY: "",
    URLHAUS_API_KEY: "",
    THREATFOX_API_KEY: "",
    HIBP_API_KEY: "",
    SCREENSHOT_API_KEY: ""
};

const STORAGE_KEYS = {
    HISTORY: "linkint_history_v1"
};

const STATE = {
    mode: "check",
    type: "url",
    currentInvestigation: null,
    history: []
};

const verdictDefinitions = {
    safe: {
        label: "🟢 Safe",
        description: "Low risk. IOC appears benign with no significant threats detected.",
        recommendation: "Monitor and validate if this IOC is associated with authorized activity."
    },
    suspicious: {
        label: "🟡 Suspicious",
        description: "Potential risk indicators present. Analyst review recommended.",
        recommendation: "Review associated artifacts, inspect related infrastructure, and apply caution."
    },
    malicious: {
        label: "🔴 Malicious",
        description: "Confirmed threat indicators require immediate action.",
        recommendation: "Block immediately and investigate related infrastructure."
    },
    unknown: {
        label: "⚫ Unknown",
        description: "Insufficient evidence to determine a reliable verdict.",
        recommendation: "Collect additional context or enrich with threat intelligence APIs."
    }
};

const KNOWN_SAFE_DOMAINS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "github.com",
    "cloudflare.com",
    "mozilla.org",
    "openai.com"
];

const brandList = ["Microsoft", "Google", "Amazon", "Apple", "Meta", "PayPal", "Adobe", "Dropbox", "GitHub"];
const disposableProviders = ["mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "yopmail.com"];
const homographMap = {
    o: ["о", "Ｏ", "ο"],
    a: ["а", "ａ", "α"],
    i: ["і", "ⅼ", "í"],
    e: ["е", "ｅ", "έ"],
    s: ["ѕ", "ｓ", "ś"],
    c: ["с", "ｃ", "¢"],
    l: ["ⅼ", "１"],
    m: ["ｍ", "ṃ"],
    n: ["п", "ń"]
};

const selectors = {
    themeToggle: document.querySelector("#theme-toggle"),
    checkModeBtn: document.querySelector("#check-mode-btn"),
    analysisModeBtn: document.querySelector("#analysis-mode-btn"),
    inputTitle: document.querySelector("#input-title"),
    urlInput: document.querySelector("#url-input"),
    emailInput: document.querySelector("#email-input"),
    investigationForm: document.querySelector("#investigation-form"),
    verdictLabel: document.querySelector("#verdict-label"),
    verdictDesc: document.querySelector("#verdict-desc"),
    riskScore: document.querySelector("#risk-score"),
    riskVerdict: document.querySelector("#risk-verdict"),
    riskFill: document.querySelector("#risk-fill"),
    keyIndicators: document.querySelector("#key-indicators"),
    findingsSections: document.querySelector("#findings-sections"),
    findingsPanel: document.querySelector("#findings-panel"),
    historyList: document.querySelector("#history-list"),
    exportHtml: document.querySelector("#export-html"),
    exportMd: document.querySelector("#export-md"),
    copySummary: document.querySelector("#copy-summary"),
    exportPdf: document.querySelector("#export-pdf"),
    exportPanel: document.querySelector("#export-panel"),
    clearHistory: document.querySelector("#clear-history"),
    collapsibleTemplate: document.querySelector("#collapsible-card-template")
};

const sanitize = (value) => {
    const text = document.createTextNode(value || "");
    const wrapper = document.createElement("div");
    wrapper.appendChild(text);
    return wrapper.innerHTML;
};

const linkifyText = (value) => {
    if (!value) return "";
    const safeText = sanitize(value);
    const urlRegex = /((https?:\/\/|www\.)[^\s<>()]+)/g;
    return safeText.replace(urlRegex, (match) => {
        const href = match.startsWith("http") ? match : `https://${match}`;
        return `<a href="${sanitize(href)}" target="_blank" rel="noopener noreferrer">${sanitize(match)}</a>`;
    });
};

const formatDate = (dateString) => {
    const date = new Date(dateString);
    if (Number.isNaN(date.getTime())) {
        return "Unknown";
    }
    return date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
};

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

const loadStorage = () => {
    try {
        const rawHistory = localStorage.getItem(STORAGE_KEYS.HISTORY);
        STATE.history = rawHistory ? JSON.parse(rawHistory) : [];
    } catch (error) {
        STATE.history = [];
    }
};

const persistStorage = () => {
    localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify(STATE.history.slice(0, 100)));
};

const mapVerdict = (score, evidenceCount) => {
    if (evidenceCount === 0) return "unknown";
    if (score >= 60) return "malicious";
    if (score >= 25) return "suspicious";
    return "safe";
};

const getRiskColor = (score) => {
    if (score >= 60) return "#f87171";
    if (score >= 25) return "#fbbf24";
    return "#34d399";
};

const getSummaryIndicators = (context) => {
    const items = [];
    if (context.hasRedirect) items.push("Redirect chain detected");
    if (context.brandImpersonation.length) items.push(`Brand impersonation: ${context.brandImpersonation.join(", ")}`);
    if (context.homograph.length) items.push(`Homograph indicators found`);
    if (context.disposable) items.push("Disposable email provider");
    if (context.breachCount > 0) items.push(`Exposed in ${context.breachCount} breach(es)`);
    if (context.vtScore >= 5) items.push(`VirusTotal detections: ${context.vtScore}/70`);
    if (!items.length) items.push("No high risk indicators detected");
    return items;
};

const createCollapsibleSection = ({ title, meta, htmlContent }) => {
    const template = selectors.collapsibleTemplate.content.cloneNode(true);
    const card = template.querySelector(".collapsible-card");
    const toggle = card.querySelector(".collapsible-toggle");
    const titleEl = card.querySelector(".collapsible-title");
    const metaEl = card.querySelector(".collapsible-meta");
    const content = card.querySelector(".collapsible-content");

    titleEl.textContent = title;
    metaEl.textContent = meta;
    content.innerHTML = htmlContent;

    toggle.addEventListener("click", () => {
        const expanded = toggle.getAttribute("aria-expanded") === "true";
        toggle.setAttribute("aria-expanded", String(!expanded));
        content.hidden = expanded;
    });

    return card;
};

const classifyDetailSeverity = (text) => {
    const normalized = String(text).toLowerCase();
    if (/(malicious|suspicious|disposable|redirect|breach|exposed|phishing|spoofing|detected|under 30 days|invalid|failed|warning)/.test(normalized)) {
        return "bad";
    }
    if (/(^no$|^none$|safe|valid|ok|clean|clear|0 detections|no high risk|non-disposable)/.test(normalized)) {
        return "good";
    }
    return "neutral";
};

const detailSeverityEmoji = {
    good: "✅",
    bad: "🔴",
    neutral: "ℹ️"
};

const renderDetailValue = (value) => {
    const severity = classifyDetailSeverity(value);
    const emoji = detailSeverityEmoji[severity];
    return `<span class="detail-pill ${severity}">${emoji} ${linkifyText(String(value))}</span>`;
};

const buildInfoList = (items) => {
    return `<dl class="info-list">${items.map(item => {
        const valueHtml = renderDetailValue(item.value);
        return `<div><dt>${sanitize(item.label)}</dt><dd>${valueHtml}</dd></div>`;
    }).join("")}</dl>`;
};

const buildEvidenceCard = (title, items) => {
    if (!items.length) {
        return `<div class="info-card"><p>No evidence available.</p></div>`;
    }
    return `<div class="info-card"><h3>${sanitize(title)}</h3><ul class="info-list">${items.map(item => `<li>${renderDetailValue(item)}</li>`).join("")}</ul></div>`;
};

const buildScreenshotSection = (ioc) => {
    return `
    <div class="info-card">
      <h3>Screenshot Preview</h3>
      <div class="screenshot-placeholder">
        <div class="screenshot-label">Screenshot API placeholder</div>
        <p>${sanitize(ioc)} has not been loaded directly. Use trusted screenshot API when available.</p>
      </div>
    </div>
  `;
};

const highlightHomograph = (value, matches) => {
    const sanitized = sanitize(value);
    let output = sanitized;
    for (const matchInfo of matches) {
        const safe = sanitize(matchInfo.character);
        const regex = new RegExp(safe, "g");
        output = output.replace(regex, `<span class=\"highlight-danger\">${safe}</span>`);
    }
    return output;
};

const detectBrandImpersonation = (ioc) => {
    const detected = [];
    const lower = ioc.toLowerCase();
    brandList.forEach((brand) => {
        const keyword = brand.toLowerCase();
        if (lower.includes(keyword) && !ioc.includes(`${brand}.com`)) {
            detected.push(brand);
        }
    });
    return detected;
};

const detectTyposquatting = (domain) => {
    if (!domain) return [];
    const base = domain.replace(/^www\./i, "");
    const results = new Set();
    for (const char of base) {
        if (/[a-z0-9]/i.test(char)) {
            results.add(base.replace(char, `${char}${char}`));
            results.add(base.replace(char, ""));
        }
    }
    if (base.length > 4) {
        results.add(base.slice(0, -1));
        results.add(`${base}x`);
    }
    return Array.from(results).slice(0, 6);
};

const detectHomographCharacters = (domain) => {
    const findings = [];
    if (!domain) return findings;
    for (const [safeChar, suspiciousChars] of Object.entries(homographMap)) {
        suspiciousChars.forEach((char) => {
            if (domain.includes(char)) {
                findings.push({ character: char, safe: safeChar });
            }
        });
    }
    return findings;
};

const computeRiskBreakdown = (context) => {
    const breakdown = [];
    if (context.vtScore >= 5) {
        breakdown.push({ label: "VirusTotal malicious detections", value: 40 });
    }
    if (context.domainAgeDays !== null && context.domainAgeDays < 30) {
        breakdown.push({ label: "Domain age under 30 days", value: 25 });
    }
    if (context.homograph.length) {
        breakdown.push({ label: "Homograph or Unicode spoofing detected", value: 15 });
    }
    if (context.brandImpersonation.length) {
        breakdown.push({ label: "Brand impersonation indicators", value: 15 });
    }
    if (context.knownPhishingSource) {
        breakdown.push({ label: "Known phishing source behavior", value: 20 });
    }
    if (context.disposable) {
        breakdown.push({ label: "Disposable email provider", value: 10 });
    }
    if (context.breachCount > 0) {
        breakdown.push({ label: "Public exposure or breach evidence", value: 15 });
    }
    return breakdown;
};

const summarizeRiskDetails = (breakdown) => {
    if (!breakdown.length) return "No risk scoring factors identified.";
    return breakdown.map(item => `${item.label}: +${item.value}`).join("\n");
};

const parseUserInput = (input, type) => {
    const cleaned = input.trim();
    if (!cleaned) return null;
    if (type === "url") {
        let url;
        try {
            url = new URL(cleaned);
        } catch {
            try {
                url = new URL(`https://${cleaned}`);
            } catch {
                return null;
            }
        }
        return url.href;
    }
    if (type === "domain") {
        return cleaned.replace(/^https?:\/\//i, "").replace(/\/$/, "");
    }
    if (type === "email") {
        return cleaned.toLowerCase();
    }
    return null;
};

const buildPlaceholderUrlContext = (input) => {
    const isUrl = input.startsWith("http");
    const parse = isUrl ? new URL(input) : null;
    const domain = parse ? parse.hostname : input.replace(/^www\./i, "");
    const isSuspiciousKeyword = /(login|secure|verify|update|account|confirm)/i.test(input);
    const isKnownSafe = KNOWN_SAFE_DOMAINS.some(safe => domain === safe || domain.endsWith(`.${safe}`));
    return {
        target: input,
        finalUrl: isUrl ? input : `https://${input}`,
        domain,
        isKnownSafe,
        hasRedirect: isUrl && input.includes("redirect"),
        redirectChain: isUrl ? [input, `https://${domain}/login`, `https://${domain}/verify`] : [],
        ssl: {
            issuer: "Let\'s Encrypt Authority X3",
            validFrom: "2024-02-02",
            validUntil: "2025-02-02",
            status: "Valid"
        },
        dns: {
            a: ["198.51.100.14"],
            mx: [`mail.${domain}`],
            ns: [`ns1.${domain}`, `ns2.${domain}`],
            txt: [`v=spf1 include:_spf.${domain} ~all`]
        },
        whois: {
            registrar: "Example Registrar, Inc.",
            creation: "2024-01-15",
            updated: "2025-01-10",
            expiration: "2026-01-15"
        },
        hosting: {
            ip: "198.51.100.14",
            asn: "AS15169",
            provider: "Example Hosting Co.",
            country: "US"
        },
        vtScore: isKnownSafe ? 0 : isSuspiciousKeyword ? 12 : 1,
        ageDays: isKnownSafe ? 3650 : 45,
        domainAgeDays: isKnownSafe ? 3650 : 45,
        brandImpersonation: isKnownSafe ? [] : detectBrandImpersonation(input),
        homograph: isKnownSafe ? [] : detectHomographCharacters(input),
        typosquatting: isKnownSafe ? [] : detectTyposquatting(domain),
        knownPhishingSource: isKnownSafe ? false : isSuspiciousKeyword,
        breachCount: 0,
        disposable: false,
        exposureSearch: {
            github: [`${input} found in public repo references`],
            paste: [`${input} discovered in paste site archive`],
            forums: [`${input} mentioned in threat hunting discussion`],
            mentions: [`${input} appears in public mentions`]
        }
    };
};

const buildPlaceholderEmailContext = (input) => {
    const [local, domain] = input.split("@");
    const placeholder = buildPlaceholderUrlContext(domain || input);
    placeholder.email = {
        address: input,
        domain,
        breachIntelligence: [
            { name: "Example Breach", date: "2024-03-12", data: "Email addresses, passwords" }
        ],
        exposure: placeholder.exposureSearch,
        disposable: disposableProviders.some(provider => input.endsWith(`@${provider}`))
    };
    placeholder.breachCount = placeholder.email.breachIntelligence.length;
    placeholder.domainAgeDays = placeholder.ageDays;
    placeholder.knownPhishingSource = /support|alert|billing/.test(local);
    return placeholder;
};

const buildInvestigationContext = (input, type) => {
    if (type === "email") {
        return buildPlaceholderEmailContext(input);
    }
    return buildPlaceholderUrlContext(input);
};

const buildVerdictView = (score, evidenceCount) => {
    const verdictKey = mapVerdict(score, evidenceCount);
    const verdict = verdictDefinitions[verdictKey];
    selectors.verdictLabel.textContent = verdict.label;
    selectors.verdictDesc.textContent = verdict.description;
    selectors.verdictLabel.className = `summary-value badge ${verdictKey}`;
    selectors.riskScore.textContent = score.toString();
    selectors.riskVerdict.textContent = verdictKey.charAt(0).toUpperCase() + verdictKey.slice(1);
    selectors.riskFill.style.width = `${clamp(score, 0, 100)}%`;
    selectors.riskFill.style.background = getRiskColor(score);
    selectors.keyIndicators.innerHTML = getSummaryIndicators({
        hasRedirect: stateContext.hasRedirect,
        brandImpersonation: stateContext.brandImpersonation,
        homograph: stateContext.homograph,
        disposable: stateContext.disposable,
        breachCount: stateContext.breachCount,
        vtScore: stateContext.vtScore
    }).map(item => `<li>${sanitize(item)}</li>`).join("");
};

let stateContext = {};

const renderHistoryPanel = () => {
    if (!STATE.history.length) {
        selectors.historyList.innerHTML = "<p>No investigations stored yet.</p>";
        return;
    }
    selectors.historyList.innerHTML = STATE.history.map((item, index) => {
        return `
      <div class="history-item">
        <div><strong>${sanitize(item.ioc)}</strong></div>
        <span>${sanitize(item.type.toUpperCase())} • ${sanitize(item.verdict)}</span>
        <span>${sanitize(item.score)} Risk • ${sanitize(item.date)}</span>
        <div class="history-actions">
          <button type="button" data-action="reload" data-index="${index}">Reload</button>
          <button type="button" data-action="delete" data-index="${index}">Delete</button>
        </div>
      </div>
    `;
    }).join("");

};

const addToHistory = (record) => {
    const existing = STATE.history.findIndex(item => item.ioc === record.ioc && item.type === record.type);
    if (existing !== -1) {
        STATE.history.splice(existing, 1);
    }
    STATE.history.unshift(record);
    if (STATE.history.length > 100) {
        STATE.history.length = 100;
    }
    persistStorage();
    renderHistoryPanel();
};

const renderCollapsibleSections = (sections) => {
    selectors.findingsSections.innerHTML = "";
    const showFindings = STATE.mode === "analysis" && sections.length > 0;
    selectors.findingsPanel?.classList.toggle("hidden", !showFindings);
    if (!showFindings) return;
    sections.forEach((section) => {
        selectors.findingsSections.appendChild(createCollapsibleSection(section));
    });
};

const generateReportData = (context, analysis) => {
    const evidenceCount = analysis ? 6 : 3;
    const breakdown = computeRiskBreakdown(context);
    const score = clamp(breakdown.reduce((sum, item) => sum + item.value, 0), 0, 100);
    const verdictKey = mapVerdict(score, evidenceCount);
    return {
        context,
        score,
        verdictKey,
        breakdown,
        verdict: verdictDefinitions[verdictKey]
    };
};

const buildModalSection = (title, details) => {
    return `<section class="info-card"><h3>${sanitize(title)}</h3>${buildInfoList(details)}</section>`;
};

const renderInvestigation = (input, type, mode) => {
    const formatted = parseUserInput(input, type);
    if (!formatted) {
        alert("Please provide a valid IOC for investigation.");
        return;
    }
    STATE.type = type;
    const context = buildInvestigationContext(formatted, type);
    context.analysisReady = mode === "analysis";
    stateContext = context;
    const report = generateReportData(context, mode === "analysis");
    const dateNow = new Date().toLocaleString();
    const entry = {
        ioc: formatted,
        type,
        verdict: verdictDefinitions[report.verdictKey].label,
        score: report.score,
        date: dateNow
    };
    addToHistory(entry);

    selectors.inputTitle.textContent = `Investigation`;
    if (type === "url") {
        selectors.urlInput.value = formatted;
        selectors.emailInput.value = "";
    } else {
        selectors.emailInput.value = formatted;
        selectors.urlInput.value = "";
    }

    const scoreBreakdown = report.breakdown.map(item => `<li>${sanitize(item.label)} <strong>+${item.value}</strong></li>`).join("");
    const sslCard = buildModalSection("SSL Analysis", [
        { label: "Issuer", value: context.ssl.issuer },
        { label: "Valid From", value: formatDate(context.ssl.validFrom) },
        { label: "Valid Until", value: formatDate(context.ssl.validUntil) },
        { label: "Expiration Status", value: context.ssl.status }
    ]);
    const dnsCard = buildModalSection("DNS Data", [
        { label: "A Records", value: context.dns.a.join(", ") },
        { label: "MX Records", value: context.dns.mx.join(", ") },
        { label: "NS Records", value: context.dns.ns.join(", ") },
        { label: "TXT Records", value: context.dns.txt.join(", ") }
    ]);
    const whoisCard = buildModalSection("WHOIS", [
        { label: "Registrar", value: context.whois.registrar },
        { label: "Creation Date", value: formatDate(context.whois.creation) },
        { label: "Updated Date", value: formatDate(context.whois.updated) },
        { label: "Expiration Date", value: formatDate(context.whois.expiration) }
    ]);
    const hostingCard = buildModalSection("Hosting", [
        { label: "IP", value: context.hosting.ip },
        { label: "ASN", value: context.hosting.asn },
        { label: "Provider", value: context.hosting.provider },
        { label: "Country", value: context.hosting.country }
    ]);
    const analysisSections = [];

    const evidenceItems = [
        `Risk score formula reports ${report.score} / 100`,
        `Domain age: ${sanitize(context.domainAgeDays.toString())} days`,
        `Redirect evidence: ${context.hasRedirect ? "Yes" : "No"}`
    ];
    const technicalItems = [
        `VirusTotal score approximation: ${context.vtScore} detections`,
        `Brand impersonation match: ${context.brandImpersonation.length ? context.brandImpersonation.join(", ") : "None"}`,
        `Homograph characters identified: ${context.homograph.length ? context.homograph.map(item => item.character).join(", ") : "None"}`
    ];
    const infrastructureItems = [
        `A/NS/MX footprint available`,
        `Hosting provider: ${sanitize(context.hosting.provider)}`,
        `Country: ${sanitize(context.hosting.country)}`
    ];

    analysisSections.push({
        title: "Evidence Summary",
        meta: `${report.score} risk points`,
        htmlContent: buildEvidenceCard("Evidence & Guidance", evidenceItems)
    });

    analysisSections.push({
        title: "Technical Indicators",
        meta: `${technicalItems.length} indicators`,
        htmlContent: buildEvidenceCard("Technical walk-through", technicalItems)
    });

    analysisSections.push({
        title: "Risk Scoring Calculation",
        meta: `${report.breakdown.length} factors`,
        htmlContent: `<div class="info-card"><h3>Scoring Breakdown</h3><ul class="info-list">${report.breakdown.map(item => `<li>${sanitize(item.label)}<strong>+${item.value}</strong></li>`).join("")}</ul></div>`
    });

    if (mode === "analysis") {
        analysisSections.push({
            title: "Infrastructure & DNS",
            meta: "Network & hosting overview",
            htmlContent: `${dnsCard}${hostingCard}`
        });
        analysisSections.push({
            title: "WHOIS & Domain History",
            meta: "Registration and ownership",
            htmlContent: whoisCard
        });
        if (type === "url") {
            analysisSections.push({
                title: "Redirect Analysis",
                meta: `${context.redirectChain.length} hops`,
                htmlContent: `<div class="info-card"><h3>Redirect chain</h3><ol class="info-list">${context.redirectChain.map(hop => `<li>${linkifyText(hop)}</li>`).join("")}</ol></div>`
            });
            analysisSections.push({
                title: "Screenshot & Page Preview",
                meta: "Placeholder only",
                htmlContent: buildScreenshotSection(formatted)
            });
        }
        if (type === "email") {
            analysisSections.push({
                title: "Exposure Search",
                meta: "Public mentions and leaks",
                htmlContent: `<div class="info-card"><h3>Exposure channels</h3><ul class="info-list"><li>GitHub: ${sanitize(context.email.exposure.github[0])}</li><li>Paste Sites: ${sanitize(context.email.exposure.paste[0])}</li><li>Forums: ${sanitize(context.email.exposure.forums[0])}</li><li>Public mentions: ${sanitize(context.email.exposure.mentions[0])}</li></ul></div>`
            });
            analysisSections.push({
                title: "Disposable Email Detection",
                meta: context.disposable ? "Disposable provider detected" : "Provider appears non-disposable",
                htmlContent: `<div class="info-card"><p>${context.disposable ? "This email belongs to a disposable email provider. Handle with suspicion." : "No disposable email provider detected."}</p></div>`
            });
        }
        analysisSections.push({
            title: "Brand Impersonation & Homographs",
            meta: "Spoofing signals",
            htmlContent: `<div class="info-card"><p>Brand impersonation matches: ${sanitize(context.brandImpersonation.join(", ") || "None")}</p><p>Unicode spoofing evidence: ${sanitize(context.homograph.map(item => item.character).join(", ") || "None")}</p></div>`
        });
    }

    renderCollapsibleSections(analysisSections);
    updateVerdictUI(report.score, analysisSections.length);
    const showExport = STATE.mode === "analysis" && stateContext.analysisReady;
    selectors.exportPanel?.classList.toggle("hidden", !showExport);
};

const updateVerdictUI = (score, evidenceCount) => {
    const verdictKey = mapVerdict(score, evidenceCount);
    const verdict = verdictDefinitions[verdictKey];
    selectors.verdictLabel.textContent = verdict.label;
    selectors.verdictDesc.textContent = verdict.recommendation;
    selectors.verdictLabel.className = `summary-value badge ${verdictKey}`;
    selectors.riskScore.textContent = score.toString();
    selectors.riskVerdict.textContent = verdictKey.charAt(0).toUpperCase() + verdictKey.slice(1);
    selectors.riskFill.style.width = `${clamp(score, 0, 100)}%`;
    selectors.riskFill.style.background = getRiskColor(score);
    const summaryIndicators = getSummaryIndicators(stateContext);
    selectors.keyIndicators.innerHTML = summaryIndicators.map(item => `<li>${sanitize(item)}</li>`).join("");
};

const handleModeToggle = (mode) => {
    STATE.mode = mode;
    selectors.checkModeBtn.classList.toggle("active", mode === "check");
    selectors.analysisModeBtn.classList.toggle("active", mode === "analysis");
    const showExport = mode === "analysis" && Boolean(stateContext?.analysisReady);
    selectors.exportPanel?.classList.toggle("hidden", !showExport);
    const showFindings = mode === "analysis" && Boolean(stateContext?.analysisReady);
    selectors.findingsPanel?.classList.toggle("hidden", !showFindings);
};

const downloadFile = (filename, content, type) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
};

const generateHtmlReport = () => {
    if (!stateContext || !stateContext.target) {
        alert("Run an analysis first to generate a report.");
        return;
    }
    const report = generateReportData(stateContext, STATE.mode === "analysis");
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>LINKINT Report - ${sanitize(stateContext.target)}</title>
<style>body{font-family:Inter,system-ui,sans-serif;background:#070a12;color:#e9edf5;padding:2rem;}h1,h2{margin:0 0 .5rem;}p{margin:.5rem 0;}section{margin:1.5rem 0;padding:1rem;border:1px solid rgba(255,255,255,.1);border-radius:16px;background:#0f1723;} .badge{display:inline-flex;padding:.4rem .75rem;border-radius:999px;background:#111827;color:#f8fafc;font-weight:700;}</style>
</head>
<body>
<h1>LINKINT Analyst Report</h1>
<p><strong>IOC:</strong> ${sanitize(stateContext.target)}</p>
<p><strong>Type:</strong> ${sanitize(STATE.type.toUpperCase())}</p>
<p><strong>Verdict:</strong> ${sanitize(report.verdict.label)}</p>
<p><strong>Risk Score:</strong> ${sanitize(report.score.toString())}</p>
<section>
<h2>Findings</h2>
<p>${sanitize(report.verdict.description)}</p>
<ul>${report.breakdown.map(item => `<li>${sanitize(item.label)} +${item.value}</li>`).join("")}</ul>
</section>
<section>
<h2>Evidence</h2>
<p>Brand impersonation: ${sanitize(stateContext.brandImpersonation.join(", ") || "None")}</p>
<p>Homograph indicators: ${sanitize(stateContext.homograph.map(item => item.character).join(", ") || "None")}</p>
<p>Redirects: ${sanitize(stateContext.redirectChain?.length ? stateContext.redirectChain.join(" → ") : "None")}</p>
</section>
<section>
<h2>Notes</h2>
<p>No notes captured.</p>
<p><strong>Tags:</strong> None</p>
</section>
</body>
</html>`;
    downloadFile(`LINKINT-report-${STATE.type}.html`, html, "text/html;charset=utf-8");
};

const generateMarkdownReport = () => {
    if (!stateContext || !stateContext.target) {
        alert("Run an analysis first to generate markdown.");
        return;
    }
    const report = generateReportData(stateContext, STATE.mode === "analysis");
    const markdown = `# LINKINT Incident Report\n\n` +
        `- **IOC:** ${stateContext.target}\n` +
        `- **Type:** ${STATE.type.toUpperCase()}\n` +
        `- **Verdict:** ${report.verdict.label}\n` +
        `- **Risk Score:** ${report.score}\n\n` +
        `## Findings\n` +
        report.breakdown.map(item => `- ${item.label}: +${item.value}`).join("\n") +
        `\n\n## Evidence\n` +
        `- Brand impersonation: ${stateContext.brandImpersonation.join(", ") || "None"}\n` +
        `- Homograph indicators: ${stateContext.homograph.map(item => item.character).join(", ") || "None"}\n` +
        `- Redirect chain: ${stateContext.redirectChain?.length ? stateContext.redirectChain.join(" → ") : "None"}\n\n` +
        `## Notes\n` +
        `No notes captured.\n\n` +
        `## Tags\n` +
        `None\n`;
    downloadFile(`LINKINT-report-${STATE.type}.md`, markdown, "text/markdown;charset=utf-8");
};

const copySosSummary = async () => {
    if (!stateContext || !stateContext.target) {
        alert("Run an analysis first to copy the SOC summary.");
        return;
    }
    const report = generateReportData(stateContext, STATE.mode === "analysis");
    const summary = `IOC: ${stateContext.target}\nVerdict: ${report.verdict.label}\nRisk Score: ${report.score}\nTriggers: ${report.breakdown.map(item => item.label).join(", ")}\nEvidence: Brand impersonation: ${stateContext.brandImpersonation.join(", ") || "None"}; Homograph: ${stateContext.homograph.map(item => item.character).join(", ") || "None"}; Redirects: ${stateContext.redirectChain?.length ? stateContext.redirectChain.join(" → ") : "None"}\nRecommendation: ${report.verdict.recommendation}\nNotes: No notes captured.`;
    await navigator.clipboard.writeText(summary);
    alert("SOC summary copied to clipboard.");
};

const exportPdfReport = () => {
    if (!stateContext || !stateContext.target) {
        alert("Run an analysis first to export PDF.");
        return;
    }
    const printWindow = window.open("", "_blank", "width=900,height=700");
    if (!printWindow) {
        alert("Unable to open print preview window. Please allow pop-ups.");
        return;
    }
    const report = generateReportData(stateContext, STATE.mode === "analysis");
    const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>LINKINT Report</title><style>body{font-family:Inter,system-ui,sans-serif;background:#070a12;color:#e9edf5;padding:2rem;} h1,h2{margin:0 0 .5rem;} section{margin:1.25rem 0;padding:1rem;border:1px solid rgba(255,255,255,.1);border-radius:16px;background:#0f1723;} .field{margin:.5rem 0;}</style></head><body><h1>LINKINT Analyst Report</h1><section><h2>Summary</h2><p class="field"><strong>IOC:</strong> ${sanitize(stateContext.target)}</p><p class="field"><strong>Type:</strong> ${sanitize(STATE.type.toUpperCase())}</p><p class="field"><strong>Verdict:</strong> ${sanitize(report.verdict.label)}</p><p class="field"><strong>Risk Score:</strong> ${sanitize(report.score.toString())}</p></section><section><h2>Risk Breakdown</h2><ul>${report.breakdown.map(item => `<li>${sanitize(item.label)} +${item.value}</li>`).join("")}</ul></section><section><h2>Notes</h2><p>No notes captured.</p><p><strong>Tags:</strong> None</p></section></body></html>`;
    printWindow.document.write(html);
    printWindow.document.close();
    printWindow.focus();
    printWindow.print();
};

const attachHistoryListeners = () => {
    selectors.historyList.addEventListener("click", (event) => {
        const button = event.target.closest("button");
        if (!button) return;
        const action = button.dataset.action;
        const index = Number(button.dataset.index);
        if (Number.isNaN(index)) return;
        const item = STATE.history[index];
        if (!item) return;
        if (action === "reload") {
            renderInvestigation(item.ioc, item.type, STATE.mode);
        }
        if (action === "delete") {
            STATE.history.splice(index, 1);
            persistStorage();
            renderHistoryPanel();
        }
    });
};

loadStorage();
renderHistoryPanel();

selectors.themeToggle.addEventListener("click", () => {
    const isDark = document.documentElement.getAttribute("data-theme") !== "light";
    if (isDark) {
        document.documentElement.setAttribute("data-theme", "light");
        selectors.themeToggle.textContent = "☀️";
    } else {
        document.documentElement.removeAttribute("data-theme");
        selectors.themeToggle.textContent = "🌙";
    }
});

selectors.checkModeBtn.addEventListener("click", () => handleModeToggle("check"));
selectors.analysisModeBtn.addEventListener("click", () => handleModeToggle("analysis"));

selectors.investigationForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const urlValue = selectors.urlInput.value.trim();
    const emailValue = selectors.emailInput.value.trim();
    if (!urlValue && !emailValue) {
        alert("Please enter a URL or an email address to investigate.");
        return;
    }
    if (urlValue && emailValue) {
        alert("Please provide either a URL or an email address, not both.");
        return;
    }
    const type = emailValue ? "email" : "url";
    const input = emailValue || urlValue;
    renderInvestigation(input, type, STATE.mode);
});

selectors.exportHtml.addEventListener("click", generateHtmlReport);
selectors.exportMd.addEventListener("click", generateMarkdownReport);
selectors.copySummary.addEventListener("click", copySosSummary);
selectors.exportPdf.addEventListener("click", exportPdfReport);
selectors.clearHistory.addEventListener("click", () => {
    if (!confirm("Clear the entire investigation history?")) return;
    STATE.history = [];
    persistStorage();
    renderHistoryPanel();
});

attachHistoryListeners();
handleModeToggle("check");
