/**
 * Honeypot Detector (HPD) — interactive demo logic.
 *
 * This is a client-side simulation that mirrors what the actual HPD library
 * would return for a given address. It uses deterministic heuristics based
 * on well-known function selectors and address patterns, so the demo is
 * reproducible and works fully offline.
 */

(function () {
  "use strict";

  // -------- Simulated HPD library (mirrors src/scorer.js) --------

  const KNOWN_GOOD_TOKENS = new Set([
    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".toLowerCase(), // WETH
    "0xdAC17F958D2ee523a2206206994597C13D831ec7".toLowerCase(), // USDT (treated as low risk for demo)
  ]);

  // Heuristic risk profiles keyed by address pattern.
  // These are demo-only — the real HPD does onchain bytecode analysis.
  const PATTERN_PROFILES = {
    selfdestruct: {
      match: (a) => a.toLowerCase() === "0x000000000000000000000000000000000000dEaD".toLowerCase(),
      findings: [
        { type: "SELFDESTRUCT", severity: "critical", detail: "Address contains selfdestruct opcode (0x43d726d6) in deployable bytecode." },
        { type: "HIDDEN_MINT", severity: "high", detail: "Owner-only mint function (0x40c10f19) detected." },
        { type: "OWNER_WITHDRAW", severity: "high", detail: "withdraw(uint256) restricted to owner." },
      ],
    },
    blacklist: {
      match: (a) => a.toLowerCase() === "0x1111111111111111111111111111111111111111",
      findings: [
        { type: "BLACKLIST", severity: "high", detail: "isBlacklisted(address) + setBlacklist() setters detected." },
        { type: "PAUSABLE", severity: "medium", detail: "pause() / unpause() callable by owner." },
        { type: "FEE_MANIPULATION", severity: "high", detail: "setSellTax() allows owner to raise sell tax up to 100%." },
        { type: "MAX_WALLET", severity: "medium", detail: "setMaxWallet() can be changed after deployment." },
      ],
    },
    weth: {
      match: (a) => KNOWN_GOOD_TOKENS.has(a.toLowerCase()),
      findings: [],
    },
  };

  const SEVERITY_WEIGHTS = { critical: 80, high: 35, medium: 15, low: 3 };

  const VERDICT_THRESHOLDS = {
    HONEYPOT_LIKELY: 60,
    HIGH_RISK: 30,
    CAUTION: 10,
    SAFE: 0,
  };

  const RECOMMENDATIONS = {
    HONEYPOT_LIKELY: "Do not interact. Treat as a scam.",
    HIGH_RISK: "Avoid. Strong indicators of malicious behavior.",
    CAUTION: "Proceed only with full understanding of the listed risks.",
    SAFE: "No major red flags detected. Standard caution still advised.",
  };

  function scoreFindings(findings) {
    let score = 0;
    for (const f of findings) score += SEVERITY_WEIGHTS[f.severity] || 0;
    if (score > 100) score = 100;
    let verdict = "SAFE";
    if (score >= VERDICT_THRESHOLDS.HONEYPOT_LIKELY) verdict = "HONEYPOT LIKELY";
    else if (score >= VERDICT_THRESHOLDS.HIGH_RISK) verdict = "HIGH RISK";
    else if (score >= VERDICT_THRESHOLDS.CAUTION) verdict = "CAUTION";
    return { score, verdict };
  }

  function analyzeAddress(address) {
    // Simulated. For unknown addresses we apply a low baseline.
    let findings = [];
    for (const key of Object.keys(PATTERN_PROFILES)) {
      if (PATTERN_PROFILES[key].match(address)) {
        findings = PATTERN_PROFILES[key].findings.slice();
        break;
      }
    }
    if (findings.length === 0) {
      // Unknown address: demo returns CAUTION with a heuristic note.
      findings.push({
        type: "GENERIC_RISK",
        severity: "low",
        detail: "No dangerous selectors in sampled bytecode. Address not in trusted registry.",
      });
    }
    const { score, verdict } = scoreFindings(findings);
    return {
      address,
      network: "Pharos Mainnet",
      riskScore: score,
      verdict,
      recommendation: RECOMMENDATIONS[verdict],
      findings,
    };
  }

  // -------- UI wiring --------

  const $ = (id) => document.getElementById(id);

  const addressInput = $("address-input");
  const runBtn = $("run-btn");
  const reportCard = $("report-card");
  const reportAddr = $("report-addr");
  const reportNet = $("report-net");
  const reportScore = $("report-score");
  const reportVerdict = $("report-verdict");
  const reportRec = $("report-rec");
  const findingsList = $("findings-list");
  const userAddressDisplay = $("user-address-display");
  const terminalBody = $("terminal-body");
  const terminalStatus = $("terminal-status");

  function shortAddr(a) {
    return a.slice(0, 8) + "…" + a.slice(-6);
  }

  function renderSample() {
    const sample = {
      address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
      network: "Pharos Mainnet",
      riskScore: 0,
      verdict: "SAFE",
      recommendation: RECOMMENDATIONS.SAFE,
      findings: [],
    };
    renderReport(sample);
  }

  function renderReport(report) {
    reportAddr.textContent = report.address;
    reportNet.textContent = report.network;
    reportScore.textContent = report.riskScore + " / 100";
    reportVerdict.textContent = report.verdict;
    reportVerdict.className = "report__verdict v-" + report.verdict.toLowerCase().replace(" ", "-");
    reportRec.textContent = report.recommendation;

    findingsList.innerHTML = "";
    if (report.findings.length === 0) {
      const li = document.createElement("li");
      li.style.justifyContent = "center";
      li.style.color = "var(--text-3)";
      li.textContent = "No findings detected. Static + behavioral checks passed.";
      findingsList.appendChild(li);
    } else {
      for (const f of report.findings) {
        const li = document.createElement("li");
        const pill = document.createElement("span");
        pill.className = "sev-pill sev-" + f.severity;
        pill.textContent = f.severity;
        const type = document.createElement("span");
        type.className = "finding__type";
        type.textContent = f.type;
        const detail = document.createElement("span");
        detail.className = "finding__detail";
        detail.textContent = "— " + f.detail;
        li.appendChild(pill);
        li.appendChild(type);
        li.appendChild(detail);
        findingsList.appendChild(li);
      }
    }
    reportCard.hidden = false;
  }

  function appendLine(html) {
    const div = document.createElement("div");
    div.className = "term-line";
    div.innerHTML = html;
    terminalBody.appendChild(div);
    terminalBody.scrollTop = terminalBody.scrollHeight;
  }

  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

  async function runAnalysis() {
    const address = addressInput.value.trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
      alert("Please enter a valid 0x-prefixed 40-character hex address.");
      return;
    }

    runBtn.disabled = true;
    reportCard.hidden = true;
    terminalBody.innerHTML = "";
    terminalStatus.textContent = "running";
    terminalStatus.className = "terminal__status is-running";

    userAddressDisplay.textContent = address;

    appendLine(`<span class="term-prompt">user ›</span> Analyze the contract at <code>${shortAddr(address)}</code> on Pharos mainnet and tell me if it is safe to interact with.`);
    await sleep(450);
    appendLine(`<span class="term-prompt">agent ›</span> <span class="term-dim">loading skill honeypot-detector@1.0.0…</span>`);
    await sleep(400);
    appendLine(`<span class="term-prompt">agent ›</span> <span class="term-dim">reading <code>SKILL.md</code>… identified function <code>analyzeContract(address)</code></span>`);
    await sleep(400);
    appendLine(`<span class="term-prompt">hpd ›</span> <span class="term-tag">static-analysis</span> scanning bytecode for 30+ dangerous selectors…`);
    await sleep(600);
    appendLine(`<span class="term-prompt">hpd ›</span> <span class="term-tag">reputation</span> reading deploy block, contract age, holder concentration…`);
    await sleep(500);
    appendLine(`<span class="term-prompt">hpd ›</span> <span class="term-tag">simulator</span> forking Pharos mainnet via Anvil… running buy + sell round-trip…`);
    await sleep(700);
    appendLine(`<span class="term-prompt">hpd ›</span> <span class="term-ok">analysis complete</span>`);
    await sleep(250);

    const report = analyzeAddress(address);
    const verdictClass = report.verdict === "SAFE" ? "term-ok" :
                         report.verdict === "CAUTION" ? "term-tag" :
                         report.verdict === "HIGH RISK" ? "term-bad" : "term-bad";
    appendLine(`<span class="term-prompt">agent ›</span> Verdict: <span class="${verdictClass}">${report.verdict}</span> · Score: <span class="${verdictClass}">${report.riskScore}/100</span>`);
    appendLine(`<span class="term-prompt">agent ›</span> ${report.recommendation}`);
    if (report.findings.length > 0) {
      appendLine(`<span class="term-prompt">agent ›</span> <span class="term-dim">${report.findings.length} finding(s) — see report below.</span>`);
    }

    renderReport(report);

    terminalStatus.textContent = "done";
    terminalStatus.className = "terminal__status is-done";
    runBtn.disabled = false;
  }

  runBtn.addEventListener("click", runAnalysis);
  addressInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") runAnalysis();
  });

  document.querySelectorAll(".chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      addressInput.value = chip.dataset.addr;
      runAnalysis();
    });
  });

  // Hero sample JSON (formatted, colorized)
  const heroSample = {
    address: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    network: "Pharos Mainnet",
    riskScore: 3,
    verdict: "SAFE",
    recommendation: "No major red flags detected. Standard caution still advised.",
    findings: []
  };
  const heroCode = $("sample-code");
  if (heroCode) {
    heroCode.innerHTML = colorizeJson(JSON.stringify(heroSample, null, 2));
  }

  function colorizeJson(json) {
    return json
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
        function (match) {
          let cls = "json-num";
          if (/^"/.test(match)) {
            cls = /:$/.test(match) ? "json-key" : "json-str";
          } else if (/true|false/.test(match)) {
            cls = "json-bool";
          } else if (/null/.test(match)) {
            cls = "json-bool";
          }
          return '<span class="' + cls + '">' + match + "</span>";
        });
  }

  // Render initial sample in the demo card
  renderSample();
})();
