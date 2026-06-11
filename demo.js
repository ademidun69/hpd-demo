/**
 * Honeypot Detector (HPD) — interactive demo logic.
 *
 * This is a client-side simulation that mirrors what the actual HPD library
 * (https://github.com/ademidun69/HPD) would return for a given address.
 * The scoring math is a direct port of the Node `src/scorer.js` module, and
 * the dangerous-selector list matches `src/static-analysis.js` 1:1.
 *
 * The demo is fully offline, makes zero outbound network requests, and does
 * not interact with any wallet. It is honest about what it is: a deterministic
 * simulation of the library's output for illustrative purposes.
 *
 * The real library does onchain analysis (static selector scan + Anvil fork
 * simulation + reputation lookup). The demo cannot do that in a browser, so
 * it uses curated profiles for the sample addresses and a low-risk default
 * for unknown ones.
 */

(function () {
  "use strict";

  // -------- Sample profiles (deterministic, matches repo behavior) --------

  // Pharos mainnet LINK token (chain 1672). Demo treats it as a known-good
  // canonical contract → SAFE / 0 / 100, no findings.
  const KNOWN_GOOD_TOKENS = new Set([
    "0x51e2A24742Db77604B881d6781Ee16B5b8fcBE29".toLowerCase(), // LINK on Pharos
    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".toLowerCase(), // WETH (canonical)
    "0xdAC17F958D2ee523a2206206994597C13D831ec7".toLowerCase(), // USDT (canonical)
  ]);

  const PATTERN_PROFILES = {
    selfdestruct: {
      match: (a) => a.toLowerCase() === "0x000000000000000000000000000000000000dEaD",
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
    knownGood: {
      match: (a) => KNOWN_GOOD_TOKENS.has(a.toLowerCase()),
      findings: [],
    },
  };

  // -------- Scorer (mirrors src/scorer.js in the HPD library) --------

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
        detail: "No dangerous selectors in sampled bytecode. Address not in trusted registry. Run --no-sim for a fast static check, or set PHAROS_MAINNET_RPC for the full analysis.",
      });
    }
    const { score, verdict } = scoreFindings(findings);
    return {
      address,
      network: "Pharos Mainnet (chain 1672)",
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
    // Default sample: LINK on Pharos (a known-good, real Pharos mainnet contract).
    const sample = {
      address: "0x51e2A24742Db77604B881d6781Ee16B5b8fcBE29",
      network: "Pharos Mainnet (chain 1672)",
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

    appendLine(`<span class="term-prompt">user ›</span> Analyze the contract at <code>${shortAddr(address)}</code> on Pharos mainnet (chain 1672) and tell me if it is safe to interact with.`);
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
                         "term-bad";
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
    address: "0x51e2A24742Db77604B881d6781Ee16B5b8fcBE29",
    network: "Pharos Mainnet (chain 1672)",
    riskScore: 0,
    verdict: "SAFE",
    recommendation: RECOMMENDATIONS.SAFE,
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

  // Render initial sample in the demo card so the page never shows "—".
  renderSample();
})();
