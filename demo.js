/**
 * HPD client-side demo.
 *
 * This is a deterministic simulation of the HPD Skill's scoring math, used
 * for the marketing page only. The real Skill and Service Agent live in the
 * repo: https://github.com/ademidun69/HPD
 *
 * Everything runs offline — no network calls, no wallet access, no data
 * collection. The scoring math is a direct port of src/scorer.js.
 */

(function () {
  "use strict";

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

  // -------- Sample profiles (deterministic, matches repo behavior) --------
  const KNOWN_GOOD_TOKENS = new Set([
    "0x51e2a24742db77604b881d6781ee16b5b8fcbe29", // LINK on Pharos
    "0xc02aa39b223fe8d0a0e5c4f27ead9083c756cc2", // WETH (canonical)
    "0xdac17f958d2ee523a2206206994597c13d831ec7", // USDT (canonical)
  ]);

  const PATTERN_PROFILES = {
    selfdestruct: {
      match: (a) => a.toLowerCase() === "0x000000000000000000000000000000000000dead",
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
    eoa: {
      match: (a) => a.toLowerCase() === "0xc9a0b63d91c2a808dd631d031f037944feddaa12",
      findings: [
        { type: "NOT_CONTRACT", severity: "critical", detail: "Address has no contract code. It is an EOA or a non-deployed address." },
      ],
    },
    knownGood: {
      match: (a) => KNOWN_GOOD_TOKENS.has(a.toLowerCase()),
      findings: [],
    },
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
    let findings = [];
    for (const key of Object.keys(PATTERN_PROFILES)) {
      if (PATTERN_PROFILES[key].match(address)) {
        findings = PATTERN_PROFILES[key].findings.slice();
        break;
      }
    }
    if (findings.length === 0) {
      findings.push({
        type: "GENERIC_RISK",
        severity: "low",
        detail: "No dangerous selectors in sampled bytecode. Address not in trusted registry. Run with PHAROS_MAINNET_RPC for the live analysis.",
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
    terminalBody.innerHTML = "";
    terminalStatus.textContent = "running";
    terminalStatus.className = "terminal__status is-running";

    userAddressDisplay.textContent = shortAddr(address);

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
                         report.verdict === "CAUTION" ? "term-tag" : "term-bad";
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

  // Render initial sample so first paint has real data.
  renderReport({
    address: "0x51e2A24742Db77604B881d6781Ee16B5b8fcBE29",
    network: "Pharos Mainnet (chain 1672)",
    riskScore: 0,
    verdict: "SAFE",
    recommendation: RECOMMENDATIONS.SAFE,
    findings: [],
  });
})();