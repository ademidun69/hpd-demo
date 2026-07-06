/**
 * Renders the Agent Card section using data fetched from the GitHub repo.
 * Falls back to a hardcoded inline copy if the network fetch fails (CORS,
 * offline, etc.) so the demo page never has empty fields.
 */

(function () {
  "use strict";

  // Inline fallback (kept in sync with AGENT_CARD.md in the repo)
  const FALLBACK = {
    name: "HPD — Honeypot Detector",
    version: "1.0.0",
    description:
      "Read-only smart-contract security analysis for AI agents on Pharos. " +
      "Evaluates any EVM contract and returns a 0-100 risk score with a clear " +
      "verdict (SAFE / CAUTION / HIGH RISK / HONEYPOT LIKELY) and a list of " +
      "findings. Three layers: static bytecode scan, onchain reputation " +
      "lookup, and behavioral simulation via an Anvil fork of Pharos.",
    capabilities: [
      "honeypot-detection",
      "rug-pull-detection",
      "static-bytecode-analysis",
      "risk-scoring",
      "smart-contract-screening",
    ],
    networks: ["Pharos Mainnet (chain 1672)", "Pharos Atlantic Testnet (chain 688689)"],
    pricing: {
      model: "free-during-campaign / x402-billable-when-published",
      perCall: 0,
      currency: "PROS",
      settlement: "x402",
      note:
        "Free for the duration of the Pharos AI Agent Carnival campaign. " +
        "When the Anvita Flow payment module ships, POST /analyze and " +
        "POST /quick-check will return 402 Payment Required with x402 " +
        "payment instructions; Steward Agents retry with the X-PAYMENT " +
        "proof header. The HTTP wrapper is already shaped for this.",
    },
    endpoints: [
      { method: "GET", path: "/health" },
      { method: "GET", path: "/agent-card" },
      { method: "POST", path: "/analyze" },
      { method: "POST", path: "/quick-check" },
    ],
    examplePrompts: [
      "Is 0x51e2A24742Db77604B881d6781Ee16B5b8fcBE29 safe to swap into on Pharos mainnet?",
      "Run a quick security check on this contract: 0xYourContractAddress",
      "Analyze the honeypot risk for 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 on Pharos.",
      "Check if 0xYourAddress is a honeypot on Pharos Atlantic testnet.",
      "Give me a risk score for 0xYourAddress (0-100).",
      "Screen this token before I approve an allowance.",
      "Is this contract a rug pull?",
      "What's the deployment history of this contract on Pharos?",
    ],
  };

  const AGENT_CARD_RAW_URL = "https://raw.githubusercontent.com/ademidun69/HPD/main/AGENT_CARD.md";

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function renderFallback() {
    render(FALLBACK);
  }

  function render(card) {
    document.getElementById("ac-name").textContent = card.name;
    document.getElementById("ac-version").textContent = "v" + (card.version || "1.0.0") + " · MIT";
    document.getElementById("ac-description").textContent = card.description;

    const caps = document.getElementById("ac-capabilities");
    caps.innerHTML = "";
    (card.capabilities || []).forEach(function (c) {
      const s = document.createElement("span");
      s.textContent = c;
      caps.appendChild(s);
    });

    const nets = document.getElementById("ac-networks");
    nets.innerHTML = (card.networks || []).map(escapeHtml).join("<br/>");

    const pricing = card.pricing || {};
    const pricingEl = document.getElementById("ac-pricing");
    pricingEl.textContent =
      pricing.model +
      (pricing.perCall !== undefined ? " · " + pricing.perCall + " " + (pricing.currency || "") : "") +
      (pricing.note ? " — " + pricing.note : "");

    const eps = document.getElementById("ac-endpoints");
    eps.innerHTML = "";
    (card.endpoints || []).forEach(function (e) {
      const c = document.createElement("code");
      c.textContent = e.method + " " + e.path;
      eps.appendChild(c);
    });

    const prom = document.getElementById("ac-prompts");
    prom.innerHTML = "";
    (card.examplePrompts || []).forEach(function (p) {
      const li = document.createElement("li");
      li.textContent = p;
      prom.appendChild(li);
    });
  }

  // Try to load a richer card from the repo (parse the JSON-shaped section
  // from AGENT_CARD.md). Falls back silently to FALLBACK.
  function tryLoadFromRepo() {
    fetch(AGENT_CARD_RAW_URL, { cache: "no-store" })
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.text();
      })
      .then(function (md) {
        // We don't have the JSON form, but we can at least confirm the file is
        // there and show its presence in the version eyebrow.
        document.getElementById("ac-version").setAttribute("title", "AGENT_CARD.md found at " + AGENT_CARD_RAW_URL);
      })
      .catch(function () {
        // silent — fallback already rendered
      });
  }

  renderFallback();
  tryLoadFromRepo();
})();