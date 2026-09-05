import { examples } from "./examples.js";

const $ = (id) => document.getElementById(id);
let toastTimer;
function notify(message) {
  clearTimeout(toastTimer);
  $("toast").textContent = message;
  $("toast").classList.add("show");
  toastTimer = setTimeout(() => $("toast").classList.remove("show"), 3500);
}
async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    notify("Copied. Your shell is one step closer.");
  } catch {
    notify("Clipboard unavailable. Select the command or code to copy it.");
  }
}
document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", () => copy(button.dataset.copy));
});

let integration = "core";
const integrationTabs = [...document.querySelectorAll("[data-integration]")];
function highlight(code) {
  const fragment = document.createDocumentFragment();
  const tokens =
    /\/\/[^\n]*|#[^\n]*|'[^'\n]*'|"[^"\n]*"|\b(?:import|from|const|await|new|false|true)\b/g;
  let cursor = 0;
  for (const match of code.matchAll(tokens)) {
    fragment.append(document.createTextNode(code.slice(cursor, match.index)));
    const span = document.createElement("span");
    span.className =
      match[0].startsWith("//") || match[0].startsWith("#")
        ? "code-comment"
        : /^['"]/.test(match[0])
          ? "code-string"
          : "code-keyword";
    span.textContent = match[0];
    fragment.append(span);
    cursor = match.index + match[0].length;
  }
  fragment.append(document.createTextNode(code.slice(cursor)));
  return fragment;
}
function selectIntegration(id, focus = false) {
  integration = id;
  const example = examples[id];
  for (const tab of integrationTabs) {
    const active = tab.dataset.integration === id;
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
    if (active && focus) tab.focus();
  }
  $("code-panel").setAttribute("aria-labelledby", `tab-${id}`);
  $("integration-code").replaceChildren(highlight(example.code));
  $("code-filename").textContent = example.filename;
  $("code-note").textContent = example.note;
}
integrationTabs.forEach((tab, index) => {
  tab.addEventListener("click", () =>
    selectIntegration(tab.dataset.integration),
  );
  tab.addEventListener("keydown", (event) => {
    let next;
    if (event.key === "ArrowRight") next = (index + 1) % integrationTabs.length;
    if (event.key === "ArrowLeft")
      next = (index + integrationTabs.length - 1) % integrationTabs.length;
    if (event.key === "Home") next = 0;
    if (event.key === "End") next = integrationTabs.length - 1;
    if (next === undefined) return;
    event.preventDefault();
    selectIntegration(integrationTabs[next].dataset.integration, true);
  });
});
$("copy-code").addEventListener("click", () =>
  copy(examples[integration].code),
);
selectIntegration("core");

const scenarioButtons = [...document.querySelectorAll("[data-scenario]")];
const descriptions = {
  attack:
    "An instruction to exfiltrate secrets is quarantined. Its untrusted source also falls below the promotion floor.",
  trusted:
    "This preference comes from the authenticated principal. It passes the content checks and the promotion gate.",
  untrusted:
    "The words are harmless, but a web page cannot establish the principal’s preferences. Its source falls below the promotion floor.",
};
let scenarios;
function selectScenario(id) {
  const scenario = scenarios.find((entry) => entry.id === id);
  if (!scenario) return;
  for (const button of scenarioButtons)
    button.setAttribute("aria-pressed", String(button.dataset.scenario === id));
  $("decision-lab").dataset.verdict = scenario.decision.verdict;
  $("scenario-content").textContent = `“${scenario.content}”`;
  $("scenario-source").textContent = scenario.provenance.source;
  $("scenario-auth").textContent = scenario.provenance.authenticated
    ? "Verified principal"
    : "Unverified";
  $("scenario-trust").textContent = scenario.trust;
  $("scenario-scan").textContent = scenario.injection.flagged
    ? "INJECTION FLAGGED"
    : "NO INJECTION FLAG";
  $("scenario-verdict").textContent =
    scenario.decision.verdict === "allow" ? "Allowed." : "Rejected.";
  $("scenario-explanation").textContent = descriptions[id];
  const reasons = scenario.decision.reasons.map((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    return item;
  });
  $("scenario-reasons").replaceChildren(...reasons);
  $("scenario-ledger").textContent =
    `${scenario.ledger.valid ? "verified" : "invalid"} / ${scenario.ledger.entries} entries`;
  $("scenario-json").textContent = JSON.stringify(scenario, null, 2);
}
scenarioButtons.forEach((button) => {
  button.disabled = true;
  button.addEventListener("click", () =>
    selectScenario(button.dataset.scenario),
  );
});
try {
  const response = await fetch("./demo-results.json");
  if (!response.ok) throw new Error("Scenario data unavailable");
  const data = await response.json();
  if (
    !Array.isArray(data.scenarios) ||
    !["attack", "trusted", "untrusted"].every((id) =>
      data.scenarios.some((item) => item.id === id),
    )
  )
    throw new Error("Incomplete scenario data");
  scenarios = data.scenarios;
  selectScenario("attack");
  scenarioButtons.forEach((button) => {
    button.disabled = false;
  });
} catch {
  $("scenario-content").textContent = "The recorded examples could not load.";
  $("scenario-verdict").textContent = "Unavailable.";
  $("scenario-explanation").textContent =
    "Reload the page to try again, or run npm run demo from the repository.";
  $("scenario-json").textContent =
    "Scenario data unavailable. No evaluation has been made.";
  $("scenario-ledger").textContent = "not evaluated";
} finally {
  $("decision-lab").setAttribute("aria-busy", "false");
}
