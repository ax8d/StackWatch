async function load() {
  const { nvdApiKey, activeProbingEnabled } = await chrome.storage.local.get(["nvdApiKey", "activeProbingEnabled"]);
  document.getElementById("nvd-key").value = nvdApiKey || "";
  document.getElementById("active-probing").checked = activeProbingEnabled !== false;
}

document.getElementById("toggle-key-btn").addEventListener("click", () => {
  const input = document.getElementById("nvd-key");
  const btn = document.getElementById("toggle-key-btn");
  const revealed = input.type === "text";
  input.type = revealed ? "password" : "text";
  btn.textContent = revealed ? "Show" : "Hide";
  btn.classList.toggle("revealed", !revealed);
});

document.getElementById("save-btn").addEventListener("click", async () => {
  const nvdApiKey = document.getElementById("nvd-key").value.trim();
  const activeProbingEnabled = document.getElementById("active-probing").checked;
  await chrome.storage.local.set({ nvdApiKey, activeProbingEnabled });

  const status = document.getElementById("save-status");
  status.textContent = "Saved.";
  setTimeout(() => (status.textContent = ""), 2000);
});

load();
