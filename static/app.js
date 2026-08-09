"use strict";

const state = {
  csrfToken: null,
  scan: null,
  selected: new Set(),
  filter: "all",
  previewImageId: null,
  scanning: false,
  pruning: false,
  shuttingDown: false,
};

const elements = {};
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

class ApiError extends Error {
  constructor(code, message, status, details = null) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

document.addEventListener("DOMContentLoaded", initialize);

async function initialize() {
  collectElements();
  bindEvents();
  refreshIcons();
  restoreLastThreadId();

  try {
    const bootstrap = await apiRequest("/api/bootstrap");
    state.csrfToken = bootstrap.csrf_token;
    updateScanButton();
  } catch (error) {
    showStatus(humanizeError(error), "error");
  }
}

function collectElements() {
  elements.scanForm = document.querySelector("#scan-form");
  elements.threadInput = document.querySelector("#thread-id");
  elements.threadInputShell = elements.threadInput.closest(".input-shell");
  elements.threadError = document.querySelector("#thread-id-error");
  elements.scanButton = document.querySelector("#scan-button");
  elements.status = document.querySelector("#status");
  elements.statusText = elements.status.querySelector("[data-status-text]");
  elements.statusIcon = elements.status.querySelector("[data-status-icon]");
  elements.loading = document.querySelector("#loading-state");
  elements.sessionResult = document.querySelector("#session-result");
  elements.threadTitle = document.querySelector("[data-thread-title]");
  elements.threadId = document.querySelector("[data-thread-id]");
  elements.threadCwd = document.querySelector("[data-thread-cwd]");
  elements.rolloutPath = document.querySelector("[data-rollout-path]");
  elements.metricImages = document.querySelector("[data-metric-images]");
  elements.metricSources = document.querySelector("[data-metric-sources]");
  elements.metricImageSize = document.querySelector("[data-metric-image-size]");
  elements.metricFileSize = document.querySelector("[data-metric-file-size]");
  elements.metricLines = document.querySelector("[data-metric-lines]");
  elements.metricHash = document.querySelector("[data-metric-hash]");
  elements.workspaceToolbar = document.querySelector(".workspace-toolbar");
  elements.imageGrid = document.querySelector("#image-grid");
  elements.imageTemplate = document.querySelector("#image-card-template");
  elements.emptyState = document.querySelector("#empty-state");
  elements.filterEmptyState = document.querySelector("#filter-empty-state");
  elements.filterButtons = [...document.querySelectorAll("[data-filter]")];
  elements.filterCounts = [...document.querySelectorAll("[data-filter-count]")];
  elements.selectVisible = document.querySelector("[data-select-visible]");
  elements.clearSelection = document.querySelector("[data-clear-selection]");
  elements.selectionDock = document.querySelector(".selection-dock");
  elements.selectedCount = document.querySelector("[data-selected-count]");
  elements.selectedSize = document.querySelector("[data-selected-size]");
  elements.deleteButton = document.querySelector("#delete-button");
  elements.previewDialog = document.querySelector("#preview-dialog");
  elements.previewImage = document.querySelector("[data-preview-image]");
  elements.previewSource = document.querySelector("[data-preview-source]");
  elements.previewDetails = document.querySelector("[data-preview-details]");
  elements.previewToggle = document.querySelector("[data-toggle-preview-selection]");
  elements.previewToggleText = elements.previewToggle.querySelector("span");
  elements.confirmDialog = document.querySelector("#confirm-dialog");
  elements.confirmSummary = document.querySelector("[data-confirm-summary]");
  elements.writerStopped = document.querySelector("[data-writer-stopped]");
  elements.confirmDelete = document.querySelector("[data-confirm-delete]");
  elements.confirmDeleteText = elements.confirmDelete.querySelector("span");
  elements.operationResult = document.querySelector("#operation-result");
  elements.operationSummary = document.querySelector("[data-operation-summary]");
  elements.backupPath = document.querySelector("[data-backup-path]");
  elements.shutdownButton = document.querySelector("[data-shutdown]");
}

function bindEvents() {
  elements.scanForm.addEventListener("submit", handleScanSubmit);
  elements.threadInput.addEventListener("input", () => {
    clearThreadError();
    updateScanButton();
  });
  elements.threadInput.addEventListener("blur", () => {
    if (elements.threadInput.value.trim() && !isValidThreadId(elements.threadInput.value)) {
      showThreadError("请输入完整的 UUID 对话 ID");
    }
  });

  for (const button of elements.filterButtons) {
    button.addEventListener("click", () => setFilter(button.dataset.filter));
  }
  elements.selectVisible.addEventListener("click", selectVisibleImages);
  elements.clearSelection.addEventListener("click", clearSelection);
  elements.deleteButton.addEventListener("click", openConfirmDialog);

  document.querySelector("[data-close-preview]").addEventListener("click", closePreviewDialog);
  elements.previewToggle.addEventListener("click", togglePreviewSelection);
  elements.previewDialog.addEventListener("click", (event) => {
    if (event.target === elements.previewDialog) closePreviewDialog();
  });
  elements.previewDialog.addEventListener("close", () => {
    elements.previewImage.removeAttribute("src");
    state.previewImageId = null;
  });

  document.querySelector("[data-close-confirm]").addEventListener("click", closeConfirmDialog);
  document.querySelector("[data-cancel-confirm]").addEventListener("click", closeConfirmDialog);
  elements.confirmDialog.addEventListener("click", (event) => {
    if (event.target === elements.confirmDialog && !state.pruning) closeConfirmDialog();
  });
  elements.writerStopped.addEventListener("change", () => {
    elements.confirmDelete.disabled = !elements.writerStopped.checked || state.pruning;
  });
  elements.confirmDelete.addEventListener("click", pruneSelectedImages);

  document.querySelector("[data-copy-backup]").addEventListener("click", copyBackupPath);
  document.querySelector("[data-dismiss-result]").addEventListener("click", () => {
    elements.operationResult.hidden = true;
  });
  elements.shutdownButton.addEventListener("click", shutdownApplication);
}

async function shutdownApplication() {
  if (state.shuttingDown || !state.csrfToken) return;
  state.shuttingDown = true;
  elements.shutdownButton.disabled = true;
  setButtonIcon(elements.shutdownButton, "loader-circle");
  showStatus("正在退出本地程序...", "working");

  try {
    await apiRequest("/api/shutdown", { method: "POST", body: {} });
    document.querySelectorAll("button, input").forEach((control) => {
      control.disabled = true;
    });
    showStatus("程序已退出，可以关闭此页面。", "success");
  } catch (error) {
    state.shuttingDown = false;
    elements.shutdownButton.disabled = false;
    setButtonIcon(elements.shutdownButton, "power");
    showStatus(humanizeError(error), "error");
  }
}

async function handleScanSubmit(event) {
  event.preventDefault();
  const rawId = elements.threadInput.value.trim();
  if (!isValidThreadId(rawId)) {
    showThreadError("请输入完整的 UUID 对话 ID");
    elements.threadInput.focus();
    return;
  }
  elements.threadInput.value = rawId.toLowerCase();
  await scanConversation();
}

async function scanConversation(options = {}) {
  if (state.scanning || !state.csrfToken) return;
  const threadId = elements.threadInput.value.trim().toLowerCase();
  if (!isValidThreadId(threadId)) return;

  state.scanning = true;
  state.scan = null;
  state.selected.clear();
  state.filter = "all";
  setButtonBusy(elements.scanButton, true, "正在扫描", "loader-circle");
  elements.loading.hidden = false;
  elements.sessionResult.hidden = true;
  showStatus("正在读取会话并建立文件快照…", "working");

  try {
    const scan = await apiRequest("/api/scan", {
      method: "POST",
      body: { thread_id: threadId },
    });
    state.scan = scan;
    rememberThreadId(threadId);
    renderSession();
    elements.sessionResult.hidden = false;
    const count = scan.summary.image_count;
    const message = options.afterPrune
      ? `已重新扫描，会话中还剩 ${count} 张图片。`
      : count
        ? `已找到 ${count} 张持久化图片。`
        : "扫描完成，没有发现持久化图片。";
    showStatus(message, "success");
  } catch (error) {
    showStatus(humanizeError(error), "error");
  } finally {
    state.scanning = false;
    elements.loading.hidden = true;
    setButtonBusy(elements.scanButton, false, "获取图片", "search");
    updateScanButton();
  }
}

function renderSession() {
  if (!state.scan) return;
  const { thread, file, summary, images } = state.scan;

  elements.threadTitle.textContent = thread.title || "未命名对话";
  elements.threadId.textContent = thread.id;
  elements.threadCwd.textContent = thread.cwd || "—";
  elements.threadCwd.title = thread.cwd || "";
  elements.rolloutPath.textContent = file.path;
  elements.rolloutPath.title = file.path;
  elements.metricImages.textContent = String(summary.image_count);
  elements.metricSources.textContent = `用户 ${summary.source_counts.user} / 工具 ${summary.source_counts.tool} / 其他 ${summary.source_counts.other}`;
  elements.metricImageSize.textContent = formatBytes(summary.decoded_bytes);
  elements.metricFileSize.textContent = formatBytes(file.size);
  elements.metricLines.textContent = `${formatInteger(file.line_count)} 行 JSONL`;
  elements.metricHash.textContent = `${file.sha256.slice(0, 14)}…`;
  elements.metricHash.title = file.sha256;

  updateFilterCounts(images);
  updateFilterButtons();
  elements.emptyState.hidden = images.length !== 0;
  elements.workspaceToolbar.hidden = images.length === 0;
  elements.selectionDock.hidden = images.length === 0;
  renderGrid();
  renderSelection();
  refreshIcons();
}

function updateFilterCounts(images) {
  const counts = {
    all: images.length,
    user: images.filter((image) => image.source === "user").length,
    tool: images.filter((image) => image.source === "tool").length,
    other: images.filter((image) => image.source === "other").length,
  };
  for (const element of elements.filterCounts) {
    element.textContent = String(counts[element.dataset.filterCount] || 0);
  }
}

function setFilter(filter) {
  if (!state.scan || !["all", "user", "tool", "other"].includes(filter)) return;
  state.filter = filter;
  updateFilterButtons();
  renderGrid();
}

function updateFilterButtons() {
  for (const button of elements.filterButtons) {
    const active = button.dataset.filter === state.filter;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
  }
}

function filteredImages() {
  if (!state.scan) return [];
  if (state.filter === "all") return state.scan.images;
  return state.scan.images.filter((image) => image.source === state.filter);
}

function renderGrid() {
  elements.imageGrid.replaceChildren();
  if (!state.scan || state.scan.images.length === 0) {
    elements.filterEmptyState.hidden = true;
    return;
  }

  const images = filteredImages();
  elements.filterEmptyState.hidden = images.length !== 0;
  const fullIndex = new Map(state.scan.images.map((image, index) => [image.id, index + 1]));
  const fragment = document.createDocumentFragment();

  for (const image of images) {
    const cardFragment = elements.imageTemplate.content.cloneNode(true);
    const card = cardFragment.querySelector(".image-card");
    const previewButton = card.querySelector(".image-card__preview");
    const imageElement = card.querySelector("img");
    const fallback = card.querySelector(".image-card__fallback");
    const checkbox = card.querySelector("input[type='checkbox']");
    const sourceBadge = card.querySelector(".source-badge");
    const number = fullIndex.get(image.id);

    card.dataset.imageId = image.id;
    card.classList.toggle("is-selected", state.selected.has(image.id));
    previewButton.setAttribute("aria-label", `打开第 ${number} 张图片预览`);
    previewButton.addEventListener("click", () => openPreviewDialog(image.id));

    imageElement.src = image.preview_url;
    imageElement.addEventListener("error", () => {
      imageElement.hidden = true;
      fallback.hidden = false;
      refreshIcons(fallback);
    }, { once: true });

    checkbox.checked = state.selected.has(image.id);
    checkbox.setAttribute("aria-label", `选择第 ${number} 张图片`);
    checkbox.addEventListener("change", () => setImageSelected(image.id, checkbox.checked));

    sourceBadge.dataset.source = image.source;
    sourceBadge.textContent = sourceLabel(image.source);
    card.querySelector("[data-card-number]").textContent = `图片 ${String(number).padStart(2, "0")}`;
    card.querySelector("[data-card-size]").textContent = formatBytes(image.decoded_bytes);
    card.querySelector("[data-card-dimensions]").textContent = image.width && image.height
      ? `${image.width} × ${image.height}`
      : mimeLabel(image.mime_type);
    card.querySelector("[data-card-line]").textContent = `L${formatInteger(image.line_number)}`;
    const time = card.querySelector("[data-card-time]");
    time.textContent = formatTimestamp(image.timestamp);
    if (image.timestamp) time.dateTime = image.timestamp;
    fragment.append(cardFragment);
  }

  elements.imageGrid.append(fragment);
  refreshIcons(elements.imageGrid);
}

function setImageSelected(imageId, selected) {
  if (selected) state.selected.add(imageId);
  else state.selected.delete(imageId);
  syncVisibleCards();
  renderSelection();
}

function selectVisibleImages() {
  for (const image of filteredImages()) state.selected.add(image.id);
  syncVisibleCards();
  renderSelection();
}

function clearSelection() {
  state.selected.clear();
  syncVisibleCards();
  renderSelection();
}

function syncVisibleCards() {
  for (const card of elements.imageGrid.querySelectorAll(".image-card")) {
    const selected = state.selected.has(card.dataset.imageId);
    card.classList.toggle("is-selected", selected);
    card.querySelector("input[type='checkbox']").checked = selected;
  }
}

function renderSelection() {
  const selectedImages = state.scan
    ? state.scan.images.filter((image) => state.selected.has(image.id))
    : [];
  const count = selectedImages.length;
  const bytes = selectedImages.reduce((total, image) => total + image.decoded_bytes, 0);
  elements.selectionDock.hidden = !state.scan || state.scan.images.length === 0 || count === 0;
  elements.selectedCount.textContent = count ? `已选择 ${count} 张图片` : "未选择图片";
  elements.selectedSize.textContent = formatBytes(bytes);
  elements.clearSelection.disabled = count === 0 || state.pruning;
  elements.deleteButton.disabled = count === 0 || state.pruning;
  elements.selectVisible.disabled = filteredImages().length === 0 || state.pruning;
  updatePreviewToggle();
}

function openPreviewDialog(imageId) {
  const image = findImage(imageId);
  if (!image) return;
  state.previewImageId = imageId;
  elements.previewImage.src = image.preview_url;
  elements.previewSource.textContent = sourceLabel(image.source);
  const dimensions = image.width && image.height ? `${image.width} × ${image.height}` : mimeLabel(image.mime_type);
  elements.previewDetails.textContent = `${dimensions} · ${formatBytes(image.decoded_bytes)} · L${formatInteger(image.line_number)} · ${formatTimestamp(image.timestamp)}`;
  updatePreviewToggle();
  elements.previewDialog.showModal();
  refreshIcons(elements.previewDialog);
}

function closePreviewDialog() {
  if (elements.previewDialog.open) elements.previewDialog.close();
}

function togglePreviewSelection() {
  if (!state.previewImageId) return;
  setImageSelected(state.previewImageId, !state.selected.has(state.previewImageId));
}

function updatePreviewToggle() {
  if (!state.previewImageId) return;
  const selected = state.selected.has(state.previewImageId);
  elements.previewToggleText.textContent = selected ? "取消选择" : "选择此图";
  const icon = elements.previewToggle.querySelector("svg, i");
  if (icon) icon.setAttribute("data-lucide", selected ? "square" : "check-square");
  refreshIcons(elements.previewToggle);
}

function openConfirmDialog() {
  const selectedImages = getSelectedImages();
  if (!selectedImages.length || state.pruning) return;
  const bytes = selectedImages.reduce((total, image) => total + image.decoded_bytes, 0);
  elements.confirmSummary.textContent = `将从本地会话中移除 ${selectedImages.length} 张图片（${formatBytes(bytes)}）。`;
  elements.writerStopped.checked = false;
  elements.confirmDelete.disabled = true;
  elements.confirmDialog.showModal();
  document.querySelector("[data-cancel-confirm]").focus();
  refreshIcons(elements.confirmDialog);
}

function closeConfirmDialog() {
  if (!state.pruning && elements.confirmDialog.open) elements.confirmDialog.close();
}

async function pruneSelectedImages() {
  if (!state.scan || state.pruning || !elements.writerStopped.checked) return;
  const imageIds = [...state.selected];
  if (!imageIds.length) return;

  state.pruning = true;
  elements.confirmDelete.disabled = true;
  elements.writerStopped.disabled = true;
  elements.confirmDeleteText.textContent = "正在删除";
  setButtonIcon(elements.confirmDelete, "loader-circle");
  showStatus("正在核对快照、创建备份并改写会话…", "working");
  renderSelection();

  try {
    const result = await apiRequest("/api/prune", {
      method: "POST",
      body: {
        snapshot_id: state.scan.snapshot_id,
        image_ids: imageIds,
        writer_stopped: true,
      },
    });
    elements.confirmDialog.close();
    showOperationResult(result);
    state.selected.clear();
    await scanConversation({ afterPrune: true });
  } catch (error) {
    if (elements.confirmDialog.open) elements.confirmDialog.close();
    showStatus(humanizeError(error), "error");
    if (["SNAPSHOT_STALE", "SESSION_CHANGED_DURING_SCAN", "IMAGE_CHANGED"].includes(error.code)) {
      await scanConversation();
    }
  } finally {
    state.pruning = false;
    elements.writerStopped.disabled = false;
    elements.confirmDeleteText.textContent = "确认删除";
    setButtonIcon(elements.confirmDelete, "trash-2");
    elements.confirmDelete.disabled = !elements.writerStopped.checked;
    renderSelection();
  }
}

function showOperationResult(result) {
  const reloadNotice = result.install_mode === "locked_in_place"
    ? "旧 Codex 进程仍保留删除前的内存上下文，请退出该会话后再用 codex resume 重新打开。"
    : "请重新打开目标会话，让 Codex 从修改后的文件载入。";
  elements.operationSummary.textContent = `已删除 ${result.removed_count} 张图片，会话文件减少 ${formatBytes(result.freed_file_bytes)}。${reloadNotice}`;
  elements.backupPath.textContent = result.backup_path;
  elements.backupPath.title = result.backup_path;
  elements.operationResult.hidden = false;
  refreshIcons(elements.operationResult);
}

async function copyBackupPath() {
  const value = elements.backupPath.textContent;
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    showStatus("备份路径已复制。", "success");
  } catch {
    showStatus("无法访问剪贴板，请直接选择备份路径。", "error");
  }
}

function findImage(imageId) {
  return state.scan?.images.find((image) => image.id === imageId) || null;
}

function getSelectedImages() {
  return state.scan?.images.filter((image) => state.selected.has(image.id)) || [];
}

async function apiRequest(path, options = {}) {
  const method = options.method || "GET";
  const headers = { Accept: "application/json" };
  const request = {
    method,
    headers,
    cache: "no-store",
    credentials: "same-origin",
  };
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-CSRF-Token"] = state.csrfToken || "";
    request.body = JSON.stringify(options.body || {});
  }

  let response;
  try {
    response = await fetch(path, request);
  } catch (error) {
    const networkError = new ApiError("NETWORK_ERROR", "The local server is unavailable.", 0);
    networkError.cause = error;
    throw networkError;
  }

  let payload = null;
  try {
    payload = await response.json();
  } catch {
    if (!response.ok) throw new ApiError("INVALID_RESPONSE", "The local server returned an invalid response.", response.status);
  }
  if (!response.ok) {
    const apiError = payload?.error || {};
    throw new ApiError(
      apiError.code || "REQUEST_FAILED",
      apiError.message || "The request failed.",
      response.status,
      apiError.details || null,
    );
  }
  return payload;
}

function showStatus(message, tone = "info") {
  elements.status.hidden = false;
  elements.status.dataset.tone = tone;
  elements.statusText.textContent = message;
  const iconNames = {
    error: "circle-alert",
    working: "loader-circle",
    success: "circle-check",
    info: "info",
  };
  elements.statusIcon.setAttribute("data-lucide", iconNames[tone] || "info");
  refreshIcons(elements.status);
}

function humanizeError(error) {
  const messages = {
    NETWORK_ERROR: "无法连接本地工具，请确认服务仍在运行。",
    INVALID_THREAD_ID: "对话 ID 格式不正确。",
    THREAD_NOT_FOUND: "没有找到这个对话 ID。",
    STATE_DB_NOT_FOUND: "没有找到 Codex 会话索引。",
    STATE_DB_ERROR: "Codex 会话索引暂时无法读取。",
    ROLLOUT_NOT_FOUND: "这个对话的会话文件不存在。",
    UNTRUSTED_ROLLOUT_PATH: "会话文件不在 Codex 的受信目录中。",
    INVALID_JSONL: "会话文件格式异常，未执行任何修改。",
    PERMISSION_DENIED: "没有权限读取或改写会话文件。",
    FILE_IN_USE: "目标会话仍在写入或被独占，请停止后重新扫描。",
    IN_PLACE_REWRITE_FAILED: "原位改写失败，已从备份恢复原会话。",
    RECOVERY_FAILED: "改写和自动恢复都失败，请使用备份文件恢复。",
    SNAPSHOT_STALE: "会话在扫描后发生了变化，请重新扫描。",
    SESSION_CHANGED_DURING_SCAN: "会话在扫描时仍在写入，请停止后重试。",
    IMAGE_CHANGED: "所选图片已经变化，请重新扫描。",
    SNAPSHOT_NOT_FOUND: "扫描结果已过期，请重新扫描。",
    INVALID_CSRF: "本地页面令牌已失效，请刷新页面。",
    WRITER_ACK_REQUIRED: "请确认目标对话已经停止写入。",
    AUDIT_LOG_UNAVAILABLE: "审计日志不可写，因此没有修改会话。",
    REQUEST_TOO_LARGE: "提交的数据过大。",
    RATE_LIMITED: "请求过于频繁，请稍后再试。",
  };
  if (error instanceof ApiError) return messages[error.code] || error.message || "操作失败。";
  return "本地工具发生了未预期的错误。";
}

function showThreadError(message) {
  elements.threadError.textContent = message;
  elements.threadError.hidden = false;
  elements.threadInputShell.classList.add("is-invalid");
  elements.threadInput.setAttribute("aria-invalid", "true");
}

function clearThreadError() {
  elements.threadError.hidden = true;
  elements.threadInputShell.classList.remove("is-invalid");
  elements.threadInput.removeAttribute("aria-invalid");
}

function updateScanButton() {
  elements.scanButton.disabled = !state.csrfToken || state.scanning || !isValidThreadId(elements.threadInput.value);
}

function setButtonBusy(button, busy, label, iconName) {
  button.classList.toggle("is-busy", busy);
  const labelElement = button.querySelector("span");
  if (labelElement) labelElement.textContent = label;
  setButtonIcon(button, iconName);
}

function setButtonIcon(button, iconName) {
  const icon = button.querySelector("svg, i");
  if (!icon) return;
  icon.setAttribute("data-lucide", iconName);
  refreshIcons(button);
}

function isValidThreadId(value) {
  return UUID_PATTERN.test(String(value || "").trim());
}

function sourceLabel(source) {
  return { user: "用户附件", tool: "工具截图", other: "其他来源" }[source] || "其他来源";
}

function mimeLabel(mimeType) {
  return String(mimeType || "image").replace("image/", "").toUpperCase();
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${formatInteger(bytes)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = bytes / 1024;
  let unit = units[0];
  for (let index = 1; index < units.length && size >= 1024; index += 1) {
    size /= 1024;
    unit = units[index];
  }
  const digits = size >= 100 ? 0 : size >= 10 ? 1 : 2;
  return `${size.toFixed(digits)} ${unit}`;
}

function formatInteger(value) {
  return new Intl.NumberFormat("zh-CN", { maximumFractionDigits: 0 }).format(Number(value) || 0);
}

function formatTimestamp(value) {
  if (!value) return "时间未知";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value).slice(0, 24);
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function rememberThreadId(threadId) {
  try {
    localStorage.setItem("codex-413-fix:last-thread", threadId);
  } catch {
    // Local storage is optional.
  }
}

function restoreLastThreadId() {
  try {
    const threadId = localStorage.getItem("codex-413-fix:last-thread");
    if (threadId && isValidThreadId(threadId)) elements.threadInput.value = threadId;
  } catch {
    // Local storage is optional.
  }
}

function refreshIcons(root = document) {
  if (!window.lucide) return;
  window.lucide.createIcons({
    root,
    attrs: {
      width: "18",
      height: "18",
      "stroke-width": "1.8",
      "aria-hidden": "true",
    },
  });
}
