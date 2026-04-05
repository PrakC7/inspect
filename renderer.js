// DOM Elements
const form = document.getElementById('url-form');
const input = document.getElementById('url-input');
const btnBack = document.getElementById('btn-back');
const btnForward = document.getElementById('btn-forward');
const btnReload = document.getElementById('btn-reload');
const btnInspect = document.getElementById('btn-inspect');
const btnExt = document.getElementById('btn-ext');
const btnSniff = document.getElementById('btn-sniff'); // New video button
const sniffBadge = document.getElementById('sniff-badge'); // Notification bubble
const addTabBtn = document.getElementById('add-tab-btn');
const tabStrip = document.getElementById('tab-strip');

// Extension Modal
const extModal = document.getElementById('ext-modal');
const extInput = document.getElementById('ext-input');
const closeExtBtn = document.getElementById('close-ext-modal');
const submitExtBtn = document.getElementById('submit-ext-modal');

// Media Modal DOM
const mediaModal = document.getElementById('media-modal');
const mediaList = document.getElementById('media-list');
const closeMediaBtns = [
  document.getElementById('close-media-modal'), 
  document.getElementById('close-media-icon')
];
const filterType = document.getElementById('filter-type');
const filterFormat = document.getElementById('filter-format');
const filterSizeMin = document.getElementById('filter-size-min');
const filterSizeMax = document.getElementById('filter-size-max');
const filterMinWidth = document.getElementById('filter-min-width');
const filterMinHeight = document.getElementById('filter-min-height');
const selectAllCheck = document.getElementById('select-all');
const btnClearAll = document.getElementById('btn-clear-all');
const btnDownloadSelected = document.getElementById('btn-download-selected');
const btnDownloadDomain = document.getElementById('btn-download-domain');
const btnScanDomain = document.getElementById('btn-scan-domain');
const btnStopScan = document.getElementById('btn-stop-scan');
const selectionCount = document.getElementById('selection-count');
const scanStatus = document.getElementById('scan-status');
const scanDomainInput = document.getElementById('scan-domain');

let activeMediaSnippets = [];
let domainScanRunning = false;
let filterSyncTimer = null;

// Helpers
function processUrlOrSearch(inputVal) {
  let url = inputVal.trim();
  if (url === "") return;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    if (url.includes('.') && !url.includes(' ')) url = 'https://' + url;
    else url = 'https://duckduckgo.com/?q=' + encodeURIComponent(url);
  }
  if (url.startsWith('http://')) url = url.replace('http://', 'https://');
  return url;
}

function parseFilenameFromUrl(url) {
  try {
    const urlObj = new URL(url);
    const pathParts = (urlObj.pathname || '').split('/').filter(Boolean);
    let lastPart = pathParts[pathParts.length - 1] || '';

    if (!lastPart && urlObj.searchParams.get('filename')) {
      lastPart = urlObj.searchParams.get('filename');
    }

    if (lastPart.length > 0) {
      const cleanName = decodeURIComponent(lastPart).replace(/[?#].*$/, '');
      if (cleanName.length > 56) return cleanName.substring(0, 53) + '...';
      return cleanName;
    }
  } catch (e) {}
  return "Unknown_Media_Stream";
}

function syncModalVisibility() {
  const anyModalVisible = extModal.style.display === 'flex' || mediaModal.style.display === 'flex';
  window.browserAPI.toggleModal(anyModalVisible);
}

function showModal(modalEl) {
  modalEl.style.display = 'flex';
  syncModalVisibility();
}

function hideModal(modalEl) {
  modalEl.style.display = 'none';
  syncModalVisibility();
}

function updateSelectionCount() {
  const total = document.querySelectorAll('.item-checkbox').length;
  const selected = document.querySelectorAll('.item-checkbox:checked').length;
  selectionCount.textContent = `${selected} selected`;

  if (total === 0) {
    selectAllCheck.checked = false;
    selectAllCheck.indeterminate = false;
    return;
  }

  selectAllCheck.checked = selected > 0 && selected === total;
  selectAllCheck.indeterminate = selected > 0 && selected < total;
}

function updateSnifferUiState() {
  const mediaCount = activeMediaSnippets.length;
  sniffBadge.textContent = String(mediaCount);

  if (mediaCount > 0) {
    sniffBadge.classList.add('active');
    btnSniff.style.opacity = '1';
    btnSniff.style.color = 'var(--text)';
  } else {
    sniffBadge.classList.remove('active');
    btnSniff.style.opacity = '0.68';
    btnSniff.style.color = 'var(--icon-fill)';
  }
}

function requestFreshMediaScan() {
  window.browserAPI.scanMedia();
}

function getMediaFilterPayload() {
  const minSizeMb = Number.parseFloat(filterSizeMin.value || '0') || 0;
  const maxSizeMb = Number.parseFloat(filterSizeMax.value || '0') || 0;

  return {
    type: String(filterType.value || '').trim().toLowerCase(),
    format: String(filterFormat.value || '').trim().toLowerCase(),
    minSizeBytes: Math.max(0, minSizeMb) * 1024 * 1024,
    maxSizeBytes: Math.max(0, maxSizeMb) * 1024 * 1024,
    minWidth: Number.parseInt(filterMinWidth.value || '0', 10) || 0,
    minHeight: Number.parseInt(filterMinHeight.value || '0', 10) || 0
  };
}

function applyBackendFilterAndRescan() {
  const payload = getMediaFilterPayload();
  window.browserAPI.setMediaFilter(payload);
  requestFreshMediaScan();
}

function queueFilterSync() {
  if (filterSyncTimer) {
    clearTimeout(filterSyncTimer);
  }
  filterSyncTimer = setTimeout(() => {
    filterSyncTimer = null;
    applyBackendFilterAndRescan();
    if (domainScanRunning) {
      startDomainScan();
    }
  }, 220);
}

function startDomainScan() {
  const payload = getMediaFilterPayload();
  const targetDomain = String(scanDomainInput.value || '').trim();
  window.browserAPI.setMediaFilter(payload);
  window.browserAPI.startDomainScan({
    domain: targetDomain,
    maxPages: 180,
    maxSubdomains: 50,
    concurrency: 1,
    legalComplianceMode: true,
    respectRobots: true,
    overrideRobots: false,
    useExternalTools: false,
    externalTools: ['katana', 'hakrawler', 'linkfinder', 'zap']
  });
}

function updateDomainScanStatus(status = {}) {
  domainScanRunning = Boolean(status.running);
  const pages = Number(status.pagesVisited || 0);
  const queued = Number(status.queued || 0);
  const found = Number(status.mediaFound || 0);
  const subdomainsDiscovered = Number(status.subdomainsDiscovered || 0);
  const subdomainsScanned = Number(status.subdomainsScanned || 0);

  if (status.stage === 'discovering-subdomains') {
    scanStatus.textContent = `Discovering subdomains for ${status.domain || 'domain'}...`;
  } else if (status.stage === 'legal-policy-blocked') {
    const reason = String(status.message || status.reason || 'authorization policy');
    scanStatus.textContent = `Scan blocked by legal-safe policy (${reason}).`;
  } else if (status.stage === 'external-discovery') {
    const tool = String(status.externalTool || 'tool').toUpperCase();
    const host = String(status.externalHost || status.currentHost || '').trim();
    const found = Number(status.externalFound || 0);
    const queuedByTool = Number(status.externalQueued || 0);
    const mediaByTool = Number(status.externalMedia || 0);
    scanStatus.textContent = `External discovery (${tool}) ${host ? `on ${host}` : ''} • found ${found} • queued ${queuedByTool} • media ${mediaByTool}`.trim();
  } else if (status.running) {
    scanStatus.textContent = `Scanning ${status.domain || 'domain'} one-by-one • subs ${subdomainsScanned}/${subdomainsDiscovered} • pages ${pages} • queue ${queued} • media ${found}`;
  } else if (status.finished) {
    scanStatus.textContent = `Scan finished • subs ${subdomainsScanned}/${subdomainsDiscovered} • pages ${pages} • media ${found}`;
  } else if (status.stopped) {
    scanStatus.textContent = `Scan stopped • subs ${subdomainsScanned}/${subdomainsDiscovered} • pages ${pages} • media ${found}`;
  } else {
    scanStatus.textContent = 'Idle';
  }
}

function isDomainMedia(media) {
  const scope = String(media.sourceScope || '').toLowerCase();
  return scope === 'domain' || scope === 'both';
}

function getIconSvgForMedia(media) {
  const category = String(media.category || media.type || '').toLowerCase();
  if (category.includes('image') || category === 'gif' || category === 'svg') {
    return '<svg fill="currentColor" width="20" height="20" viewBox="0 0 24 24"><path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zm-11.5-6.5l2.5 3.01L15.5 11l4.5 6H5l4.5-4.5z"></path></svg>';
  }
  if (category.includes('audio')) {
    return '<svg fill="currentColor" width="20" height="20" viewBox="0 0 24 24"><path d="M12 3v10.55A4 4 0 1 0 14 17V7h4V3h-6z"></path></svg>';
  }
  return '<svg fill="currentColor" width="20" height="20" viewBox="0 0 24 24"><path d="M18 3v2h-2V3H8v2H6V3H4v18h2v-2h2v2h8v-2h2v2h2V3h-2zM8 17H6v-2h2v2zm0-4H6v-2h2v2zm0-4H6V7h2v2zm10 8h-2v-2h2v2zm0-4h-2v-2h2v2zm0-4h-2V7h2v2z"></path></svg>';
}

// Event Listeners for Toolbar
form.addEventListener('submit', (e) => {
  e.preventDefault();
  const targetUrl = processUrlOrSearch(input.value);
  if (targetUrl) window.browserAPI.navigate(targetUrl);
});

btnBack.addEventListener('click', () => window.browserAPI.goBack());
btnForward.addEventListener('click', () => window.browserAPI.goForward());
btnReload.addEventListener('click', () => window.browserAPI.reload());
btnInspect.addEventListener('click', () => window.browserAPI.toggleInspect());

// Extension Handler fixes prompt() block
btnExt.addEventListener('click', () => {
  showModal(extModal);
  extInput.focus();
});
closeExtBtn.addEventListener('click', () => {
  hideModal(extModal);
});
submitExtBtn.addEventListener('click', () => {
  if (extInput.value.trim() !== '') {
    window.browserAPI.loadExtension(extInput.value.trim());
    extInput.value = '';
    hideModal(extModal);
  }
});
extInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    submitExtBtn.click();
  }
  if (event.key === 'Escape') {
    event.preventDefault();
    hideModal(extModal);
  }
});
extModal.addEventListener('click', (event) => {
  if (event.target === extModal) hideModal(extModal);
});

// Media Modal Logic
btnSniff.addEventListener('click', () => {
  showModal(mediaModal);
  applyBackendFilterAndRescan();
  requestFreshMediaScan();
  startDomainScan();
  renderMediaList();
});

closeMediaBtns.forEach(btn => btn.addEventListener('click', () => {
  hideModal(mediaModal);
}));
mediaModal.addEventListener('click', (event) => {
  if (event.target === mediaModal) hideModal(mediaModal);
});

[filterType, filterFormat, filterSizeMin, filterSizeMax, filterMinWidth, filterMinHeight].forEach((node) => {
  node.addEventListener('input', queueFilterSync);
  node.addEventListener('change', queueFilterSync);
});

btnScanDomain.addEventListener('click', () => {
  startDomainScan();
});

btnStopScan.addEventListener('click', () => {
  window.browserAPI.stopDomainScan();
});

selectAllCheck.addEventListener('change', (e) => {
  const checkboxes = document.querySelectorAll('.item-checkbox');
  checkboxes.forEach(cb => {
    cb.checked = e.target.checked;
  });
  updateSelectionCount();
});

btnClearAll.addEventListener('click', () => {
  window.browserAPI.clearMedia(); // Call back end to erase arrays securely
  hideModal(mediaModal);
});

btnDownloadSelected.addEventListener('click', () => {
  const checkboxes = document.querySelectorAll('.item-checkbox');
  checkboxes.forEach((cb) => {
    if (cb.checked) {
      const url = cb.getAttribute('data-url');
      const referrer = cb.getAttribute('data-referrer') || '';
      if (url) window.browserAPI.downloadVideo({ url, referrer });
    }
  });
  hideModal(mediaModal);
});

btnDownloadDomain.addEventListener('click', () => {
  const domainItems = activeMediaSnippets.filter((media) => isDomainMedia(media));
  domainItems.forEach((media) => {
    if (!media.url) return;
    window.browserAPI.downloadVideo({
      url: media.url,
      referrer: media.sourcePage || ''
    });
  });
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    if (extModal.style.display === 'flex') hideModal(extModal);
    else if (mediaModal.style.display === 'flex') hideModal(mediaModal);
  }
});

function renderMediaList() {
  mediaList.innerHTML = '';
  selectAllCheck.checked = false;
  selectAllCheck.indeterminate = false;

  const filtered = activeMediaSnippets;

  if (filtered.length === 0) {
    mediaList.innerHTML = '<div style="padding: 28px; color: #5f6368; text-align: center; font-size: 14px;">No media matches your current filters yet. Keep browsing and this scanner will keep sniffing downloadable files in the background.</div>';
    updateSelectionCount();
    return;
  }

  filtered.forEach((media) => {
    const item = document.createElement('div');
    item.className = 'media-item';

    const niceFilename = parseFilenameFromUrl(media.url);

    const check = document.createElement('input');
    check.type = 'checkbox';
    check.className = 'media-checkbox item-checkbox';
    check.setAttribute('data-url', media.url || '');
    check.setAttribute('data-referrer', media.sourcePage || '');
    check.setAttribute('data-scope', media.sourceScope || 'page');
    check.addEventListener('change', updateSelectionCount);

    const icon = document.createElement('div');
    icon.className = 'media-icon';
    icon.innerHTML = getIconSvgForMedia(media);

    const info = document.createElement('div');
    info.className = 'media-info';

    const filenameEl = document.createElement('div');
    filenameEl.className = 'media-filename';
    filenameEl.title = niceFilename;
    filenameEl.textContent = niceFilename;

    const metaEl = document.createElement('div');
    metaEl.className = 'media-meta';
    const displayType = (media.category || media.type || 'media').toString().toUpperCase();
    const displayResolution = media.resolution || 'Unknown';
    const displayFormat = (media.format || media.extension || 'unknown').toString().toLowerCase();
    const displayQuality = media.quality || 'Unknown';
    const qualityTag = String(media.qualityTag || '').trim().toUpperCase();
    const qualityBadge = qualityTag ? ` • ${qualityTag}` : '';
    const sourceBadge = isDomainMedia(media) ? ' • DOMAIN' : ' • PAGE';
    metaEl.textContent = `${media.sizeStr || 'Unknown Size'} • ${displayType} • ${displayResolution} • ${displayFormat} • ${displayQuality}${qualityBadge}${sourceBadge}`;

    info.appendChild(filenameEl);
    info.appendChild(metaEl);

    const dlBtn = document.createElement('button');
    dlBtn.className = 'item-download-btn';
    dlBtn.type = 'button';
    dlBtn.textContent = 'Download';
    dlBtn.addEventListener('click', (e) => {
      e.preventDefault();
      window.browserAPI.downloadVideo({
        url: media.url,
        referrer: media.sourcePage || ''
      });
    });

    item.appendChild(check);
    item.appendChild(icon);
    item.appendChild(info);
    item.appendChild(dlBtn);

    mediaList.appendChild(item);
  });

  updateSelectionCount();
}

// Event Listeners for Tabs
addTabBtn.addEventListener('click', () => window.browserAPI.createTab());

// Responding to events from main process (State Sync)
window.browserAPI.onUrlChanged((url) => {
  input.value = url;
});

window.browserAPI.onNavigationStateChange((state) => {
  btnBack.disabled = !state.canGoBack;
  btnForward.disabled = !state.canGoForward;
  
  if (state.canGoBack) btnBack.style.opacity = '1';
  else btnBack.style.opacity = '0.5';
  
  if (state.canGoForward) btnForward.style.opacity = '1';
  else btnForward.style.opacity = '0.5';

  // State sync for video detector badge
  if (state.sniffedMedia && state.sniffedMedia.length > 0) {
    activeMediaSnippets = state.sniffedMedia;
    updateSnifferUiState();
    if (mediaModal.style.display === 'flex') {
      renderMediaList();
    }
  } else {
    activeMediaSnippets = [];
    updateSnifferUiState();

    if (mediaModal.style.display === 'flex') {
      renderMediaList();
    }
  }
});

window.browserAPI.onDomainScanStatus((status) => {
  updateDomainScanStatus(status || {});
});

// Render Dynamic Tabs
window.browserAPI.onTabsUpdated((tabsData) => {
  document.querySelectorAll('.tab').forEach(t => t.remove());

  tabsData.forEach(tabData => {
    const tabEl = document.createElement('div');
    tabEl.className = 'tab' + (tabData.isActive ? ' active' : '');
    
    const faviconEl = document.createElement('div');
    faviconEl.className = 'favicon';
    faviconEl.textContent = '🧭';
    
    const titleEl = document.createElement('div');
    titleEl.className = 'title';
    titleEl.textContent = tabData.title;
    
    const closeBtn = document.createElement('button');
    closeBtn.className = 'close-btn';
    closeBtn.innerHTML = '×';
    closeBtn.title = 'Close Tab';

    closeBtn.addEventListener('click', (e) => {
      e.stopPropagation(); 
      window.browserAPI.closeTab(tabData.id);
    });

    tabEl.addEventListener('click', () => {
      if (!tabData.isActive) window.browserAPI.switchTab(tabData.id);
    });

    tabEl.appendChild(faviconEl);
    tabEl.appendChild(titleEl);
    tabEl.appendChild(closeBtn);
    
    tabStrip.insertBefore(tabEl, addTabBtn);
  });
});

// Initial state
btnBack.style.opacity = '0.5';
btnForward.style.opacity = '0.5';
updateSnifferUiState();
updateDomainScanStatus({ running: false });
