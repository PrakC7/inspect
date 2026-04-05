const { app, BrowserWindow, BrowserView, ipcMain, dialog, session } = require('electron');
const path = require('path');
const fs = require('fs');
const dns = require('dns').promises;
const { spawn } = require('child_process');
const { ElectronBlocker } = require('@cliqz/adblocker-electron');
const fetch = require('cross-fetch');
const { installExtension } = require('electron-extension-installer');

let mainWindow;
let incognitoSession;
const tabs = new Map();
let activeTabId = null;
let tabCounter = 0;

const MEDIA_URL_PATTERN = /\.(mp4|m4v|m3u8|mpd|webm|mkv|mov|avi|flv|ts|m2ts|m4s|ismv|ism|mp3|m4a|aac|ogg|opus|wav)(?:$|[?#&])/i;
const MEDIA_RESOURCE_TYPES = new Set(['media', 'xhr', 'fetch', 'other']);
const IMAGE_URL_PATTERN = /\.(jpg|jpeg|png|webp|gif|bmp|svg|avif)(?:$|[?#&])/i;
const SIZE_PROBE_MAX_CONCURRENCY = 4;
const SIZE_PROBE_TIMEOUT_MS = 4500;
const DOMAIN_SCAN_NAV_TIMEOUT_MS = 15000;
const DOMAIN_SCAN_SCROLL_STEPS = 5;
const DOMAIN_SCAN_SCROLL_WAIT_MS = 180;
const DOMAIN_SCAN_SCROLL_MAX_ROUNDS = 36;
const DOMAIN_SCAN_SCROLL_IDLE_ROUNDS = 4;
const DOMAIN_SCAN_MAX_SUBDOMAINS = 80;
const DOMAIN_MEDIA_PROBE_TIMEOUT_MS = 4500;
const DOMAIN_MEDIA_PROBE_CONCURRENCY = 6;
const DOMAIN_MEDIA_PROBE_MAX_PER_PAGE = 45;
const BLOCK_NAVIGATION_REDIRECTS = true;
const ENABLE_STRICT_HARDENING = true;
const ENFORCE_LEGAL_USAGE_GUARDS = true;
const BLOCK_PRIVATE_NETWORK_ACCESS = true;
const ALLOW_DEVTOOLS = !ENABLE_STRICT_HARDENING;
const EXTERNAL_DISCOVERY_TOOL_TIMEOUT_MS = 22000;
const EXTERNAL_DISCOVERY_MAX_URLS_PER_TOOL = 2500;
const EXTERNAL_DISCOVERY_MAX_OUTPUT_CHARS = 1400000;
const LOCAL_TOOLS_BASE_DIR = path.join(__dirname, 'tools');
const LOCAL_KATANA_SOURCE_DIR = path.join(LOCAL_TOOLS_BASE_DIR, 'katana-dev', 'katana-dev');
const LOCAL_HAKRAWLER_SOURCE_DIR = path.join(LOCAL_TOOLS_BASE_DIR, 'hakrawler-master', 'hakrawler-master');
const LOCAL_LINKFINDER_SOURCE_DIR = path.join(LOCAL_TOOLS_BASE_DIR, 'LinkFinder-master', 'LinkFinder-master');
const LOCAL_ZAP_SOURCE_DIR = path.join(LOCAL_TOOLS_BASE_DIR, 'zaproxy-main', 'zaproxy-main');
const LOCAL_KATANA_EXE = path.join(LOCAL_KATANA_SOURCE_DIR, 'katana.exe');
const LOCAL_HAKRAWLER_EXE = path.join(LOCAL_HAKRAWLER_SOURCE_DIR, 'hakrawler.exe');
const DEFAULT_GO_EXE = 'C:\\Program Files\\Go\\bin\\go.exe';

const sizeProbeQueue = [];
let sizeProbeActiveCount = 0;
const sizeProbeInFlight = new Set();
const sizeProbeAttemptedAt = new Map();
const sizeProbeCache = new Map();
const mediaProbeCache = new Map();
const probeMergeInProgress = new Set();
const robotsCache = new Map();
const domainScanJobs = new Map();
const domainCrawlerWebContentsToTab = new Map();
const externalToolPreferredCandidate = new Map();
const externalToolUnavailable = new Set();
const legalConsentByRootDomain = new Set();

function applyHardeningCommandLineSwitches() {
  if (!ENABLE_STRICT_HARDENING) return;

  app.commandLine.appendSwitch('disable-background-networking');
  app.commandLine.appendSwitch('disable-default-apps');
  app.commandLine.appendSwitch('disable-sync');
  app.commandLine.appendSwitch('metrics-recording-only');
  app.commandLine.appendSwitch('no-first-run');
  app.commandLine.appendSwitch('no-pings');
  app.commandLine.appendSwitch('force-webrtc-ip-handling-policy', 'disable_non_proxied_udp');
  app.commandLine.appendSwitch('webrtc-ip-handling-policy', 'disable_non_proxied_udp');
  app.commandLine.appendSwitch(
    'disable-features',
    [
      'InterestCohortAPI',
      'PrivacySandboxSettings4',
      'AutofillServerCommunication',
      'OptimizationHints',
      'MediaRouter'
    ].join(',')
  );
}

applyHardeningCommandLineSwitches();

function parseHeaderValue(headers, key) {
  if (!headers) return '';
  const variants = [key, key.toLowerCase(), key.toUpperCase()];
  for (const variant of variants) {
    if (headers[variant] && headers[variant][0]) {
      return String(headers[variant][0]);
    }
  }
  return '';
}

function localPathExists(targetPath) {
  try {
    return fs.existsSync(targetPath);
  } catch {
    return false;
  }
}

function getGoCommand() {
  return localPathExists(DEFAULT_GO_EXE) ? DEFAULT_GO_EXE : 'go';
}

function runToolCommand(command, args = [], options = {}) {
  return new Promise((resolve) => {
    const timeoutMs = Number(options.timeoutMs || EXTERNAL_DISCOVERY_TOOL_TIMEOUT_MS);
    const cwd = options.cwd && localPathExists(options.cwd) ? options.cwd : undefined;
    const shell = options.shell === true;
    const stdinText = typeof options.stdinText === 'string' ? options.stdinText : '';

    let stdout = '';
    let stderr = '';
    let finished = false;

    let child;
    try {
      child = spawn(command, args, {
        cwd,
        windowsHide: true,
        shell
      });
    } catch (error) {
      resolve({ ok: false, code: -1, stdout: '', stderr: String(error.message || error), timedOut: false });
      return;
    }

    const finish = (payload) => {
      if (finished) return;
      finished = true;
      resolve(payload);
    };

    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        // ignore
      }
      finish({ ok: false, code: -1, stdout, stderr, timedOut: true });
    }, Math.max(1200, Number(timeoutMs || 0)));

    if (stdinText) {
      try {
        child.stdin.write(stdinText);
        child.stdin.end();
      } catch {
        // ignore stdin failures
      }
    }

    child.stdout.on('data', (chunk) => {
      if (stdout.length >= EXTERNAL_DISCOVERY_MAX_OUTPUT_CHARS) return;
      stdout += String(chunk || '');
      if (stdout.length > EXTERNAL_DISCOVERY_MAX_OUTPUT_CHARS) {
        stdout = stdout.slice(0, EXTERNAL_DISCOVERY_MAX_OUTPUT_CHARS);
      }
    });

    child.stderr.on('data', (chunk) => {
      if (stderr.length >= EXTERNAL_DISCOVERY_MAX_OUTPUT_CHARS) return;
      stderr += String(chunk || '');
      if (stderr.length > EXTERNAL_DISCOVERY_MAX_OUTPUT_CHARS) {
        stderr = stderr.slice(0, EXTERNAL_DISCOVERY_MAX_OUTPUT_CHARS);
      }
    });

    child.on('error', (error) => {
      clearTimeout(timer);
      finish({ ok: false, code: -1, stdout, stderr: String(error.message || error), timedOut: false });
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      finish({ ok: Number(code || 0) === 0, code: Number(code || 0), stdout, stderr, timedOut: false });
    });
  });
}

function extractUrlsFromToolOutput(output, baseUrl = '') {
  const text = String(output || '');
  if (!text.trim()) return [];

  const found = new Set();
  const addUrl = (raw) => {
    const candidate = String(raw || '').trim().replace(/["'<>\]\[()]+$/g, '').replace(/^["'<>\]\[()]+/g, '');
    if (!candidate) return;

    let parsed = '';
    try {
      if (/^https?:\/\//i.test(candidate)) {
        parsed = new URL(candidate).toString();
      } else if (baseUrl && (/^\//.test(candidate) || /^\?/.test(candidate) || /^\.\//.test(candidate) || /^\.\.\//.test(candidate))) {
        parsed = new URL(candidate, baseUrl).toString();
      }
    } catch {
      parsed = '';
    }

    if (!parsed) return;
    const lower = parsed.toLowerCase();
    if (!lower.startsWith('http://') && !lower.startsWith('https://')) return;
    found.add(parsed);
  };

  const absoluteMatches = text.match(/https?:\/\/[^\s"'<>`]+/gi) || [];
  absoluteMatches.forEach((item) => addUrl(item));

  const pathMatches = text.match(/(?:^|\s)(\/[^\s"'<>`]{2,})/gmi) || [];
  pathMatches.forEach((item) => addUrl(String(item || '').trim()));

  const lineParts = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  lineParts.forEach((line) => {
    if (line.length < 2 || line.length > 1800) return;
    addUrl(line);
    const eqSplit = line.split(/[\s=,:]+/);
    eqSplit.forEach((token) => {
      if (/^https?:\/\//i.test(token) || /^\//.test(token)) {
        addUrl(token);
      }
    });
  });

  return Array.from(found).slice(0, EXTERNAL_DISCOVERY_MAX_URLS_PER_TOOL);
}

function getExternalToolCommandCandidates(toolName, targetUrl) {
  const safeTarget = String(targetUrl || '').trim();
  if (!safeTarget) return [];

  const goCommand = getGoCommand();
  const localZapBat = path.join(LOCAL_ZAP_SOURCE_DIR, 'zap', 'src', 'main', 'dist', 'zap.bat');
  const localLinkFinderScript = path.join(LOCAL_LINKFINDER_SOURCE_DIR, 'linkfinder.py');

  switch (String(toolName || '').toLowerCase()) {
    case 'katana':
      return [
        {
          command: LOCAL_KATANA_EXE,
          args: ['-u', safeTarget, '-d', '5', '-silent', '-jc', '-dr'],
          cwd: LOCAL_KATANA_SOURCE_DIR,
          timeoutMs: 30000
        },
        {
          command: goCommand,
          args: ['run', './cmd/katana', '-u', safeTarget, '-d', '5', '-silent', '-jc', '-dr'],
          cwd: LOCAL_KATANA_SOURCE_DIR,
          timeoutMs: 32000
        },
        {
          command: 'docker',
          args: ['run', '--rm', 'projectdiscovery/katana:latest', '-u', safeTarget, '-d', '5', '-silent', '-dr'],
          timeoutMs: 34000
        },
        { command: 'katana', args: ['-u', safeTarget, '-d', '5', '-silent', '-dr'] },
        { command: 'katana', args: ['-u', safeTarget, '-d', '5', '-jc', '-dr'] }
      ];
    case 'hakrawler':
      return [
        {
          command: goCommand,
          args: ['run', '.', '-d', '4', '-subs', '-u', '-dr'],
          cwd: LOCAL_HAKRAWLER_SOURCE_DIR,
          stdinText: `${safeTarget}\n`,
          timeoutMs: 32000
        },
        {
          command: LOCAL_HAKRAWLER_EXE,
          args: ['-d', '4', '-subs', '-u', '-dr'],
          cwd: LOCAL_HAKRAWLER_SOURCE_DIR,
          stdinText: `${safeTarget}\n`,
          timeoutMs: 30000
        },
        {
          command: 'docker',
          args: ['run', '--rm', '-i', 'hakluke/hakrawler:v2', '-d', '4', '-subs', '-u', '-dr'],
          stdinText: `${safeTarget}\n`,
          timeoutMs: 34000
        },
        { command: 'hakrawler', args: ['-d', '4', '-subs', '-u', '-dr'], stdinText: `${safeTarget}\n` },
        { command: 'hakrawler', args: ['-d', '3', '-u', '-dr'], stdinText: `${safeTarget}\n` }
      ];
    case 'linkfinder':
      return [
        {
          command: 'py',
          args: ['-3', localLinkFinderScript, '-i', safeTarget, '-d', '-o', 'cli'],
          cwd: LOCAL_LINKFINDER_SOURCE_DIR,
          timeoutMs: 28000
        },
        {
          command: 'python',
          args: [localLinkFinderScript, '-i', safeTarget, '-d', '-o', 'cli'],
          cwd: LOCAL_LINKFINDER_SOURCE_DIR,
          timeoutMs: 28000
        },
        {
          command: 'py',
          args: [localLinkFinderScript, '-i', safeTarget, '-d', '-o', 'cli'],
          cwd: LOCAL_LINKFINDER_SOURCE_DIR,
          timeoutMs: 28000
        },
        { command: 'linkfinder', args: ['-i', safeTarget, '-o', 'cli'] },
        { command: 'py', args: ['-3', '-m', 'linkfinder', '-i', safeTarget, '-o', 'cli'] },
        { command: 'python', args: ['-m', 'linkfinder', '-i', safeTarget, '-o', 'cli'] },
        { command: 'py', args: ['-m', 'linkfinder', '-i', safeTarget, '-o', 'cli'] }
      ];
    case 'zap':
      return [
        {
          command: localZapBat,
          args: ['-cmd', '-quickurl', safeTarget, '-quickprogress'],
          cwd: path.dirname(localZapBat),
          shell: true,
          timeoutMs: 42000
        },
        { command: 'zap-cli', args: ['quick-scan', '--spider', safeTarget] },
        { command: 'zap.bat', args: ['-cmd', '-quickurl', safeTarget, '-quickprogress'], shell: true },
        { command: 'zap.sh', args: ['-cmd', '-quickurl', safeTarget, '-quickprogress'] }
      ];
    default:
      return [];
  }
}

async function runExternalDiscoveryTool(toolName, targetUrl) {
  const normalizedToolName = String(toolName || '').toLowerCase();
  if (externalToolUnavailable.has(normalizedToolName)) {
    return { tool: normalizedToolName, attempted: false, available: false, urls: [] };
  }

  const candidates = getExternalToolCommandCandidates(toolName, targetUrl);
  if (candidates.length === 0) {
    externalToolUnavailable.add(normalizedToolName);
    return { tool: normalizedToolName, attempted: false, available: false, urls: [] };
  }

  const preferred = externalToolPreferredCandidate.get(normalizedToolName);
  const orderedCandidates = preferred
    ? [preferred, ...candidates.filter((candidate) => !(candidate.command === preferred.command && JSON.stringify(candidate.args || []) === JSON.stringify(preferred.args || []) && String(candidate.cwd || '') === String(preferred.cwd || '')))]
    : candidates;

  let onlyMissingToolErrors = true;
  let anyRunnableCandidate = false;

  for (const candidate of orderedCandidates) {
    const result = await runToolCommand(candidate.command, candidate.args, {
      timeoutMs: candidate.timeoutMs || EXTERNAL_DISCOVERY_TOOL_TIMEOUT_MS,
      cwd: candidate.cwd,
      stdinText: candidate.stdinText,
      shell: candidate.shell
    });

    const combinedOutput = `${result.stdout || ''}\n${result.stderr || ''}`;
    const urls = extractUrlsFromToolOutput(combinedOutput, targetUrl);

    const stderrLower = String(result.stderr || '').toLowerCase();
    const blockedByPolicy =
      stderrLower.includes('application control policy has blocked this file') ||
      stderrLower.includes('has blocked this file');

    if (result.ok || urls.length > 0) {
      externalToolPreferredCandidate.set(normalizedToolName, candidate);
      return {
        tool: normalizedToolName,
        attempted: true,
        available: true,
        command: candidate.command,
        urls,
        timedOut: Boolean(result.timedOut)
      };
    }

    const missingTool = /not recognized|not found|enoent|cannot find|is not recognized/i.test(String(result.stderr || ''));
    if (!missingTool && !blockedByPolicy) {
      anyRunnableCandidate = true;
    }
    if (!missingTool) {
      onlyMissingToolErrors = false;
    }
  }

  if (onlyMissingToolErrors) {
    externalToolUnavailable.add(normalizedToolName);
  }

  if (anyRunnableCandidate) {
    return { tool: normalizedToolName, attempted: true, available: true, urls: [] };
  }

  return { tool: normalizedToolName, attempted: true, available: false, urls: [] };
}

function mergeExternalDiscoveredUrlsIntoJob(tabId, job, urls = [], sourcePage = '') {
  if (!tabs.has(tabId) || !job || !Array.isArray(urls)) return { queued: 0, media: 0 };

  let queuedCount = 0;
  let mediaCount = 0;

  urls.forEach((rawUrl) => {
    const normalized = normalizeCrawlPageUrl(rawUrl);
    if (!normalized) return;
    if (!isWithinRootDomain(normalized, job.rootDomain)) return;
    if (job.externalDiscoveredUrls.has(normalized)) return;
    job.externalDiscoveredUrls.add(normalized);

    const linkUrl = safeUrl(normalized);
    const host = linkUrl ? linkUrl.hostname.toLowerCase() : '';
    if (host && !job.discoveredHosts.has(host) && job.discoveredHosts.size < job.maxSubdomains) {
      job.discoveredHosts.add(host);
      job.hostQueue.push(host);
    }

    if (isLikelyMediaUrl(normalized) || IMAGE_URL_PATTERN.test(normalized)) {
      addMediaCandidateToTab(tabId, {
        url: normalized,
        type: 'external-discovery',
        sourceScope: 'domain',
        sourcePage: sourcePage || normalized
      });
      mediaCount += 1;
    }

    if (host && !job.scannedHosts.has(host)) {
      return;
    }

    if (!job.overrideRobots && !isPathAllowedByRobots(normalized, job.robotsPolicy)) return;
    if (job.visited.has(normalized) || job.queued.has(normalized)) return;
    if (job.visited.size + job.queue.length >= job.maxPages) return;

    job.queued.add(normalized);
    job.queue.push(normalized);
    queuedCount += 1;
  });

  return { queued: queuedCount, media: mediaCount };
}

async function runExternalDiscoveryForHost(tabId, job, host) {
  if (!tabs.has(tabId) || !job || !job.active || !job.useExternalTools) return;
  const hostLower = String(host || '').toLowerCase();
  if (!hostLower) return;
  if (job.externalDiscoveryHostsInFlight.has(hostLower) || job.externalDiscoveryHostsDone.has(hostLower)) return;

  job.externalDiscoveryHostsInFlight.add(hostLower);
  const targetUrl = normalizeCrawlPageUrl(`https://${hostLower}/`) || `https://${hostLower}/`;

  try {
    for (const toolName of job.externalTools) {
      if (!job.active || !tabs.has(tabId)) break;

      emitDomainScanStatus(tabId, {
        stage: 'external-discovery',
        externalTool: toolName,
        externalHost: hostLower
      });

      const result = await runExternalDiscoveryTool(toolName, targetUrl);
      if (!result.available || !Array.isArray(result.urls) || result.urls.length === 0) continue;

      const merged = mergeExternalDiscoveredUrlsIntoJob(tabId, job, result.urls, targetUrl);
      if (merged.media > 0 || merged.queued > 0) {
        emitDomainScanStatus(tabId, {
          stage: 'external-discovery',
          externalTool: toolName,
          externalHost: hostLower,
          externalFound: Number(result.urls.length || 0),
          externalQueued: merged.queued,
          externalMedia: merged.media
        });
      }
    }
  } catch (error) {
    console.log(`External discovery failed for host ${hostLower}:`, error && (error.message || String(error)));
  } finally {
    job.externalDiscoveryHostsInFlight.delete(hostLower);
    job.externalDiscoveryHostsDone.add(hostLower);
    if (job.active) {
      emitDomainScanStatus(tabId, { stage: 'crawling', externalHost: hostLower });
      pumpDomainScan(tabId);
    }
  }
}

function withTimeout(promise, timeoutMs, timeoutMessage) {
  let timeoutId;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
  });

  return Promise.race([promise, timeoutPromise]).finally(() => {
    clearTimeout(timeoutId);
  });
}

function safeUrl(input) {
  try {
    return new URL(String(input));
  } catch {
    return null;
  }
}

function normalizeMediaUrl(url) {
  const urlObj = safeUrl(url);
  if (!urlObj) return '';
  urlObj.hash = '';

  const cleanParams = [];
  for (const [key, value] of urlObj.searchParams.entries()) {
    const lowerKey = key.toLowerCase();
    if (
      lowerKey.startsWith('utm_') ||
      lowerKey === 'fbclid' ||
      lowerKey === 'gclid' ||
      lowerKey === 'igshid' ||
      lowerKey === 'ref'
    ) {
      continue;
    }
    cleanParams.push([key, value]);
  }
  cleanParams.sort((a, b) => `${a[0]}=${a[1]}`.localeCompare(`${b[0]}=${b[1]}`));
  urlObj.search = '';
  for (const [key, value] of cleanParams) {
    urlObj.searchParams.append(key, value);
  }

  return urlObj.toString();
}

function deriveRootDomain(hostname) {
  const host = String(hostname || '').toLowerCase();
  const labels = host.replace(/^www\./, '').split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  return labels.slice(-2).join('.');
}

function isPrivateOrLocalHost(hostname = '') {
  const host = String(hostname || '').trim().toLowerCase();
  if (!host) return true;

  if (
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '::1' ||
    host.endsWith('.local') ||
    host.endsWith('.localdomain') ||
    host.endsWith('.internal') ||
    host.endsWith('.lan')
  ) {
    return true;
  }

  const ipv4 = host.match(/^(\d{1,3})(?:\.(\d{1,3})){3}$/);
  if (ipv4) {
    const parts = host.split('.').map((p) => Number.parseInt(p, 10));
    if (parts.some((part) => !Number.isFinite(part) || part < 0 || part > 255)) return true;
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 0) return true;
  }

  if (host.includes(':')) {
    if (host.startsWith('fe80:') || host.startsWith('fc') || host.startsWith('fd')) return true;
  }

  return false;
}

function getLegalBlockMessageForReason(reason = 'blocked') {
  const key = String(reason || '').toLowerCase();
  if (key === 'private-network-blocked') {
    return 'Access to local/private-network targets is blocked in legal-safe mode.';
  }
  if (key === 'insecure-url-blocked') {
    return 'Only HTTPS targets are allowed in legal-safe mode.';
  }
  if (key === 'robots-disallow-all') {
    return 'robots.txt disallows crawling for this target.';
  }
  if (key === 'robots-path-disallowed') {
    return 'Requested path is disallowed by robots.txt policy.';
  }
  if (key === 'legal-consent-declined') {
    return 'You declined legal authorization confirmation for this domain.';
  }
  return 'Operation blocked by legal-safe compliance policy.';
}

function ensureLegalConsentForRootDomain(rootDomain = '', actionLabel = 'operation') {
  const domain = String(rootDomain || '').trim().toLowerCase();
  if (!domain) return false;
  if (legalConsentByRootDomain.has(domain)) return true;

  const response = dialog.showMessageBoxSync(mainWindow, {
    type: 'question',
    buttons: ['Cancel', 'I Am Authorized'],
    defaultId: 0,
    cancelId: 0,
    title: 'Legal Authorization Required',
    message: `Confirm legal authorization before ${actionLabel}`,
    detail: `Domain: ${domain}\n\nBy continuing, you confirm that:\n- You are authorized to access/download this media.\n- Your use complies with local laws, site terms, and copyright rules in your region.\n\nIf unsure, cancel.`
  });

  if (response !== 1) return false;
  legalConsentByRootDomain.add(domain);
  return true;
}

async function ensureLegalAccessForUrl(targetUrl, actionLabel = 'operation') {
  const target = safeUrl(targetUrl);
  if (!target) return { ok: false, reason: 'insecure-url-blocked' };
  if (target.protocol !== 'https:') return { ok: false, reason: 'insecure-url-blocked' };

  if (BLOCK_PRIVATE_NETWORK_ACCESS && isPrivateOrLocalHost(target.hostname)) {
    return { ok: false, reason: 'private-network-blocked' };
  }

  const policy = await getRobotsPolicyForUrl(target.toString());
  if (robotsDisallowAll(policy)) {
    return { ok: false, reason: 'robots-disallow-all', policy };
  }
  if (!isPathAllowedByRobots(target.toString(), policy)) {
    return { ok: false, reason: 'robots-path-disallowed', policy };
  }

  const rootDomain = deriveRootDomain(target.hostname);
  if (!ensureLegalConsentForRootDomain(rootDomain, actionLabel)) {
    return { ok: false, reason: 'legal-consent-declined', policy };
  }

  return { ok: true, policy, rootDomain };
}

function isWithinRootDomain(candidateUrl, rootDomain) {
  const candidate = safeUrl(candidateUrl);
  if (!candidate) return false;
  const host = candidate.hostname.toLowerCase();
  return host === rootDomain || host.endsWith(`.${rootDomain}`);
}

function shouldBlockNavigationRedirect(fromUrl, toUrl, rootDomain = '') {
  if (!BLOCK_NAVIGATION_REDIRECTS) return false;

  const target = safeUrl(toUrl);
  if (!target) return true;
  if (target.protocol !== 'https:') return true;

  if (rootDomain) {
    return !isWithinRootDomain(target.toString(), rootDomain);
  }

  const from = safeUrl(fromUrl);
  if (!from) return false;
  return normalizeCrawlPageUrl(from.toString()) !== normalizeCrawlPageUrl(target.toString());
}

function normalizeCrawlPageUrl(url) {
  const urlObj = safeUrl(url);
  if (!urlObj) return '';
  urlObj.hash = '';
  if (urlObj.pathname.endsWith('/') && urlObj.pathname !== '/') {
    urlObj.pathname = urlObj.pathname.slice(0, -1);
  }
  return urlObj.toString();
}

function guessFormatFromTypeOrExt(type = '', extension = '', url = '') {
  if (extension) return extension.toLowerCase();

  const typePart = String(type).toLowerCase();
  if (typePart.includes('/')) {
    return typePart.split('/')[1].split(';')[0].trim();
  }

  const urlObj = safeUrl(url);
  if (!urlObj) return '';
  const match = urlObj.pathname.toLowerCase().match(/\.([a-z0-9]{2,5})$/i);
  return match ? match[1] : '';
}

function classifyMediaType(type = '', extension = '', url = '') {
  const lowerType = String(type).toLowerCase();
  const fmt = guessFormatFromTypeOrExt(lowerType, extension, url);
  if (fmt === 'gif') return 'gif';
  if (fmt === 'svg') return 'svg';
  if (lowerType.startsWith('image/') || IMAGE_URL_PATTERN.test(url) || ['jpg', 'jpeg', 'png', 'webp', 'bmp', 'avif'].includes(fmt)) return 'image';
  if (lowerType.startsWith('video/') || ['mp4', 'm4v', 'webm', 'mkv', 'mov', 'avi', 'flv', 'ts', 'm2ts', 'm4s', 'ismv', 'ism', 'm3u8', 'mpd'].includes(fmt)) return 'video';
  if (lowerType.startsWith('audio/') || ['mp3', 'm4a', 'aac', 'ogg', 'opus', 'wav'].includes(fmt)) return 'audio';
  return 'media';
}

function normalizeDimension(value) {
  const parsed = Number.parseInt(String(value || '0'), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function detectQuality(width, height) {
  const w = normalizeDimension(width);
  const h = normalizeDimension(height);
  if (!w && !h) return 'Unknown';

  const maxDim = Math.max(w || 0, h || 0);

  if (h > 0 && h >= 700 && h < 900) return '720p';
  if (w > 0 && w >= 1200 && w < 1600) return '720p';
  if (maxDim >= 7680) return '8K';
  if (maxDim >= 3840) return '4K';
  if (maxDim >= 2560) return 'QHD';
  if (maxDim >= 1920) return 'HD';
  if (maxDim >= 1280) return 'SD+';
  return 'SD';
}

function normalizeQualityTag(tag = '') {
  const value = String(tag || '').trim().toUpperCase();
  if (!value) return '';
  if (value === 'TOP' || value === 'MAX') return 'TOP';
  if (value === '720P' || value === '720') return '720P';
  return value;
}

function qualityTagRank(tag = '') {
  const normalized = normalizeQualityTag(tag);
  if (normalized === 'TOP') return 3;
  if (normalized === '720P') return 2;
  if (normalized) return 1;
  return 0;
}

function formatResolution(width, height) {
  const w = normalizeDimension(width);
  const h = normalizeDimension(height);
  if (w > 0 && h > 0) return `${w}x${h}`;
  if (w > 0) return `${w}x?`;
  if (h > 0) return `?x${h}`;
  return 'Unknown';
}

function inferQualityFromUrl(url = '') {
  const lower = String(url || '').toLowerCase();
  let width = 0;
  let height = 0;
  let qualityTag = '';

  const resMatch = lower.match(/(\d{3,5})x(\d{3,5})/i);
  if (resMatch) {
    width = Number.parseInt(resMatch[1], 10) || 0;
    height = Number.parseInt(resMatch[2], 10) || 0;
  }

  if (height === 0) {
    const pMatch = lower.match(/(?:_|-|\/|\.)(240|360|480|540|720|1080|1440|2160|4320)p(?:_|-|\/|\.|$)/i);
    if (pMatch) {
      height = Number.parseInt(pMatch[1], 10) || 0;
      if (height > 0 && width === 0) {
        width = Math.round((height * 16) / 9);
      }
    }
  }

  if (lower.includes('4k') || lower.includes('2160p')) {
    qualityTag = 'TOP';
    if (!height) {
      height = 2160;
      width = 3840;
    }
  }

  if (!qualityTag && (lower.includes('1080p') || lower.includes('fhd'))) {
    qualityTag = 'TOP';
    if (!height) {
      height = 1080;
      width = 1920;
    }
  }

  if (!qualityTag && (lower.includes('720p') || lower.includes('hd'))) {
    qualityTag = '720P';
    if (!height) {
      height = 720;
      width = 1280;
    }
  }

  const quality = detectQuality(width, height);
  return {
    width,
    height,
    quality,
    qualityTag: normalizeQualityTag(qualityTag)
  };
}

function deriveMediaGroupKey(url, category = 'media') {
  const urlObj = safeUrl(url);
  if (!urlObj) return '';
  const copy = new URL(urlObj.toString());

  if (String(category).toLowerCase() === 'image' || String(category).toLowerCase() === 'gif' || String(category).toLowerCase() === 'svg') {
    ['w', 'width', 'h', 'height', 'dpr', 'q', 'quality', 'fit', 'crop', 'fm', 'format', 'auto'].forEach((key) => {
      copy.searchParams.delete(key);
    });
  }

  copy.hash = '';
  return copy.toString();
}

function sanitizeMediaFilter(raw = {}) {
  const type = String(raw.type || '').trim().toLowerCase();
  const format = String(raw.format || '').trim().toLowerCase();
  const minWidth = normalizeDimension(raw.minWidth);
  const minHeight = normalizeDimension(raw.minHeight);
  const minSizeBytes = Math.max(0, Number(raw.minSizeBytes || 0));
  const maxSizeBytes = Math.max(0, Number(raw.maxSizeBytes || 0));

  return {
    type,
    format,
    minWidth,
    minHeight,
    minSizeBytes,
    maxSizeBytes
  };
}

function filterRequiresKnownSize(filter) {
  return Number(filter.minSizeBytes || 0) > 0 || Number(filter.maxSizeBytes || 0) > 0;
}

function mediaPassesFilter(media, filter) {
  if (!filter) return true;
  const type = String(media.category || media.type || '').toLowerCase();
  const rawType = String(media.type || '').toLowerCase();
  const format = String(media.format || '').toLowerCase();
  const width = normalizeDimension(media.width);
  const height = normalizeDimension(media.height);
  const sizeRaw = Number(media.sizeRaw || 0);
  const videoLike = type === 'video' || rawType.startsWith('video/') || isStreamLikeMedia(media.url, rawType);

  if (filter.type && type !== filter.type) return false;
  if (filter.format && format !== filter.format) return false;

  if (filter.minWidth > 0 && width < filter.minWidth) return false;
  if (filter.minHeight > 0 && height < filter.minHeight) return false;

  if (filterRequiresKnownSize(filter) && sizeRaw <= 0) {
    // Keep likely stream videos visible while metadata/size probing is in progress.
    if (!(filter.type === 'video' && videoLike)) {
      return false;
    }
  }
  if (filter.minSizeBytes > 0 && sizeRaw < filter.minSizeBytes) return false;
  if (filter.maxSizeBytes > 0 && sizeRaw > filter.maxSizeBytes) return false;

  return true;
}

function parseRobotsTxt(content = '') {
  const lines = String(content).split(/\r?\n/);
  const groups = [];
  let currentGroup = null;

  for (const lineRaw of lines) {
    const line = lineRaw.split('#')[0].trim();
    if (!line) continue;

    const sep = line.indexOf(':');
    if (sep === -1) continue;
    const key = line.slice(0, sep).trim().toLowerCase();
    const value = line.slice(sep + 1).trim();

    if (key === 'user-agent') {
      currentGroup = { userAgents: [value.toLowerCase()], allow: [], disallow: [] };
      groups.push(currentGroup);
      continue;
    }

    if (!currentGroup) continue;
    if (key === 'allow') currentGroup.allow.push(value);
    if (key === 'disallow') currentGroup.disallow.push(value);
  }

  const wildcardGroup = groups.find((g) => g.userAgents.includes('*')) || { allow: [], disallow: [] };
  return {
    allow: wildcardGroup.allow.filter(Boolean),
    disallow: wildcardGroup.disallow.filter(Boolean)
  };
}

function inferWidthFromUrl(url) {
  const urlObj = safeUrl(url);
  if (!urlObj) return 0;
  const possibleKeys = ['w', 'width', 'im_w', 'mw'];
  for (const key of possibleKeys) {
    const value = Number.parseInt(urlObj.searchParams.get(key) || '0', 10);
    if (Number.isFinite(value) && value > 0) return value;
  }
  return 0;
}

function extractLinksAndMediaFromHtml(html, pageUrl) {
  const links = new Set();
  const mediaMap = new Map();

  const toAbs = (value) => {
    if (!value || typeof value !== 'string') return '';
    try {
      return new URL(value.trim(), pageUrl).toString();
    } catch {
      return '';
    }
  };

  const maybeAddMedia = (absolute, typeHint = 'media') => {
    if (!absolute) return;
    const lower = absolute.toLowerCase();
    if (lower.startsWith('data:') || lower.startsWith('blob:') || lower.startsWith('javascript:')) return;

    const isMedia =
      IMAGE_URL_PATTERN.test(lower) ||
      MEDIA_URL_PATTERN.test(lower) ||
      lower.includes('mime=video') ||
      lower.includes('mime=audio') ||
      lower.includes('image=');

    if (!isMedia) return;

    if (!mediaMap.has(absolute)) {
      mediaMap.set(absolute, {
        url: absolute,
        type: String(typeHint || 'media').toLowerCase(),
        sourceScope: 'domain',
        sourcePage: pageUrl,
        width: inferWidthFromUrl(absolute),
        height: 0,
        sizeRaw: 0
      });
    }
  };

  const attrRegex = /(href|src|poster)\s*=\s*["']([^"']+)["']/gi;
  let match;
  while ((match = attrRegex.exec(html)) !== null) {
    const raw = match[2] || '';
    const absolute = toAbs(raw);
    if (!absolute) continue;
    links.add(absolute);
    maybeAddMedia(absolute, match[1] === 'poster' ? 'image' : 'resource');
  }

  const srcSetRegex = /srcset\s*=\s*["']([^"']+)["']/gi;
  while ((match = srcSetRegex.exec(html)) !== null) {
    const value = match[1] || '';
    value.split(',').forEach((entry) => {
      const src = entry.trim().split(/\s+/)[0];
      const absolute = toAbs(src);
      maybeAddMedia(absolute, 'image');
      if (absolute) links.add(absolute);
    });
  }

  const styleUrlRegex = /url\((['\"]?)(.*?)\1\)/gi;
  while ((match = styleUrlRegex.exec(html)) !== null) {
    const absolute = toAbs(match[2] || '');
    maybeAddMedia(absolute, 'image');
    if (absolute) links.add(absolute);
  }

  const absoluteUrlRegex = /https?:\/\/[^\s"'<>]+/gi;
  while ((match = absoluteUrlRegex.exec(html)) !== null) {
    const absolute = toAbs(match[0] || '');
    if (!absolute) continue;
    links.add(absolute);
    maybeAddMedia(absolute, 'resource');
  }

  return {
    links: Array.from(links).slice(0, 1200),
    media: Array.from(mediaMap.values()).slice(0, 1200)
  };
}

async function fetchPageSourceData(pageUrl) {
  if (!incognitoSession || typeof incognitoSession.fetch !== 'function') {
    return { links: [], media: [] };
  }

  try {
    const response = await withTimeout(
      incognitoSession.fetch(pageUrl, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          Accept: 'text/html,*/*;q=0.8'
        }
      }),
      9000,
      `html fetch timeout for ${pageUrl}`
    );

    if (!response.ok) return { links: [], media: [] };

    const contentType = String(response.headers.get('content-type') || '').toLowerCase();
    if (contentType && !contentType.includes('text/html')) {
      return { links: [], media: [] };
    }

    const html = await response.text();
    if (!html) return { links: [], media: [] };
    return extractLinksAndMediaFromHtml(html, pageUrl);
  } catch {
    return { links: [], media: [] };
  }
}

function isMediaContentType(contentType = '') {
  const lower = String(contentType || '').toLowerCase();
  return (
    lower.startsWith('video/') ||
    lower.startsWith('audio/') ||
    lower.startsWith('image/') ||
    lower.includes('mpegurl') ||
    lower.includes('dash+xml')
  );
}

function looksPotentialMediaEndpoint(url) {
  const lower = String(url || '').toLowerCase();
  if (!lower) return false;
  if (MEDIA_URL_PATTERN.test(lower) || IMAGE_URL_PATTERN.test(lower)) return true;
  return (
    lower.includes('video') ||
    lower.includes('stream') ||
    lower.includes('playlist') ||
    lower.includes('manifest') ||
    lower.includes('media') ||
    lower.includes('source') ||
    lower.includes('download') ||
    lower.includes('mime=video') ||
    lower.includes('mime=audio') ||
    lower.includes('format=mp4') ||
    lower.includes('ext=mp4')
  );
}

async function probeDomainMediaEndpoint(url, sourcePage) {
  if (!incognitoSession || typeof incognitoSession.fetch !== 'function') {
    return null;
  }

  const doFetch = async (options) => {
    return await withTimeout(
      incognitoSession.fetch(url, {
        redirect: 'manual',
        ...options
      }),
      DOMAIN_MEDIA_PROBE_TIMEOUT_MS,
      `media probe timeout for ${url}`
    );
  };

  try {
    const head = await doFetch({ method: 'HEAD', headers: { Accept: '*/*' } });
    const headStatus = Number(head.status || 0);
    if (headStatus >= 300 || isUnauthorizedStatusCode(headStatus)) {
      return null;
    }
    const contentType = String(head.headers.get('content-type') || '').toLowerCase();
    const len = Number.parseInt(head.headers.get('content-length') || '0', 10);

    if (isMediaContentType(contentType)) {
      return {
        url,
        type: contentType || 'media',
        sourceScope: 'domain',
        sourcePage,
        sizeRaw: Number.isFinite(len) ? len : 0,
        width: 0,
        height: 0
      };
    }

    if (contentType.includes('text/html')) {
      return null;
    }
  } catch {
    // fall through to range probe
  }

  try {
    const range = await doFetch({
      method: 'GET',
      headers: {
        Accept: '*/*',
        Range: 'bytes=0-0'
      }
    });

    const rangeStatus = Number(range.status || 0);
    if (rangeStatus >= 300 || isUnauthorizedStatusCode(rangeStatus)) {
      return null;
    }

    const contentType = String(range.headers.get('content-type') || '').toLowerCase();
    const contentLength = Number.parseInt(range.headers.get('content-length') || '0', 10);
    const rangeTotal = parseTotalFromContentRange(range.headers.get('content-range') || '');

    if (isMediaContentType(contentType)) {
      return {
        url,
        type: contentType || 'media',
        sourceScope: 'domain',
        sourcePage,
        sizeRaw: rangeTotal || (Number.isFinite(contentLength) ? contentLength : 0),
        width: 0,
        height: 0
      };
    }
  } catch {
    return null;
  }

  return null;
}

async function probeDomainMediaLinks(tabId, sourcePage, links, job) {
  if (!Array.isArray(links) || links.length === 0 || !tabs.has(tabId)) return;

  const candidates = [];
  for (const link of links) {
    const normalized = normalizeCrawlPageUrl(link);
    if (!normalized) continue;
    if (!looksPotentialMediaEndpoint(normalized)) continue;
    if (!isWithinRootDomain(normalized, job.rootDomain)) continue;
    if (job.probedMediaUrls.has(normalized)) continue;

    job.probedMediaUrls.add(normalized);
    candidates.push(normalized);
    if (candidates.length >= DOMAIN_MEDIA_PROBE_MAX_PER_PAGE) break;
  }

  if (candidates.length === 0) return;

  let idx = 0;
  const workers = new Array(Math.min(DOMAIN_MEDIA_PROBE_CONCURRENCY, candidates.length)).fill(0).map(async () => {
    while (idx < candidates.length) {
      const current = candidates[idx];
      idx += 1;
      const media = await probeDomainMediaEndpoint(current, sourcePage);
      if (media) {
        addMediaCandidateToTab(tabId, media);
      }
    }
  });

  await Promise.all(workers);
}

async function getRobotsPolicyForUrl(url) {
  const urlObj = safeUrl(url);
  if (!urlObj) return { allow: [], disallow: [] };
  const origin = `${urlObj.protocol}//${urlObj.hostname}`;
  if (robotsCache.has(origin)) {
    return robotsCache.get(origin);
  }

  let policy = { allow: [], disallow: [] };
  try {
    const response = await withTimeout(
      incognitoSession.fetch(`${origin}/robots.txt`, { method: 'GET', redirect: 'follow' }),
      4000,
      'robots timeout'
    );
    if (response.ok) {
      const content = await response.text();
      policy = parseRobotsTxt(content);
    }
  } catch {
    policy = { allow: [], disallow: [] };
  }

  robotsCache.set(origin, policy);
  return policy;
}

function isPathAllowedByRobots(url, policy) {
  if (!policy) return true;
  const urlObj = safeUrl(url);
  if (!urlObj) return false;

  const path = `${urlObj.pathname || '/'}${urlObj.search || ''}`;
  const allowMatches = (policy.allow || []).filter((rule) => rule && path.startsWith(rule));
  const disallowMatches = (policy.disallow || []).filter((rule) => rule && path.startsWith(rule));
  const bestAllow = allowMatches.sort((a, b) => b.length - a.length)[0] || '';
  const bestDisallow = disallowMatches.sort((a, b) => b.length - a.length)[0] || '';

  if (!bestDisallow) return true;
  return bestAllow.length >= bestDisallow.length;
}

function robotsDisallowAll(policy) {
  if (!policy) return false;
  const allowRules = Array.isArray(policy.allow) ? policy.allow : [];
  const disallowRules = Array.isArray(policy.disallow) ? policy.disallow : [];

  const hasGlobalDisallow = disallowRules.some((rule) => {
    const value = String(rule || '').trim();
    return value === '/' || value === '/*';
  });
  if (!hasGlobalDisallow) return false;

  const hasGlobalAllow = allowRules.some((rule) => {
    const value = String(rule || '').trim();
    return value === '/' || value === '/*';
  });

  return !hasGlobalAllow;
}

function isUnauthorizedStatusCode(statusCode = 0) {
  const code = Number(statusCode || 0);
  return code === 401 || code === 403 || code === 407 || code === 451;
}

function getPreferredSubdomainPrefixes() {
  return ['www', 'm', 'img', 'images', 'media', 'cdn', 'static', 'video', 'files', 'assets'];
}

async function hostResolves(hostname) {
  try {
    await withTimeout(dns.lookup(hostname), 1800, `dns timeout for ${hostname}`);
    return true;
  } catch {
    return false;
  }
}

async function discoverInitialSubdomains(rootDomain) {
  const normalizedRoot = String(rootDomain || '').trim().toLowerCase();
  if (!normalizedRoot) return [rootDomain];

  const candidates = [
    normalizedRoot,
    ...getPreferredSubdomainPrefixes().map((prefix) => `${prefix}.${normalizedRoot}`)
  ];

  const discovered = new Set([normalizedRoot]);
  await Promise.all(
    candidates.map(async (candidate) => {
      if (await hostResolves(candidate)) {
        discovered.add(candidate.toLowerCase());
      }
    })
  );

  return Array.from(discovered).slice(0, DOMAIN_SCAN_MAX_SUBDOMAINS);
}

function formatByteSize(sizeRaw, fallbackUrl = '') {
  if (Number.isFinite(sizeRaw) && sizeRaw > 0) {
    if (sizeRaw >= 1024 * 1024) {
      return `${(sizeRaw / (1024 * 1024)).toFixed(2)} MB`;
    }
    return `${Math.max(1, Math.floor(sizeRaw / 1024))} KB`;
  }
  if (String(fallbackUrl).toLowerCase().includes('.m3u8') || String(fallbackUrl).toLowerCase().includes('.mpd')) {
    return 'Stream';
  }
  return 'Unknown Size';
}

function isStreamLikeMedia(url = '', type = '') {
  const lowerUrl = String(url).toLowerCase();
  const lowerType = String(type).toLowerCase();
  return (
    lowerUrl.includes('.m3u8') ||
    lowerUrl.includes('.mpd') ||
    lowerType.includes('mpegurl') ||
    lowerType.includes('dash+xml')
  );
}

function parseTotalFromContentRange(contentRange) {
  const value = String(contentRange || '');
  const match = value.match(/\/(\d+)\s*$/);
  if (!match) return 0;
  const total = Number.parseInt(match[1], 10);
  return Number.isFinite(total) && total > 0 ? total : 0;
}

function inferExtension(url) {
  try {
    const urlObj = new URL(url);
    const match = urlObj.pathname.toLowerCase().match(/\.([a-z0-9]{2,5})$/i);
    return match ? match[1] : '';
  } catch {
    return '';
  }
}

function isLikelyMediaUrl(url) {
  if (!url) return false;
  const lower = String(url).toLowerCase();
  if (lower.startsWith('blob:') || lower.startsWith('data:')) return false;
  if (MEDIA_URL_PATTERN.test(lower)) return true;
  return (
    lower.includes('mime=video') ||
    lower.includes('mime=audio') ||
    lower.includes('video=') ||
    lower.includes('audio=') ||
    lower.includes('manifest') ||
    lower.includes('playlist') ||
    lower.includes('.ism/')
  );
}

function resolveSourceTabIdFromWebContentsId(webContentsId) {
  if (domainCrawlerWebContentsToTab.has(webContentsId)) {
    const mappedTabId = domainCrawlerWebContentsToTab.get(webContentsId);
    if (tabs.has(mappedTabId)) {
      return mappedTabId;
    }
    domainCrawlerWebContentsToTab.delete(webContentsId);
  }

  for (const [id, tab] of tabs.entries()) {
    const wc = tab && tab.view ? tab.view.webContents : null;
    if (!wc) continue;
    if (typeof wc.isDestroyed === 'function' && wc.isDestroyed()) continue;
    if (wc.id === webContentsId) {
      return id;
    }
  }
  return null;
}

function isDomainCrawlerWebContents(webContentsId) {
  return domainCrawlerWebContentsToTab.has(webContentsId);
}

function canGoBackSafe(webContentsRef) {
  if (!webContentsRef) return false;
  try {
    if (webContentsRef.navigationHistory && typeof webContentsRef.navigationHistory.canGoBack === 'function') {
      return webContentsRef.navigationHistory.canGoBack();
    }
    return typeof webContentsRef.canGoBack === 'function' ? webContentsRef.canGoBack() : false;
  } catch {
    return false;
  }
}

function canGoForwardSafe(webContentsRef) {
  if (!webContentsRef) return false;
  try {
    if (webContentsRef.navigationHistory && typeof webContentsRef.navigationHistory.canGoForward === 'function') {
      return webContentsRef.navigationHistory.canGoForward();
    }
    return typeof webContentsRef.canGoForward === 'function' ? webContentsRef.canGoForward() : false;
  } catch {
    return false;
  }
}

function goBackSafe(webContentsRef) {
  if (!webContentsRef) return;
  try {
    if (webContentsRef.navigationHistory && typeof webContentsRef.navigationHistory.goBack === 'function') {
      webContentsRef.navigationHistory.goBack();
      return;
    }
    if (typeof webContentsRef.goBack === 'function') {
      webContentsRef.goBack();
    }
  } catch {
    // ignore
  }
}

function goForwardSafe(webContentsRef) {
  if (!webContentsRef) return;
  try {
    if (webContentsRef.navigationHistory && typeof webContentsRef.navigationHistory.goForward === 'function') {
      webContentsRef.navigationHistory.goForward();
      return;
    }
    if (typeof webContentsRef.goForward === 'function') {
      webContentsRef.goForward();
    }
  } catch {
    // ignore
  }
}

function emitNavStateForTab(tabId) {
  if (!tabId || tabId !== activeTabId) return;
  if (!mainWindow || mainWindow.isDestroyed() || !tabs.has(tabId)) return;

  const tab = tabs.get(tabId);
  const wc = tab && tab.view ? tab.view.webContents : null;
  if (!wc || (typeof wc.isDestroyed === 'function' && wc.isDestroyed())) return;

  mainWindow.webContents.send('nav-state-changed', {
    canGoBack: canGoBackSafe(wc),
    canGoForward: canGoForwardSafe(wc),
    sniffedMedia: tab.sniffedMedia || []
  });
}

function clearSniffedMediaForTab(tabId) {
  if (!tabs.has(tabId)) return;
  const tab = tabs.get(tabId);
  tab.sniffedMedia = [];
  tab.mediaByUrl = new Map();
  tab.filteredMediaUrls = new Set();
  emitNavStateForTab(tabId);
}

function applyProbedMetadata(media, metadata = {}) {
  let changed = false;

  const probedSize = Number(metadata.sizeRaw || 0);
  if ((!media.sizeRaw || media.sizeRaw <= 0) && probedSize > 0) {
    media.sizeRaw = probedSize;
    media.sizeStr = formatByteSize(probedSize, media.url);
    changed = true;
  }

  const width = normalizeDimension(metadata.width);
  const height = normalizeDimension(metadata.height);
  if ((!media.width || media.width <= 0) && width > 0) {
    media.width = width;
    changed = true;
  }
  if ((!media.height || media.height <= 0) && height > 0) {
    media.height = height;
    changed = true;
  }

  if (changed) {
    media.resolution = formatResolution(media.width, media.height);
  }

  const nextQualityTag = normalizeQualityTag(metadata.qualityTag || '');
  if (qualityTagRank(nextQualityTag) > qualityTagRank(media.qualityTag || '')) {
    media.qualityTag = nextQualityTag;
    changed = true;
  }

  if (media.qualityTag === 'TOP') {
    if (media.quality !== 'TOP') {
      media.quality = 'TOP';
      changed = true;
    }
  } else if (media.qualityTag === '720P') {
    if (media.quality !== '720p') {
      media.quality = '720p';
      changed = true;
    }
  } else {
    const inferredQuality = detectQuality(media.width, media.height);
    if ((!media.quality || media.quality === 'Unknown') && inferredQuality && inferredQuality !== 'Unknown') {
      media.quality = inferredQuality;
      changed = true;
    } else if ((!media.quality || media.quality === 'Unknown') && (String(media.category || '').toLowerCase() === 'video' || String(media.type || '').toLowerCase().startsWith('video/'))) {
      media.quality = 'Auto';
      changed = true;
    }
  }

  return changed;
}

function needsMediaMetadataProbe(media) {
  const category = String(media.category || '').toLowerCase();
  const type = String(media.type || '').toLowerCase();
  const isVideoLike = category === 'video' || type.startsWith('video/') || isStreamLikeMedia(media.url, type);
  const needsSize = Number(media.sizeRaw || 0) <= 0;
  const needsQuality = isVideoLike && (!media.quality || media.quality === 'Unknown');
  return needsSize || needsQuality;
}

function assignKnownSizeIfCached(media) {
  let changed = false;

  const cachedMetadata = mediaProbeCache.get(media.url);
  if (cachedMetadata) {
    changed = applyProbedMetadata(media, cachedMetadata) || changed;
  }

  const cached = sizeProbeCache.get(media.url);
  if (Number.isFinite(cached) && cached > 0 && (!media.sizeRaw || media.sizeRaw <= 0)) {
    media.sizeRaw = cached;
    media.sizeStr = formatByteSize(cached, media.url);
    changed = true;
  }

  return changed;
}

function parseIso8601DurationSeconds(value = '') {
  const text = String(value || '').trim();
  const match = text.match(/P(?:([0-9.]+)D)?T?(?:([0-9.]+)H)?(?:([0-9.]+)M)?(?:([0-9.]+)S)?/i);
  if (!match) return 0;
  const days = Number.parseFloat(match[1] || '0') || 0;
  const hours = Number.parseFloat(match[2] || '0') || 0;
  const minutes = Number.parseFloat(match[3] || '0') || 0;
  const seconds = Number.parseFloat(match[4] || '0') || 0;
  return Math.max(0, days * 86400 + hours * 3600 + minutes * 60 + seconds);
}

function mergeProbeMetadata(base = {}, extra = {}) {
  const out = {
    sizeRaw: Number(base.sizeRaw || 0),
    width: normalizeDimension(base.width),
    height: normalizeDimension(base.height),
    qualityTag: normalizeQualityTag(base.qualityTag || ''),
    contentType: String(base.contentType || '')
  };

  const nextSize = Number(extra.sizeRaw || 0);
  if (nextSize > out.sizeRaw) out.sizeRaw = nextSize;
  if (!out.width) out.width = normalizeDimension(extra.width);
  if (!out.height) out.height = normalizeDimension(extra.height);

  const nextTag = normalizeQualityTag(extra.qualityTag || '');
  if (qualityTagRank(nextTag) > qualityTagRank(out.qualityTag)) {
    out.qualityTag = nextTag;
  }

  if (!out.contentType && extra.contentType) {
    out.contentType = String(extra.contentType || '');
  }

  return out;
}

async function fetchTextFromSession(url, timeoutMs = SIZE_PROBE_TIMEOUT_MS * 2) {
  if (!incognitoSession || typeof incognitoSession.fetch !== 'function') return '';
  try {
    const response = await withTimeout(
      incognitoSession.fetch(url, {
        method: 'GET',
        redirect: 'follow',
        headers: {
          Accept: '*/*'
        }
      }),
      timeoutMs,
      `text probe timeout for ${url}`
    );
    if (!response.ok) return '';
    return await response.text();
  } catch {
    return '';
  }
}

async function probeM3u8Metadata(url) {
  const text = await fetchTextFromSession(url);
  if (!text || !text.includes('#EXTM3U')) return {};

  const output = { sizeRaw: 0, width: 0, height: 0, qualityTag: '' };

  const variants = [];
  const variantRegex = /#EXT-X-STREAM-INF:([^\r\n]+)[\r\n]+([^\r\n#][^\r\n]*)/gi;
  let match;
  while ((match = variantRegex.exec(text)) !== null) {
    const attrs = String(match[1] || '');
    const uriLine = String(match[2] || '').trim();
    const resolutionMatch = attrs.match(/RESOLUTION=(\d+)x(\d+)/i);
    const bandwidthMatch = attrs.match(/(?:AVERAGE-)?BANDWIDTH=(\d+)/i);
    const width = resolutionMatch ? Number.parseInt(resolutionMatch[1], 10) || 0 : 0;
    const height = resolutionMatch ? Number.parseInt(resolutionMatch[2], 10) || 0 : 0;
    const bandwidth = bandwidthMatch ? Number.parseInt(bandwidthMatch[1], 10) || 0 : 0;
    let absoluteUri = '';
    try {
      absoluteUri = new URL(uriLine, url).toString();
    } catch {
      absoluteUri = '';
    }
    variants.push({ width, height, bandwidth, uri: absoluteUri });
  }

  let chosen = null;
  if (variants.length > 0) {
    chosen = [...variants].sort((a, b) => {
      const areaA = (a.width || 0) * (a.height || 0);
      const areaB = (b.width || 0) * (b.height || 0);
      if (areaA !== areaB) return areaB - areaA;
      return (b.bandwidth || 0) - (a.bandwidth || 0);
    })[0];
    output.width = chosen.width || 0;
    output.height = chosen.height || 0;
    if (output.height >= 1000) output.qualityTag = 'TOP';
    else if (output.height >= 700 && output.height < 900) output.qualityTag = '720P';
  }

  const durations = Array.from(text.matchAll(/#EXTINF:([0-9.]+)/gi)).map((m) => Number.parseFloat(m[1] || '0') || 0);
  let totalDuration = durations.reduce((sum, v) => sum + v, 0);
  let effectiveBandwidth = chosen ? Number(chosen.bandwidth || 0) : 0;

  if (totalDuration <= 0 && chosen && chosen.uri) {
    const variantText = await fetchTextFromSession(chosen.uri);
    if (variantText) {
      const variantDurations = Array.from(variantText.matchAll(/#EXTINF:([0-9.]+)/gi)).map((m) => Number.parseFloat(m[1] || '0') || 0);
      totalDuration = variantDurations.reduce((sum, v) => sum + v, 0);
    }
  }

  if (effectiveBandwidth > 0 && totalDuration > 0) {
    output.sizeRaw = Math.floor((effectiveBandwidth * totalDuration) / 8);
  }

  if (output.sizeRaw <= 0) {
    const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const segmentUris = lines
      .filter((line) => !line.startsWith('#'))
      .map((line) => {
        try {
          return new URL(line, url).toString();
        } catch {
          return '';
        }
      })
      .filter(Boolean);

    if (segmentUris.length > 0) {
      const sampleUris = segmentUris.slice(0, 4);
      const sampleSizes = await Promise.all(sampleUris.map(async (segmentUrl) => {
        try {
          const response = await withTimeout(
            incognitoSession.fetch(segmentUrl, {
              method: 'HEAD',
              redirect: 'follow',
              headers: { Accept: '*/*' }
            }),
            SIZE_PROBE_TIMEOUT_MS,
            `segment size timeout for ${segmentUrl}`
          );
          const len = Number.parseInt(response.headers.get('content-length') || '0', 10);
          return Number.isFinite(len) && len > 0 ? len : 0;
        } catch {
          return 0;
        }
      }));

      const knownSamples = sampleSizes.filter((size) => size > 0);
      if (knownSamples.length > 0) {
        const avg = knownSamples.reduce((sum, value) => sum + value, 0) / knownSamples.length;
        output.sizeRaw = Math.floor(avg * segmentUris.length);
      }
    }
  }

  return output;
}

async function probeMpdMetadata(url) {
  const text = await fetchTextFromSession(url);
  if (!text || !text.includes('<MPD')) return {};

  const output = { sizeRaw: 0, width: 0, height: 0, qualityTag: '' };
  const durationMatch = text.match(/mediaPresentationDuration="([^"]+)"/i);
  const totalSeconds = durationMatch ? parseIso8601DurationSeconds(durationMatch[1]) : 0;

  const repRegex = /<Representation\b([^>]+)>/gi;
  let match;
  const representations = [];
  while ((match = repRegex.exec(text)) !== null) {
    const attrs = String(match[1] || '');
    const widthMatch = attrs.match(/width="(\d+)"/i);
    const heightMatch = attrs.match(/height="(\d+)"/i);
    const bandwidthMatch = attrs.match(/bandwidth="(\d+)"/i);
    representations.push({
      width: widthMatch ? Number.parseInt(widthMatch[1], 10) || 0 : 0,
      height: heightMatch ? Number.parseInt(heightMatch[1], 10) || 0 : 0,
      bandwidth: bandwidthMatch ? Number.parseInt(bandwidthMatch[1], 10) || 0 : 0
    });
  }

  if (representations.length > 0) {
    const chosen = [...representations].sort((a, b) => {
      const areaA = (a.width || 0) * (a.height || 0);
      const areaB = (b.width || 0) * (b.height || 0);
      if (areaA !== areaB) return areaB - areaA;
      return (b.bandwidth || 0) - (a.bandwidth || 0);
    })[0];

    output.width = chosen.width || 0;
    output.height = chosen.height || 0;
    if (output.height >= 1000) output.qualityTag = 'TOP';
    else if (output.height >= 700 && output.height < 900) output.qualityTag = '720P';

    if (chosen.bandwidth > 0 && totalSeconds > 0) {
      output.sizeRaw = Math.floor((chosen.bandwidth * totalSeconds) / 8);
    }
  }

  return output;
}

async function probeMediaMetadataFromSession(url, mediaType = 'media') {
  if (!incognitoSession || typeof incognitoSession.fetch !== 'function') {
    return { sizeRaw: 0, width: 0, height: 0, qualityTag: '' };
  }

  let metadata = { sizeRaw: 0, width: 0, height: 0, qualityTag: '' };
  const urlInference = inferQualityFromUrl(url);
  metadata = mergeProbeMetadata(metadata, {
    width: urlInference.width,
    height: urlInference.height,
    qualityTag: urlInference.qualityTag
  });

  const doFetchWithTimeout = async (options) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), SIZE_PROBE_TIMEOUT_MS);
    try {
      return await incognitoSession.fetch(url, {
        redirect: 'follow',
        signal: controller.signal,
        ...options
      });
    } finally {
      clearTimeout(timeout);
    }
  };

  try {
    const headRes = await doFetchWithTimeout({
      method: 'HEAD',
      headers: { Accept: '*/*' }
    });

    const contentType = String(headRes.headers.get('content-type') || '').toLowerCase();
    const headLen = Number.parseInt(headRes.headers.get('content-length') || '0', 10);
    const headRangeTotal = parseTotalFromContentRange(headRes.headers.get('content-range') || '');

    metadata = mergeProbeMetadata(metadata, {
      sizeRaw: headRangeTotal || (Number.isFinite(headLen) ? headLen : 0),
      contentType
    });
  } catch {
    // continue to range/manifest probing
  }

  if (!metadata.sizeRaw) {
    try {
      const rangeRes = await doFetchWithTimeout({
        method: 'GET',
        headers: {
          Accept: '*/*',
          Range: 'bytes=0-0'
        }
      });

      const contentType = String(rangeRes.headers.get('content-type') || '').toLowerCase();
      const rangeTotal = parseTotalFromContentRange(rangeRes.headers.get('content-range') || '');
      const rangeLen = Number.parseInt(rangeRes.headers.get('content-length') || '0', 10);

      metadata = mergeProbeMetadata(metadata, {
        sizeRaw: rangeTotal || (Number.isFinite(rangeLen) ? rangeLen : 0),
        contentType
      });

      if (rangeRes.body && typeof rangeRes.body.cancel === 'function') {
        rangeRes.body.cancel().catch(() => {});
      }
    } catch {
      // ignore
    }
  }

  const streamLike = isStreamLikeMedia(url, mediaType) || isStreamLikeMedia(url, metadata.contentType || mediaType);
  if (streamLike) {
    if (String(url).toLowerCase().includes('.mpd') || String(metadata.contentType || '').toLowerCase().includes('dash+xml')) {
      metadata = mergeProbeMetadata(metadata, await probeMpdMetadata(url));
    } else {
      metadata = mergeProbeMetadata(metadata, await probeM3u8Metadata(url));
    }
  }

  if (!metadata.qualityTag && metadata.height >= 1000) metadata.qualityTag = 'TOP';
  if (!metadata.qualityTag && metadata.height >= 700 && metadata.height < 900) metadata.qualityTag = '720P';

  return metadata;
}

function processSizeProbeQueue() {
  while (sizeProbeActiveCount < SIZE_PROBE_MAX_CONCURRENCY && sizeProbeQueue.length > 0) {
    const task = sizeProbeQueue.shift();
    sizeProbeActiveCount += 1;

    probeMediaMetadataFromSession(task.url, task.type)
      .then((metadata) => {
        if (metadata && typeof metadata === 'object') {
          mediaProbeCache.set(task.url, metadata);
          if (Number(metadata.sizeRaw || 0) > 0) {
            sizeProbeCache.set(task.url, Number(metadata.sizeRaw || 0));
          }

          try {
            addMediaCandidateToTab(task.tabId, {
              url: task.url,
              type: task.type,
              extension: inferExtension(task.url),
              sizeRaw: Number(metadata.sizeRaw || 0),
              width: Number(metadata.width || 0),
              height: Number(metadata.height || 0),
              qualityTag: String(metadata.qualityTag || '')
            });
          } catch (error) {
            console.warn('Failed to merge probed media metadata:', error.message || error);
          }
        }
      })
      .finally(() => {
        sizeProbeActiveCount -= 1;
        sizeProbeInFlight.delete(task.key);
        processSizeProbeQueue();
      });
  }
}

function queueMediaSizeProbe(tabId, mediaUrl, mediaType = 'media') {
  if (!tabs.has(tabId) || !mediaUrl) return;

  if (mediaProbeCache.has(mediaUrl) || sizeProbeCache.has(mediaUrl)) {
    const mergeKey = `${tabId}|${mediaUrl}`;
    if (probeMergeInProgress.has(mergeKey)) return;
    probeMergeInProgress.add(mergeKey);
    try {
      addMediaCandidateToTab(tabId, {
        url: mediaUrl,
        type: mediaType,
        extension: inferExtension(mediaUrl),
        sizeRaw: Number(sizeProbeCache.get(mediaUrl) || 0),
        width: Number((mediaProbeCache.get(mediaUrl) || {}).width || 0),
        height: Number((mediaProbeCache.get(mediaUrl) || {}).height || 0),
        qualityTag: String((mediaProbeCache.get(mediaUrl) || {}).qualityTag || ''),
        __skipProbeRequeue: true
      });
    } finally {
      probeMergeInProgress.delete(mergeKey);
    }
    return;
  }

  const lastAttemptAt = Number(sizeProbeAttemptedAt.get(mediaUrl) || 0);
  if (Date.now() - lastAttemptAt < 5 * 60 * 1000) return;

  const key = `${tabId}|${mediaUrl}`;
  if (sizeProbeInFlight.has(key)) return;

  sizeProbeAttemptedAt.set(mediaUrl, Date.now());
  sizeProbeInFlight.add(key);
  sizeProbeQueue.push({ tabId, url: mediaUrl, type: mediaType, key });
  processSizeProbeQueue();
}

function normalizeMediaCandidate(candidate) {
  const normalizedUrl = normalizeMediaUrl(candidate.url);
  if (!normalizedUrl) return null;
  if (normalizedUrl.startsWith('blob:') || normalizedUrl.startsWith('data:')) return null;

  const extension = String(candidate.extension || inferExtension(normalizedUrl) || '').toLowerCase();
  const type = String(candidate.type || '').toLowerCase() || 'media';
  const category = classifyMediaType(type, extension, normalizedUrl);
  const format = guessFormatFromTypeOrExt(type, extension, normalizedUrl);
  const inferredFromUrl = inferQualityFromUrl(normalizedUrl);
  const width = normalizeDimension(candidate.width) || inferredFromUrl.width;
  const height = normalizeDimension(candidate.height) || inferredFromUrl.height;
  const qualityTag = normalizeQualityTag(candidate.qualityTag || inferredFromUrl.qualityTag || '');
  const sizeRaw = Number.isFinite(candidate.sizeRaw) ? Number(candidate.sizeRaw) : 0;
  const sourceScope = String(candidate.sourceScope || 'page').toLowerCase();
  let quality = detectQuality(width, height);
  if (qualityTag === 'TOP') quality = 'TOP';
  if (qualityTag === '720P') quality = '720p';
  if (quality === 'Unknown' && (category === 'video' || type.startsWith('video/'))) {
    quality = 'Auto';
  }

  return {
    url: normalizedUrl,
    type,
    category,
    format,
    extension,
    sourceScope,
    sourcePage: String(candidate.sourcePage || ''),
    groupKey: deriveMediaGroupKey(normalizedUrl, category),
    qualityTag,
    width,
    height,
    resolution: formatResolution(width, height),
    quality,
    sizeRaw,
    sizeStr: formatByteSize(sizeRaw, normalizedUrl)
  };
}

function rebuildFilteredMediaForTab(tabId) {
  if (!tabs.has(tabId)) return;
  const tab = tabs.get(tabId);
  if (!tab.mediaByUrl) tab.mediaByUrl = new Map();
  if (!tab.mediaFilter) tab.mediaFilter = sanitizeMediaFilter({});

  const nextList = [];
  const nextSet = new Set();

  for (const media of tab.mediaByUrl.values()) {
    if (mediaPassesFilter(media, tab.mediaFilter)) {
      nextList.push(media);
      nextSet.add(media.url);
    }
  }

  tab.sniffedMedia = nextList;
  tab.filteredMediaUrls = nextSet;
  emitNavStateForTab(tabId);
}

function addMediaCandidateToTab(tabId, candidate) {
  if (!tabs.has(tabId) || !candidate || !candidate.url) return false;
  const tab = tabs.get(tabId);

  if (!tab.sniffedMedia) tab.sniffedMedia = [];
  if (!tab.mediaByUrl) tab.mediaByUrl = new Map();
  if (!tab.filteredMediaUrls) tab.filteredMediaUrls = new Set();
  if (!tab.mediaFilter) tab.mediaFilter = sanitizeMediaFilter({});

  const normalized = normalizeMediaCandidate(candidate);
  if (!normalized) return false;
  const mergeKey = `${tabId}|${normalized.url}`;
  const skipProbeRequeue = Boolean(candidate.__skipProbeRequeue) || probeMergeInProgress.has(mergeKey);

  const existing = tab.mediaByUrl.get(normalized.url);

  if (existing) {
    let changed = false;

    if ((!existing.sizeRaw || existing.sizeRaw <= 0) && normalized.sizeRaw > 0) {
      existing.sizeRaw = normalized.sizeRaw;
      existing.sizeStr = formatByteSize(normalized.sizeRaw, existing.url);
      changed = true;
    }

    if ((!existing.type || existing.type === 'media') && normalized.type && normalized.type !== 'media') {
      existing.type = normalized.type;
      changed = true;
    }

    if (!existing.category || existing.category === 'media') {
      existing.category = normalized.category;
      changed = true;
    }

    if (!existing.format && normalized.format) {
      existing.format = normalized.format;
      changed = true;
    }

    if (!existing.extension && normalized.extension) {
      existing.extension = normalized.extension;
      changed = true;
    }

    if (!existing.groupKey && normalized.groupKey) {
      existing.groupKey = normalized.groupKey;
      changed = true;
    }

    if (qualityTagRank(normalized.qualityTag) > qualityTagRank(existing.qualityTag)) {
      existing.qualityTag = normalized.qualityTag;
      if (existing.qualityTag === 'TOP') {
        existing.quality = 'TOP';
      } else if (existing.qualityTag === '720P') {
        existing.quality = '720p';
      }
      changed = true;
    }

    if (!existing.sourcePage && normalized.sourcePage) {
      existing.sourcePage = normalized.sourcePage;
      changed = true;
    }

    if (existing.sourceScope !== normalized.sourceScope) {
      existing.sourceScope = 'both';
      changed = true;
    }

    if ((!existing.width || existing.width <= 0) && normalized.width > 0) {
      existing.width = normalized.width;
      changed = true;
    }
    if ((!existing.height || existing.height <= 0) && normalized.height > 0) {
      existing.height = normalized.height;
      changed = true;
    }

    if (changed) {
      existing.resolution = formatResolution(existing.width, existing.height);
      if (!existing.qualityTag && (!existing.quality || existing.quality === 'Unknown')) {
        existing.quality = detectQuality(existing.width, existing.height);
      }
    }

    if ((!existing.sizeRaw || existing.sizeRaw <= 0) && assignKnownSizeIfCached(existing)) {
      changed = true;
    }

    if (!skipProbeRequeue && needsMediaMetadataProbe(existing)) {
      queueMediaSizeProbe(tabId, existing.url, existing.type || normalized.type);
    }

    const inFilteredList = tab.filteredMediaUrls.has(existing.url);
    const passesFilter = mediaPassesFilter(existing, tab.mediaFilter);

    if (passesFilter && !inFilteredList) {
      tab.sniffedMedia.push(existing);
      tab.filteredMediaUrls.add(existing.url);
      changed = true;
    }

    if (!passesFilter && inFilteredList) {
      tab.sniffedMedia = tab.sniffedMedia.filter((item) => item.url !== existing.url);
      tab.filteredMediaUrls.delete(existing.url);
      changed = true;
    }

    if (changed) emitNavStateForTab(tabId);
    return changed;
  }

  const mediaItem = { ...normalized };
  if (mediaItem.sizeRaw <= 0) assignKnownSizeIfCached(mediaItem);

  tab.mediaByUrl.set(mediaItem.url, mediaItem);

  const passesFilter = mediaPassesFilter(mediaItem, tab.mediaFilter);
  if (!passesFilter) {
    if (filterRequiresKnownSize(tab.mediaFilter) && mediaItem.sizeRaw <= 0) {
      queueMediaSizeProbe(tabId, mediaItem.url, mediaItem.type);
    }
    return false;
  }

  tab.sniffedMedia.push(mediaItem);
  tab.filteredMediaUrls.add(mediaItem.url);

  if (!skipProbeRequeue && needsMediaMetadataProbe(mediaItem)) {
    queueMediaSizeProbe(tabId, mediaItem.url, mediaItem.type);
  }

  emitNavStateForTab(tabId);
  return true;
}

function scheduleDomMediaScan(tabId, delayMs = 220, force = false) {
  if (!tabs.has(tabId)) return;
  const tab = tabs.get(tabId);
  if (tab.domScanTimer) {
    clearTimeout(tab.domScanTimer);
  }

  tab.domScanTimer = setTimeout(() => {
    tab.domScanTimer = null;
    runDomMediaScan(tabId, force);
  }, delayMs);
}

async function runDomMediaScan(tabId, force = false) {
  if (!tabs.has(tabId)) return;
  const tab = tabs.get(tabId);
  if (!tab || tab.domScanInFlight || tab.view.webContents.isDestroyed()) return;

  const now = Date.now();
  if (!force && now - (tab.lastDomScanAt || 0) < 260) return;

  tab.domScanInFlight = true;
  tab.lastDomScanAt = now;
  try {
    const candidates = await tab.view.webContents.executeJavaScript(`(() => {
      const results = [];
      const seen = new Set();
      const pageUrl = location.href;
      const mediaHints = ['.mp4', '.m4v', '.m3u8', '.mpd', '.webm', '.mkv', '.mov', '.avi', '.flv', '.ts', '.m2ts', '.m4s', '.ismv', '.ism', '.mp3', '.m4a', '.aac', '.ogg', '.opus', '.wav', '.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp', '.svg', '.avif'];

      const toAbs = (value) => {
        if (!value || typeof value !== 'string') return '';
        try {
          return new URL(value.trim(), location.href).toString();
        } catch {
          return '';
        }
      };

      const parseSrcSet = (value) => {
        if (!value || typeof value !== 'string') return [];
        return value
          .split(',')
          .map((part) => part.trim())
          .filter(Boolean)
          .map((part) => {
            const bits = part.split(/\s+/);
            const src = bits[0] || '';
            const width = Number.parseInt(bits[1] || '0', 10) || 0;
            return { src, width };
          });
      };

      const choosePreferred = (entries) => {
        if (!Array.isArray(entries) || entries.length === 0) return [];
        const withWidth = entries.filter((e) => Number(e.width || 0) > 0);
        if (withWidth.length === 0) {
          return [{ ...entries[0], qualityTag: 'TOP' }];
        }
        const sorted = [...withWidth].sort((a, b) => Number(b.width || 0) - Number(a.width || 0));
        const top = sorted[0];
        const near720 = [...withWidth].sort((a, b) => Math.abs(Number(a.width || 0) - 1280) - Math.abs(Number(b.width || 0) - 1280))[0];
        const out = [];
        if (top && top.src) out.push({ ...top, qualityTag: 'TOP' });
        if (near720 && near720.src && (!top || near720.src !== top.src)) {
          out.push({ ...near720, qualityTag: '720P' });
        }
        return out;
      };

      const looksLikeMedia = (abs) => {
        const lower = String(abs || '').toLowerCase();
        if (!lower || lower.startsWith('data:') || lower.startsWith('blob:') || lower.startsWith('javascript:')) return false;
        if (lower.includes('mime=video') || lower.includes('mime=audio') || lower.includes('manifest') || lower.includes('playlist')) return true;
        return mediaHints.some((hint) => lower.includes(hint));
      };

      const add = (value, typeHint = 'media', sizeHint = 0, widthHint = 0, heightHint = 0, qualityTag = '') => {
        const abs = toAbs(value);
        if (!abs || !looksLikeMedia(abs)) return;
        if (seen.has(abs)) return;
        seen.add(abs);

        results.push({
          url: abs,
          type: String(typeHint || 'media').toLowerCase(),
          sourceScope: 'page',
          sourcePage: pageUrl,
          qualityTag: String(qualityTag || '').toUpperCase(),
          sizeRaw: Number(sizeHint || 0) || 0,
          width: Number(widthHint || 0) || 0,
          height: Number(heightHint || 0) || 0
        });
      };

      try {
        document.querySelectorAll('video, audio').forEach((node) => {
          add(
            node.currentSrc || node.src || '',
            node.tagName.toLowerCase(),
            0,
            node.videoWidth || node.clientWidth || 0,
            node.videoHeight || node.clientHeight || 0
          );

          if (node.tagName && node.tagName.toLowerCase() === 'video') {
            try {
              node.muted = true;
              node.preload = 'auto';
              const playPromise = node.play();
              if (playPromise && typeof playPromise.catch === 'function') {
                playPromise.catch(() => {});
              }
            } catch {}
          }

          node.querySelectorAll('source').forEach((srcNode) => {
            add(srcNode.src || '', srcNode.type || 'source');
          });
        });
      } catch {}

      try {
        document.querySelectorAll('img').forEach((node) => {
          add(node.currentSrc || node.src || node.getAttribute('data-src') || '', 'image', 0, node.naturalWidth || node.width || 0, node.naturalHeight || node.height || 0);
          const srcSetEntries = parseSrcSet(node.srcset || '');
          srcSetEntries.forEach((entry) => add(entry.src || '', 'image', 0, entry.width || 0, node.naturalHeight || node.height || 0));
          choosePreferred(srcSetEntries).forEach((entry) => add(entry.src || '', 'image', 0, entry.width || 0, node.naturalHeight || node.height || 0, entry.qualityTag || ''));
        });
      } catch {}

      try {
        document.querySelectorAll('picture source, source').forEach((node) => {
          const srcSetEntries = parseSrcSet(node.srcset || '');
          srcSetEntries.forEach((entry) => add(entry.src || '', node.type || 'source', 0, entry.width || 0, 0));
          choosePreferred(srcSetEntries).forEach((entry) => add(entry.src || '', node.type || 'source', 0, entry.width || 0, 0, entry.qualityTag || ''));
          add(node.src || '', node.type || 'source');
        });
      } catch {}

      try {
        document.querySelectorAll('a[href]').forEach((node) => {
          const href = node.getAttribute('href') || '';
          add(href, 'link');
        });
      } catch {}

      try {
        if (performance && typeof performance.getEntriesByType === 'function') {
          performance.getEntriesByType('resource').slice(-260).forEach((entry) => {
            add(entry.name || '', entry.initiatorType || 'resource', Number(entry.decodedBodySize || entry.transferSize || 0) || 0);
          });
        }
      } catch {}

      return results.slice(0, 600);
    })();`, true);

    if (Array.isArray(candidates)) {
      candidates.forEach((candidate) => {
        addMediaCandidateToTab(tabId, candidate);
      });
    }
  } catch (error) {
    const errText = String((error && (error.message || error.stack)) || error || '').toLowerCase();
    const expected =
      errText.includes('execution context was destroyed') ||
      errText.includes('script failed to execute') ||
      errText.includes('cannot access contents of url');

    if (!expected) {
      console.log(`DOM media scan failed for tab ${tabId}:`, error && (error.stack || error.message || String(error)));
    }
  } finally {
    tab.domScanInFlight = false;
  }
}

function emitDomainScanStatus(tabId, patch = {}) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  const job = domainScanJobs.get(tabId);
  const payload = {
    running: Boolean(job && job.active),
    pagesVisited: job ? job.visited.size : 0,
    queued: job ? job.queue.length : 0,
    mediaFound: tabs.has(tabId) ? (tabs.get(tabId).sniffedMedia || []).length : 0,
    domain: job ? job.rootDomain : '',
    currentHost: job ? job.currentHost || '' : '',
    subdomainsDiscovered: job ? job.discoveredHosts.size : 0,
    subdomainsScanned: job ? job.scannedHosts.size : 0,
    ...patch
  };
  mainWindow.webContents.send('domain-scan-status', payload);
}

function ensureDomainCrawlerWindow(job) {
  if (job.workerWindow && !job.workerWindow.isDestroyed()) {
    return job.workerWindow;
  }

  const workerWindow = new BrowserWindow({
    show: false,
    webPreferences: {
      session: incognitoSession,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  // Domain crawler must never create additional popup windows.
  workerWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

  workerWindow.webContents.on('will-redirect', (event, redirectUrl, isInPlace, isMainFrame) => {
    if (!isMainFrame) return;
    const fromUrl = String(job.currentCrawlUrl || workerWindow.webContents.getURL() || '');
    if (shouldBlockNavigationRedirect(fromUrl, redirectUrl, job.rootDomain)) {
      event.preventDefault();
      console.log(`Blocked crawler redirect: ${fromUrl} -> ${redirectUrl}`);
    }
  });

  const workerWebContentsId = workerWindow.webContents.id;
  domainCrawlerWebContentsToTab.set(workerWebContentsId, job.tabId);
  workerWindow.on('closed', () => {
    domainCrawlerWebContentsToTab.delete(workerWebContentsId);
  });

  job.workerWebContentsId = workerWebContentsId;

  job.workerWindow = workerWindow;
  return workerWindow;
}

function destroyDomainCrawlerWindow(job) {
  if (!job || !job.workerWindow) return;
  if (job.workerWebContentsId) {
    domainCrawlerWebContentsToTab.delete(job.workerWebContentsId);
  }
  if (!job.workerWindow.isDestroyed()) {
    job.workerWindow.destroy();
  }
  job.workerWebContentsId = null;
  job.workerWindow = null;
}

async function crawlPageForDomainData(job, url) {
  const crawlWindow = ensureDomainCrawlerWindow(job);
  job.currentCrawlUrl = String(url || '');

  await withTimeout(
    crawlWindow.loadURL(url),
    DOMAIN_SCAN_NAV_TIMEOUT_MS,
    `domain scan timeout for ${url}`
  );

  await crawlWindow.webContents.executeJavaScript(`new Promise((resolve) => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms));
    const maxRounds = ${DOMAIN_SCAN_SCROLL_MAX_ROUNDS};
    const idleRoundsTarget = ${DOMAIN_SCAN_SCROLL_IDLE_ROUNDS};
    const waitMs = ${DOMAIN_SCAN_SCROLL_WAIT_MS};

    const getBottom = () => {
      const body = document.body || { scrollHeight: 0 };
      const doc = document.documentElement || { scrollHeight: 0 };
      return Math.max(body.scrollHeight || 0, doc.scrollHeight || 0);
    };

    (async () => {
      const pokeVideos = () => {
        try {
          document.querySelectorAll('video').forEach((video) => {
            try {
              video.muted = true;
              video.preload = 'auto';
              const p = video.play();
              if (p && typeof p.catch === 'function') {
                p.catch(() => {});
              }
            } catch {}
          });
        } catch {}
      };

      let previousBottom = 0;
      let idleRounds = 0;

      for (let i = 0; i < maxRounds; i += 1) {
        pokeVideos();
        const bottom = getBottom();
        window.scrollTo(0, bottom + window.innerHeight);
        await wait(waitMs);

        const nextBottom = getBottom();
        const changed = nextBottom > previousBottom + 2;
        previousBottom = Math.max(previousBottom, nextBottom);

        if (!changed) {
          idleRounds += 1;
        } else {
          idleRounds = 0;
        }

        if (idleRounds >= idleRoundsTarget) {
          break;
        }
      }

      await wait(waitMs);
      resolve();
    })();
  });`, true);

  const data = await crawlWindow.webContents.executeJavaScript(`(() => {
      const links = [];
      const media = [];
      const linkSeen = new Set();
      const mediaSeen = new Set();
      const pageUrl = location.href;
      const extPattern = /\.(mp4|m4v|m3u8|mpd|webm|mkv|mov|avi|flv|ts|m2ts|mp3|m4a|aac|ogg|opus|wav|jpg|jpeg|png|webp|gif|bmp|svg|avif)(?:$|[?#&])/i;

      const toAbs = (value) => {
        if (!value || typeof value !== 'string') return '';
        try {
          return new URL(value.trim(), location.href).toString();
        } catch {
          return '';
        }
      };

      const parseSrcSet = (value) => {
        if (!value || typeof value !== 'string') return [];
        return value
          .split(',')
          .map((part) => {
            const trimmed = part.trim();
            if (!trimmed) return null;
            const tokens = trimmed.split(/\s+/);
            const src = tokens[0] || '';
            const descriptor = tokens[1] || '';
            const widthMatch = descriptor.match(/(\d+)w/i);
            const width = widthMatch ? Number(widthMatch[1]) : 0;
            return { src, width };
          })
          .filter(Boolean);
      };

      const selectPreferredQualityVariants = (entries) => {
        if (!Array.isArray(entries) || entries.length === 0) return [];
        const withWidth = entries.filter((entry) => Number(entry.width || 0) > 0);
        if (withWidth.length === 0) {
          return [{ ...entries[0], qualityTag: 'TOP' }];
        }

        const sorted = [...withWidth].sort((a, b) => Number(b.width || 0) - Number(a.width || 0));
        const top = sorted[0];
        const target720 = [...withWidth].sort((a, b) => Math.abs(Number(a.width || 0) - 1280) - Math.abs(Number(b.width || 0) - 1280))[0];

        const selected = [];
        if (top && top.src) selected.push({ ...top, qualityTag: 'TOP' });
        if (target720 && target720.src && (!top || target720.src !== top.src)) {
          selected.push({ ...target720, qualityTag: '720P' });
        }
        return selected;
      };

      const pushLink = (value) => {
        const absolute = toAbs(value);
        if (!absolute || linkSeen.has(absolute)) return;
        const lower = absolute.toLowerCase();
        if (!lower.startsWith('http://') && !lower.startsWith('https://')) return;
        linkSeen.add(absolute);
        links.push(absolute);
      };

      const pushMedia = (value, typeHint = 'media', widthHint = 0, heightHint = 0, sizeHint = 0, qualityTag = '') => {
        const absolute = toAbs(value);
        if (!absolute || mediaSeen.has(absolute)) return;
        const lower = absolute.toLowerCase();
        if (lower.startsWith('blob:') || lower.startsWith('data:') || lower.startsWith('javascript:')) return;
        if (!extPattern.test(lower) && !lower.includes('mime=video') && !lower.includes('mime=audio') && !lower.includes('image=')) return;
        mediaSeen.add(absolute);
        media.push({
          url: absolute,
          type: String(typeHint || 'media').toLowerCase(),
          sourceScope: 'domain',
          sourcePage: pageUrl,
          qualityTag: String(qualityTag || '').toUpperCase(),
          width: Number(widthHint) || 0,
          height: Number(heightHint) || 0,
          sizeRaw: Number(sizeHint) || 0
        });
      };

      document.querySelectorAll('a[href]').forEach((a) => {
        const href = a.getAttribute('href') || '';
        pushLink(href);
        if (a.hasAttribute('download')) pushMedia(href, 'download-link', 0, 0, 0);
      });

      document.querySelectorAll('img').forEach((img) => {
        const width = img.naturalWidth || img.width || 0;
        const height = img.naturalHeight || img.height || 0;
        pushMedia(img.currentSrc || img.src || img.getAttribute('data-src') || '', 'image', width, height, 0);
        const srcSetEntries = parseSrcSet(img.srcset || '');
        srcSetEntries.forEach((entry) => pushMedia(entry.src || '', 'image', Number(entry.width || 0), height, 0));
        const preferred = selectPreferredQualityVariants(srcSetEntries);
        preferred.forEach((entry) => pushMedia(entry.src || '', 'image', Number(entry.width || 0), height, 0, entry.qualityTag || ''));
      });

      document.querySelectorAll('picture source').forEach((source) => {
        const srcSetEntries = parseSrcSet(source.srcset || '');
        srcSetEntries.forEach((entry) => pushMedia(entry.src || '', source.type || 'image', Number(entry.width || 0), 0, 0));
        const preferred = selectPreferredQualityVariants(srcSetEntries);
        preferred.forEach((entry) => pushMedia(entry.src || '', source.type || 'image', Number(entry.width || 0), 0, 0, entry.qualityTag || ''));
      });

      document.querySelectorAll('video, audio').forEach((node) => {
        const width = node.videoWidth || node.clientWidth || 0;
        const height = node.videoHeight || node.clientHeight || 0;
        pushMedia(node.currentSrc || node.src || '', node.tagName.toLowerCase(), width, height, 0);
      });

      document.querySelectorAll('source').forEach((source) => {
        const srcSetEntries = parseSrcSet(source.srcset || '');
        srcSetEntries.forEach((entry) => pushMedia(entry.src || '', source.type || 'source', Number(entry.width || 0), 0, 0));
        const preferred = selectPreferredQualityVariants(srcSetEntries);
        preferred.forEach((entry) => pushMedia(entry.src || '', source.type || 'source', Number(entry.width || 0), 0, 0, entry.qualityTag || ''));
        pushMedia(source.src || '', source.type || 'source', 0, 0, 0);
      });

      document.querySelectorAll('[style*="background-image"]').forEach((node) => {
        const styleVal = node.getAttribute('style') || '';
        const matches = styleVal.match(/url\((['\"]?)(.*?)\\1\)/gi) || [];
        matches.forEach((raw) => {
          const cleaned = raw.replace(/^url\((['\"]?)/i, '').replace(/(['\"]?)\)$/i, '').trim();
          pushMedia(cleaned, 'background', node.clientWidth || 0, node.clientHeight || 0, 0);
        });
      });

      if (performance && typeof performance.getEntriesByType === 'function') {
        performance.getEntriesByType('resource').slice(-250).forEach((entry) => {
          pushMedia(
            entry.name || '',
            entry.initiatorType || 'resource',
            0,
            0,
            Number(entry.decodedBodySize || entry.transferSize || 0)
          );
        });
      }

      return {
        links: links.slice(0, 800),
        media: media.slice(0, 1000)
      };
    })();`, true);

  return data && typeof data === 'object' ? data : { links: [], media: [] };
}

async function crawlSingleDomainPage(tabId, pageUrl) {
  const job = domainScanJobs.get(tabId);
  if (!job || !job.active || !tabs.has(tabId)) return;

  if (job.visited.has(pageUrl)) return;
  job.visited.add(pageUrl);
  emitDomainScanStatus(tabId, { currentUrl: pageUrl });

  try {
    const renderedData = await crawlPageForDomainData(job, pageUrl).catch(() => ({ links: [], media: [] }));
    const fetchedData = await fetchPageSourceData(pageUrl);

    const links = [
      ...(Array.isArray(renderedData.links) ? renderedData.links : []),
      ...(Array.isArray(fetchedData.links) ? fetchedData.links : [])
    ];

    const media = [
      ...(Array.isArray(renderedData.media) ? renderedData.media : []),
      ...(Array.isArray(fetchedData.media) ? fetchedData.media : [])
    ];

    links.forEach((link) => {
      if (!job.active) return;
      const normalized = normalizeCrawlPageUrl(link);
      if (!normalized) return;
      if (!isWithinRootDomain(normalized, job.rootDomain)) return;

      const linkUrl = safeUrl(normalized);
      const linkHost = linkUrl ? linkUrl.hostname.toLowerCase() : '';
      if (linkHost && !job.discoveredHosts.has(linkHost) && job.discoveredHosts.size < job.maxSubdomains) {
        job.discoveredHosts.add(linkHost);
        job.hostQueue.push(linkHost);
      }

      if (linkHost && !job.scannedHosts.has(linkHost)) {
        return;
      }

      if (!job.overrideRobots && !isPathAllowedByRobots(normalized, job.robotsPolicy)) return;
      if (job.visited.has(normalized) || job.queued.has(normalized)) return;
      if (job.visited.size + job.queue.length >= job.maxPages) return;

      job.queued.add(normalized);
      job.queue.push(normalized);
    });

    media.forEach((item) => {
      if (!item || !item.url) return;
      if (!isWithinRootDomain(item.url, job.rootDomain)) return;
      addMediaCandidateToTab(tabId, {
        ...item,
        sourceScope: 'domain'
      });
    });

    await probeDomainMediaLinks(tabId, pageUrl, links, job);
  } catch (error) {
    console.log(`Domain crawl page failed: ${pageUrl}`, error.message);
  }
}

function enqueueNextSubdomainSeed(job) {
  while (job.hostQueue.length > 0) {
    const host = String(job.hostQueue.shift() || '').toLowerCase();
    if (!host) continue;
    if (job.scannedHosts.has(host)) continue;

    job.scannedHosts.add(host);
    job.currentHost = host;

    const seedUrl = normalizeCrawlPageUrl(`https://${host}/`);
    if (!seedUrl) continue;
    if (!isWithinRootDomain(seedUrl, job.rootDomain)) continue;
    if (!job.overrideRobots && !isPathAllowedByRobots(seedUrl, job.robotsPolicy)) continue;
    if (job.visited.has(seedUrl) || job.queued.has(seedUrl)) continue;
    if (job.visited.size + job.queue.length >= job.maxPages) return;

    job.queued.add(seedUrl);
    job.queue.push(seedUrl);
    if (job.useExternalTools) {
      runExternalDiscoveryForHost(job.tabId, job, host).catch(() => {});
    }
    return;
  }
}

function pumpDomainScan(tabId) {
  const job = domainScanJobs.get(tabId);
  if (!job || !job.active) return;

  if (job.queue.length === 0 && job.hostQueue.length > 0) {
    enqueueNextSubdomainSeed(job);
  }

  while (job.active && job.running < job.concurrency && job.visited.size < job.maxPages) {
    if (job.queue.length === 0) {
      enqueueNextSubdomainSeed(job);
      if (job.queue.length === 0) break;
    }

    const nextUrl = job.queue.shift();
    job.running += 1;

    crawlSingleDomainPage(tabId, nextUrl)
      .finally(() => {
        const activeJob = domainScanJobs.get(tabId);
        if (!activeJob) return;
        activeJob.running -= 1;

        if (!activeJob.active) {
          destroyDomainCrawlerWindow(activeJob);
          emitDomainScanStatus(tabId, { finished: true });
          return;
        }

        if (activeJob.running === 0 && activeJob.queue.length === 0 && activeJob.hostQueue.length > 0) {
          enqueueNextSubdomainSeed(activeJob);
        }

        if ((activeJob.queue.length === 0 && activeJob.running === 0 && activeJob.hostQueue.length === 0) || activeJob.visited.size >= activeJob.maxPages) {
          activeJob.active = false;
          destroyDomainCrawlerWindow(activeJob);
          emitDomainScanStatus(tabId, { finished: true });
          return;
        }

        emitDomainScanStatus(tabId);
        pumpDomainScan(tabId);
      });
  }

  emitDomainScanStatus(tabId);
}

async function startDomainScanForTab(tabId, options = {}) {
  if (!tabs.has(tabId)) return;

  const tab = tabs.get(tabId);
  const currentUrl = options.startUrl || tab.view.webContents.getURL() || tab.url;
  const urlObj = safeUrl(currentUrl);
  if (!urlObj) return;

  let rootDomain = deriveRootDomain(urlObj.hostname);
  if (options.domain) {
    const rawDomain = String(options.domain).trim();
    const withScheme = rawDomain.includes('://') ? rawDomain : `https://${rawDomain}`;
    const domainUrl = safeUrl(withScheme);
    if (domainUrl && domainUrl.hostname) {
      rootDomain = deriveRootDomain(domainUrl.hostname);
    } else {
      rootDomain = rawDomain.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
    }
  }
  rootDomain = String(rootDomain || '').toLowerCase();
  if (!rootDomain) return;
  let seed = normalizeCrawlPageUrl(urlObj.toString());
  if (!seed || !isWithinRootDomain(seed, rootDomain)) {
    seed = normalizeCrawlPageUrl(`https://${rootDomain}/`);
  }
  if (!seed) return;

  const maxPages = Math.min(Math.max(Number(options.maxPages || 120), 1), 600);
  const concurrency = Math.min(Math.max(Number(options.concurrency || 1), 1), 2);
  const legalComplianceMode = options.legalComplianceMode !== false;
  const respectRobots = legalComplianceMode ? true : options.respectRobots === true;
  const overrideRobots = legalComplianceMode ? false : options.overrideRobots === true;
  const useExternalTools = legalComplianceMode ? false : options.useExternalTools !== false;

  let legalAccess = { ok: true, policy: { allow: [], disallow: [] }, reason: '' };
  if (legalComplianceMode && ENFORCE_LEGAL_USAGE_GUARDS) {
    legalAccess = await ensureLegalAccessForUrl(seed, 'domain scan');
    if (!legalAccess.ok) {
      emitDomainScanStatus(tabId, {
        started: false,
        blocked: true,
        finished: true,
        stage: 'legal-policy-blocked',
        reason: legalAccess.reason,
        message: getLegalBlockMessageForReason(legalAccess.reason),
        domain: rootDomain
      });
      return;
    }
  }

  let requestedTools = Array.isArray(options.externalTools) ? options.externalTools : [];
  requestedTools = requestedTools.map((tool) => String(tool || '').trim().toLowerCase()).filter(Boolean);
  if (requestedTools.length === 0) {
    requestedTools = ['katana', 'hakrawler', 'linkfinder', 'zap'];
  }

  const externalTools = Array.from(new Set(requestedTools)).filter((tool) => ['katana', 'hakrawler', 'linkfinder', 'zap'].includes(tool));

  if (domainScanJobs.has(tabId)) {
    const prevJob = domainScanJobs.get(tabId);
    prevJob.active = false;
    destroyDomainCrawlerWindow(prevJob);
    domainScanJobs.delete(tabId);
  }

  const robotsPolicy =
    respectRobots && !overrideRobots
      ? (legalComplianceMode && legalAccess.policy ? legalAccess.policy : await getRobotsPolicyForUrl(seed))
      : { allow: [], disallow: [] };
  if (legalComplianceMode && robotsDisallowAll(robotsPolicy)) {
    emitDomainScanStatus(tabId, {
      started: false,
      blocked: true,
      finished: true,
      stage: 'legal-policy-blocked',
      reason: 'robots-disallow-all',
      message: getLegalBlockMessageForReason('robots-disallow-all'),
      domain: rootDomain
    });
    return;
  }

  emitDomainScanStatus(tabId, { started: true, stage: 'discovering-subdomains' });
  const discoveredHosts = await discoverInitialSubdomains(rootDomain);

  const seedHost = safeUrl(seed) ? safeUrl(seed).hostname.toLowerCase() : rootDomain;
  if (!discoveredHosts.includes(seedHost)) {
    discoveredHosts.unshift(seedHost);
  }

  const job = {
    tabId,
    active: true,
    rootDomain,
    queue: [],
    queued: new Set(),
    visited: new Set(),
    running: 0,
    maxPages,
    maxSubdomains: Math.min(Math.max(Number(options.maxSubdomains || 40), 1), DOMAIN_SCAN_MAX_SUBDOMAINS),
    concurrency,
    respectRobots,
    overrideRobots,
    robotsPolicy,
    discoveredHosts: new Set(discoveredHosts),
    scannedHosts: new Set(),
    hostQueue: discoveredHosts.slice(0, DOMAIN_SCAN_MAX_SUBDOMAINS),
    currentHost: '',
    probedMediaUrls: new Set(),
    useExternalTools,
    legalComplianceMode,
    externalTools,
    externalDiscoveredUrls: new Set(),
    externalDiscoveryHostsInFlight: new Set(),
    externalDiscoveryHostsDone: new Set()
  };

  const seededUrl = normalizeCrawlPageUrl(`https://${seedHost}/`) || seed;
  if (seededUrl && (!respectRobots || overrideRobots || isPathAllowedByRobots(seededUrl, robotsPolicy))) {
    job.queue.push(seededUrl);
    job.queued.add(seededUrl);
    job.currentHost = seedHost;
    job.scannedHosts.add(seedHost);
    if (job.useExternalTools) {
      runExternalDiscoveryForHost(tabId, job, seedHost).catch(() => {});
    }
  }

  domainScanJobs.set(tabId, job);
  emitDomainScanStatus(tabId, { started: true, currentUrl: seed });
  pumpDomainScan(tabId);
}

function stopDomainScanForTab(tabId) {
  const job = domainScanJobs.get(tabId);
  if (!job) return;
  job.active = false;
  destroyDomainCrawlerWindow(job);
  domainScanJobs.delete(tabId);
  emitDomainScanStatus(tabId, { stopped: true, finished: true });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    title: "Secure DevBrowser",
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: false,
      devTools: ALLOW_DEVTOOLS
    }
  });

  mainWindow.loadFile('index.html');
  incognitoSession = session.fromPartition('incognito-dev', { cache: false });

  // Spoof the User-Agent
  const defaultUserAgent = incognitoSession.getUserAgent();
  const spoofedUserAgent = defaultUserAgent.replace(/Electron\/[0-9.-]+ /, '').replace(/inspect\/[0-9.-]+ /, '');
  incognitoSession.setUserAgent(spoofedUserAgent);
  app.userAgentFallback = spoofedUserAgent;

  setupSecurityPolicies(incognitoSession);

  ElectronBlocker.fromPrebuiltAdsAndTracking(fetch).then((blocker) => {
    blocker.enableBlockingInSession(incognitoSession);
    console.log("Adblocker and Tracker blocker initialized successfully.");
  });

  mainWindow.on('resize', () => {
    if (activeTabId && tabs.has(activeTabId)) {
      resizeView(tabs.get(activeTabId).view);
    }
  });

  // Create initial tab
  createTab('https://duckduckgo.com/');
}

function resizeView(view) {
  const defaultToolbarHeight = 84; 
  const [width, height] = mainWindow.getSize();
  view.setBounds({ x: 0, y: defaultToolbarHeight, width, height: height - defaultToolbarHeight - 28 });
}

function createTab(url = 'https://duckduckgo.com/') {
  tabCounter++;
  const id = tabCounter.toString();
  const view = new BrowserView({
    webPreferences: {
      session: incognitoSession,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: false,
      devTools: ALLOW_DEVTOOLS
    }
  });

  view.setAutoResize({ width: true, height: true, horizontal: true, vertical: true });

  const tab = {
    id,
    view,
    title: 'Loading...',
    url,
    sniffedMedia: [],
    mediaByUrl: new Map(),
    filteredMediaUrls: new Set(),
    mediaFilter: sanitizeMediaFilter({}),
    domScanTimer: null,
    domScanInFlight: false,
    lastDomScanAt: 0
  };
  tabs.set(id, tab);

  // Sync state back to our custom UI toolbar ONLY IF it is active
  const syncUiState = () => {
    if (id !== activeTabId) return;
    mainWindow.webContents.send('url-changed', view.webContents.getURL());
    emitNavStateForTab(id);
  };

  // Deny popup navigation to prevent ad/search auto-redirects.
  // If popup URL is a direct media/file endpoint, trigger download instead.
  view.webContents.setWindowOpenHandler(({ url: targetUrl }) => {
    if (!targetUrl || targetUrl === 'about:blank') {
      return { action: 'deny' };
    }

    if (targetUrl.startsWith('http://')) {
      dialog.showErrorBox('Insecure URL', 'HTTP connections are disabled. Please use HTTPS.');
      return { action: 'deny' };
    }

    try {
      const parsed = new URL(targetUrl);
      if (parsed.protocol === 'https:') {
        const lowerTarget = targetUrl.toLowerCase();
        if (isLikelyMediaUrl(lowerTarget) || IMAGE_URL_PATTERN.test(lowerTarget)) {
          view.webContents.downloadURL(targetUrl);
        } else {
          console.log(`Blocked popup navigation: ${targetUrl}`);
        }
      }
    } catch {
      // Ignore malformed popup URLs.
    }

    return { action: 'deny' };
  });

  view.webContents.on('did-start-navigation', (event, navigationUrl, isInPlace, isMainFrame) => {
    if (isMainFrame) {
      tab.url = navigationUrl;
      stopDomainScanForTab(id);
      clearSniffedMediaForTab(id);
      syncUiState();
    }
  });

  view.webContents.on('did-navigate', () => {
    tab.url = view.webContents.getURL();
    syncUiState();
    scheduleDomMediaScan(id, 110, true);
  });
  view.webContents.on('did-navigate-in-page', () => {
    tab.url = view.webContents.getURL();
    syncUiState();
    scheduleDomMediaScan(id, 140);
  });
  view.webContents.on('did-start-loading', syncUiState);
  view.webContents.on('did-finish-load', () => {
    syncUiState();
    scheduleDomMediaScan(id, 35, true);
    setTimeout(() => {
      if (tabs.has(id)) {
        scheduleDomMediaScan(id, 0, true);
      }
    }, 900);
  });
  view.webContents.on('did-stop-loading', () => {
    scheduleDomMediaScan(id, 180);
  });

  view.webContents.on('page-title-updated', (event, title) => {
    tab.title = title;
    broadcastTabsState();
  });

  view.webContents.on('will-redirect', (event, redirectUrl) => {
    const fromUrl = String(view.webContents.getURL() || tab.url || '');
    if (shouldBlockNavigationRedirect(fromUrl, redirectUrl)) {
      event.preventDefault();
      console.log(`Blocked navigation redirect: ${fromUrl} -> ${redirectUrl}`);
    }
  });

  view.webContents.loadURL(url).catch(err => console.log('Navigation failed', err.message));
  switchTab(id);
}

function switchTab(id) {
  if (!tabs.has(id)) return;
  
  if (activeTabId && tabs.has(activeTabId)) {
    mainWindow.removeBrowserView(tabs.get(activeTabId).view);
  }
  
  activeTabId = id;
  const activeView = tabs.get(id).view;
  mainWindow.addBrowserView(activeView);
  resizeView(activeView);
  
  // Resync toolbar for newly active view
  mainWindow.webContents.send('url-changed', activeView.webContents.getURL());
  emitNavStateForTab(id);
  emitDomainScanStatus(id);
  scheduleDomMediaScan(id, 80);
  broadcastTabsState();
}

function closeTab(id) {
  if (!tabs.has(id)) return;
  const tab = tabs.get(id);
  stopDomainScanForTab(id);
  if (tab.domScanTimer) {
    clearTimeout(tab.domScanTimer);
  }
  tabs.delete(id);
  mainWindow.removeBrowserView(tab.view);
  // Ensure we free resources immediately since user is highly security conscious
  if (tab.view && tab.view.webContents && !tab.view.webContents.isDestroyed()) {
    tab.view.webContents.destroy();
  }

  const remainingIds = Array.from(tabs.keys());
  if (remainingIds.length === 0) {
    if (process.platform !== 'darwin') app.quit();
  } else if (activeTabId === id) {
    switchTab(remainingIds[remainingIds.length - 1]);
  } else {
    broadcastTabsState();
  }
}

function broadcastTabsState() {
  const tabsData = Array.from(tabs.values()).map(t => ({
    id: t.id,
    title: t.title,
    url: t.url,
    isActive: t.id === activeTabId
  }));
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('tabs-updated', tabsData);
  }
}

function setupSecurityPolicies(customSession) {
  customSession.webRequest.onBeforeRequest((details, callback) => {
    const resourceType = String(details.resourceType || '').toLowerCase();

    if (details.url.startsWith('http://')) {
      console.log(`Blocked insecure request: ${details.url}`);
      return callback({ cancel: true });
    }

    const lowerUrl = String(details.url || '').toLowerCase();
    if (
      lowerUrl.startsWith('file:') ||
      lowerUrl.startsWith('ftp:') ||
      lowerUrl.startsWith('chrome:') ||
      lowerUrl.startsWith('chrome-extension:')
    ) {
      return callback({ cancel: true });
    }

    if (BLOCK_PRIVATE_NETWORK_ACCESS && ENABLE_STRICT_HARDENING) {
      const parsed = safeUrl(details.url);
      if (parsed && isPrivateOrLocalHost(parsed.hostname)) {
        return callback({ cancel: true });
      }
    }

    if (ENABLE_STRICT_HARDENING && resourceType === 'serviceworker') {
      return callback({ cancel: true });
    }

    const sourceTabId = resolveSourceTabIdFromWebContentsId(details.webContentsId);
    if (sourceTabId) {
      const sourceTab = tabs.get(sourceTabId);
      const sourceScope = isDomainCrawlerWebContents(details.webContentsId) ? 'domain' : 'page';
      if (resourceType === 'media' || resourceType === 'image' || isLikelyMediaUrl(details.url) || IMAGE_URL_PATTERN.test(details.url.toLowerCase())) {
        addMediaCandidateToTab(sourceTabId, {
          url: details.url,
          type: resourceType || 'media',
          sourceScope,
          sourcePage: String(details.referrer || (sourceTab ? sourceTab.url : '') || ''),
          extension: inferExtension(details.url),
          sizeRaw: 0
        });
      }
    }

    callback({ cancel: false });
  });

  customSession.webRequest.onBeforeSendHeaders((details, callback) => {
    const headers = { ...(details.requestHeaders || {}) };

    headers['DNT'] = '1';
    headers['Sec-GPC'] = '1';
    delete headers['X-Client-Data'];
    delete headers['x-client-data'];

    if (ENABLE_STRICT_HARDENING) {
      const targetUrl = safeUrl(details.url);
      const refText = String(details.referrer || headers['Referer'] || headers['referer'] || '');
      const refUrl = safeUrl(refText);
      const isMainFrame = String(details.resourceType || '').toLowerCase() === 'mainframe';
      const isCrossSite = Boolean(targetUrl && refUrl && targetUrl.hostname.toLowerCase() !== refUrl.hostname.toLowerCase());

      if (!isMainFrame && isCrossSite) {
        delete headers['Referer'];
        delete headers['referer'];
        delete headers['Origin'];
        delete headers['origin'];
      }
    }

    callback({ cancel: false, requestHeaders: headers });
  });

  customSession.on('will-download', (event, item, webContents) => {
    item.pause();
    const response = dialog.showMessageBoxSync(mainWindow, {
      type: 'warning',
      buttons: ['Cancel Download', 'Allow (Untrusted)'],
      defaultId: 0,
      title: 'Unverified Download Warning',
      message: 'You are about to download a file from the internet.',
      detail: `File: ${item.getFilename()}\nURL: ${item.getURL()}\n\nWarning: This browser is operating in high-security mode.`
    });

    if (response === 1) {
      item.resume();
    } else {
      item.cancel();
    }
  });

  customSession.setPermissionRequestHandler((webContents, permission, callback) => {
    callback(false);
  });

  customSession.setPermissionCheckHandler(() => false);

  if (typeof customSession.setDevicePermissionHandler === 'function') {
    customSession.setDevicePermissionHandler(() => false);
  }

  // Native media sniffer (captures network-level media links)
  customSession.webRequest.onResponseStarted((details) => {
    if (!details || !details.url || !details.responseHeaders) return;
    if (isUnauthorizedStatusCode(details.statusCode)) return;

    const sourceTabId = resolveSourceTabIdFromWebContentsId(details.webContentsId);
    if (!sourceTabId) return;
    const sourceTab = tabs.get(sourceTabId);
    const sourceScope = isDomainCrawlerWebContents(details.webContentsId) ? 'domain' : 'page';

    const contentTypeRaw = parseHeaderValue(details.responseHeaders, 'content-type');
    const contentType = contentTypeRaw.split(';')[0].trim().toLowerCase();
    const resourceType = String(details.resourceType || '').toLowerCase();
    const urlLower = details.url.toLowerCase();
    const contentRange = parseHeaderValue(details.responseHeaders, 'content-range');
    const statusCode = Number(details.statusCode || 0);
    const isRangeResponse = Boolean(contentRange) || statusCode === 206;

    const mediaByType =
      contentType.startsWith('video/') ||
      contentType.startsWith('audio/') ||
      contentType.startsWith('image/') ||
      contentType.includes('mpegurl') ||
      contentType.includes('dash+xml');

    const mediaByUrl = isLikelyMediaUrl(urlLower);
    const imageByUrl = IMAGE_URL_PATTERN.test(urlLower);
    const mediaByResourceType = MEDIA_RESOURCE_TYPES.has(resourceType) && mediaByUrl;
    const isImageResource = resourceType === 'image' || imageByUrl;
    const isGenericBinaryMedia = contentType === 'application/octet-stream' && (mediaByUrl || imageByUrl);
    const mediaByRangeHeuristic =
      isRangeResponse &&
      (resourceType === 'media' || resourceType === 'xhr' || resourceType === 'fetch') &&
      !contentType.includes('text/html') &&
      !contentType.includes('application/json') &&
      !contentType.includes('javascript') &&
      !contentType.includes('css');

    if (!mediaByType && !mediaByUrl && !mediaByResourceType && !isImageResource && !isGenericBinaryMedia && !mediaByRangeHeuristic) {
      return;
    }

    const contentLength = parseHeaderValue(details.responseHeaders, 'content-length');
    const parsedSize = Number.parseInt(contentLength, 10);
    const parsedTotalFromRange = parseTotalFromContentRange(contentRange);
    const effectiveSize = parsedTotalFromRange || (Number.isFinite(parsedSize) ? parsedSize : 0);
    const normalizedType = mediaByRangeHeuristic && (!contentType || contentType === 'application/octet-stream')
      ? 'video/stream'
      : (contentType || resourceType || (isImageResource ? 'image' : 'media'));

    addMediaCandidateToTab(sourceTabId, {
      url: details.url,
      type: normalizedType,
      sourceScope,
      sourcePage: String(details.referrer || (sourceTab ? sourceTab.url : '') || ''),
      extension: inferExtension(details.url),
      sizeRaw: effectiveSize
    });
  });
}

const getActiveView = () => (activeTabId && tabs.has(activeTabId)) ? tabs.get(activeTabId).view : null;

// Tab IPC
ipcMain.on('create-tab', () => createTab());
ipcMain.on('switch-tab', (event, id) => switchTab(id));
ipcMain.on('close-tab', (event, id) => closeTab(id));

ipcMain.on('download-video', async (event, url) => {
  const view = getActiveView();
  if (!view || !url) return;

  const payload = typeof url === 'string' ? { url, referrer: '' } : (url || {});
  const targetUrl = String(payload.url || '').trim();
  const referrer = String(payload.referrer || '').trim();
  if (!targetUrl) return;

  if (ENFORCE_LEGAL_USAGE_GUARDS) {
    const legalAccess = await ensureLegalAccessForUrl(targetUrl, 'download');
    if (!legalAccess.ok) {
      dialog.showMessageBox(mainWindow, {
        type: 'warning',
        title: 'Download Blocked By Legal-Safe Mode',
        message: getLegalBlockMessageForReason(legalAccess.reason),
        detail: `Target: ${targetUrl}`
      });
      return;
    }
  }

  if (referrer) {
    view.webContents.downloadURL(targetUrl, {
      headers: {
        Referer: referrer
      }
    });
  } else {
    view.webContents.downloadURL(targetUrl);
  }
});

ipcMain.on('scan-media', () => {
  if (!activeTabId || !tabs.has(activeTabId)) return;
  scheduleDomMediaScan(activeTabId, 0, true);
});

ipcMain.on('set-media-filter', (event, filterPayload) => {
  if (!activeTabId || !tabs.has(activeTabId)) return;
  const tab = tabs.get(activeTabId);
  const nextFilter = sanitizeMediaFilter(filterPayload || {});
  const prevFilterSerialized = JSON.stringify(tab.mediaFilter || {});
  const nextFilterSerialized = JSON.stringify(nextFilter);
  tab.mediaFilter = nextFilter;
  rebuildFilteredMediaForTab(activeTabId);

  if (prevFilterSerialized !== nextFilterSerialized) {
    scheduleDomMediaScan(activeTabId, 0, true);
  }
});

ipcMain.on('start-domain-scan', (event, options) => {
  if (!activeTabId || !tabs.has(activeTabId)) return;
  startDomainScanForTab(activeTabId, options || {});
});

ipcMain.on('stop-domain-scan', () => {
  if (!activeTabId || !tabs.has(activeTabId)) return;
  stopDomainScanForTab(activeTabId);
});

ipcMain.on('clear-media', () => {
  if (activeTabId && tabs.has(activeTabId)) {
    stopDomainScanForTab(activeTabId);
    clearSniffedMediaForTab(activeTabId);
  }
});

ipcMain.on('toggle-modal', (event, modalIsVisible) => {
  const view = getActiveView();
  if (!view) return;
  if (modalIsVisible) {
    // Hide view out of bounds securely so HTML layer can paint
    view.setBounds({ x: 0, y: 0, width: 0, height: 0 });
  } else {
    // Restore bounds
    resizeView(view);
  }
});

ipcMain.on('navigate', (event, url) => {
  const view = getActiveView();
  if (view) {
    if (url.startsWith('http://')) {
      dialog.showErrorBox('Insecure URL', 'HTTP connections are disabled. Please use HTTPS.');
      return;
    }

    const parsed = safeUrl(url);
    if (parsed && BLOCK_PRIVATE_NETWORK_ACCESS && isPrivateOrLocalHost(parsed.hostname)) {
      dialog.showErrorBox('Blocked Private Network Target', 'Access to local/private-network addresses is blocked in strict mode.');
      return;
    }

    view.webContents.loadURL(url).catch(err => console.log('Navigation failed', err.message));
  }
});

ipcMain.on('go-back', () => {
  const view = getActiveView();
  if (view && canGoBackSafe(view.webContents)) goBackSafe(view.webContents);
});

ipcMain.on('go-forward', () => {
  const view = getActiveView();
  if (view && canGoForwardSafe(view.webContents)) goForwardSafe(view.webContents);
});

ipcMain.on('reload', () => {
  const view = getActiveView();
  if (view) view.webContents.reload();
});

ipcMain.on('toggle-inspect', () => {
  if (!ALLOW_DEVTOOLS) {
    dialog.showMessageBox(mainWindow, {
      type: 'info',
      title: 'Inspect Disabled',
      message: 'Developer tools are disabled in strict hardening mode.'
    });
    return;
  }

  const view = getActiveView();
  if (view) {
    if (view.webContents.isDevToolsOpened()) view.webContents.closeDevTools();
    else view.webContents.openDevTools({ mode: 'right' });
  }
});

// Load Extension implementation
ipcMain.on('load-extension', async (event, extRef) => {
  if (ENABLE_STRICT_HARDENING) {
    dialog.showErrorBox(
      'Extension Install Disabled',
      'Extension installation is disabled in strict hardening mode to reduce attack surface.'
    );
    return;
  }

  if (!extRef) return;
  const idMatch = extRef.match(/[a-z]{32}/);
  if (!idMatch) {
    dialog.showErrorBox('Invalid Extension', 'Could not find a valid 32-character Chrome Extension ID.');
    return;
  }
  const extId = idMatch[0];
  const trustResponse = dialog.showMessageBoxSync(mainWindow, {
    type: 'question',
    buttons: ['Cancel', 'Fetch & Install Securely'],
    defaultId: 0,
    title: 'Trust Chrome Extension?',
    message: 'Auto-Installing Web Store Extension',
    detail: `Extension ID: ${extId}`
  });
  if (trustResponse === 1) {
    try {
      const extName = await installExtension(extId, { loadExtensionOptions: { allowFileAccess: true } });
      dialog.showMessageBox(mainWindow, {
        type: 'info',
        title: 'Extension Installed',
        message: `Successfully installed "${extName}" to the browser.`
      });
    } catch (err) {
      dialog.showErrorBox('Installation Failed', `Could not fetch or install extension:\n\n${err.message}`);
    }
  }
});

app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  event.preventDefault();
  callback(false);
  if (mainWindow) {
    dialog.showMessageBox(mainWindow, {
      type: 'error',
      title: 'Insecure Connection Prevented',
      message: 'Certificate Error Detected',
      detail: `The site at ${url} has an invalid or insecure SSL certificate.\n\nError: ${error}\n\nFor your safety, access to this site has been strictly blocked.`
    });
  }
});

app.on('before-quit', () => {
  if (!incognitoSession) return;
  incognitoSession.clearStorageData().catch(() => {});
  incognitoSession.clearCache().catch(() => {});
});

app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
