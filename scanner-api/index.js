'use strict';

const express = require('express');
const cors = require('cors');
const chromium = require('@sparticuz/chromium');
const puppeteer = require('puppeteer-core');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Tracker domain lists ─────────────────────────────────────────────────────
const TRACKER_DOMAINS = {
  analytics: [
    'google-analytics.com','googletagmanager.com','analytics.google.com',
    'mixpanel.com','segment.io','segment.com','cdn.segment.com',
    'amplitude.com','heap.io','hotjar.com','fullstory.com',
    'logrocket.com','clarity.ms','crazyegg.com','mouseflow.com',
    'luckyorange.com','inspectlet.com','smartlook.com','sessionstack.com',
    'contentsquare.com','glassbox.com','quantummetric.com',
    'decibel.com','piwik.pro','matomo.org','plausible.io',
    'rudderstack.com','freshpaint.io','june.so','posthog.com',
    'intercom.io','intercomcdn.com','widget.intercom.io',
    'js.driftt.com','app.drift.com','js.hsforms.net',
    'js.hs-analytics.net','js.hubspot.com','forms.hubspot.com',
    'cdn.heapanalytics.com','cdn.pendo.io','pendo.io',
    'cdn.appcues.com','app.appcues.com',
    'js.sentry-cdn.com','browser.sentry-cdn.com',
    'cdn.lr-ingest.io','cdn.lr-intake.com',
  ],
  advertising: [
    'connect.facebook.net','facebook.com','fbcdn.net','graph.facebook.com',
    'pixel.facebook.com','www.facebook.com',
    'doubleclick.net','googlesyndication.com','googleadservices.com',
    'google.com','googleads.g.doubleclick.net',
    'ads.twitter.com','static.ads-twitter.com','analytics.twitter.com',
    't.co','ads.linkedin.com','platform.linkedin.com',
    'snap.com','sc-static.net','snapchat.com',
    'ads.pinterest.com','ct.pinterest.com','analytics.tiktok.com',
    'business.tiktok.com','tiktok.com',
    'amazon-adsystem.com','criteo.com','criteo.net',
    'quantserve.com','scorecardresearch.com','adnxs.com',
    'pubmatic.com','rubiconproject.com','openx.net',
    'taboola.com','outbrain.com','bat.bing.com','bing.com',
    'adform.net','liveramp.com','id5-sync.com',
    'casalemedia.com','indexexchange.com','appnexus.com',
    'thetradedesk.com','adsrvr.org','yahoo.com',
    'advertising.com','verizonmedia.com','oath.com',
    'moatads.com','doubleverify.com','sizmek.com',
    'yieldify.com','sharethrough.com','zemanta.com',
    'spotxchange.com','spotx.tv','sharethrough.com',
    'triplelift.com','sovrn.com','33across.com',
    'smartadserver.com','teads.tv','outbrain.com',
    'pinterest.com','linkedin.com','reddit.com','redd.it',
  ],
  social: [
    'connect.facebook.net','facebook.com','fbcdn.net',
    'platform.twitter.com','analytics.twitter.com','t.co',
    'platform.linkedin.com','snap.com','sc-static.net',
    'assets.pinterest.com','ct.pinterest.com',
    'analytics.tiktok.com','tiktok.com',
    'instagram.com',
  ],
  fingerprinting: [
    'fingerprint.com','fpjs.io','api.fpjs.io',
    'threatmetrix.com','h.online-metrix.net',
    'iovation.com','tapad.com','id5-sync.com',
    'liveramp.com','rampjs.com',
  ],
};

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// 60-second request timeout
app.use((req, res, next) => {
  res.setTimeout(90000, () => {
    res.status(503).json({ error: 'Request timed out' });
  });
  next();
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ service: 'osano-compliance-scanner', status: 'ok', endpoints: ['POST /scan', 'GET /health'] });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Given a URL string, return its hostname (or null on error).
 */
function hostnameOf(urlStr) {
  try {
    return new URL(urlStr).hostname;
  } catch {
    return null;
  }
}

/**
 * Determine which tracker category a hostname belongs to (or null).
 */
function classifyTracker(hostname) {
  if (!hostname) return null;
  for (const [category, domains] of Object.entries(TRACKER_DOMAINS)) {
    if (domains.some((d) => hostname === d || hostname.endsWith('.' + d))) {
      return category;
    }
  }
  return null;
}

// Known tracking cookie name patterns (regex)
const TRACKING_COOKIE_PATTERNS = [
  /^_ga/, /^_gid/, /^_gat/, /^__utm/, /^ajs_/,
  /^_fbp/, /^_fbc/, /^fr$/, /^MUID$/, /^IDE$/,
  /^_hjid/, /^_hjSession/, /^_hjSessionUser/, /^_hjAbsoluteSessionInProgress/,
  /^amplitude_id/, /^mp_/, /^__insp/, /^_pin_unauth/,
  /^_tt_enable_cookie/, /^_ttp/, /^TDID$/, /^criteo_/,
  /^lidc$/, /^VISITOR_INFO1_LIVE/, /^YSC$/, /^NID$/,
  /^1P_JAR/, /^_gcl_/, /^ads_prefs/, /^ttwid/,
  /^__gads/, /^__gpi/, /^_uetsid/, /^_uetvid/,
  /^personalization_id/, /^guest_id/, /^muc_ads/,
  /^s_cc/, /^s_sq/, /^s_vi/, /^AMCV_/, /^demdex/,
  /^__qca/, /^quantcast/, /^mc$/, /^_clck/, /^_clsk/,
];

function isTrackingCookie(name) {
  return TRACKING_COOKIE_PATTERNS.some(p => p.test(name));
}

/**
 * Normalize a URL to have a scheme. Defaults to https.
 */
function normalizeUrl(raw) {
  if (!/^https?:\/\//i.test(raw)) {
    return 'https://' + raw;
  }
  return raw;
}

// ─── Main scan handler ────────────────────────────────────────────────────────
app.post('/scan', async (req, res) => {
  const rawUrl = (req.body && req.body.url) ? req.body.url.trim() : null;
  if (!rawUrl) {
    return res.status(400).json({ error: 'Missing required field: url' });
  }

  const targetUrl = normalizeUrl(rawUrl);
  const startTime = Date.now();
  console.log(`[scan] Starting scan: ${targetUrl}`);

  let browser = null;

  try {
    // ── 1. Launch browser ───────────────────────────────────────────────────
    browser = await puppeteer.launch({
      args: chromium.args,
      defaultViewport: chromium.defaultViewport,
      executablePath: await chromium.executablePath(),
      headless: chromium.headless,
    });

    // ── 2. Open page, set UA + viewport ────────────────────────────────────
    const page = await browser.newPage();
    await page.setUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
        '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    );
    await page.setViewport({ width: 1280, height: 800 });

    // ── 3. Request interception — capture pre-consent trackers ──────────────
    const preConsentTrackers = { analytics: new Set(), advertising: new Set(), social: new Set(), fingerprinting: new Set() };
    await page.setRequestInterception(true);
    page.on('request', (request) => {
      const hostname = hostnameOf(request.url());
      if (hostname) {
        const cat = classifyTracker(hostname);
        if (cat) preConsentTrackers[cat].add(hostname);
      }
      request.continue();
    });

    // ── 4. Capture set-cookie headers from responses ────────────────────────
    const rawResponseCookies = [];
    page.on('response', (response) => {
      const headers = response.headers();
      if (headers['set-cookie']) {
        rawResponseCookies.push(headers['set-cookie']);
      }
    });

    // ── 5. Navigate — domcontentloaded first, then wait for network quiet ───────
    let finalUrl = targetUrl;
    try {
      await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 20000 });
    } catch (navErr) {
      console.log(`[scan] Navigation failed: ${navErr.message}`);
      // Continue anyway — partial data is still useful
    }
    // Let network settle and JS execute (CMPs init after DOM ready)
    await Promise.race([
      page.waitForNetworkIdle({ idleTime: 500, timeout: 8000 }).catch(() => {}),
      new Promise((r) => setTimeout(r, 8000)),
    ]);
    finalUrl = page.url();

    // ── 6. Wait 3 s for CMP to fully render ─────────────────────────────────
    await new Promise((r) => setTimeout(r, 3000));

    // Capture page title for diagnostics
    const pageTitle = await page.title().catch(() => '');
    console.log(`[scan] Page title: "${pageTitle}" at ${page.url()}`);

    // Detect bot-challenge pages — return 403 so the frontend falls back to proxy
    const blockedTitles = ['attention required', 'just a moment', 'ddos-guard', 'access denied', 'robot check'];
    if (blockedTitles.some((t) => pageTitle.toLowerCase().includes(t))) {
      console.log(`[scan] Bot challenge detected, reporting as blocked`);
      return res.status(403).json({ error: 'blocked', pageTitle });
    }

    // ── 7. Detect CMP ───────────────────────────────────────────────────────
    const cmpResult = await page.evaluate(() => {
      const checks = [
        {
          name: 'Osano',
          detected:
            typeof window.Osano !== 'undefined' ||
            !!document.querySelector('[class*="osano"]'),
        },
        {
          name: 'OneTrust',
          detected:
            typeof window.OneTrust !== 'undefined' ||
            !!document.querySelector('#onetrust-banner-sdk'),
        },
        {
          name: 'Cookiebot',
          detected:
            typeof window.Cookiebot !== 'undefined' ||
            !!document.querySelector('#CybotCookiebotDialog'),
        },
        {
          name: 'TrustArc',
          detected:
            typeof window.truste !== 'undefined' ||
            !!document.querySelector('.trustarc-banner-container'),
        },
        {
          name: 'Usercentrics',
          detected: typeof window.UC_UI !== 'undefined',
        },
        {
          name: 'Didomi',
          detected:
            typeof window.Didomi !== 'undefined' ||
            !!document.querySelector('#didomi-host'),
        },
        {
          name: 'Iubenda',
          detected: typeof window._iub !== 'undefined',
        },
      ];

      // Generic cookie-consent selectors as a fallback
      const genericSelectors = [
        '[class*="cookie-consent"]',
        '[id*="cookie-banner"]',
        '[class*="consent-banner"]',
        '[aria-label*="cookie"]',
      ];
      const genericDetected = genericSelectors.some((sel) => !!document.querySelector(sel));

      const namedMatch = checks.find((c) => c.detected);
      if (namedMatch) return { name: namedMatch.name, detected: true };
      if (genericDetected) return { name: 'Unknown CMP', detected: true };
      return { name: null, detected: false };
    });

    // ── 8. Check granular controls ───────────────────────────────────────────
    const hasGranularCMP = await page.evaluate(() => {
      const selectors = [
        '[class*="osano"] input[type="checkbox"]',
        '.ot-cat-item',
        '#onetrust-pc-sdk input[type="checkbox"]',
        '[class*="cookie-category"] input',
        '[class*="purpose"] input[type="checkbox"]',
      ];
      return selectors.some((sel) => !!document.querySelector(sel));
    });

    // ── 9. Check consent withdrawal link ────────────────────────────────────
    const hasConsentWithdrawLink = await page.evaluate(() => {
      const phrases = [
        'cookie settings',
        'manage cookies',
        'cookie preferences',
        'privacy settings',
        'manage consent',
      ];
      const els = [...document.querySelectorAll('a, button')];
      return els.some((el) => {
        const text = (el.innerText || el.textContent || '').toLowerCase().trim();
        return phrases.some((p) => text.includes(p));
      });
    });

    // ── 10. Find privacy policy URL ──────────────────────────────────────────
    const policyUrl = await page.evaluate((base) => {
      const anchors = [...document.querySelectorAll('a[href]')];
      let best = null;
      let bestScore = 0;

      for (const a of anchors) {
        let score = 0;
        const href = (a.getAttribute('href') || '').toLowerCase();
        const text = (a.innerText || a.textContent || '').toLowerCase().trim();

        if (href.includes('privacy')) score += 3;
        if (text === 'privacy policy' || text === 'privacy notice') score += 4;
        else if (text.includes('privacy')) score += 2;

        if (score > bestScore) {
          bestScore = score;
          // Resolve to absolute URL
          try {
            best = new URL(a.getAttribute('href'), base).href;
          } catch {
            best = a.getAttribute('href');
          }
        }
      }
      return best;
    }, finalUrl);

    // ── 11. Find Do Not Sell link ────────────────────────────────────────────
    const hasDoNotSell = await page.evaluate(() => {
      const phrases = [
        'do not sell',
        'do not share',
        'your privacy choices',
        'opt out of sale',
      ];
      const els = [...document.querySelectorAll('a, button, span, p, div')];
      return els.some((el) => {
        const text = (el.innerText || el.textContent || '').toLowerCase();
        return phrases.some((p) => text.includes(p));
      });
    });

    // ── 12. Find cookie policy link ──────────────────────────────────────────
    const hasCookiePolicy = await page.evaluate(() => {
      const anchors = [...document.querySelectorAll('a[href]')];
      return anchors.some((a) => {
        const href = (a.getAttribute('href') || '').toLowerCase();
        const text = (a.innerText || a.textContent || '').toLowerCase().trim();
        return (
          href.includes('cookie') ||
          text === 'cookie policy' ||
          text === 'cookie notice'
        );
      });
    });

    // ── 13. Get and analyze cookies ──────────────────────────────────────────
    const pageCookies = await page.cookies();
    const isLocalhost =
      finalUrl.includes('localhost') || finalUrl.includes('127.0.0.1');

    const insecureCookies = pageCookies.filter(
      (c) => c.secure !== true && !isLocalhost
    ).map((c) => c.name);

    const noHttpOnly = pageCookies.filter((c) => c.httpOnly !== true).map((c) => c.name);
    const noSameSite = pageCookies
      .filter((c) => c.sameSite === undefined || c.sameSite === 'None')
      .map((c) => c.name);

    const cookieFlags = {
      total: pageCookies.length,
      insecureCookies,
      noHttpOnly,
      noSameSite,
      allSecure: insecureCookies.length === 0,
    };

    // ── 13b. Pre-consent cookie analysis ─────────────────────────────────
    const trackingCookiesFound = pageCookies
      .filter(c => isTrackingCookie(c.name))
      .map(c => c.name);

    const preConsentCookies = {
      total: pageCookies.length,
      trackingCookies: trackingCookiesFound,
      trackingCount: trackingCookiesFound.length,
    };

    // ── 13c. Pre-consent storage (localStorage / sessionStorage) ──────────
    const storageData = await page.evaluate(() => {
      const trackPatterns = [
        '_ga','_gid','amplitude','ajs_','mixpanel','heap','hjid',
        '_fbp','_fbc','MUID','IDE','criteo','_tt_','liveramp',
        'segment','posthog','logrocket','fullstory','hotjar',
      ];
      const isTrackKey = (k) => trackPatterns.some(p => k.toLowerCase().includes(p));
      const lsKeys = [];
      const ssKeys = [];
      try {
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i);
          if (k && isTrackKey(k)) lsKeys.push(k);
        }
      } catch(e) {}
      try {
        for (let i = 0; i < sessionStorage.length; i++) {
          const k = sessionStorage.key(i);
          if (k && isTrackKey(k)) ssKeys.push(k);
        }
      } catch(e) {}
      return { localStorageTrackingKeys: lsKeys, sessionStorageTrackingKeys: ssKeys };
    });

    const preConsentStorage = {
      localStorageTrackingKeys: storageData.localStorageTrackingKeys,
      sessionStorageTrackingKeys: storageData.sessionStorageTrackingKeys,
      hasTrackingStorage: storageData.localStorageTrackingKeys.length > 0 || storageData.sessionStorageTrackingKeys.length > 0,
    };

    // ── 14. Fetch privacy policy page ────────────────────────────────────────
    let policyText = '';
    if (policyUrl) {
      let policyPage = null;
      try {
        policyPage = await browser.newPage();
        await policyPage.setUserAgent(
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
            '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        );
        await policyPage.goto(policyUrl, { waitUntil: 'domcontentloaded', timeout: 20000 });
        await new Promise((r) => setTimeout(r, 1500));
        policyText = await policyPage.evaluate(() => document.body.innerText || '');
      } catch (policyErr) {
        console.log(`[scan] Could not fetch policy page: ${policyErr.message}`);
      } finally {
        if (policyPage) {
          try { await policyPage.close(); } catch {}
        }
      }
    }

    // ── 14b. CMP disclosure extraction ──────────────────────────────────
    let cmpDisclosure = {
      hasCMP: cmpResult.detected,
      cmpName: cmpResult.name,
      hasDisclosureTable: false,
      disclosedCookies: [],
      actualCookieNames: pageCookies.map(c => c.name),
      trackingCookiesOnPage: trackingCookiesFound,
      missingDisclosures: [],
      allDisclosed: false,
    };

    if (cmpResult.detected) {
      try {
        // Try to open the CMP drawer to access disclosure table
        await page.evaluate(() => {
          // Osano: click widget button
          const osanoWidget = document.querySelector(
            '.osano-cm-widget button, [class*="osano-cm-widget"], .osano-cm-widget'
          );
          if (osanoWidget) { osanoWidget.click(); return; }
          // OneTrust
          const otBtn = document.querySelector('#ot-sdk-btn, .ot-sdk-show-settings');
          if (otBtn) { otBtn.click(); return; }
          // Generic
          const generic = document.querySelector(
            '[class*="cookie-settings"], [class*="manage-cookies"], [class*="cookie-preferences"]'
          );
          if (generic) generic.click();
        });
        await new Promise(r => setTimeout(r, 2000));

        const drawerData = await page.evaluate(() => {
          const names = new Set();
          let hasTable = false;

          // Osano disclosure selectors
          const osanoSelectors = [
            '.osano-cm-disclosure__list-item',
            '[class*="osano-cm-disclosure"] tr',
            '[class*="osano-cm-cookie"]',
            '.osano-cm-cookie-item',
          ];
          for (const sel of osanoSelectors) {
            const els = document.querySelectorAll(sel);
            if (els.length) {
              hasTable = true;
              els.forEach(el => {
                const nameEl = el.querySelector(
                  '[class*="cookie-name"], [class*="name"], td:first-child, th:first-child'
                );
                const txt = (nameEl || el).textContent.trim();
                if (txt && txt.length < 80 && !txt.toLowerCase().includes('cookie name')) {
                  names.add(txt);
                }
              });
            }
          }

          // Osano table fallback
          const tables = document.querySelectorAll('[class*="osano"] table, [class*="cmp"] table, [class*="cookie-consent"] table');
          if (tables.length) {
            hasTable = true;
            tables.forEach(t => {
              t.querySelectorAll('tr').forEach((row, i) => {
                if (i === 0) return; // skip header
                const first = row.querySelector('td:first-child');
                if (first && first.textContent.trim()) names.add(first.textContent.trim());
              });
            });
          }

          // OneTrust
          const otCookies = document.querySelectorAll('.ot-cookies-td[data-label="Cookie Subgroup"], .ot-table-column:first-child .ot-mobile-border');
          if (otCookies.length) {
            hasTable = true;
            otCookies.forEach(el => { if (el.textContent.trim()) names.add(el.textContent.trim()); });
          }

          // Generic disclosure tables
          const genericTable = document.querySelector('[class*="disclosure-table"], [class*="cookie-table"], [id*="cookie-table"]');
          if (genericTable) {
            hasTable = true;
            genericTable.querySelectorAll('tr').forEach((row, i) => {
              if (i === 0) return;
              const td = row.querySelector('td');
              if (td && td.textContent.trim()) names.add(td.textContent.trim());
            });
          }

          // Check for any table with "cookie" heading at all
          if (!hasTable) {
            const allTables = document.querySelectorAll('table');
            allTables.forEach(t => {
              const header = t.querySelector('th');
              if (header && header.textContent.toLowerCase().includes('cookie')) {
                hasTable = true;
              }
            });
          }

          return { hasTable, cookies: [...names] };
        });

        cmpDisclosure.hasDisclosureTable = drawerData.hasTable;
        cmpDisclosure.disclosedCookies = drawerData.cookies;

        // Find tracking cookies on page not present in disclosure
        if (drawerData.hasTable) {
          cmpDisclosure.missingDisclosures = trackingCookiesFound.filter(name =>
            !drawerData.cookies.some(d =>
              d.toLowerCase() === name.toLowerCase() ||
              name.toLowerCase().startsWith(d.toLowerCase().replace('*','').slice(0,5))
            )
          );
          cmpDisclosure.allDisclosed = cmpDisclosure.missingDisclosures.length === 0;
        }

        // Try to close the drawer
        await page.evaluate(() => {
          const closeBtn = document.querySelector(
            '.osano-cm-dialog__close, [class*="osano"][class*="close"], ' +
            '[aria-label="Close"], [aria-label="close"], .ot-pc-refuse-all-handler'
          );
          if (closeBtn) closeBtn.click();
        });
      } catch (e) {
        console.log('[scan] CMP disclosure extraction error:', e.message);
      }
    }

    // ── 14c. Privacy policy location (banner vs footer) ──────────────────
    const privacyPolicyLocations = await page.evaluate(() => {
      const isPrivLink = (el) => {
        const href = (el.href || el.getAttribute('href') || '').toLowerCase();
        const text = (el.innerText || el.textContent || '').toLowerCase().trim();
        return href.includes('privacy') || text.includes('privacy policy') ||
               text.includes('privacy notice') || text === 'privacy';
      };
      // CMP banner
      const cmpRoots = document.querySelectorAll(
        '[class*="osano-cm"], #onetrust-banner-sdk, .trustarc-banner-container, ' +
        '[class*="cookie-banner"], [class*="consent-banner"], [class*="CybotCookiebot"], ' +
        '[id*="cookie-law"], [class*="cookie-consent"], [class*="cc-window"]'
      );
      let inBanner = false;
      cmpRoots.forEach(root => {
        if ([...root.querySelectorAll('a')].some(isPrivLink)) inBanner = true;
      });
      // Footer
      const footerRoots = document.querySelectorAll('footer, [role="contentinfo"], [class*="footer"], #footer');
      let inFooter = false;
      footerRoots.forEach(root => {
        if ([...root.querySelectorAll('a')].some(isPrivLink)) inFooter = true;
      });
      // Header/nav
      const headerRoots = document.querySelectorAll('header, nav, [role="navigation"], [class*="header"], [class*="navbar"]');
      let inHeader = false;
      headerRoots.forEach(root => {
        if ([...root.querySelectorAll('a')].some(isPrivLink)) inHeader = true;
      });
      return { inBanner, inFooter, inHeader };
    });

    // ── 15. Analyze policy text ──────────────────────────────────────────────
    const pt = policyText.toLowerCase();

    const hasDataCats = /personal (data|information)|categories of (data|information)|types of (data|information)/.test(pt);
    const hasThirdParty = /third.party|third party|share.*with|partners|vendors/.test(pt);
    const hasDPO = /data protection officer|dpo/.test(pt);
    const hasContact = /contact us|contact@|privacy@|email us/.test(pt);
    const hasPolicyDate = /last updated|last revised|effective date|updated on/.test(pt);
    const hasRightAccess = /right to access|access your (data|information)|request.*copy/.test(pt);
    const hasRightDelete = /right to (delete|erasure|be forgotten)|delete your (data|account)|erasure/.test(pt);
    const hasGDPR = /gdpr|general data protection regulation/.test(pt);
    const hasCCPA = /ccpa|california consumer privacy|california privacy rights/.test(pt);
    const hasLGPD = /lgpd|lei geral de prote/.test(pt);
    const hasBreachPolicy = /data breach|security incident|breach notification/.test(pt);
    const hasRetention = /retention|how long we (keep|store|retain)|data.*retention/.test(pt);

    // Analytics tool disclosure in policy text
    const analyticsToolNames = [
      'google analytics', 'mixpanel', 'segment', 'amplitude', 'hotjar',
      'fullstory', 'logrocket', 'clarity', 'heap',
    ];
    const hasAnalyticsDisclosure = analyticsToolNames.some((name) => pt.includes(name));

    // Analytics scripts actually loaded on the page
    const hasAnalyticsScript = preConsentTrackers.analytics.size > 0;

    // hasOptOut: either do-not-sell link or consent withdrawal
    const hasOptOut = hasDoNotSell || hasConsentWithdrawLink;

    // ── 16. Derive HTTPS signals from finalUrl ───────────────────────────────
    const hasHttps = finalUrl.startsWith('https://');
    const httpsRedirectEnforced =
      !targetUrl.startsWith('https://') && finalUrl.startsWith('https://');

    // ── 17. Close main page ──────────────────────────────────────────────────
    await page.close();

    // ── 18. Build signals object ─────────────────────────────────────────────
    const preConsentOut = {
      analytics: [...preConsentTrackers.analytics],
      advertising: [...preConsentTrackers.advertising],
      social: [...preConsentTrackers.social],
      fingerprinting: [...(preConsentTrackers.fingerprinting || new Set())],
    };
    const preConsentTotal =
      preConsentOut.analytics.length +
      preConsentOut.advertising.length +
      preConsentOut.social.length +
      preConsentOut.fingerprinting.length;

    const signals = {
      // HTTPS
      hasHttps,
      httpsRedirectEnforced,

      // Pre-consent cookies & storage
      preConsentCookies,
      preConsentStorage,

      // CMP disclosure
      cmpDisclosure,

      // Privacy policy locations
      privacyPolicyLocations,

      // CMP
      hasCMP: cmpResult.detected,
      cmpName: cmpResult.name,
      hasOsano: cmpResult.name === 'Osano',
      hasGranularCMP,
      hasConsentWithdrawLink,

      // Pre-consent trackers
      preConsentTrackers: preConsentOut,
      preConsentTotal,

      // Cookies
      cookieFlags,

      // Privacy policy
      hasPrivacyPolicyLink: !!policyUrl,
      policyUrl: policyUrl || null,

      // Policy content
      hasPolicyText: policyText.length > 100,
      hasDataCats,
      hasThirdParty,
      hasDPO,
      hasContact,
      hasPolicyDate,
      hasRightAccess,
      hasRightDelete,
      hasGDPR,
      hasCCPA,
      hasLGPD,
      hasBreachPolicy,
      hasRetention,
      hasAnalyticsScript,
      hasAnalyticsDisclosure,

      // Additional links
      hasDoNotSell,
      hasCookiePolicy,
      hasOptOut,
    };

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log(`[scan] Completed ${targetUrl} in ${duration}s`);

    return res.json(signals);

  } catch (err) {
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    console.error(`[scan] Error scanning ${targetUrl} after ${duration}s:`, err.message);
    return res.status(500).json({ error: err.message || 'Scan failed' });
  } finally {
    if (browser) {
      try { await browser.close(); } catch {}
    }
  }
});

// ─── DSAR Mock Data ───────────────────────────────────────────────────────────

const MOCK_DATASTORES = [
  {
    id: 'ds_salesforce',
    name: 'Salesforce CRM',
    type: 'CRM',
    icon: 'sf',
    color: '#00A1E0',
    tables: ['Contact', 'Lead', 'Account', 'Opportunity', 'Case'],
    foundIn: true,
  },
  {
    id: 'ds_hubspot',
    name: 'HubSpot Marketing',
    type: 'Marketing',
    icon: 'hs',
    color: '#FF7A59',
    tables: ['contacts', 'companies', 'deals', 'email_events', 'form_submissions'],
    foundIn: true,
  },
  {
    id: 'ds_snowflake',
    name: 'Snowflake Data Warehouse',
    type: 'Data Warehouse',
    icon: 'snow',
    color: '#29B5E8',
    tables: ['USERS', 'EVENTS', 'SESSIONS', 'PURCHASES', 'PROFILE_SNAPSHOTS'],
    foundIn: true,
  },
  {
    id: 'ds_segment',
    name: 'Segment',
    type: 'CDP',
    icon: 'seg',
    color: '#52BD94',
    tables: ['identifies', 'tracks', 'pages', 'groups'],
    foundIn: true,
  },
  {
    id: 'ds_sendgrid',
    name: 'SendGrid',
    type: 'Email',
    icon: 'sg',
    color: '#1A82E2',
    tables: ['contacts', 'email_activity', 'suppressions', 'lists'],
    foundIn: true,
  },
  {
    id: 'ds_intercom',
    name: 'Intercom',
    type: 'Support',
    icon: 'ic',
    color: '#286EFA',
    tables: ['users', 'conversations', 'events', 'notes'],
    foundIn: false,
  },
  {
    id: 'ds_postgres',
    name: 'PostgreSQL prod-db',
    type: 'Database',
    icon: 'pg',
    color: '#336791',
    tables: ['users', 'user_preferences', 'audit_log', 'consent_records'],
    foundIn: true,
  },
  {
    id: 'ds_ga4',
    name: 'Google Analytics 4',
    type: 'Analytics',
    icon: 'ga',
    color: '#E37400',
    tables: ['events', 'user_properties', 'sessions'],
    foundIn: false,
  },
];

let MOCK_REQUESTS = [
  {
    id: 'dsr_xK9mP2qR8vL',
    type: 'DELETE',
    status: 'IN_PROGRESS',
    source: 'OSANO_FORM',
    subject: { name: 'Jane Doe', email: 'jane.doe@example.com', country: 'US' },
    createdAt: '2026-05-20T00:00:00.000Z',
    dueAt: '2026-06-19T00:00:00.000Z',
  },
  {
    id: 'dsr_mR3vQ8nP4sK',
    type: 'ACCESS',
    status: 'COMPLETED',
    source: 'OSANO_FORM',
    subject: { name: 'John Smith', email: 'john.smith@acmecorp.io', country: 'UK' },
    createdAt: '2026-05-15T00:00:00.000Z',
    dueAt: '2026-05-30T00:00:00.000Z',
  },
  {
    id: 'dsr_nT7wL1kM5vP',
    type: 'CORRECT',
    status: 'PENDING_VERIFICATION',
    source: 'API',
    subject: { name: 'Amy Chen', email: 'amy.chen@globex.com', country: 'DE' },
    createdAt: '2026-05-18T00:00:00.000Z',
    dueAt: '2026-06-05T00:00:00.000Z',
  },
  {
    id: 'dsr_pQ2xB9rN7mL',
    type: 'OPT_OUT',
    status: 'NEW',
    source: 'OSANO_FORM',
    subject: { name: 'Marcus Williams', email: 'm.williams@initech.net', country: 'CA' },
    createdAt: '2026-05-22T00:00:00.000Z',
    dueAt: '2026-06-21T00:00:00.000Z',
  },
  {
    id: 'dsr_kL5nV3xQ1pR',
    type: 'PORTABILITY',
    status: 'NEW',
    source: 'MANUAL',
    subject: { name: 'Sofia Rossi', email: 's.rossi@dinoco.it', country: 'IT' },
    createdAt: '2026-05-21T00:00:00.000Z',
    dueAt: '2026-06-20T00:00:00.000Z',
  },
];

// ─── DSAR Routes ──────────────────────────────────────────────────────────────

// GET /dsar/requests — list all requests, optional ?status= filter
app.get('/dsar/requests', (req, res) => {
  try {
    const { status } = req.query;
    const results = status
      ? MOCK_REQUESTS.filter((r) => r.status === status)
      : MOCK_REQUESTS;
    return res.json(results);
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Failed to list requests' });
  }
});

// GET /dsar/requests/:id — single request
app.get('/dsar/requests/:id', (req, res) => {
  try {
    const request = MOCK_REQUESTS.find((r) => r.id === req.params.id);
    if (!request) {
      return res.status(404).json({ error: `Request not found: ${req.params.id}` });
    }
    return res.json(request);
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Failed to get request' });
  }
});

// GET /dsar/datastores — list all datastores
app.get('/dsar/datastores', (req, res) => {
  try {
    return res.json(MOCK_DATASTORES);
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Failed to list datastores' });
  }
});

// GET /dsar/requests/:id/datastores — datastores with match info for a given request
app.get('/dsar/requests/:id/datastores', (req, res) => {
  try {
    const request = MOCK_REQUESTS.find((r) => r.id === req.params.id);
    if (!request) {
      return res.status(404).json({ error: `Request not found: ${req.params.id}` });
    }

    const result = MOCK_DATASTORES.map((ds) => {
      if (!ds.foundIn) {
        return {
          datastoreId: ds.id,
          name: ds.name,
          type: ds.type,
          icon: ds.icon,
          color: ds.color,
          found: false,
          recordCount: 0,
          tables: [],
        };
      }
      // Generate a realistic random record count
      const recordCount = Math.floor(Math.random() * 45) + 1;
      // Return a subset of matching tables (first 2–3)
      const matchedTables = ds.tables.slice(0, Math.min(3, ds.tables.length));
      return {
        datastoreId: ds.id,
        name: ds.name,
        type: ds.type,
        icon: ds.icon,
        color: ds.color,
        found: true,
        recordCount,
        tables: matchedTables,
      };
    });

    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Failed to get datastores for request' });
  }
});

// POST /dsar/requests/:id/fulfill — simulate fulfillment
app.post('/dsar/requests/:id/fulfill', (req, res) => {
  try {
    const idx = MOCK_REQUESTS.findIndex((r) => r.id === req.params.id);
    if (idx === -1) {
      return res.status(404).json({ error: `Request not found: ${req.params.id}` });
    }

    const request = MOCK_REQUESTS[idx];

    // Map request type to action verb
    const actionMap = {
      DELETE: 'deleted',
      ACCESS: 'exported',
      CORRECT: 'updated',
      OPT_OUT: 'suppressed',
      PORTABILITY: 'exported',
    };
    const action = actionMap[request.type] || 'processed';

    // Build results for all found datastores
    const results = MOCK_DATASTORES
      .filter((ds) => ds.foundIn)
      .map((ds) => {
        const recordsAffected = Math.floor(Math.random() * 45) + 1;
        // Randomly mark one or two as manual_required for realism
        const status = Math.random() < 0.15 ? 'manual_required' : 'success';
        return {
          datastoreId: ds.id,
          name: ds.name,
          status,
          recordsAffected,
          action,
        };
      });

    // Update status in-memory
    MOCK_REQUESTS[idx] = { ...request, status: 'COMPLETED' };

    const webhook = {
      fired: true,
      url: 'https://hooks.acmecorp.io/osano-dsar',
      payload: {
        event: 'dsar.completed',
        requestId: request.id,
        type: request.type,
        subject: request.subject,
      },
    };

    return res.json({
      requestId: request.id,
      status: 'COMPLETED',
      results,
      webhook,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Failed to fulfill request' });
  }
});

// POST /dsar/requests — create a new request
app.post('/dsar/requests', (req, res) => {
  try {
    const { type, subject } = req.body || {};

    if (!type) {
      return res.status(400).json({ error: 'Missing required field: type' });
    }
    if (!subject || !subject.name || !subject.email || !subject.country) {
      return res.status(400).json({ error: 'Missing required fields: subject.name, subject.email, subject.country' });
    }

    const validTypes = ['DELETE', 'ACCESS', 'CORRECT', 'OPT_OUT', 'PORTABILITY'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: `Invalid type. Must be one of: ${validTypes.join(', ')}` });
    }

    // Generate a new ID
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    const randomSegment = Array.from({ length: 12 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
    const newId = `dsr_${randomSegment}`;

    const now = new Date();
    const dueDate = new Date(now);
    dueDate.setDate(dueDate.getDate() + 30);

    const newRequest = {
      id: newId,
      type,
      status: 'NEW',
      source: 'API',
      subject: {
        name: subject.name,
        email: subject.email,
        country: subject.country,
      },
      createdAt: now.toISOString(),
      dueAt: dueDate.toISOString(),
    };

    MOCK_REQUESTS.push(newRequest);

    return res.status(201).json(newRequest);
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Failed to create request' });
  }
});

// ─── Start server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Osano compliance scanner listening on port ${PORT}`);
});
