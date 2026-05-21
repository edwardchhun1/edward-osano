'use strict';

const express = require('express');
const cors = require('cors');
const chromium = require('@sparticuz/chromium');
const puppeteerExtra = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
puppeteerExtra.use(StealthPlugin());
puppeteerExtra.connect = require('puppeteer-core').connect;

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Tracker domain lists ─────────────────────────────────────────────────────
const TRACKER_DOMAINS = {
  analytics: [
    'google-analytics.com',
    'googletagmanager.com',
    'analytics.google.com',
    'mixpanel.com',
    'segment.io',
    'segment.com',
    'amplitude.com',
    'heap.io',
    'hotjar.com',
    'fullstory.com',
    'logrocket.com',
    'clarity.ms',
    'crazyegg.com',
    'mouseflow.com',
  ],
  advertising: [
    'doubleclick.net',
    'googlesyndication.com',
    'connect.facebook.net',
    'ads.twitter.com',
    'amazon-adsystem.com',
    'criteo.com',
    'quantserve.com',
    'scorecardresearch.com',
    'adnxs.com',
    'pubmatic.com',
    'rubiconproject.com',
    'openx.net',
    'taboola.com',
    'outbrain.com',
    'bing.com',
  ],
  social: [
    'connect.facebook.net',
    'platform.twitter.com',
    'platform.linkedin.com',
    'assets.pinterest.com',
  ],
};

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// 60-second request timeout
app.use((req, res, next) => {
  res.setTimeout(60000, () => {
    res.status(503).json({ error: 'Request timed out after 60 seconds' });
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
    browser = await puppeteerExtra.launch({
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
    const preConsentTrackers = { analytics: new Set(), advertising: new Set(), social: new Set() };
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

    // ── 5. Navigate with networkidle2, fall back to domcontentloaded ─────────
    let finalUrl = targetUrl;
    try {
      await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 30000 });
    } catch (navErr) {
      if (navErr.name === 'TimeoutError' || (navErr.message && navErr.message.includes('timeout'))) {
        console.log(`[scan] networkidle2 timeout, retrying with domcontentloaded`);
        try {
          await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
        } catch (fallbackErr) {
          console.log(`[scan] domcontentloaded also failed: ${fallbackErr.message}`);
          // Continue anyway — partial data is still useful
        }
      } else {
        throw navErr;
      }
    }
    finalUrl = page.url();

    // ── 6. Wait 5 s for JS/CMP to init (and Cloudflare challenges to resolve) ─
    await new Promise((r) => setTimeout(r, 5000));

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
    };
    const preConsentTotal =
      preConsentOut.analytics.length +
      preConsentOut.advertising.length +
      preConsentOut.social.length;

    const signals = {
      // HTTPS
      hasHttps,
      httpsRedirectEnforced,

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

// ─── Start server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Osano compliance scanner listening on port ${PORT}`);
});
