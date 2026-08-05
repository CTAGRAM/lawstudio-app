import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import path from 'path';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.join(__dirname, 'dist');
app.use(express.json({ limit: '25mb' }));
app.use(cookieParser());

const EMAIL = process.env.LOGIN_EMAIL || '';
const PASS = process.env.LOGIN_PASSWORD || '';
const SECRET = process.env.AUTH_SECRET || 'change-me';
const token = () => crypto.createHmac('sha256', SECRET).update(EMAIL).digest('hex');
const authed = (req) => req.cookies && req.cookies.ls_auth === token();

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (email === EMAIL && password === PASS) {
    res.cookie('ls_auth', token(), { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 30 * 864e5 });
    return res.json({ ok: true });
  }
  return res.status(401).json({ error: 'Wrong email or password' });
});
app.post('/api/logout', (_req, res) => { res.clearCookie('ls_auth'); res.json({ ok: true }); });

// ---------------------------------------------------------------------------
// YouTube integration (OAuth connect + publish enqueue).
// Refresh tokens live in Supabase (youtube_channels, RLS-locked to the secret
// key). The browser never touches that table — it goes through these routes.
// ---------------------------------------------------------------------------
const GCID = process.env.GOOGLE_CLIENT_ID || '';
const GCSECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const REDIRECT = process.env.YOUTUBE_REDIRECT_URI
  || 'https://lawstudio-app-goodfor-2789d27c.koyeb.app/api/youtube/callback';
const SB_URL = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const SB_KEY = process.env.SUPABASE_SECRET || '';
const SCOPES = [
  'https://www.googleapis.com/auth/youtube.upload',
  'https://www.googleapis.com/auth/youtube.readonly',
  'https://www.googleapis.com/auth/userinfo.email',
].join(' ');

async function sb(method, pathq, body) {
  const r = await fetch(`${SB_URL}/rest/v1/${pathq}`, {
    method,
    headers: {
      apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}`,
      'Content-Type': 'application/json', Prefer: 'return=representation',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) throw new Error(`supabase ${method} ${pathq}: ${r.status} ${await r.text()}`);
  const t = await r.text();
  return t ? JSON.parse(t) : null;
}

// signed state carries the brand/label through the OAuth round-trip (CSRF guard)
const signState = (obj) => {
  const p = Buffer.from(JSON.stringify(obj)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
  return `${p}.${sig}`;
};
const readState = (s) => {
  const [p, sig] = String(s || '').split('.');
  if (!p || !sig) return null;
  const exp = crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
  if (exp !== sig) return null;
  try { return JSON.parse(Buffer.from(p, 'base64url').toString()); } catch { return null; }
};

// Step 1: send the user to Google's consent screen.
app.get('/api/youtube/connect', (req, res) => {
  if (!authed(req)) return res.redirect('/');
  if (!GCID) return res.status(500).send('YouTube is not configured (missing GOOGLE_CLIENT_ID).');
  const state = signState({ b: req.query.brand || '', l: req.query.label || '', t: Date.now() });
  const p = new URLSearchParams({
    client_id: GCID, redirect_uri: REDIRECT, response_type: 'code', scope: SCOPES,
    access_type: 'offline', prompt: 'consent', include_granted_scopes: 'true', state,
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${p}`);
});

// Step 2: Google redirects back with a code — exchange it, store the channel.
app.get('/api/youtube/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;
    if (error) return res.redirect('/youtube?err=' + encodeURIComponent(error));
    const st = readState(state);
    if (!code || !st) return res.redirect('/youtube?err=badstate');

    const tokRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code, client_id: GCID, client_secret: GCSECRET,
        redirect_uri: REDIRECT, grant_type: 'authorization_code',
      }),
    });
    const tok = await tokRes.json();
    if (!tok.access_token) return res.redirect('/youtube?err=notoken');

    const chRes = await fetch(
      'https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true',
      { headers: { Authorization: `Bearer ${tok.access_token}` } });
    const ch = await chRes.json();
    const item = (ch.items || [])[0];
    if (!item) return res.redirect('/youtube?err=nochannel');

    let email = '';
    try {
      const ui = await (await fetch('https://www.googleapis.com/oauth2/v2/userinfo',
        { headers: { Authorization: `Bearer ${tok.access_token}` } })).json();
      email = ui.email || '';
    } catch { /* email is best-effort */ }

    const row = {
      brand_slug: st.b || null,
      label: st.l || (item.snippet && item.snippet.title) || 'YouTube channel',
      channel_id: item.id,
      channel_title: item.snippet && item.snippet.title,
      channel_thumb: item.snippet && item.snippet.thumbnails
        && item.snippet.thumbnails.default && item.snippet.thumbnails.default.url,
      google_email: email,
      access_token: tok.access_token,
      refresh_token: tok.refresh_token || null,
      token_expiry: new Date(Date.now() + (tok.expires_in || 3500) * 1000).toISOString(),
      scopes: tok.scope || SCOPES,
      updated_at: new Date().toISOString(),
    };

    const existing = await sb('GET',
      `youtube_channels?channel_id=eq.${encodeURIComponent(item.id)}&select=id`);
    if (existing && existing.length) {
      // keep the stored refresh_token if Google didn't hand back a new one
      if (!row.refresh_token) delete row.refresh_token;
      await sb('PATCH', `youtube_channels?id=eq.${existing[0].id}`, row);
    } else {
      await sb('POST', 'youtube_channels', row);
    }
    res.redirect('/youtube?ok=1');
  } catch (e) {
    res.redirect('/youtube?err=' + encodeURIComponent(String(e.message || e)));
  }
});

// List connected channels — non-sensitive fields only (no tokens ever leave the server).
app.get('/api/youtube/channels', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const rows = await sb('GET', 'youtube_channels?select=id,brand_slug,label,'
      + 'channel_id,channel_title,channel_thumb,google_email,created_at&order=created_at.desc');
    res.json(rows || []);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.delete('/api/youtube/channels/:id', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    await sb('DELETE', `youtube_channels?id=eq.${encodeURIComponent(req.params.id)}`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// Enqueue a publish job — the Python worker does the actual upload.
app.post('/api/youtube/publish', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const { video_id, channel_row_id, title, description, tags, privacy } = req.body || {};
    if (!video_id || !channel_row_id) {
      return res.status(400).json({ error: 'video_id and channel_row_id required' });
    }
    const job = await sb('POST', 'jobs', {
      type: 'youtube_publish', video_id,
      payload: {
        channel_row_id, title: title || null, description: description || null,
        tags: tags || [], privacy: privacy || 'private',
      },
    });
    await sb('PATCH', `videos?id=eq.${encodeURIComponent(video_id)}`, { youtube_status: 'queued' });
    res.json({ ok: true, job: Array.isArray(job) ? job[0] : job });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// --- manage + analytics: quick YouTube Data API calls done inline (no worker) ---

// Refresh a channel's access token from its stored refresh_token; persist it.
async function ytAccessToken(channel) {
  if (!channel.refresh_token) throw new Error('channel has no refresh_token — reconnect it');
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: GCID, client_secret: GCSECRET,
      refresh_token: channel.refresh_token, grant_type: 'refresh_token',
    }),
  });
  const t = await r.json();
  if (!t.access_token) throw new Error('token refresh failed: ' + JSON.stringify(t).slice(0, 200));
  try {
    await sb('PATCH', `youtube_channels?id=eq.${channel.id}`, {
      access_token: t.access_token,
      token_expiry: new Date(Date.now() + (t.expires_in || 3500) * 1000).toISOString(),
      updated_at: new Date().toISOString(),
    });
  } catch { /* stale stored token is harmless */ }
  return t.access_token;
}

async function channelWithTokens(id) {
  const r = await sb('GET', `youtube_channels?id=eq.${encodeURIComponent(id)}`
    + '&select=id,refresh_token,channel_id,channel_title');
  if (!r || !r.length) throw new Error('channel not found');
  return r[0];
}

async function videoYtId(videoId) {
  const r = await sb('GET', `videos?id=eq.${encodeURIComponent(videoId)}&select=youtube_video_id`);
  const yt = r && r[0] && r[0].youtube_video_id;
  if (!yt) throw new Error('this video has not been published to YouTube');
  return yt;
}

// Edit a published video's title / description / visibility.
app.post('/api/youtube/update', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const { video_id, channel_row_id, title, description, privacy, tags } = req.body || {};
    if (!video_id || !channel_row_id) return res.status(400).json({ error: 'video_id and channel_row_id required' });
    const ytId = await videoYtId(video_id);
    const access = await ytAccessToken(await channelWithTokens(channel_row_id));

    const cur = await (await fetch(
      `https://www.googleapis.com/youtube/v3/videos?part=snippet,status&id=${ytId}`,
      { headers: { Authorization: `Bearer ${access}` } })).json();
    const item = (cur.items || [])[0];
    if (!item) return res.status(404).json({ error: 'video not found on YouTube' });

    const body = {
      id: ytId,
      snippet: {
        title: title != null ? title : item.snippet.title,
        description: description != null ? description : item.snippet.description,
        categoryId: item.snippet.categoryId || '27',
        tags: (Array.isArray(tags) && tags.length) ? tags : item.snippet.tags,
      },
      status: { privacyStatus: privacy || item.status.privacyStatus },
    };
    const up = await fetch('https://www.googleapis.com/youtube/v3/videos?part=snippet,status', {
      method: 'PUT', headers: { Authorization: `Bearer ${access}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!up.ok) throw new Error('update failed: ' + (await up.text()).slice(0, 300));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// Delete a video from YouTube (user-initiated). Clears our stored link.
app.post('/api/youtube/delete', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const { video_id, channel_row_id } = req.body || {};
    if (!video_id || !channel_row_id) return res.status(400).json({ error: 'video_id and channel_row_id required' });
    const ytId = await videoYtId(video_id);
    const access = await ytAccessToken(await channelWithTokens(channel_row_id));
    const del = await fetch(`https://www.googleapis.com/youtube/v3/videos?id=${ytId}`,
      { method: 'DELETE', headers: { Authorization: `Bearer ${access}` } });
    if (!del.ok && del.status !== 204) throw new Error('delete failed: ' + (await del.text()).slice(0, 300));
    await sb('PATCH', `videos?id=eq.${encodeURIComponent(video_id)}`,
      { youtube_video_id: null, youtube_url: null, youtube_status: 'deleted' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// Analytics for a connected channel: channel-level stats + stats for every
// video we published to it.
app.get('/api/youtube/analytics', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const channel = await channelWithTokens(req.query.channel_row_id);
    const access = await ytAccessToken(channel);

    const ch = await (await fetch(
      'https://www.googleapis.com/youtube/v3/channels?part=snippet,statistics&mine=true',
      { headers: { Authorization: `Bearer ${access}` } })).json();
    const cItem = (ch.items || [])[0] || {};
    const cStats = cItem.statistics || {};

    // Our published videos (any channel) — filter to this one by snippet.channelId.
    const ours = await sb('GET', 'videos?select=id,title,youtube_video_id'
      + '&youtube_video_id=not.is.null&order=created_at.desc&limit=50');
    let videos = [];
    const ids = (ours || []).map((v) => v.youtube_video_id).filter(Boolean);
    if (ids.length) {
      const vl = await (await fetch(
        `https://www.googleapis.com/youtube/v3/videos?part=snippet,statistics&id=${ids.join(',')}`,
        { headers: { Authorization: `Bearer ${access}` } })).json();
      videos = (vl.items || [])
        .filter((it) => it.snippet && it.snippet.channelId === channel.channel_id)
        .map((it) => ({
          id: it.id,
          title: it.snippet.title,
          publishedAt: it.snippet.publishedAt,
          thumb: it.snippet.thumbnails && it.snippet.thumbnails.default && it.snippet.thumbnails.default.url,
          views: Number(it.statistics.viewCount || 0),
          likes: Number(it.statistics.likeCount || 0),
          comments: Number(it.statistics.commentCount || 0),
        }));
    }
    res.json({
      channel: {
        title: cItem.snippet && cItem.snippet.title,
        thumb: cItem.snippet && cItem.snippet.thumbnails && cItem.snippet.thumbnails.default && cItem.snippet.thumbnails.default.url,
        subscribers: Number(cStats.subscriberCount || 0),
        views: Number(cStats.viewCount || 0),
        videos: Number(cStats.videoCount || 0),
      },
      videos,
    });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// Time-series analytics (views / watch-time / retention) via the YouTube
// Analytics API. Needs the yt-analytics.readonly scope — if the stored token
// predates it, we tell the UI to prompt a reconnect.
app.get('/api/youtube/analytics-timeseries', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const channel = await channelWithTokens(req.query.channel_row_id);
    const access = await ytAccessToken(channel);
    const fmt = (d) => d.toISOString().slice(0, 10);
    const start = fmt(new Date(Date.now() - 28 * 864e5));
    const end = fmt(new Date());
    const url = 'https://youtubeanalytics.googleapis.com/v2/reports?ids=channel==MINE'
      + `&startDate=${start}&endDate=${end}`
      + '&metrics=views,estimatedMinutesWatched,averageViewPercentage&dimensions=day&sort=day';
    const r = await fetch(url, { headers: { Authorization: `Bearer ${access}` } });
    const d = await r.json();
    if (!r.ok) {
      const msg = JSON.stringify(d);
      if (r.status === 403 || /insufficient|scope|forbidden/i.test(msg)) return res.json({ needs_reconnect: true });
      throw new Error('analytics error: ' + msg.slice(0, 200));
    }
    const rows = (d.rows || []).map((row) => ({ date: row[0], views: row[1], minutes: row[2], avgPct: row[3] }));
    const totals = rows.reduce((a, x) => ({
      views: a.views + (x.views || 0),
      minutes: a.minutes + (x.minutes || 0),
    }), { views: 0, minutes: 0 });
    const avgPct = rows.length ? rows.reduce((s, x) => s + (x.avgPct || 0), 0) / rows.length : 0;
    res.json({ rows, totals, avgPct });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY || '';

// Small helper: ask Fable 5 for a JSON object and parse it.
async function aiJSON(prompt, maxTokens = 1500) {
  if (!ANTHROPIC_KEY) throw new Error('AI not configured');
  const ar = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'claude-fable-5', max_tokens: maxTokens, messages: [{ role: 'user', content: prompt }] }),
  });
  const data = await ar.json();
  if (!ar.ok) throw new Error('AI error: ' + JSON.stringify(data).slice(0, 200));
  const text = (data.content || []).map((c) => c.text || '').join('');
  const m = text.match(/\{[\s\S]*\}/);
  if (!m) throw new Error('AI returned no JSON');
  return JSON.parse(m[0]);
}

// -------------------------------------------------------------- Series engine
// One brief -> AI plans a season -> user approves -> each episode becomes a
// normal video (a 'plan' job), reusing the whole per-video pipeline.
app.post('/api/series', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const { brand_id, topic, style, episode_count, cast_keys } = req.body || {};
    if (!topic) return res.status(400).json({ error: 'topic required' });
    let brandName = '';
    if (brand_id) {
      const b = await sb('GET', `brands?id=eq.${encodeURIComponent(brand_id)}&select=name`);
      brandName = (b && b[0] && b[0].name) || '';
    }
    const srow = (await sb('POST', 'series', {
      brand_id: brand_id || null, topic, style: style || 'vyond',
      episode_count: episode_count || null, status: 'planning',
      cast_keys: Array.isArray(cast_keys) ? cast_keys : [],
    }))[0];

    const n = episode_count ? `exactly ${episode_count}` : 'the right number (8-12)';

    // the showrunner is briefed by the style, not hardcoded — a kids season must
    // not come back as legal explainers
    const st = (await sb('GET', `styles?key=eq.${encodeURIComponent(style || 'vyond')}`
      + '&select=name,director_who,director_rules'))[0] || {};
    const who = st.director_who || 'the showrunner for an explainer video channel';
    const rules = st.director_rules ? `\nHouse rules: ${st.director_rules}` : '';

    // the cast are the reason people come back — name them in the episodes
    const castRows = await sb('GET', `characters?style=eq.${encodeURIComponent(style || 'vyond')}`
      + '&select=name,personality,relations');
    const castLine = (castRows || []).length
      ? '\nThe recurring cast (write the season around THEM — the audience follows these characters):\n'
        + castRows.map((c) => `- ${c.name}${c.personality ? ` — ${c.personality}` : ''}`).join('\n')
      : '';

    const plan = await aiJSON(
      `You are ${who}${brandName ? ` (brand: ${brandName})` : ''}.${rules}${castLine}
Plan a coherent series (a "season") of ${n} standalone episodes on the theme: "${topic}".
Give the SEASON a title an audience would follow, then title each episode so the subject is obvious at a glance —
e.g. a season "Around the World" has "Episode 1 — Japan", "Episode 2 — Morocco"; a season "Leo Learns Arabic" has
"Episode 1 — The Alphabet, Part 1". Order them as a real arc (foundations -> specifics -> advanced).
Every episode must stand alone for someone who starts there. No invented facts or statistics.
Return ONLY JSON: {"season_title": "...", "episodes": [ {"title": "<=70 chars", "angle": "one sentence describing exactly what this episode covers — this becomes the video brief", "synopsis": "one viewer-facing sentence"} ]}`,
      4000);

    const updated = (await sb('PATCH', `series?id=eq.${srow.id}`, {
      status: 'plan_review', plan,
      title: plan.season_title || topic,
      episode_count: (plan.episodes || []).length,
      updated_at: new Date().toISOString(),
    }))[0];
    res.json(updated);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.get('/api/series', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    res.json(await sb('GET', 'series?select=*&order=created_at.desc') || []);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.get('/api/series/:id', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const s = (await sb('GET', `series?id=eq.${encodeURIComponent(req.params.id)}&select=*`))[0];
    if (!s) return res.status(404).json({ error: 'not found' });
    const episodes = await sb('GET', `videos?series_id=eq.${encodeURIComponent(req.params.id)}`
      + '&select=id,title,status,episode_idx,youtube_status,youtube_url&order=episode_idx.asc');
    res.json({ series: s, episodes: episodes || [] });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.delete('/api/series/:id', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try { await sb('DELETE', `series?id=eq.${encodeURIComponent(req.params.id)}`); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// Approve a season plan. Episodes are NOT generated here — Karim wanted the
// season laid out first, then each episode made with one click.
app.post('/api/series/:id/approve', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const s = (await sb('GET', `series?id=eq.${encodeURIComponent(req.params.id)}&select=*`))[0];
    if (!s) return res.status(404).json({ error: 'not found' });
    const episodes = (req.body && req.body.episodes) || (s.plan && s.plan.episodes) || [];
    if (!episodes.length) return res.status(400).json({ error: 'no episodes to create' });
    const updated = (await sb('PATCH', `series?id=eq.${s.id}`, {
      status: 'ready', plan: { ...(s.plan || {}), episodes },
      episode_count: episodes.length, updated_at: new Date().toISOString(),
    }))[0];
    res.json(updated);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// Generate one episode of an approved season.
app.post('/api/series/:id/episodes/:idx/generate', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const s = (await sb('GET', `series?id=eq.${encodeURIComponent(req.params.id)}&select=*`))[0];
    if (!s) return res.status(404).json({ error: 'not found' });
    const idx = parseInt(req.params.idx, 10);
    const ep = ((s.plan || {}).episodes || [])[idx];
    if (!ep) return res.status(404).json({ error: 'no such episode' });

    const existing = await sb('GET', `videos?series_id=eq.${s.id}&episode_idx=eq.${idx}&select=id,status`);
    if (existing && existing[0]) return res.json({ already: true, video_id: existing[0].id, status: existing[0].status });

    // a series keeps one fixed cast so the characters never drift between episodes
    const cast = Array.isArray(s.cast_keys) ? s.cast_keys : [];
    const brief = `${ep.angle || ep.title || s.topic}\n\n(Episode ${idx + 1} of the series "${s.title || s.topic}".`
      + ` It must stand alone for a viewer who starts here.)`;
    const v = (await sb('POST', 'videos', {
      title: ep.title || `Episode ${idx + 1}`, topic: brief,
      style: s.style || 'vyond', brand_id: s.brand_id || null,
      series_id: s.id, episode_idx: idx, status: 'queued',
      progress: cast.length ? { cast_keys: cast } : {},
    }))[0];
    await sb('POST', 'jobs', {
      type: 'plan', video_id: v.id,
      payload: { style: s.style || 'vyond', topic: brief, brand_id: s.brand_id || null,
                 series_id: s.id, cast_keys: cast.length ? cast : undefined },
    });
    if (s.status !== 'generating') {
      await sb('PATCH', `series?id=eq.${s.id}`, { status: 'generating', updated_at: new Date().toISOString() });
    }
    res.json({ video_id: v.id, episode_idx: idx });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// ----------------------------------------------------------------- Research
// Competitor tracking, trending topics and "steal the structure of this video".
// Public reads go through a connected channel's OAuth token (no extra API key).

async function ytToken() {
  const rows = await sb('GET', 'youtube_channels?select=id,refresh_token,channel_id&limit=1');
  if (!rows || !rows.length) throw new Error('connect a YouTube channel first — research uses its API access');
  return ytAccessToken(rows[0]);
}
const ytGet = async (path, access) => {
  const r = await fetch(`https://www.googleapis.com/youtube/v3/${path}`, { headers: { Authorization: `Bearer ${access}` } });
  const d = await r.json();
  if (!r.ok) throw new Error('youtube: ' + JSON.stringify(d).slice(0, 200));
  return d;
};

// Revenue estimates. YouTube never exposes another channel's real earnings —
// this is views x an RPM band, the same inference Social Blade makes.
const RPM_BAND = { legal: [8, 25], finance: [10, 30], education: [3, 9], kids: [1, 4], default: [2, 7] };
function revenueEstimate(views, category = 'default') {
  const [lo, hi] = RPM_BAND[category] || RPM_BAND.default;
  const monetisable = views * 0.55;          // not every view is monetised
  return { low: Math.round((monetisable / 1000) * lo), high: Math.round((monetisable / 1000) * hi) };
}
// Karim wants "best revenue videos per month" — so rank on what a video is
// earning NOW (recent daily views x 30), not what it earned over its lifetime.
function monthlyEstimate(viewsPerDay, category = 'default') {
  return revenueEstimate(viewsPerDay * 30, category);
}

// Add a competitor by channel URL, @handle or channel id.
app.post('/api/competitors', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const { input, brand_id } = req.body || {};
    if (!input) return res.status(400).json({ error: 'paste a channel URL or @handle' });
    const access = await ytToken();
    const raw = String(input).trim();

    let channelId = null;
    const idM = raw.match(/channel\/(UC[\w-]{20,})/) || raw.match(/^(UC[\w-]{20,})$/);
    if (idM) channelId = idM[1];
    if (!channelId) {
      const handle = (raw.match(/@([\w.-]+)/) || [])[1];
      if (handle) {
        const d = await ytGet(`channels?part=snippet,statistics&forHandle=@${encodeURIComponent(handle)}`, access);
        if ((d.items || []).length) channelId = d.items[0].id;
      }
    }
    if (!channelId) { // last resort: search by name
      const d = await ytGet(`search?part=snippet&type=channel&maxResults=1&q=${encodeURIComponent(raw)}`, access);
      channelId = (((d.items || [])[0] || {}).snippet || {}).channelId || (((d.items || [])[0] || {}).id || {}).channelId;
    }
    if (!channelId) return res.status(404).json({ error: 'could not find that channel' });

    const ch = await ytGet(`channels?part=snippet,statistics&id=${channelId}`, access);
    const item = (ch.items || [])[0];
    if (!item) return res.status(404).json({ error: 'channel not found' });
    const row = {
      channel_id: channelId, title: item.snippet.title,
      handle: item.snippet.customUrl || null,
      thumb: item.snippet.thumbnails?.default?.url || null,
      subscribers: Number(item.statistics.subscriberCount || 0),
      views: Number(item.statistics.viewCount || 0),
      video_count: Number(item.statistics.videoCount || 0),
      brand_id: brand_id || null, updated_at: new Date().toISOString(),
    };
    const existing = await sb('GET', `competitors?channel_id=eq.${encodeURIComponent(channelId)}&select=id`);
    const saved = existing && existing.length
      ? await sb('PATCH', `competitors?id=eq.${existing[0].id}`, row)
      : await sb('POST', 'competitors', row);
    res.json(Array.isArray(saved) ? saved[0] : saved);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.get('/api/competitors', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try { res.json(await sb('GET', 'competitors?select=*&order=subscribers.desc') || []); }
  catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.delete('/api/competitors/:id', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try { await sb('DELETE', `competitors?id=eq.${encodeURIComponent(req.params.id)}`); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// A competitor's recent uploads, ranked, with view velocity and revenue estimate.
app.get('/api/competitors/:id/videos', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const rows = await sb('GET', `competitors?id=eq.${encodeURIComponent(req.params.id)}&select=*`);
    const c = (rows || [])[0];
    if (!c) return res.status(404).json({ error: 'competitor not found' });
    const access = await ytToken();
    const s = await ytGet(`search?part=snippet&type=video&order=date&maxResults=25&channelId=${c.channel_id}`, access);
    const ids = (s.items || []).map((i) => i.id.videoId).filter(Boolean);
    if (!ids.length) return res.json({ competitor: c, videos: [] });
    const v = await ytGet(`videos?part=snippet,statistics,contentDetails&id=${ids.join(',')}`, access);
    const cat = (req.query.category || 'default');
    const videos = (v.items || []).map((it) => {
      const views = Number(it.statistics.viewCount || 0);
      const days = Math.max(1, (Date.now() - new Date(it.snippet.publishedAt).getTime()) / 864e5);
      return {
        id: it.id, title: it.snippet.title, publishedAt: it.snippet.publishedAt,
        thumb: it.snippet.thumbnails?.medium?.url,
        views, likes: Number(it.statistics.likeCount || 0), comments: Number(it.statistics.commentCount || 0),
        perDay: Math.round(views / days),
        revenue: revenueEstimate(views, cat),                       // lifetime
        monthly: monthlyEstimate(Math.round(views / days), cat),    // earning right now
      };
    }).sort((a, b) => b.monthly.high - a.monthly.high);             // best earners first
    res.json({ competitor: c, videos, revenue_note: 'Estimated from views x typical RPM — YouTube does not publish other channels’ real revenue.' });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// Trending / outrank research: what's performing for a keyword right now.
app.get('/api/research/trending', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const q = String(req.query.q || '').trim();
    if (!q) return res.status(400).json({ error: 'give a topic or keyword' });
    const access = await ytToken();
    const s = await ytGet(`search?part=snippet&type=video&order=viewCount&maxResults=20&publishedAfter=`
      + `${new Date(Date.now() - 180 * 864e5).toISOString()}&q=${encodeURIComponent(q)}`, access);
    const ids = (s.items || []).map((i) => i.id.videoId).filter(Boolean);
    let videos = [];
    if (ids.length) {
      const v = await ytGet(`videos?part=snippet,statistics&id=${ids.join(',')}`, access);
      videos = (v.items || []).map((it) => {
        const views = Number(it.statistics.viewCount || 0);
        const days = Math.max(1, (Date.now() - new Date(it.snippet.publishedAt).getTime()) / 864e5);
        return { id: it.id, title: it.snippet.title, channel: it.snippet.channelTitle,
                 publishedAt: it.snippet.publishedAt, thumb: it.snippet.thumbnails?.medium?.url,
                 views, perDay: Math.round(views / days) };
      }).sort((a, b) => b.perDay - a.perDay);
    }
    // let the AI turn what's winning into angles we could actually outrank
    let angles = [];
    try {
      const out = await aiJSON(
        `These YouTube videos are currently performing for "${q}":\n`
        + videos.slice(0, 12).map((v) => `- ${v.title} (${v.views} views, ${v.perDay}/day)`).join('\n')
        + `\n\nPropose 5 video angles we could make that would compete with or beat these — `
        + `find the gaps and the under-served questions, don't just copy the titles.\n`
        + 'Return ONLY JSON: {"angles":[{"title":"a strong YouTube title","why":"one line on why this can win"}]}', 1100);
      angles = out.angles || [];
    } catch { /* research still useful without angles */ }
    res.json({ videos, angles });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// Paste a competitor video link -> pull what we can and reverse-engineer a brief.
app.post('/api/research/extract', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const { url } = req.body || {};
    const vid = String(url || '').match(/(?:v=|youtu\.be\/|shorts\/|embed\/)([\w-]{11})/);
    if (!vid) return res.status(400).json({ error: 'paste a YouTube video link' });
    const access = await ytToken();
    const d = await ytGet(`videos?part=snippet,contentDetails,statistics&id=${vid[1]}`, access);
    const it = (d.items || [])[0];
    if (!it) return res.status(404).json({ error: 'video not found' });

    // captions are only downloadable by the owner, so try the public timedtext
    // endpoint and fall back to title/description if it isn't available
    let transcript = '';
    try {
      const t = await fetch(`https://www.youtube.com/api/timedtext?v=${vid[1]}&lang=en&fmt=json3`);
      if (t.ok) {
        const j = await t.json();
        transcript = (j.events || []).flatMap((e) => (e.segs || []).map((s) => s.utf8)).join(' ')
          .replace(/\s+/g, ' ').trim();
      }
    } catch { /* optional */ }

    const source = transcript
      ? `TRANSCRIPT:\n${transcript.slice(0, 6000)}`
      : `TITLE: ${it.snippet.title}\nDESCRIPTION: ${(it.snippet.description || '').slice(0, 2000)}`;

    const out = await aiJSON(
      `Reverse-engineer the structure of this YouTube video so we can make our own, better version `
      + `on the same subject. Do NOT copy its wording — describe the structure and write original angles.\n\n${source}\n\n`
      + 'Return ONLY JSON: {"topic":"one-sentence brief we could feed a video generator",'
      + '"structure":[{"beat":"what this section does","note":"why it works"}],'
      + '"hooks":["3 alternative opening lines, original wording"],'
      + '"our_angle":"how our version should differ to be more useful"}', 1800);

    res.json({
      video: { id: it.id, title: it.snippet.title, channel: it.snippet.channelTitle,
               views: Number(it.statistics.viewCount || 0), thumb: it.snippet.thumbnails?.medium?.url },
      had_transcript: !!transcript, ...out,
    });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// ------------------------------------------------------------------ Thumbnails
// Generate a few 16:9 thumbnail options for a video. The image model handles the
// art; the headline is chosen by Fable 5 from the video's own topic.
app.post('/api/thumbnails', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const { video_id, count } = req.body || {};
    if (!video_id) return res.status(400).json({ error: 'video_id required' });
    const gem = process.env.GEMINI_API_KEY;
    if (!gem) return res.status(500).json({ error: 'image generation is not configured' });

    const vr = await sb('GET', `videos?id=eq.${encodeURIComponent(video_id)}&select=id,title,topic,style,brand_id`);
    const v = (vr || [])[0];
    if (!v) return res.status(404).json({ error: 'video not found' });

    let ideas = [];
    try {
      const out = await aiJSON(
        `Design YouTube thumbnails for this video.\nTitle: ${v.title}\nTopic: ${v.topic || ''}\n`
        + `Give ${count || 3} distinct concepts. Each needs a punchy 2-4 WORD headline (it will be drawn `
        + `large on the thumbnail) and a one-sentence visual description that suits a `
        + `${v.style === 'kids' ? 'bright playful cartoon for children' : 'clean flat-2D explainer'}.\n`
        + 'Return ONLY JSON: {"ideas":[{"headline":"...","visual":"..."}]}', 900);
      ideas = out.ideas || [];
    } catch { /* fall back below */ }
    if (!ideas.length) ideas = [{ headline: (v.title || 'Watch this').split(' ').slice(0, 3).join(' '), visual: v.topic || v.title }];

    const look = v.style === 'kids'
      ? "Bright friendly flat-2D cartoon for a children's channel, bold rounded shapes, cheerful palette"
      : 'Clean flat-2D vector explainer illustration, warm flat colours, simple geometric shapes';

    const made = [];
    for (const idea of ideas.slice(0, count || 3)) {
      const prompt = `YouTube thumbnail, 16:9, extremely eye-catching and readable at small size. ${look}. `
        + `Scene: ${idea.visual}. Leave a clear area for a short headline. High contrast, bold, uncluttered. `
        + `Do not render any text, letters or numbers in the image.`;
      try {
        const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-3-pro-image:generateContent?key=${gem}`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { responseModalities: ['IMAGE'] } }),
        });
        const d = await r.json();
        const part = ((((d.candidates || [])[0] || {}).content || {}).parts || []).find((p) => p.inlineData);
        if (!part) continue;
        const bytes = Buffer.from(part.inlineData.data, 'base64');
        const path = `graphic/${crypto.randomUUID()}.png`;
        const up = await fetch(`${SB_URL}/storage/v1/object/assets/${path}`, {
          method: 'POST',
          headers: { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}`, 'Content-Type': 'image/png', 'x-upsert': 'true' },
          body: bytes,
        });
        if (!up.ok) continue;
        const asset = await sb('POST', 'assets', {
          kind: 'graphic', title: `Thumbnail — ${idea.headline}`, tags: ['thumbnail'],
          style: v.style || null, brand_id: v.brand_id || null, storage_path: path,
          mime: 'image/png', source_video: v.id, meta: { headline: idea.headline },
        });
        made.push({ id: (Array.isArray(asset) ? asset[0] : asset).id, headline: idea.headline,
                    url: `${SB_URL}/storage/v1/object/public/assets/${path}` });
      } catch { /* skip a failed option */ }
    }
    if (!made.length) return res.status(500).json({ error: 'no thumbnails could be generated' });
    res.json({ thumbnails: made });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// Set a chosen thumbnail on the published YouTube video.
app.post('/api/youtube/thumbnail', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const { video_id, channel_row_id, asset_id } = req.body || {};
    if (!video_id || !channel_row_id || !asset_id) return res.status(400).json({ error: 'video_id, channel_row_id and asset_id required' });
    const ytId = await videoYtId(video_id);
    const access = await ytAccessToken(await channelWithTokens(channel_row_id));
    const ar = await sb('GET', `assets?id=eq.${encodeURIComponent(asset_id)}&select=storage_path`);
    const path = ar && ar[0] && ar[0].storage_path;
    if (!path) return res.status(404).json({ error: 'thumbnail asset not found' });
    const img = await fetch(`${SB_URL}/storage/v1/object/public/assets/${path}`);
    const bytes = Buffer.from(await img.arrayBuffer());
    const up = await fetch(`https://www.googleapis.com/upload/youtube/v3/thumbnails/set?videoId=${ytId}`, {
      method: 'POST', headers: { Authorization: `Bearer ${access}`, 'Content-Type': 'image/png' }, body: bytes,
    });
    if (!up.ok) throw new Error('thumbnail set failed: ' + (await up.text()).slice(0, 300));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// ---------------------------------------------------------------- Styles
// A style is a self-contained pack: look, beat grammar, director briefing,
// motion, voice and render path. Adding one is data, not code — so the studio
// can grow into any vertical without touching the pipeline, and no style shares
// anything with another.
app.get('/api/styles', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try { res.json(await sb('GET', 'styles?select=*&order=is_builtin.desc,name.asc') || []); }
  catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.patch('/api/styles/:id', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const allow = ['name', 'tagline', 'look_prompt', 'motion_prompt', 'director_who', 'director_rules',
                   'beat_grammar', 'voice_name', 'voice_style', 'render_mode', 'bg_options',
                   'default_cast', 'palette', 'cover_url', 'lip_sync'];
    const patch = {};
    for (const k of allow) if (k in (req.body || {})) patch[k] = req.body[k];
    patch.updated_at = new Date().toISOString();
    const row = await sb('PATCH', `styles?id=eq.${encodeURIComponent(req.params.id)}`, patch);
    res.json(Array.isArray(row) ? row[0] : row);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.delete('/api/styles/:id', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const r = await sb('GET', `styles?id=eq.${encodeURIComponent(req.params.id)}&select=is_builtin,key`);
    if (r && r[0] && r[0].is_builtin) return res.status(400).json({ error: 'built-in styles cannot be deleted' });
    await sb('DELETE', `styles?id=eq.${encodeURIComponent(req.params.id)}`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// Describe a style in plain words -> the AI writes the whole pack, then we
// render a cover so you can see it before it's used.
app.post('/api/styles', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const { name, brief, render_mode } = req.body || {};
    if (!name || !brief) return res.status(400).json({ error: 'give the style a name and describe it' });

    const pack = await aiJSON(
      `You are setting up a new video style for an automated animation studio. The user describes the style; `
      + `you write the complete configuration for it.\n\nSTYLE NAME: ${name}\nWHAT THEY WANT: ${brief}\n\n`
      + `Write these fields:\n`
      + `- "tagline": 3-6 words describing the look.\n`
      + `- "look_prompt": the art-direction lock sent to the image model for EVERY scene. Describe medium, `
      + `shapes, colour palette, line quality, shading and mood precisely. It must end with a rule forbidding `
      + `any text, letters, numbers, logos or watermarks in the image.\n`
      + `- "motion_prompt": how much life the animation should have (energy, expressions, camera).\n`
      + `- "director_who": one sentence starting "You are the director of..." describing whose channel this is.\n`
      + `- "director_rules": the content rules — subject matter to stay inside, tone, reading age, and an `
      + `explicit instruction never to drift into unrelated subject matter.\n`
      + `- "beat_grammar": instructions for how to structure beats. Follow this shape exactly: say how to mix `
      + `beat kinds ('scene', 'board', 'stat'), then state that every beat has id, kind and vo (1-2 spoken `
      + `sentences), that kind 'scene' also has "still" (a wide 16:9 visual description with a STRICT rule that `
      + `it must describe NO text/writing/labels) and "motion", that kind 'board' also has board {title (max 4 `
      + `words), bullets (3-5 items, max 4 words each)}, and kind 'stat' also has stat {value, label}.\n`
      + `- "voice_name": pick ONE of Charon (warm neutral male), Kore (bright friendly female), Puck (upbeat), `
      + `Aoede (calm female) — whichever suits.\n`
      + `- "voice_style": a delivery instruction that MUST name the accent explicitly (default to a natural `
+ `British/UK English accent unless the brief asks otherwise), ending with ": " — e.g. "Read in a calm, `
+ `warm British voice with a natural UK accent: ".\n`
      + `- "cover_prompt": a single striking example scene in this style, for the style's thumbnail.\n`
      + 'Return ONLY JSON with exactly those keys.', 3000);

    const key = String(name).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '').slice(0, 28)
      || 'style_' + crypto.randomUUID().slice(0, 6);

    // render a cover in the style's own look so it's recognisable in the picker
    let cover_url = '';
    const gem = process.env.GEMINI_API_KEY;
    if (gem) {
      try {
        const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-3-pro-image:generateContent?key=${gem}`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ contents: [{ parts: [{ text: `${pack.look_prompt}\n\nScene (wide 16:9): ${pack.cover_prompt}` }] }],
                                 generationConfig: { responseModalities: ['IMAGE'] } }),
        });
        const d = await r.json();
        const part = ((((d.candidates || [])[0] || {}).content || {}).parts || []).find((p) => p.inlineData);
        if (part) {
          const path = `graphic/${crypto.randomUUID()}.png`;
          const up = await fetch(`${SB_URL}/storage/v1/object/assets/${path}`, {
            method: 'POST',
            headers: { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}`, 'Content-Type': 'image/png', 'x-upsert': 'true' },
            body: Buffer.from(part.inlineData.data, 'base64'),
          });
          if (up.ok) cover_url = `${SB_URL}/storage/v1/object/public/assets/${path}`;
        }
      } catch { /* a style without a cover is still usable */ }
    }

    const row = await sb('POST', 'styles', {
      key, name, tagline: pack.tagline || '', look_prompt: pack.look_prompt || '',
      motion_prompt: pack.motion_prompt || '', director_who: pack.director_who || '',
      director_rules: pack.director_rules || '', beat_grammar: pack.beat_grammar || '',
      voice_name: pack.voice_name || 'Charon', voice_style: pack.voice_style || null,
      render_mode: render_mode || 'image_to_video', default_cast: [], cover_url, is_builtin: false,
    });
    res.json(Array.isArray(row) ? row[0] : row);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// Hear a voice before committing to it. Returns a short WAV rendered with the
// exact voice + delivery instruction that will be used in production.
const VOICES = ['Charon', 'Kore', 'Puck', 'Aoede', 'Leda', 'Fenrir', 'Orus', 'Zephyr'];
app.post('/api/voice-preview', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const gem = process.env.GEMINI_API_KEY;
    if (!gem) return res.status(500).json({ error: 'speech is not configured' });
    const { voice_name, voice_style, text } = req.body || {};
    const style = voice_style || 'Read in a calm, warm, professional British voice with a natural UK accent: ';
    const line = text || 'Here is how this voice will sound in your videos.';
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro-preview-tts:generateContent?key=${gem}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: style + line }] }],
        generationConfig: {
          responseModalities: ['AUDIO'],
          speechConfig: { voiceConfig: { prebuiltVoiceConfig: { voiceName: voice_name || 'Charon' } } },
        },
      }),
    });
    const d = await r.json();
    const part = ((((d.candidates || [])[0] || {}).content || {}).parts || [])[0];
    const inline = part && part.inlineData;
    if (!inline) throw new Error('no audio returned');
    // Gemini returns raw PCM — wrap it in a WAV header so a browser can play it
    const pcm = Buffer.from(inline.data, 'base64');
    const rate = parseInt((inline.mimeType.match(/rate=(\d+)/) || [])[1] || '24000', 10);
    const hdr = Buffer.alloc(44);
    hdr.write('RIFF', 0); hdr.writeUInt32LE(36 + pcm.length, 4); hdr.write('WAVE', 8);
    hdr.write('fmt ', 12); hdr.writeUInt32LE(16, 16); hdr.writeUInt16LE(1, 20);
    hdr.writeUInt16LE(1, 22); hdr.writeUInt32LE(rate, 24); hdr.writeUInt32LE(rate * 2, 28);
    hdr.writeUInt16LE(2, 32); hdr.writeUInt16LE(16, 34);
    hdr.write('data', 36); hdr.writeUInt32LE(pcm.length, 40);
    res.set('Content-Type', 'audio/wav').send(Buffer.concat([hdr, pcm]));
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.get('/api/voices', (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  res.json(VOICES);
});

// ---------------------------------------------------------- Custom characters
// A character is a name + description + ONE locked reference image. Every scene
// that features them is generated from that image, so they stay identical
// across beats, episodes and whole series.
const STYLE_LOOK = {
  kids: "Bright friendly flat-2D vector cartoon for a children's educational channel: clean rounded shapes, "
      + 'thick smooth outlines, warm cheerful palette, soft simple shading.',
  vyond: 'Flat 2D vector explainer cartoon: warm flat colours, simple geometric shapes, minimal facial features, '
       + 'soft shadows, clean corporate-friendly look.',
  vox: 'Editorial paper-collage cut-out character with torn paper edges and halftone texture.',
};

app.post('/api/characters', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const { name, description, style, brand_id, image_base64, image_mime,
            personality, relations, derived_from, voice_name, voice_style } = req.body || {};
    if (!name) return res.status(400).json({ error: 'give the character a name' });
    if (!description && !image_base64) {
      return res.status(400).json({ error: 'describe the character, upload a picture, or both' });
    }
    const gem = process.env.GEMINI_API_KEY;
    if (!gem) return res.status(500).json({ error: 'image generation is not configured' });

    // the style's own look wins, so a character drawn from a photo still comes
    // out on-model for the vertical it belongs to
    let look = STYLE_LOOK[style] || STYLE_LOOK.vyond;
    try {
      const sr = await sb('GET', `styles?key=eq.${encodeURIComponent(style || '')}&select=look_prompt`);
      if (sr && sr[0] && sr[0].look_prompt) look = sr[0].look_prompt;
    } catch { /* fall back to the generic look */ }

    // deriving from an existing character: use THEIR locked reference as the
    // starting point so a sibling, parent or younger self shares the family look
    let baseRef = null, baseName = '';
    if (derived_from) {
      const br = await sb('GET', `characters?id=eq.${encodeURIComponent(derived_from)}&select=name,ref_url,description`);
      if (br && br[0] && br[0].ref_url) {
        const img = await fetch(br[0].ref_url);
        if (img.ok) { baseRef = Buffer.from(await img.arrayBuffer()).toString('base64'); baseName = br[0].name; }
      }
    }

    const parts = [];
    let prompt;
    if (baseRef && !image_base64) {
      parts.push({ inline_data: { mime_type: 'image/png', data: baseRef } });
      prompt = `${look}\n\nThe supplied picture shows ${baseName}. Create a NEW, DIFFERENT character who is `
        + `related to them: ${description}. Keep a clear family resemblance — similar face shape, skin tone and `
        + `hair colour — but they must be visibly a different person of the described age and look. `
        + `Full body, facing forward, neutral friendly pose, centred on a plain solid white background, `
        + `model-sheet style. No text, letters, numbers, logos or watermarks.`;
    } else if (image_base64) {
      // redraw whatever they uploaded into this style, keeping the likeness
      parts.push({ inline_data: { mime_type: image_mime || 'image/png', data: image_base64 } });
      prompt = `${look}\n\nRedraw the character in the supplied picture in EXACTLY this art style. `
        + `Keep them clearly recognisable — same hair, face shape, skin tone, clothing and colours`
        + (description ? `. Additional direction: ${description}` : '')
        + `. Full body, facing forward, neutral friendly pose, centred on a plain solid white background, `
        + `model-sheet style. Absolutely no text, letters, numbers, logos or watermarks.`;
    } else {
      prompt = `${look}\n\nFull body, facing forward, neutral friendly pose, centred on a plain solid white `
        + `background. Character: ${description}. Consistent model-sheet style. `
        + `Absolutely no text, letters, numbers, logos or watermarks.`;
    }
    parts.push({ text: prompt });

    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-3-pro-image:generateContent?key=${gem}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts }], generationConfig: { responseModalities: ['IMAGE'] } }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error('image error: ' + JSON.stringify(d).slice(0, 200));
    const part = ((((d.candidates || [])[0] || {}).content || {}).parts || []).find((p) => p.inlineData);
    if (!part) throw new Error('no image returned');

    // upload the reference into the assets bucket
    const bytes = Buffer.from(part.inlineData.data, 'base64');
    const path = `char_ref/${crypto.randomUUID()}.png`;
    const up = await fetch(`${SB_URL}/storage/v1/object/assets/${path}`, {
      method: 'POST',
      headers: { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}`, 'Content-Type': 'image/png', 'x-upsert': 'true' },
      body: bytes,
    });
    if (!up.ok) throw new Error('upload failed: ' + (await up.text()).slice(0, 200));
    const ref_url = `${SB_URL}/storage/v1/object/public/assets/${path}`;

    const asset = await sb('POST', 'assets', {
      kind: 'char_ref', title: `${name} (character)`, tags: ['character', style || 'vyond'],
      style: style || null, brand_id: brand_id || null, storage_path: path, mime: 'image/png',
    });
    const key = String(name).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '').slice(0, 24)
      + '_' + crypto.randomUUID().slice(0, 4);
    const row = await sb('POST', 'characters', {
      key, name, description: description || `${name} (from a supplied picture)`,
      style: style || null, brand_id: brand_id || null,
      voice_name: voice_name || null, voice_style: voice_style || null,
      personality: personality || null, relations: relations || null,
      derived_from: derived_from || null,
      ref_asset: (Array.isArray(asset) ? asset[0] : asset).id, ref_url,
    });
    res.json(Array.isArray(row) ? row[0] : row);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// -------------------------------------------------------------- Growth engine
// Pull performance for everything we've published, let Fable 5 find what works,
// store guidelines. plan_video reads the latest guidelines back into planning.
app.post('/api/growth/analyze', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const channels = await sb('GET', 'youtube_channels?select=id,refresh_token,channel_id');
    const ours = await sb('GET', 'videos?select=id,title,topic,youtube_video_id'
      + '&youtube_video_id=not.is.null&order=created_at.desc&limit=50');
    const idToMeta = {}; (ours || []).forEach((v) => { idToMeta[v.youtube_video_id] = v; });
    const perf = [];
    for (const ch of channels || []) {
      const ids = (ours || []).map((v) => v.youtube_video_id).filter(Boolean);
      if (!ids.length) continue;
      let access;
      try { access = await ytAccessToken(ch); } catch { continue; }
      const vl = await (await fetch(
        `https://www.googleapis.com/youtube/v3/videos?part=snippet,statistics&id=${ids.join(',')}`,
        { headers: { Authorization: `Bearer ${access}` } })).json();
      (vl.items || []).forEach((it) => {
        if (it.snippet && it.snippet.channelId === ch.channel_id) {
          perf.push({
            title: it.snippet.title,
            topic: (idToMeta[it.id] || {}).topic || '',
            views: Number(it.statistics.viewCount || 0),
            likes: Number(it.statistics.likeCount || 0),
            comments: Number(it.statistics.commentCount || 0),
          });
        }
      });
    }
    if (!perf.length) return res.status(400).json({ error: 'No published videos with stats yet — publish a few first.' });

    perf.sort((a, b) => b.views - a.views);
    const out = await aiJSON(
      `You are the growth strategist for a UK legal-explainer YouTube operation. Here is the performance of our
published videos (JSON): ${JSON.stringify(perf.slice(0, 40))}.
Identify what actually drives views and engagement — topic themes, title patterns, length/format — and give concrete,
actionable guidance for the NEXT videos. Be specific to this data, not generic.
Return ONLY JSON: {"insight": "2-3 sentence summary of what's working", "guidelines": ["5-8 short imperative rules for future videos"]}`,
      1500);
    const row = (await sb('POST', 'growth', {
      insight: out.insight || '', guidelines: out.guidelines || [], top: perf.slice(0, 5),
    }))[0];
    res.json(row);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.get('/api/growth', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const rows = await sb('GET', 'growth?select=*&order=created_at.desc&limit=1');
    res.json((rows && rows[0]) || null);
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// Auto-cut vertical Shorts from a finished video (worker does the rendering).
app.post('/api/shorts', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    const { video_id } = req.body || {};
    if (!video_id) return res.status(400).json({ error: 'video_id required' });
    const job = await sb('POST', 'jobs', { type: 'snippets', video_id, payload: { video_id } });
    res.json({ ok: true, job: Array.isArray(job) ? job[0] : job });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// AI-suggest YouTube metadata (title/description/tags) from a video's topic+script.
app.get('/api/youtube/suggest-meta', async (req, res) => {
  if (!authed(req)) return res.status(401).json({ error: 'unauth' });
  try {
    if (!ANTHROPIC_KEY) return res.status(500).json({ error: 'AI not configured' });
    const r = await sb('GET', `videos?id=eq.${encodeURIComponent(req.query.video_id)}&select=title,topic,script`);
    const v = (r || [])[0];
    if (!v) return res.status(404).json({ error: 'video not found' });

    const prompt = `You write YouTube metadata for a legal explainer video by a UK law firm.
Topic: ${v.topic || v.title || ''}
Current title: ${v.title || '(none)'}
Script excerpt: ${(v.script || '').slice(0, 1600)}

Return ONLY a JSON object with keys:
  "title": a compelling, SEO-friendly title, max 100 characters, no clickbait.
  "description": 2-3 short paragraphs of plain text — a one-line hook, what viewers learn, and a soft close. No hashtags in the body.
  "tags": an array of 10-15 short lowercase keyword strings relevant to the topic and UK law.`;

    const ar = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-fable-5', max_tokens: 900, messages: [{ role: 'user', content: prompt }] }),
    });
    const data = await ar.json();
    if (!ar.ok) throw new Error('AI error: ' + JSON.stringify(data).slice(0, 200));
    const text = (data.content || []).map((c) => c.text || '').join('');
    const m = text.match(/\{[\s\S]*\}/);
    if (!m) throw new Error('AI returned no JSON');
    const meta = JSON.parse(m[0]);
    res.json({
      title: String(meta.title || '').slice(0, 100),
      description: String(meta.description || ''),
      tags: Array.isArray(meta.tags) ? meta.tags.slice(0, 15) : [],
    });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// static assets (js/css/img) are fine to serve; the app itself is gated at the HTML level
app.use('/assets', express.static(path.join(DIST, 'assets')));
app.get(['/favicon.png', '/favicon.svg', '/icons.svg', '/logo-64.png', '/logo-192.png', '/logo-512.png'],
  (req, res) => res.sendFile(path.join(DIST, req.path)));

// Public (ungated) pages — required for the OAuth consent screen / verification.
const PUBLIC = path.join(__dirname, 'public');
app.get('/about', (_req, res) => res.sendFile(path.join(PUBLIC, 'about.html')));
app.get('/privacy', (_req, res) => res.sendFile(path.join(PUBLIC, 'privacy.html')));
app.get('/terms', (_req, res) => res.sendFile(path.join(PUBLIC, 'terms.html')));
app.get('/login', (_req, res) => res.sendFile(path.join(__dirname, 'login.html')));

// index.html must never be cached — it names the hashed JS bundle, so a stale
// copy pins the browser to an old build after every deploy.
app.get('*', (req, res) => {
  res.set('Cache-Control', 'no-store, must-revalidate');
  if (!authed(req)) return res.sendFile(path.join(__dirname, 'login.html'));
  res.sendFile(path.join(DIST, 'index.html'));
});
app.listen(process.env.PORT || 8000, () => console.log('lawstudio on', process.env.PORT || 8000));
