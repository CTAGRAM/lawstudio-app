import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import path from 'path';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.join(__dirname, 'dist');
app.use(express.json());
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
    const { video_id, channel_row_id, title, description, privacy } = req.body || {};
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

// static assets (js/css/img) are fine to serve; the app itself is gated at the HTML level
app.use('/assets', express.static(path.join(DIST, 'assets')));
app.get(['/favicon.png', '/favicon.svg', '/icons.svg', '/logo-64.png', '/logo-192.png', '/logo-512.png'],
  (req, res) => res.sendFile(path.join(DIST, req.path)));

app.get('*', (req, res) => {
  if (!authed(req)) return res.sendFile(path.join(__dirname, 'login.html'));
  res.sendFile(path.join(DIST, 'index.html'));
});
app.listen(process.env.PORT || 8000, () => console.log('lawstudio on', process.env.PORT || 8000));
