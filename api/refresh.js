// /api/refresh.js — Live dashboard stats
// Env vars required: VERCEL_TOKEN, NETLIFY_TOKEN, SUPABASE_ACCESS_TOKEN, GITHUB_TOKEN

const TEAM_ID = 'team_HLGbORHT8BGyRovigInymK81';

const VERCEL_PROJECTS = {
  'app-assessment': 'prj_iEGW3nvUPSfkoFwpcHqcQqRniv9H',
  'adultos-v2':     'prj_4t5zj6UJpDmFWvQBLkGWVs5NQjWS',
  'lider-anti-caos':'prj_Q5nrOH2zA4T086WIDRZiDuSbqhA4',
  'tutoriais':      'prj_eCWgFNxU70flHRAH5HIaatPI4GOh',
};

const NETLIFY_SITES = {
  'painel':      '29d5a2d4-12b9-45f5-810f-b18e66d434f9',
  'recopedro':   'fdddd31c-62ca-415c-b359-ec6d0894260a',
  'indicedecaos':'e94e6da3-f817-4caa-a201-a04d7282272c',
};

const SUPABASE_PROJECTS = {
  'app-assessment': 'ywzyneepdewrpperupac',
  'adultos-v2':     'gaaouwlicfitdhhtbgix',
  'lider-anti-caos':'kyrfusioyognvxuhflmn',
};

const GITHUB_REPOS = {
  'app-assessment': 'app-assessment',
  'adultos-v2':     'app-assessments-adultos-v2',
  'lider-anti-caos':'lider-anti-caos',
  'tutoriais':      'kit-lider-indispensavel',
  'painel':         'meus-recursos-claude',
};

function relativeTime(timestamp) {
  if (!timestamp) return '—';
  const ms = typeof timestamp === 'number' ? timestamp : new Date(timestamp).getTime();
  const diff = Date.now() - ms;
  const days = Math.floor(diff / 86400000);
  if (days === 0) return 'hoje';
  if (days === 1) return 'ontem';
  if (days < 7)  return `há ${days} dias`;
  if (days < 14) return 'há 1 semana';
  if (days < 30) return `há ${Math.floor(days / 7)} semanas`;
  return `há ${Math.floor(days / 30)} meses`;
}

function deployStatus(state) {
  if (!state) return 'warning';
  const s = state.toUpperCase();
  if (s === 'READY' || s === 'CURRENT') return 'online';
  if (s === 'ERROR' || s === 'FAILED') return 'offline';
  return 'warning';
}

async function fetchVercel(projectId) {
  const token = process.env.VERCEL_TOKEN;
  if (!token) return null;
  try {
    const res = await fetch(
      `https://api.vercel.com/v6/deployments?projectId=${projectId}&limit=1&teamId=${TEAM_ID}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const data = await res.json();
    const dep = data.deployments?.[0];
    return dep ? { date: dep.createdAt, state: dep.readyState } : null;
  } catch { return null; }
}

async function fetchNetlify(siteId) {
  const token = process.env.NETLIFY_TOKEN;
  if (!token) return null;
  try {
    const res = await fetch(
      `https://api.netlify.com/api/v1/sites/${siteId}/deploys?per_page=1`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const data = await res.json();
    const dep = Array.isArray(data) ? data[0] : null;
    return dep ? { date: dep.created_at, state: dep.state } : null;
  } catch { return null; }
}

async function fetchSupabase(ref) {
  const token = process.env.SUPABASE_ACCESS_TOKEN;
  if (!token) return null;
  try {
    const res = await fetch(
      `https://api.supabase.com/v1/projects/${ref}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const data = await res.json();
    return data.status ?? null;
  } catch { return null; }
}

async function fetchGithubCommits(repo) {
  const token = process.env.GITHUB_TOKEN;
  if (!token) return null;
  try {
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const res = await fetch(
      `https://api.github.com/repos/aglslira/${repo}/commits?since=${since}&per_page=100`,
      { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' } }
    );
    const data = await res.json();
    return Array.isArray(data) ? data.length : null;
  } catch { return null; }
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://painelclaude.anti-caos.app.br');
  res.setHeader('Cache-Control', 'no-store');

  const [vercelResults, netlifyResults, supabaseResults, githubResults] = await Promise.all([
    Promise.all(Object.entries(VERCEL_PROJECTS).map(([k, id]) =>
      fetchVercel(id).then(r => [k, r]))),
    Promise.all(Object.entries(NETLIFY_SITES).map(([k, id]) =>
      fetchNetlify(id).then(r => [k, r]))),
    Promise.all(Object.entries(SUPABASE_PROJECTS).map(([k, ref]) =>
      fetchSupabase(ref).then(r => [k, r]))),
    Promise.all(Object.entries(GITHUB_REPOS).map(([k, repo]) =>
      fetchGithubCommits(repo).then(r => [k, r]))),
  ]);

  const deploy = {};
  const status = {};

  vercelResults.forEach(([k, r]) => {
    deploy[k] = r ? relativeTime(r.date) : '—';
    status[k] = r ? deployStatus(r.state) : 'warning';
  });
  netlifyResults.forEach(([k, r]) => {
    deploy[k] = r ? relativeTime(r.date) : '—';
    status[k] = r ? deployStatus(r.state) : 'warning';
  });

  const db = {};
  supabaseResults.forEach(([k, r]) => {
    if (r === null) { db[k] = '—'; return; }
    const s = r.toUpperCase();
    db[k] = s === 'ACTIVE_HEALTHY' ? 'healthy' : s === 'INACTIVE' || s === 'PAUSED' ? 'pausado' : 'offline';
  });

  const commits = {};
  githubResults.forEach(([k, r]) => {
    commits[k] = r === null ? '—' : String(r);
  });

  res.json({ deploy, db, commits, status, updatedAt: Date.now() });
}
