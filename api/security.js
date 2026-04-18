// /api/security.js — Dashboard security audit
// Env vars required: VERCEL_TOKEN, NETLIFY_TOKEN, SUPABASE_ACCESS_TOKEN, GITHUB_TOKEN

const TEAM_ID = 'team_HLGbORHT8BGyRovigInymK81';
const GITHUB_OWNER = 'aglslira';

// Regex patterns for secret detection in commits/env vars
const SECRET_PATTERNS = [
  { name: 'GitHub PAT', re: /\bghp_[A-Za-z0-9]{36}\b/ },
  { name: 'GitHub OAuth', re: /\bgho_[A-Za-z0-9]{36}\b/ },
  { name: 'GitHub App', re: /\b(ghu|ghs)_[A-Za-z0-9]{36}\b/ },
  { name: 'AWS Access Key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'Stripe Live', re: /\bsk_live_[0-9a-zA-Z]{24,}\b/ },
  { name: 'Slack Bot Token', re: /\bxox[baprs]-[0-9a-zA-Z-]{10,}\b/ },
  { name: 'Google API Key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'Private Key Block', re: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
];

const SECRET_KEY_HINTS = /(api[_-]?key|secret|token|password|passwd|pwd|auth|bearer|credential)/i;

// Helpers
function mkCheck(id, category, scope, label, status, detail, fix, docsUrl, extra) {
  return { id, category, scope, label, status, detail, fix: fix || null, docsUrl: docsUrl || null, ...(extra || {}) };
}

async function safeJson(res) {
  try { return await res.json(); } catch { return null; }
}

async function fetchWithAuth(url, token, extraHeaders, timeoutMs) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs || 8000);
  try {
    return await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        ...(extraHeaders || {}),
      },
      signal: ctl.signal,
    });
  } finally {
    clearTimeout(t);
  }
}

async function fetchNoAuth(url, timeoutMs) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs || 8000);
  try {
    return await fetch(url, { signal: ctl.signal });
  } finally {
    clearTimeout(t);
  }
}

// ──────────────────────────────────────────────────────────────────────────
// DISCOVERY — list all resources dynamically

async function listGithubRepos(token) {
  if (!token) return [];
  try {
    const res = await fetchWithAuth(
      'https://api.github.com/user/repos?per_page=100&affiliation=owner',
      token,
      { Accept: 'application/vnd.github+json' }
    );
    const data = await safeJson(res);
    return Array.isArray(data) ? data : [];
  } catch { return []; }
}

async function listVercelProjects(token) {
  if (!token) return [];
  try {
    const res = await fetchWithAuth(
      `https://api.vercel.com/v9/projects?teamId=${TEAM_ID}&limit=100`,
      token
    );
    const data = await safeJson(res);
    return data?.projects || [];
  } catch { return []; }
}

async function listNetlifySites(token) {
  if (!token) return [];
  try {
    const res = await fetchWithAuth('https://api.netlify.com/api/v1/sites?per_page=100', token);
    const data = await safeJson(res);
    return Array.isArray(data) ? data : [];
  } catch { return []; }
}

async function listSupabaseProjects(token) {
  if (!token) return [];
  try {
    const res = await fetchWithAuth('https://api.supabase.com/v1/projects', token);
    const data = await safeJson(res);
    return Array.isArray(data) ? data : [];
  } catch { return []; }
}

// ──────────────────────────────────────────────────────────────────────────
// GITHUB CHECKS

async function checkGithubSecretAlerts(token, repo) {
  const id = `gh-secrets-${repo.name}`;
  try {
    const res = await fetchWithAuth(
      `https://api.github.com/repos/${repo.full_name}/secret-scanning/alerts?state=open&per_page=30`,
      token,
      { Accept: 'application/vnd.github+json' }
    );
    if (res.status === 404) {
      return mkCheck(id, 'secrets', repo.full_name, `Secret scanning — ${repo.name}`, 'info',
        'Secret scanning não habilitado (requer plano Team/Enterprise para repos privados).', null,
        'https://docs.github.com/code-security/secret-scanning');
    }
    if (res.status === 403) {
      return mkCheck(id, 'secrets', repo.full_name, `Secret scanning — ${repo.name}`, 'error',
        'Token GitHub sem scope security_events.', null, null);
    }
    const data = await safeJson(res);
    if (!Array.isArray(data)) {
      return mkCheck(id, 'secrets', repo.full_name, `Secret scanning — ${repo.name}`, 'error',
        'Erro ao consultar alertas.', null, null);
    }
    if (data.length === 0) {
      return mkCheck(id, 'secrets', repo.full_name, `Secret scanning — ${repo.name}`, 'ok',
        'Nenhum secret exposto detectado.', null,
        'https://docs.github.com/code-security/secret-scanning');
    }
    const types = [...new Set(data.map(a => a.secret_type_display_name || a.secret_type))].slice(0, 3).join(', ');
    return mkCheck(id, 'secrets', repo.full_name, `Secret scanning — ${repo.name}`, 'critical',
      `${data.length} alerta(s) aberto(s): ${types}`,
      `Revise em: https://github.com/${repo.full_name}/security/secret-scanning`,
      'https://docs.github.com/code-security/secret-scanning');
  } catch (e) {
    return mkCheck(id, 'secrets', repo.full_name, `Secret scanning — ${repo.name}`, 'error',
      `Erro: ${e.message || 'desconhecido'}`, null, null);
  }
}

async function checkGithubCommitSecrets(token, repo) {
  const id = `gh-commit-scan-${repo.name}`;
  try {
    const res = await fetchWithAuth(
      `https://api.github.com/repos/${repo.full_name}/commits?per_page=20`,
      token,
      { Accept: 'application/vnd.github+json' }
    );
    const commits = await safeJson(res);
    if (!Array.isArray(commits)) {
      return mkCheck(id, 'secrets', repo.full_name, `Scan de commits — ${repo.name}`, 'error',
        'Não foi possível listar commits.', null, null);
    }
    const hits = [];
    for (const c of commits.slice(0, 20)) {
      const msg = c.commit?.message || '';
      for (const pat of SECRET_PATTERNS) {
        if (pat.re.test(msg)) {
          hits.push({ pattern: pat.name, sha: c.sha.slice(0, 7) });
          break;
        }
      }
    }
    if (hits.length === 0) {
      return mkCheck(id, 'secrets', repo.full_name, `Scan de commits — ${repo.name}`, 'ok',
        `20 commits recentes limpos.`, null, null);
    }
    const summary = hits.slice(0, 3).map(h => `${h.pattern} em ${h.sha}`).join('; ');
    return mkCheck(id, 'secrets', repo.full_name, `Scan de commits — ${repo.name}`, 'critical',
      `${hits.length} commit(s) com padrão de secret: ${summary}`,
      `Audite os commits e rotacione credenciais se confirmado. git log search: git log -p | grep -E "ghp_|AKIA|sk_live_"`,
      'https://docs.github.com/code-security/secret-scanning');
  } catch (e) {
    return mkCheck(id, 'secrets', repo.full_name, `Scan de commits — ${repo.name}`, 'error',
      `Erro: ${e.message || 'desconhecido'}`, null, null);
  }
}

async function checkGithubBranchProtection(token, repo) {
  const id = `gh-branch-${repo.name}`;
  const branch = repo.default_branch || 'main';
  try {
    const res = await fetchWithAuth(
      `https://api.github.com/repos/${repo.full_name}/branches/${branch}/protection`,
      token,
      { Accept: 'application/vnd.github+json' }
    );
    if (res.status === 404) {
      return mkCheck(id, 'access', repo.full_name, `Branch protection — ${repo.name}`, 'warning',
        `Sem proteção na branch ${branch}.`,
        `Habilite em: https://github.com/${repo.full_name}/settings/branches`,
        'https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches');
    }
    if (res.status === 403) {
      return mkCheck(id, 'access', repo.full_name, `Branch protection — ${repo.name}`, 'info',
        'Branch protection requer plano pago para repos privados.', null, null);
    }
    return mkCheck(id, 'access', repo.full_name, `Branch protection — ${repo.name}`, 'ok',
      `Branch ${branch} protegida.`, null, null);
  } catch (e) {
    return mkCheck(id, 'access', repo.full_name, `Branch protection — ${repo.name}`, 'error',
      `Erro: ${e.message || 'desconhecido'}`, null, null);
  }
}

async function checkGithubVisibility(token, repo) {
  const id = `gh-vis-${repo.name}`;
  if (!repo.private) {
    return mkCheck(id, 'access', repo.full_name, `Visibilidade — ${repo.name}`, 'info',
      'Repositório público. Verifique se não há dados sensíveis.',
      `Torne privado em: https://github.com/${repo.full_name}/settings`,
      null);
  }
  return mkCheck(id, 'access', repo.full_name, `Visibilidade — ${repo.name}`, 'ok',
    'Repositório privado.', null, null);
}

// ──────────────────────────────────────────────────────────────────────────
// VERCEL CHECKS

async function checkVercelEnvVars(token, project) {
  const id = `vc-env-${project.name}`;
  try {
    const res = await fetchWithAuth(
      `https://api.vercel.com/v9/projects/${project.id}/env?teamId=${TEAM_ID}`,
      token
    );
    const data = await safeJson(res);
    const envs = data?.envs || [];
    const exposed = envs.filter(e =>
      e.key && /^(NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_)/.test(e.key) &&
      SECRET_KEY_HINTS.test(e.key)
    );
    if (exposed.length === 0) {
      return mkCheck(id, 'secrets', project.name, `Env vars públicas — ${project.name}`, 'ok',
        `${envs.length} env vars, nenhuma expondo segredo.`, null, null);
    }
    const names = exposed.map(e => e.key).slice(0, 3).join(', ');
    return mkCheck(id, 'secrets', project.name, `Env vars públicas — ${project.name}`, 'critical',
      `${exposed.length} var(s) com prefixo público e nome sugerindo secret: ${names}`,
      'Remova o prefixo público ou mova o valor pra uma env var sem prefix.',
      'https://vercel.com/docs/environment-variables/sensitive-environment-variables');
  } catch (e) {
    return mkCheck(id, 'secrets', project.name, `Env vars públicas — ${project.name}`, 'error',
      `Erro: ${e.message || 'desconhecido'}`, null, null);
  }
}

async function checkVercelPreviewProtection(token, project) {
  const id = `vc-preview-${project.name}`;
  const sso = project.ssoProtection;
  const pwd = project.passwordProtection;
  if (sso || pwd) {
    const kinds = [sso ? 'SSO' : null, pwd ? 'senha' : null].filter(Boolean).join(' + ');
    return mkCheck(id, 'access', project.name, `Previews protegidos — ${project.name}`, 'ok',
      `Preview deployments protegidos por ${kinds}.`, null, null);
  }
  return mkCheck(id, 'access', project.name, `Previews protegidos — ${project.name}`, 'warning',
    'Preview deployments públicos — qualquer pessoa com a URL acessa.',
    `Habilite em: https://vercel.com/${TEAM_ID}/${project.name}/settings/deployment-protection`,
    'https://vercel.com/docs/deployment-protection');
}

// ──────────────────────────────────────────────────────────────────────────
// SUPABASE CHECKS

async function checkSupabaseAdvisors(token, project) {
  const id = `sb-advisors-${project.id}`;
  const name = project.name || project.id;
  try {
    const res = await fetchWithAuth(
      `https://api.supabase.com/v1/projects/${project.id}/advisors/security`,
      token
    );
    if (res.status === 404 || res.status === 400) {
      // advisors endpoint may not be available; fallback to assume ok
      return mkCheck(id, 'database', name, `Supabase advisors — ${name}`, 'info',
        'Endpoint de advisors indisponível neste plano.', null, null);
    }
    const data = await safeJson(res);
    const lints = data?.lints || [];
    const errors = lints.filter(l => l.level === 'ERROR');
    const warnings = lints.filter(l => l.level === 'WARN');
    if (errors.length > 0) {
      const names = [...new Set(errors.map(e => e.name))].slice(0, 3).join(', ');
      return mkCheck(id, 'database', name, `Supabase advisors — ${name}`, 'critical',
        `${errors.length} problema(s) crítico(s): ${names}`,
        `Revise em: https://supabase.com/dashboard/project/${project.id}/advisors/security`,
        'https://supabase.com/docs/guides/database/database-advisors');
    }
    if (warnings.length > 0) {
      return mkCheck(id, 'database', name, `Supabase advisors — ${name}`, 'warning',
        `${warnings.length} aviso(s) de segurança.`,
        `Revise em: https://supabase.com/dashboard/project/${project.id}/advisors/security`,
        'https://supabase.com/docs/guides/database/database-advisors');
    }
    return mkCheck(id, 'database', name, `Supabase advisors — ${name}`, 'ok',
      'Nenhum problema de segurança identificado.', null, null);
  } catch (e) {
    return mkCheck(id, 'database', name, `Supabase advisors — ${name}`, 'error',
      `Erro: ${e.message || 'desconhecido'}`, null, null);
  }
}

// ──────────────────────────────────────────────────────────────────────────
// OBSERVATORY (Mozilla)

async function checkObservatory(host) {
  const id = `obs-${host}`;
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 15000);
    const res = await fetch(
      `https://observatory-api.mdn.mozilla.net/api/v2/analyze?host=${encodeURIComponent(host)}`,
      { method: 'POST', signal: ctl.signal }
    ).finally(() => clearTimeout(t));
    const data = await safeJson(res);
    if (!data || !data.grade) {
      return mkCheck(id, 'headers', host, `Observatory — ${host}`, 'error',
        'Scan não retornou grade.', null, null);
    }
    const grade = data.grade;
    const score = data.score;
    const status = /^A/.test(grade) ? 'ok' : /^B/.test(grade) ? 'warning' : 'critical';
    return mkCheck(id, 'headers', host, `Observatory — ${host}`, status,
      `Grade ${grade} (${score}/100)`,
      'Revise em: https://developer.mozilla.org/en-US/observatory/analyze?host=' + encodeURIComponent(host),
      'https://developer.mozilla.org/en-US/observatory',
      { scoreLetter: grade, scoreNumber: score });
  } catch (e) {
    return mkCheck(id, 'headers', host, `Observatory — ${host}`, 'error',
      `Erro: ${e.message || 'desconhecido'}`, null, null);
  }
}

// ──────────────────────────────────────────────────────────────────────────
// SSL LABS (async polling)

// SSL Labs — NO polling (fire & check current state only, avoid function timeout)
async function checkSslLabs(host) {
  const id = `ssl-${host}`;
  const docsUrl = `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(host)}`;
  try {
    // Query cached result; SSL Labs will start a new scan if nothing cached
    const res = await fetchNoAuth(
      `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(host)}&fromCache=on&maxAge=24`,
      6000
    );
    const data = await safeJson(res);
    if (!data) {
      return mkCheck(id, 'ssl', host, `SSL Labs — ${host}`, 'info',
        'Scan não iniciado. Clique em Docs pra rodar manualmente (demora ~2min).',
        null, docsUrl);
    }
    if (data.status === 'READY') {
      const ep = data.endpoints?.[0];
      const grade = ep?.grade;
      // Empty/invalid grade → treat as info (not critical!)
      if (!grade || grade === '?') {
        return mkCheck(id, 'ssl', host, `SSL Labs — ${host}`, 'info',
          'Scan concluído mas sem nota (domínio pode não expor HTTPS ou ser inválido).',
          null, docsUrl);
      }
      const status = /^A/.test(grade) ? 'ok' : /^B/.test(grade) ? 'warning' : 'critical';
      return mkCheck(id, 'ssl', host, `SSL Labs — ${host}`, status,
        `Grade ${grade}`, null, docsUrl, { scoreLetter: grade });
    }
    if (data.status === 'ERROR') {
      return mkCheck(id, 'ssl', host, `SSL Labs — ${host}`, 'info',
        `SSL Labs não conseguiu testar (${data.statusMessage || 'erro'}). Comum em domínios sem HTTPS público.`,
        null, docsUrl);
    }
    // IN_PROGRESS / DNS — scan está rodando agora
    return mkCheck(id, 'ssl', host, `SSL Labs — ${host}`, 'info',
      `Primeiro scan iniciado pelo SSL Labs. Rode Auditar de novo em ~2min pra ver a nota.`,
      null, docsUrl);
  } catch (e) {
    return mkCheck(id, 'ssl', host, `SSL Labs — ${host}`, 'info',
      'Não foi possível consultar agora. Tente em ~2min.',
      null, docsUrl);
  }
}

// ──────────────────────────────────────────────────────────────────────────
// HANDLER

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://painelclaude.anti-caos.app.br');
  res.setHeader('Cache-Control', 'no-store');

  const started = Date.now();
  const githubToken = process.env.GITHUB_TOKEN;
  const vercelToken = process.env.VERCEL_TOKEN;
  const netlifyToken = process.env.NETLIFY_TOKEN;
  const supabaseToken = process.env.SUPABASE_ACCESS_TOKEN;

  // 1) Discovery in parallel
  const [repos, vcProjects, supaProjects] = await Promise.all([
    listGithubRepos(githubToken),
    listVercelProjects(vercelToken),
    listSupabaseProjects(supabaseToken),
  ]);

  // Collect custom domains from Vercel projects (via their alias/targets)
  const customDomains = new Set();
  customDomains.add('painelclaude.anti-caos.app.br');
  for (const p of vcProjects) {
    const targets = p.targets?.production?.alias || [];
    for (const a of targets) {
      if (typeof a === 'string' && !a.endsWith('.vercel.app')) customDomains.add(a);
    }
    const alias = p.alias || [];
    for (const a of alias) {
      const d = typeof a === 'string' ? a : a?.domain;
      if (typeof d === 'string' && !d.endsWith('.vercel.app')) customDomains.add(d);
    }
  }

  // 2) Run all non-SSL checks in parallel (SSL Labs runs separately)
  const checkPromises = [];

  // GitHub: for each repo, 4 checks
  for (const repo of repos) {
    checkPromises.push(checkGithubSecretAlerts(githubToken, repo));
    checkPromises.push(checkGithubCommitSecrets(githubToken, repo));
    checkPromises.push(checkGithubBranchProtection(githubToken, repo));
    checkPromises.push(checkGithubVisibility(githubToken, repo));
  }

  // Vercel: for each project, 2 checks
  for (const project of vcProjects) {
    checkPromises.push(checkVercelEnvVars(vercelToken, project));
    checkPromises.push(checkVercelPreviewProtection(vercelToken, project));
  }

  // Supabase: for each project, 1 check
  for (const project of supaProjects) {
    checkPromises.push(checkSupabaseAdvisors(supabaseToken, project));
  }

  // Observatory: for each custom domain
  const domainList = [...customDomains];
  for (const host of domainList) {
    checkPromises.push(checkObservatory(host));
  }

  const checks = await Promise.all(checkPromises);

  // 3) SSL Labs — query cached state only (no polling, fast)
  const sslChecks = await Promise.all(domainList.map(host => checkSslLabs(host)));
  checks.push(...sslChecks);

  // Summary
  const summary = { critical: 0, warning: 0, info: 0, ok: 0, error: 0 };
  for (const c of checks) {
    if (summary[c.status] !== undefined) summary[c.status]++;
  }

  res.json({
    scannedAt: Date.now(),
    elapsedMs: Date.now() - started,
    discovered: {
      githubRepos: repos.length,
      vercelProjects: vcProjects.length,
      supabaseProjects: supaProjects.length,
      domains: domainList.length,
    },
    summary,
    checks,
  });
}
