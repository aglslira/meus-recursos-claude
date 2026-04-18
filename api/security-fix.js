// /api/security-fix.js — Auto-apply SAFE security fixes
// Called before /api/security to pre-clean known issues.
//
// WHITELIST (only 100% safe, non-breaking fixes):
//   1. Supabase: function_search_path_mutable
//      → ALTER FUNCTION <schema>.<name>() SET search_path = public;
//
// Everything else stays as "requires your attention" in the audit modal.

async function fetchWithAuth(url, token, init, timeoutMs) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs || 10000);
  try {
    return await fetch(url, {
      ...init,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        'Content-Type': 'application/json',
        ...(init?.headers || {}),
      },
      signal: ctl.signal,
    });
  } finally {
    clearTimeout(t);
  }
}

async function safeJson(res) {
  try { return await res.json(); } catch { return null; }
}

async function listSupabaseProjects(token) {
  const res = await fetchWithAuth('https://api.supabase.com/v1/projects', token);
  const data = await safeJson(res);
  return Array.isArray(data) ? data : [];
}

async function getSecurityAdvisors(token, projectId) {
  const res = await fetchWithAuth(
    `https://api.supabase.com/v1/projects/${projectId}/advisors/security`,
    token
  );
  const data = await safeJson(res);
  return data?.lints || [];
}

async function runSql(token, projectId, query) {
  const res = await fetchWithAuth(
    `https://api.supabase.com/v1/projects/${projectId}/database/query`,
    token,
    { method: 'POST', body: JSON.stringify({ query }) },
    15000
  );
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(`SQL failed (${res.status}): ${errText.slice(0, 200)}`);
  }
  return safeJson(res);
}

// Validate function name is a safe identifier (letters, digits, underscore)
function isSafeIdent(s) {
  return typeof s === 'string' && /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(s) && s.length <= 63;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://painelclaude.anti-caos.app.br');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'POST only' });
    return;
  }

  const supabaseToken = process.env.SUPABASE_ACCESS_TOKEN;
  if (!supabaseToken) {
    res.status(500).json({ error: 'SUPABASE_ACCESS_TOKEN not configured' });
    return;
  }

  const started = Date.now();
  const applied = [];
  const failed = [];
  const skipped = [];

  let projects;
  try {
    projects = await listSupabaseProjects(supabaseToken);
  } catch (e) {
    res.status(500).json({ error: 'Failed to list Supabase projects', detail: e.message });
    return;
  }

  for (const project of projects) {
    const projectName = project.name || project.id;
    let lints;
    try {
      lints = await getSecurityAdvisors(supabaseToken, project.id);
    } catch (e) {
      skipped.push({
        category: 'supabase-advisors',
        project: projectName,
        reason: `Não foi possível ler advisors: ${e.message}`,
      });
      continue;
    }

    for (const lint of lints) {
      // ─── FIX 1: function_search_path_mutable ───
      if (lint.name === 'function_search_path_mutable') {
        const funcName = lint.metadata?.name;
        const schema = lint.metadata?.schema || 'public';

        if (!isSafeIdent(funcName) || !isSafeIdent(schema)) {
          skipped.push({
            category: 'search_path',
            project: projectName,
            reason: `Nome de função inseguro: ${schema}.${funcName}`,
          });
          continue;
        }

        const sql = `ALTER FUNCTION ${schema}.${funcName}() SET search_path = public;`;
        try {
          await runSql(supabaseToken, project.id, sql);
          applied.push({
            category: 'search_path',
            project: projectName,
            target: `${schema}.${funcName}()`,
            description: `Função protegida contra schema hijacking.`,
          });
        } catch (e) {
          failed.push({
            category: 'search_path',
            project: projectName,
            target: `${schema}.${funcName}()`,
            error: e.message,
          });
        }
        continue;
      }

      // Other lints: let the main audit report them
    }
  }

  res.json({
    ranAt: Date.now(),
    elapsedMs: Date.now() - started,
    applied,
    failed,
    skipped,
    summary: {
      applied: applied.length,
      failed: failed.length,
      skipped: skipped.length,
    },
  });
}
