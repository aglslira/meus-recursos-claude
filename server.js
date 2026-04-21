#!/usr/bin/env node
/**
 * Painel Claude — servidor local de deleção
 * Roda em http://localhost:3001
 * Inicie com: node server.js
 */

const http = require('http');
const fs   = require('fs');
const path = require('path');
const os   = require('os');

const PORT = 3001;
const HOME = os.homedir();

// Caminhos permitidos para deleção (segurança)
const ALLOWED_PREFIXES = [
  path.join(HOME, '.claude', 'skills'),
  path.join(HOME, '.claude', 'plans'),
  path.join(HOME, '.claude', 'references'),
  path.join(HOME, 'Documents', 'Claude', 'Projects'),
];

function resolvePath(rawPath) {
  // Aceita ~ e caminhos absolutos
  const expanded = rawPath.startsWith('~/')
    ? path.join(HOME, rawPath.slice(2))
    : rawPath;
  return path.resolve(expanded);
}

function isAllowed(resolvedPath) {
  return ALLOWED_PREFIXES.some(prefix => resolvedPath.startsWith(prefix + path.sep) || resolvedPath === prefix);
}

function setCORS(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function json(res, status, body) {
  setCORS(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

const server = http.createServer((req, res) => {
  setCORS(res);

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // GET /health — verificar se o servidor está rodando
  if (req.method === 'GET' && req.url === '/health') {
    return json(res, 200, { ok: true, version: '1.0' });
  }

  // POST /delete — deletar arquivo ou pasta
  if (req.method === 'POST' && req.url === '/delete') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      let payload;
      try { payload = JSON.parse(body); } catch {
        return json(res, 400, { error: 'JSON inválido' });
      }

      const { path: rawPath } = payload;
      if (!rawPath) return json(res, 400, { error: 'path obrigatório' });

      const resolved = resolvePath(rawPath);

      if (!isAllowed(resolved)) {
        console.warn(`[BLOQUEADO] tentativa de deletar fora da zona permitida: ${resolved}`);
        return json(res, 403, { error: 'Caminho fora da zona permitida' });
      }

      if (!fs.existsSync(resolved)) {
        return json(res, 404, { error: 'Arquivo/pasta não encontrado' });
      }

      try {
        const stat = fs.statSync(resolved);
        if (stat.isDirectory()) {
          fs.rmSync(resolved, { recursive: true, force: true });
        } else {
          fs.unlinkSync(resolved);
        }
        console.log(`[DELETADO] ${resolved}`);
        return json(res, 200, { ok: true, deleted: resolved });
      } catch (err) {
        console.error(`[ERRO] ${err.message}`);
        return json(res, 500, { error: err.message });
      }
    });
    return;
  }

  // Estado do sync
  if (req.method === 'POST' && req.url === '/sync') {
    if (syncRunning) {
      return json(res, 200, { ok: true, status: 'running', message: 'Sync já em andamento...' });
    }
    syncRunning = true;
    lastSyncResult = null;

    const { spawn } = require('child_process');
    const proc = spawn('/usr/local/bin/claude', [
      '-p', 'rode a task atualiza-painel-claude',
      '--dangerously-skip-permissions'
    ], {
      cwd: '/Users/andreschwambach/Documents/Claude/Projects/meus-recursos-claude',
      env: { ...process.env, HOME: '/Users/andreschwambach' },
      detached: false,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    proc.stdout.on('data', d => console.log('[SYNC]', d.toString().trim()));
    proc.stderr.on('data', d => console.error('[SYNC ERR]', d.toString().trim()));

    proc.on('close', (code) => {
      syncRunning = false;
      lastSyncResult = { code, time: Date.now(), ok: code === 0 };
      console.log(`[SYNC] concluído com código ${code}`);
    });

    return json(res, 200, { ok: true, status: 'started' });
  }

  // GET /sync/status — poll para saber se terminou
  if (req.method === 'GET' && req.url === '/sync/status') {
    return json(res, 200, { running: syncRunning, lastResult: lastSyncResult });
  }

  json(res, 404, { error: 'Rota não encontrada' });
});

// Estado global do sync (fora do handler)
let syncRunning = false;
let lastSyncResult = null;

server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n🗑️  Servidor do painel rodando em http://localhost:${PORT}`);
  console.log(`   Zonas permitidas:`);
  ALLOWED_PREFIXES.forEach(p => console.log(`   • ${p}`));
  console.log(`\n   Mantenha este terminal aberto enquanto usar o painel.\n`);
});
