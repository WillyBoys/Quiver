import { spawn } from 'child_process';
import http from 'http';

const PORT = parseInt(process.env.PORT || '3001', 10);
const MODEL = process.env.CLAUDE_MODEL || 'claude-haiku-4-5-20251001';
const TIMEOUT_MS = 300_000; // 5 min — long enough for large report generation

function callClaude(prompt) {
    return new Promise((resolve, reject) => {
        let settled = false;
        const finish = (fn) => (...args) => { if (!settled) { settled = true; fn(...args); } };

        const proc = spawn(
            'claude',
            ['--print', '--model', MODEL, '--output-format', 'text'],
            { env: process.env }
        );

        let stdout = '';
        let stderr = '';

        proc.stdout.on('data', d => { stdout += d; });
        proc.stderr.on('data', d => { stderr += d; });

        // Write prompt to stdin so long prompts are not subject to argv length limits
        proc.stdin.write(prompt, 'utf8');
        proc.stdin.end();

        const timer = setTimeout(() => {
            proc.kill('SIGTERM');
            finish(reject)(new Error(`Claude CLI timed out after ${TIMEOUT_MS / 1000}s`));
        }, TIMEOUT_MS);

        proc.on('close', code => {
            clearTimeout(timer);
            if (code === 0) {
                finish(resolve)(stdout.trim());
            } else {
                const detail = stderr.trim().slice(0, 400) || `exit code ${code}`;
                const err = new Error(detail);
                err.isAuth = /auth|oauth|token|401|403|unauthorized|credential|login/i.test(detail);
                finish(reject)(err);
            }
        });

        proc.on('error', err => {
            clearTimeout(timer);
            if (err.code === 'ENOENT') {
                err.message = '`claude` binary not found — was @anthropic-ai/claude-code installed correctly?';
            }
            finish(reject)(err);
        });
    });
}

const server = http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ status: 'ok' }));
    }

    if (req.method !== 'POST' || req.url !== '/generate') {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Not found' }));
    }

    const MAX_BODY_BYTES = 4 * 1024 * 1024; // 4 MB — prompts can be large but not unbounded
    let body;
    try {
        const raw = await new Promise((resolve, reject) => {
            let buf = '';
            let size = 0;
            req.on('data', c => {
                size += c.length;
                if (size > MAX_BODY_BYTES) { req.destroy(); reject(new Error('Request body too large')); return; }
                buf += c;
            });
            req.on('end', () => resolve(buf));
            req.on('error', reject);
        });
        body = JSON.parse(raw);
    } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    }

    if (!body?.prompt) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing prompt field' }));
    }

    try {
        const response = await callClaude(body.prompt);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ response }));
    } catch (err) {
        const status = err.isAuth ? 401 : 500;
        console.error(`[bridge] ${err.message}`);
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
    }
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`[bridge] ready on :${PORT}  model=${MODEL}`);
    if (!process.env.CLAUDE_CODE_OAUTH_TOKEN && !process.env.ANTHROPIC_API_KEY) {
        console.warn('[bridge] WARNING: Neither CLAUDE_CODE_OAUTH_TOKEN nor ANTHROPIC_API_KEY is set — requests will fail');
    }
});
