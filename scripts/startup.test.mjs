import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const windows = process.platform === 'win32';
const version = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')).version;

function powershell(...args) {
    return spawnSync('powershell.exe', ['-NoProfile', '-File', resolve(root, 'start.ps1'), ...args], {
        cwd: tmpdir(), encoding: 'utf8', timeout: 30_000,
    });
}

function batch(args) {
    return spawnSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', `""${resolve(root, 'start.bat')}" ${args}"`], {
        cwd: tmpdir(), encoding: 'utf8', timeout: 30_000, windowsVerbatimArguments: true,
    });
}

test('root pip manifest delegates to the backend instead of containing Markdown', () => {
    const requirements = readFileSync(resolve(root, 'requirements.txt'), 'utf8')
        .split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#'));
    assert.deepEqual(requirements, ['-r backend/requirements.txt']);
});

test('release versions agree across manifests, API, engine, UI and launcher', () => {
    const read = path => readFileSync(resolve(root, path), 'utf8');
    const lock = JSON.parse(read('package-lock.json'));
    assert.equal(lock.version, version);
    assert.equal(lock.packages[''].version, version);
    const apiVersions = [...read('backend/app/main.py').matchAll(/version["']?\s*[:=]\s*["']([\d.]+)["']/g)].map(match => match[1]);
    assert.deepEqual(apiVersions, [version, version]);
    assert.ok(read('backend/app/engine/analyzer.py').includes(`"engine_version": "${version}"`));
    assert.ok(read('start.ps1').includes(`$health.version -eq '${version}'`));
    assert.ok(read('src/App.jsx').includes(`v${version}`));
    assert.ok(read('README.md').startsWith(`# Aegis Threat ${version}`));
    for (const path of ['requirements.txt', 'backend/requirements.txt', 'backend/requirements-training.txt']) {
        assert.ok(read(path).split(/\r?\n/)[0].includes(version), path);
    }
});

test('PowerShell help works from outside the repository', { skip: !windows }, () => {
    const result = powershell('-Help');
    assert.equal(result.status, 0, result.stderr);
    assert.ok(result.stdout.includes(`Aegis Threat ${version}`));
    assert.match(result.stdout, /--stop/);
});

test('batch wrapper forwards help from a path outside the repository', { skip: !windows }, () => {
    const result = batch('--help');
    assert.equal(result.status, 0, result.stderr);
    assert.ok(result.stdout.includes(`Aegis Threat ${version}`));
});

test('batch rejects unknown flags and missing port values', { skip: !windows }, () => {
    for (const args of ['--unknown', '--backend-port', '--frontend-port']) {
        const result = batch(args);
        assert.equal(result.status, 2, `${args}: ${result.stdout} ${result.stderr}`);
        assert.match(result.stdout, /ERROR:/);
    }
});

test('invalid ports fail before any server starts', { skip: !windows }, () => {
    for (const value of ['0', '65536', 'not-a-port']) {
        const result = powershell('-BackendPort', value, '-Check');
        assert.notEqual(result.status, 0);
    }
});

test('check cannot install dependencies through either launcher', { skip: !windows }, () => {
    for (const result of [powershell('-Check', '-InstallDependencies'), batch('--check --install')]) {
        assert.equal(result.status, 1, result.stderr);
        assert.match(result.stdout, /no dependencies were changed/);
    }
});

test('both services cannot use the same port through either launcher', { skip: !windows }, () => {
    for (const result of [powershell('-BackendPort', '8000', '-FrontendPort', '8000'), batch('-b 8000 -f 8000')]) {
        assert.equal(result.status, 1, result.stderr);
        assert.match(result.stdout, /ports must differ/);
    }
});
