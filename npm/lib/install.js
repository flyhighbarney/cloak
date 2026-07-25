// cloakline npm shim — download + install runtime.
//
// Design:
//   * We publish one npm package (cloakline) that contains only this JS
//     shim. Native binaries are NOT bundled — they're downloaded from
//     GitHub Releases on first use. This keeps the npm package tiny and
//     avoids the platform-fanout matrix that packages like esbuild
//     require (cloakline-{win32,darwin}-{x64,arm64} sub-packages).
//
//   * Downloaded content lives at a stable, well-known path:
//        macOS:   ~/.cloakline/
//        Windows: %LOCALAPPDATA%\cloakline\
//     so uninstall can find it later even if the npm cache is purged.
//
//   * `npx cloakline install` downloads the release archive, extracts
//     it, and invokes the platform's bootstrap script (scripts\bootstrap.ps1
//     or scripts/bootstrap.sh) with --skip-build (because the archive
//     already contains the prebuilt binaries).
//
//   * `npx cloakline scan` (and other subcommands that don't need
//     the daemon) download only the cloak CLI and run it directly —
//     no admin needed.

'use strict';

const os              = require('os');
const path            = require('path');
const fs              = require('fs');
const { spawnSync }   = require('child_process');
const https           = require('https');

// Override with the CLOAKLINE_REPO env var if you fork.
const REPO       = process.env.CLOAKLINE_REPO || 'flyhighbarney/cloak';
const RELEASE_TAG = process.env.CLOAKLINE_TAG || 'latest';

// --- paths ---------------------------------------------------------------

function installRoot() {
    if (process.platform === 'win32') {
        const base = process.env.LOCALAPPDATA
                     || path.join(os.homedir(), 'AppData', 'Local');
        return path.join(base, 'cloakline');
    }
    return path.join(os.homedir(), '.cloakline');
}

function exeName(name) {
    return process.platform === 'win32' ? name + '.exe' : name;
}

function binPath(name) {
    return path.join(installRoot(), 'bin', exeName(name));
}

// --- OS / arch mapping ---------------------------------------------------

function releaseAssetName(version) {
    // Matches the naming used in .github/workflows/release.yml.
    // Example: cloakline-v0.1.0-windows-amd64.zip
    const platform = platformSlug();
    const arch     = archSlug();
    const ext      = process.platform === 'win32' ? 'zip' : 'tar.gz';
    return `cloakline-${version}-${platform}-${arch}.${ext}`;
}

function platformSlug() {
    switch (process.platform) {
        case 'darwin': return 'macos';
        case 'win32':  return 'windows';
        case 'linux':  return 'linux';
        default:
            throw new Error(`unsupported platform: ${process.platform}`);
    }
}

function archSlug() {
    switch (process.arch) {
        case 'x64':   return 'amd64';
        case 'arm64': return 'arm64';
        default:
            throw new Error(`unsupported arch: ${process.arch}`);
    }
}

// --- HTTPS fetch with redirects -----------------------------------------

function httpsGet(url, opts = {}) {
    return new Promise((resolve, reject) => {
        const headers = {
            'User-Agent': 'cloakline-npm-installer',
            Accept: opts.accept || 'application/octet-stream',
        };
        // Attach GitHub token if the repo is private. Users of a private
        // fork export CLOAKLINE_TOKEN=ghp_... before running npx.
        // GITHUB_TOKEN is also honoured (matches gh CLI convention).
        const tok = process.env.CLOAKLINE_TOKEN || process.env.GITHUB_TOKEN;
        if (tok) headers.Authorization = `Bearer ${tok}`;
        const req = https.get(url, { headers }, res => {
            // Follow up to 5 redirects (GitHub Releases uses S3 redirects).
            if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
                const redirects = (opts.redirects || 0) + 1;
                if (redirects > 5) {
                    reject(new Error(`too many redirects fetching ${url}`));
                    return;
                }
                res.resume();
                resolve(httpsGet(res.headers.location, { ...opts, redirects }));
                return;
            }
            if (res.statusCode >= 400) {
                reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
                return;
            }
            resolve(res);
        });
        req.on('error', reject);
    });
}

// --- release metadata ---------------------------------------------------

async function resolveReleaseTag(tag) {
    if (tag && tag !== 'latest') return tag;
    // Query the GitHub API for the latest release tag.
    const url = `https://api.github.com/repos/${REPO}/releases/latest`;
    const res = await httpsGet(url, { accept: 'application/vnd.github+json' });
    let body = '';
    for await (const chunk of res) body += chunk;
    const meta = JSON.parse(body);
    if (!meta.tag_name) {
        throw new Error(`could not resolve latest release from ${url}`);
    }
    return meta.tag_name;
}

// --- download + extract -------------------------------------------------

async function downloadRelease() {
    const tag     = await resolveReleaseTag(RELEASE_TAG);
    const asset   = releaseAssetName(tag);
    const dlUrl   = `https://github.com/${REPO}/releases/download/${tag}/${asset}`;
    const root    = installRoot();
    fs.mkdirSync(root, { recursive: true });
    const archive = path.join(root, asset);

    console.log(`  downloading ${asset}`);
    const res = await httpsGet(dlUrl);
    await new Promise((resolve, reject) => {
        const out = fs.createWriteStream(archive);
        res.pipe(out);
        out.on('finish', resolve);
        out.on('error', reject);
        res.on('error', reject);
    });

    console.log(`  extracting to ${root}`);
    if (asset.endsWith('.zip')) {
        // Use PowerShell's Expand-Archive so we don't need a native zip lib.
        const r = spawnSync('powershell', [
            '-NoProfile', '-Command',
            `Expand-Archive -Force -Path "${archive}" -DestinationPath "${root}"`,
        ], { stdio: 'inherit' });
        if (r.status !== 0) throw new Error('Expand-Archive failed');
    } else {
        const r = spawnSync('tar', ['-xzf', archive, '-C', root], { stdio: 'inherit' });
        if (r.status !== 0) throw new Error('tar -xzf failed');
    }
    fs.unlinkSync(archive);

    // Ensure binaries are executable on POSIX.
    if (process.platform !== 'win32') {
        for (const b of ['cloak', 'cloakline']) {
            const p = binPath(b);
            if (fs.existsSync(p)) fs.chmodSync(p, 0o755);
        }
        for (const sh of ['bootstrap.sh', 'install.sh', 'uninstall.sh']) {
            const p = path.join(root, 'scripts', sh);
            if (fs.existsSync(p)) fs.chmodSync(p, 0o755);
        }
    }
    return { root, tag };
}

async function ensureInstalled() {
    if (fs.existsSync(binPath('cloak')) && fs.existsSync(binPath('cloakline'))) {
        return installRoot();
    }
    const { root } = await downloadRelease();
    return root;
}

// --- public entry points ------------------------------------------------

async function cloakBin({ downloadIfMissing = false } = {}) {
    const p = binPath('cloak');
    if (fs.existsSync(p)) return p;
    if (!downloadIfMissing) {
        throw new Error(`cloak binary not found at ${p} — run: npx cloakline install`);
    }
    await ensureInstalled();
    return p;
}

function runBinary(bin, args) {
    const r = spawnSync(bin, args, { stdio: 'inherit' });
    return r.status || 0;
}

async function install(argv) {
    const root = await ensureInstalled();
    // Chain to the platform bootstrap. --skip-build because binaries
    // are already present, --skip-trust NOT set (user should trust the CA).
    if (process.platform === 'win32') {
        const script = path.join(root, 'scripts', 'bootstrap.ps1');
        if (!fs.existsSync(script)) {
            throw new Error(`bootstrap.ps1 not found at ${script}`);
        }
        const psArgs = [
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', script, '-SkipBuild', ...argv,
        ];
        return runBinary('powershell', psArgs);
    }
    if (process.platform === 'darwin') {
        const script = path.join(root, 'scripts', 'bootstrap.sh');
        if (!fs.existsSync(script)) {
            throw new Error(`bootstrap.sh not found at ${script}`);
        }
        return runBinary('bash', [script, '--skip-build', ...argv]);
    }
    throw new Error(`install not supported on platform: ${process.platform}`);
}

async function uninstall(argv) {
    const root = installRoot();
    if (!fs.existsSync(root)) {
        console.log('cloakline is not installed (no directory at ' + root + ')');
        return 0;
    }
    let status = 0;
    if (process.platform === 'win32') {
        const script = path.join(root, 'scripts', 'uninstall.ps1');
        if (!fs.existsSync(script)) {
            throw new Error(`uninstall.ps1 not found — installation is corrupt`);
        }
        // Self-elevate via a nested powershell RunAs.
        status = runBinary('powershell', [
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-Command',
            `Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','${script}' -Wait`,
        ]);
    } else if (process.platform === 'darwin') {
        const script = path.join(root, 'scripts', 'uninstall.sh');
        if (!fs.existsSync(script)) {
            throw new Error(`uninstall.sh not found — installation is corrupt`);
        }
        status = runBinary('bash', [script, ...argv]);
    } else {
        throw new Error(`uninstall not supported on platform: ${process.platform}`);
    }

    // Remove the downloaded binaries. The platform uninstall scripts
    // deliberately LEAVE these in place, but that breaks the reinstall
    // path: ensureInstalled() only downloads when the binaries are
    // missing, so a later `npx cloakline install` would silently reuse
    // the OLD binary and never pull the new release — the classic "my
    // fix didn't take effect" trap during iterative testing. Deleting the
    // bin dir here guarantees the next install fetches a fresh build.
    const binDir = path.join(root, 'bin');
    try {
        if (fs.existsSync(binDir)) {
            fs.rmSync(binDir, { recursive: true, force: true });
            console.log('  removed binaries at ' + binDir + ' (next install pulls fresh)');
        }
    } catch (e) {
        console.error('  warning: could not remove ' + binDir + ': ' + e.message);
        console.error('  delete it manually so the next install downloads a fresh build.');
    }
    return status;
}

module.exports = {
    install,
    uninstall,
    cloakBin,
    runBinary,
    installRoot,
    binPath,
};
