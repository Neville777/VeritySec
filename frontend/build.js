#!/usr/bin/env node
// Build script: copies web assets and injects env-based API URL into the SPA.
const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..', 'web');
const DIST = path.join(__dirname, 'dist');
const API_URL = process.env.VITE_API_URL || process.env.API_URL || '';
const VERSION = process.env.APP_VERSION || 'v1.0.0';

function mkdirp(dir) {
    fs.mkdirSync(dir, { recursive: true });
}

function copyDir(src, dest) {
    mkdirp(dest);
    for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);
        if (entry.isDirectory()) {
            copyDir(srcPath, destPath);
        } else {
            fs.copyFileSync(srcPath, destPath);
        }
    }
}

// 1. Copy static assets
copyDir(path.join(SRC, 'static'), path.join(DIST, 'static'));

// 2. Process index.html — replace Go template vars
let html = fs.readFileSync(path.join(SRC, 'templates', 'index.html'), 'utf8');
html = html.replace(/\{\{\.Version\}\}/g, VERSION);

// 3. Inject API base URL config before closing </head>
const configScript = `
<script>
    window.__VERITYSEC_CONFIG__ = {
        apiBaseUrl: "${API_URL}",
        version: "${VERSION}"
    };
</script>`;
html = html.replace('</head>', configScript + '\n</head>');

mkdirp(DIST);
fs.writeFileSync(path.join(DIST, 'app.html'), html);

// 4. Copy landing page
if (fs.existsSync(path.join(SRC, 'templates', 'landing.html'))) {
    let landing = fs.readFileSync(path.join(SRC, 'templates', 'landing.html'), 'utf8');
    fs.writeFileSync(path.join(DIST, 'landing.html'), landing);
}

// 5. Copy root-level files
const rootFiles = ['robots.txt', 'sitemap.xml', 'favicon.ico', 'site.webmanifest', 'security.txt'];
for (const f of rootFiles) {
    const src = path.join(SRC, 'static', f);
    if (fs.existsSync(src)) {
        fs.copyFileSync(src, path.join(DIST, f));
    }
}

console.log(`Built frontend → ${DIST} (API_URL=${API_URL || '(same-origin)'})`);
