#!/usr/bin/env node

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const scriptPath = path.join(__dirname, 'vibeguard.py');

if (!fs.existsSync(scriptPath)) {
  console.error('❌ vibeguard.py not found');
  process.exit(1);
}

try {
  execSync(`python "${scriptPath}" ${process.argv.slice(2).join(' ')}`, {
    stdio: 'inherit'
  });
} catch (e) {
  process.exit(1);
}