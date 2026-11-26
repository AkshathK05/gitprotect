#!/usr/bin/env node
'use strict';

const { spawnSync } = require('child_process');
const path = require('path');

const PLATFORMS = {
  'darwin-arm64': '@akshathk/gitprotect-darwin-arm64',
  'darwin-x64': '@akshathk/gitprotect-darwin-x64',
  'linux-x64': '@akshathk/gitprotect-linux-x64',
  'linux-arm64': '@akshathk/gitprotect-linux-arm64',
  'win32-x64': '@akshathk/gitprotect-win32-x64'
};

const key = `${process.platform}-${process.arch}`;
const pkgName = PLATFORMS[key];

if (!pkgName) {
  console.error(
    `gitprotect error: unsupported platform ${process.platform}-${process.arch}.\n` +
    `Supported platforms: darwin-arm64, darwin-x64, linux-x64, linux-arm64, win32-x64.`
  );
  process.exit(1);
}

const binName = process.platform === 'win32' ? 'gitprotect.exe' : 'gitprotect';
let binaryPath;

try {
  const pkgJson = require.resolve(`${pkgName}/package.json`);
  binaryPath = path.join(path.dirname(pkgJson), 'bin', binName);
} catch (err) {
  try {
    binaryPath = require.resolve(`${pkgName}/bin/${binName}`);
  } catch (innerErr) {
    console.error(
      `gitprotect error: platform package '${pkgName}' is not installed.\n` +
      `This can happen if npm was executed with '--omit=optional' or optional dependencies failed to install.\n` +
      `Please try reinstalling without omitting optional dependencies:\n` +
      `  npm install -g @akshathk/gitprotect`
    );
    process.exit(1);
  }
}

const result = spawnSync(binaryPath, process.argv.slice(2), {
  stdio: 'inherit'
});

if (result.error) {
  console.error(`gitprotect error: failed to run binary at ${binaryPath}: ${result.error.message}`);
  process.exit(1);
}

if (result.signal) {
  process.kill(process.pid, result.signal);
}

process.exit(result.status !== null ? result.status : 1);
