'use strict';

const { spawn } = require('child_process');
const path = require('path');

const electronExecutable = require('electron');
const appDirectory = path.resolve(__dirname, '..');
const environment = { ...process.env };

// Some build tooling uses this variable to execute Electron as plain Node.js.
// It must never leak into a normal development launch.
delete environment.ELECTRON_RUN_AS_NODE;

const child = spawn(
  electronExecutable,
  ['.', ...process.argv.slice(2)],
  {
    cwd: appDirectory,
    env: environment,
    stdio: 'inherit',
    windowsHide: false
  }
);

child.on('error', error => {
  console.error(`Unable to launch Electron: ${error.message}`);
  process.exitCode = 1;
});

child.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exitCode = code === null ? 1 : code;
});
