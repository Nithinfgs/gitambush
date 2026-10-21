#!/usr/bin/env node

/**
 * gitambush CLI entrypoint
 */

import { runCli } from '../src/cli.js';

runCli(process.argv.slice(2)).then(code => {
  process.exit(code);
}).catch(err => {
  console.error(`Unexpected failure: ${err.message}`);
  process.exit(2);
});
