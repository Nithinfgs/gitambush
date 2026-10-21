import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { safeClone } from '../src/cloner.js';

describe('gitambush Safe Cloner', () => {
  it('throws descriptive error when repository URL is missing', () => {
    assert.throws(() => {
      safeClone(null);
    }, /Repository URL is required/);
  });
});
