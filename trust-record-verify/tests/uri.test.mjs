import assert from 'node:assert/strict';
import test from 'node:test';
import { isUri } from '../dist/uri.js';

test('IPvFuture version flag is case-insensitive under RFC 3986 section 3.2.2', () => {
  for (const uri of ['https://[v1.a]/', 'https://[V1.a]/', 'https://[vF.a:b]/', 'https://[VF.a:b]/']) {
    assert.equal(isUri(uri), true, uri);
  }
  for (const uri of ['https://[V.a]/', 'https://[VG.a]/', 'https://[V1.]/', 'https://[V1.a]/\n']) {
    assert.equal(isUri(uri), false, uri);
  }
});