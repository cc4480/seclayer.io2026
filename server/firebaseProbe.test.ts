import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractFirebaseDbUrls, classifyRtdbRead } from './firebaseProbe.js';

test('extractFirebaseDbUrls finds both classic and regional RTDB URLs, deduped', () => {
  const html = `
    <script>
      const firebaseConfig = {
        apiKey: "AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        databaseURL: "https://my-app.firebaseio.com",
        projectId: "my-app"
      };
      const other = "https://my-app-default-rtdb.europe-west1.firebasedatabase.app/";
      const dup = "https://my-app.firebaseio.com/";
    </script>`;
  const urls = extractFirebaseDbUrls(html);
  assert.ok(urls.includes('https://my-app.firebaseio.com'), 'classic firebaseio.com form');
  assert.ok(urls.includes('https://my-app-default-rtdb.europe-west1.firebasedatabase.app'), 'regional firebasedatabase.app form');
  assert.equal(urls.filter((u) => u.endsWith('firebaseio.com')).length, 1, 'trailing-slash duplicate collapses');
});

test('extractFirebaseDbUrls returns nothing when no Firebase DB URL is present', () => {
  assert.deepEqual(extractFirebaseDbUrls('<script>const x = "https://example.com/api";</script>'), []);
  assert.deepEqual(extractFirebaseDbUrls(''), []);
});

test('classifyRtdbRead: a denied read (401) is SECURED, never a finding', () => {
  // The false-positive guard: a locked-down database returns 401 permission-denied.
  assert.deepEqual(classifyRtdbRead(401, '{"error":"Permission denied"}'), { open: false, hasData: false });
  assert.deepEqual(classifyRtdbRead(403, '{"error":"Permission denied"}'), { open: false, hasData: false });
});

test('classifyRtdbRead: 200 with data → open + hasData (critical); 200 null → open, no data (high)', () => {
  assert.deepEqual(classifyRtdbRead(200, '{"users":{"u1":{"email":"a@b.com"}}}'), { open: true, hasData: true });
  assert.deepEqual(classifyRtdbRead(200, 'null'), { open: true, hasData: false });
  assert.deepEqual(classifyRtdbRead(200, '{}'), { open: true, hasData: false });
});

test('classifyRtdbRead: a 200 that is not valid JSON (e.g. an HTML interstitial) is NOT claimed', () => {
  assert.deepEqual(classifyRtdbRead(200, '<!doctype html><html></html>'), { open: false, hasData: false });
});
