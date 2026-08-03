import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseNmapXml } from './parseXml.js';
import { compileNmapResult } from './compile.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const sampleXml = fs.readFileSync(path.join(__dirname, '__fixtures__', 'sample-scan.xml'), 'utf8');

test('parseNmapXml extracts host state, ports, services, OS matches, and scripts', () => {
  const parsed = parseNmapXml(sampleXml);

  assert.equal(parsed.state, 'up');
  assert.equal(parsed.ports.length, 3);

  const ssh = parsed.ports.find((p) => p.portid === 22)!;
  assert.equal(ssh.protocol, 'tcp');
  assert.equal(ssh.state, 'open');
  assert.equal(ssh.service?.name, 'ssh');
  assert.equal(ssh.service?.product, 'OpenSSH');
  assert.equal(ssh.service?.version, '7.6p1 Ubuntu 4ubuntu0.7');
  assert.equal(ssh.scripts.length, 0, 'no vuln script fired against this port');

  const http = parsed.ports.find((p) => p.portid === 80)!;
  assert.equal(http.scripts.length, 1);
  assert.equal(http.scripts[0].id, 'http-vuln-cve2021-41773');
  assert.match(http.scripts[0].output, /CVE-2021-41773/);

  const mysql = parsed.ports.find((p) => p.portid === 3306)!;
  assert.equal(mysql.scripts[0].id, 'mysql-vuln-cve2012-2122');

  assert.equal(parsed.osMatches.length, 2);
  assert.equal(parsed.osMatches[0].name, 'Linux 5.0 - 5.14');
  assert.equal(parsed.osMatches[0].accuracy, 95);

  assert.equal(parsed.hostScripts.length, 1);
  assert.equal(parsed.hostScripts[0].id, 'clock-skew');
});

test('parseNmapXml handles a host that never came up (no ports/os/scripts sections)', () => {
  const downXml = `<?xml version="1.0"?>
    <nmaprun>
      <host><status state="down"/></host>
      <runstats><finished exit="success"/></runstats>
    </nmaprun>`;
  const parsed = parseNmapXml(downXml);
  assert.equal(parsed.state, 'down');
  assert.deepEqual(parsed.ports, []);
  assert.deepEqual(parsed.osMatches, []);
  assert.deepEqual(parsed.hostScripts, []);
});

test('parseNmapXml is robust to a completely empty/malformed document', () => {
  const parsed = parseNmapXml('<?xml version="1.0"?><nmaprun></nmaprun>');
  assert.equal(parsed.state, 'down');
  assert.deepEqual(parsed.ports, []);
});

test('compileNmapResult flattens per-port and host-level scripts into vulnFindings, all DETECTED-only shape', () => {
  const parsed = parseNmapXml(sampleXml);
  const result = compileNmapResult(parsed, {
    targetHost: 'scan-me.test',
    resolvedIp: '203.0.113.10',
    nmapVersion: '7.94',
    durationMs: 120000,
    scanArgs: ['-p-', '-sV', '-O', '--script', 'vuln'],
  });

  assert.equal(result.targetHost, 'scan-me.test');
  assert.equal(result.resolvedIp, '203.0.113.10');
  assert.equal(result.state, 'up');
  assert.equal(result.ports.length, 3);
  assert.equal(result.nmapVersion, '7.94');
  assert.equal(result.durationMs, 120000);

  // Two per-port vuln scripts + one host-level script = 3 total results.
  assert.equal(result.vulnFindings.length, 3);
  const httpFinding = result.vulnFindings.find((f) => f.scriptId === 'http-vuln-cve2021-41773')!;
  assert.equal(httpFinding.port, 80);
  assert.equal(httpFinding.outcome, 'finding', 'a real VULNERABLE hit is classified as a finding');
  const hostFinding = result.vulnFindings.find((f) => f.scriptId === 'clock-skew')!;
  assert.equal(hostFinding.port, undefined, 'host-level scripts carry no port number');

  // Structural isolation from the AppSec evidence model: an NmapVulnFinding
  // has no severity/confidence/evidence fields a Finding/ExploitEvidence
  // would carry — nothing here can accidentally be scored.
  for (const f of result.vulnFindings) {
    assert.equal((f as any).severity, undefined);
    assert.equal((f as any).evidence, undefined);
  }
});

test('compileNmapResult classifies negative, errored, and inconclusive script results — never all DETECTED', () => {
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="203.0.113.20" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <script id="http-csrf" output="Couldn't find any CSRF vulnerabilities."/>
            <script id="http-vuln-cve2013-7091" output="ERROR: Script execution failed (use -d to debug)"/>
          </port>
          <port protocol="tcp" portid="443">
            <state state="open"/>
            <script id="ssl-ccs-injection" output="No reply from server (TIMEOUT)"/>
            <script id="some-vuln-check" output="State: UNKNOWN (going to safe state)"/>
            <script id="http-vuln-real" output="VULNERABLE:&#10;  State: VULNERABLE&#10;  A real hit."/>
          </port>
        </ports>
      </host>
    </nmaprun>`;
  const parsed = parseNmapXml(xml);
  const result = compileNmapResult(parsed, {
    targetHost: 'scan-me.test', resolvedIp: '203.0.113.20', nmapVersion: '7.94', durationMs: 1000, scanArgs: [],
  });

  assert.equal(result.vulnFindings.length, 5, 'every script that ran is still surfaced — nothing is silently dropped');
  const byId = Object.fromEntries(result.vulnFindings.map((f) => [f.scriptId, f.outcome]));
  assert.equal(byId['http-csrf'], 'negative');
  assert.equal(byId['http-vuln-cve2013-7091'], 'error');
  assert.equal(byId['ssl-ccs-injection'], 'error');
  assert.equal(byId['some-vuln-check'], 'inconclusive');
  assert.equal(byId['http-vuln-real'], 'finding');

  // Exactly one real finding — the previous behavior would have reported 5.
  assert.equal(result.vulnFindings.filter((f) => f.outcome === 'finding').length, 1);
});

test('compileNmapResult produces an empty port/finding list for a down host', () => {
  const parsed = parseNmapXml('<?xml version="1.0"?><nmaprun><host><status state="down"/></host></nmaprun>');
  const result = compileNmapResult(parsed, {
    targetHost: 'scan-me.test', resolvedIp: '203.0.113.10', nmapVersion: '7.94', durationMs: 5000, scanArgs: [],
  });
  assert.equal(result.state, 'down');
  assert.deepEqual(result.ports, []);
  assert.deepEqual(result.vulnFindings, []);
});
