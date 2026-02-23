'use strict';

const path = require('path');
const fs = require('fs');

const {
  analyze,
  redactPii,
  extractLogBlocks,
  isMiV2Log,
  detectStages,
  formatComment,
} = require('../index.js');

// ---------------------------------------------------------------------------
// Test data helpers
// ---------------------------------------------------------------------------
function loadSample(filename) {
  return fs.readFileSync(path.join(__dirname, 'data', filename), 'utf8');
}

// ---------------------------------------------------------------------------
// redactPii
// ---------------------------------------------------------------------------
describe('redactPii', () => {
  test('redacts a well-formed JWT token', () => {
    const input = 'token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const result = redactPii(input);
    expect(result).not.toContain('eyJhbGciOiJSUzI1NiJ9');
    expect(result).toContain('[JWT_REDACTED]');
  });

  test('redacts a Bearer token', () => {
    const input = 'Authorization: Bearer abc123.def456.ghi789';
    const result = redactPii(input);
    expect(result).toContain('Bearer [TOKEN_REDACTED]');
    expect(result).not.toContain('abc123.def456.ghi789');
  });

  test('returns content unchanged when no PII present', () => {
    const input = 'ManagedIdentityV2 token acquisition started\nNo sensitive data here';
    expect(redactPii(input)).toBe(input);
  });

  test('redacts multiple JWT tokens in one string', () => {
    const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const input = `first=${jwt} second=${jwt}`;
    const result = redactPii(input);
    expect((result.match(/\[JWT_REDACTED\]/g) || []).length).toBe(2);
  });

  test('returns empty string unchanged', () => {
    expect(redactPii('')).toBe('');
  });

  test('handles null/undefined input gracefully', () => {
    expect(redactPii(null)).toBeNull();
    expect(redactPii(undefined)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// extractLogBlocks
// ---------------------------------------------------------------------------
describe('extractLogBlocks', () => {
  test('extracts a single log code fence', () => {
    const body = 'Some text\n```log\nline1\nline2\n```\nmore text';
    const blocks = extractLogBlocks(body);
    expect(blocks).toHaveLength(1);
    expect(blocks[0]).toContain('line1');
  });

  test('extracts an unlabelled code fence', () => {
    const body = '```\nplain log line\n```';
    const blocks = extractLogBlocks(body);
    expect(blocks).toHaveLength(1);
    expect(blocks[0]).toContain('plain log line');
  });

  test('extracts multiple code fences', () => {
    const body = '```log\nblock1\n```\n\n```text\nblock2\n```';
    const blocks = extractLogBlocks(body);
    expect(blocks).toHaveLength(2);
  });

  test('falls back to text after a "Logs:" heading when no fences present', () => {
    const body = 'Description\n\nLogs:\nlog line one\nlog line two';
    const blocks = extractLogBlocks(body);
    expect(blocks).toHaveLength(1);
    expect(blocks[0]).toContain('log line one');
  });

  test('returns empty array when issue body has no log content', () => {
    const body = 'This is a plain issue with no code fences.';
    expect(extractLogBlocks(body)).toHaveLength(0);
  });

  test('returns empty array for empty issue body', () => {
    expect(extractLogBlocks('')).toHaveLength(0);
  });

  test('returns empty array for null input', () => {
    expect(extractLogBlocks(null)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// isMiV2Log
// ---------------------------------------------------------------------------
describe('isMiV2Log', () => {
  test('returns true for log containing ManagedIdentityV2', () => {
    expect(isMiV2Log('ManagedIdentityV2 token acquisition started')).toBe(true);
  });

  test('returns true for log containing MiV2', () => {
    expect(isMiV2Log('MiV2 flow initialised')).toBe(true);
  });

  test('returns true for log containing MI V2 (with space)', () => {
    expect(isMiV2Log('Using MI V2 endpoint')).toBe(true);
  });

  test('returns true for log containing mi-v2 (lowercase, hyphen)', () => {
    expect(isMiV2Log('mi-v2 token request sent')).toBe(true);
  });

  test('returns false for non-MSI v2 log content', () => {
    expect(isMiV2Log(loadSample('non-miv2.log'))).toBe(false);
  });

  test('returns false for empty string', () => {
    expect(isMiV2Log('')).toBe(false);
  });

  test('returns false for null', () => {
    expect(isMiV2Log(null)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// detectStages
// ---------------------------------------------------------------------------
describe('detectStages', () => {
  test('detects mTLS/SCHANNEL failure from real sample log', () => {
    const log = loadSample('issue-5755-mtls-schannel.log');
    const stages = detectStages(log);
    const schannel = stages.find(s => s.stage === 'mtls_schannel');
    expect(schannel).toBeDefined();
    expect(schannel.severity).toBe('error');
  });

  test('detects IMDS failure from real sample log', () => {
    const log = loadSample('imds-failure.log');
    const stages = detectStages(log);
    const imds = stages.find(s => s.stage === 'imds');
    expect(imds).toBeDefined();
    expect(imds.severity).toBe('error');
  });

  test('detects token cache hit and miss from real sample log', () => {
    const log = loadSample('cache-hit-miss.log');
    const stages = detectStages(log);
    const cache = stages.find(s => s.stage === 'token_cache');
    expect(cache).toBeDefined();
  });

  test('detects certificate cache stage', () => {
    const log = 'ManagedIdentityV2\nCertificateCache: certificate not found in store';
    const stages = detectStages(log);
    const certStage = stages.find(s => s.stage === 'cert_cache');
    expect(certStage).toBeDefined();
  });

  test('detects attestation failure', () => {
    const log = 'ManagedIdentityV2\nAttestationService returned error 403';
    const stages = detectStages(log);
    const attest = stages.find(s => s.stage === 'attestation');
    expect(attest).toBeDefined();
    expect(attest.severity).toBe('error');
  });

  test('returns empty array when no patterns match', () => {
    const log = 'ManagedIdentityV2 flow started with no errors noted';
    const stages = detectStages(log);
    // No failure-specific stages expected
    expect(stages.every(s => s.matches.length > 0)).toBe(true);
  });

  test('returns empty array for empty log', () => {
    expect(detectStages('')).toHaveLength(0);
  });

  test('returns empty array for null', () => {
    expect(detectStages(null)).toHaveLength(0);
  });

  test('limits matched lines to at most 5 per stage', () => {
    const lines = Array.from({ length: 10 }, (_, i) => `SCHANNEL error line ${i}`).join('\n');
    const log = `ManagedIdentityV2\n${lines}`;
    const stages = detectStages(log);
    const schannel = stages.find(s => s.stage === 'mtls_schannel');
    expect(schannel).toBeDefined();
    expect(schannel.matches.length).toBeLessThanOrEqual(5);
  });

  test('deduplicates identical matched log lines', () => {
    const line = 'SCHANNEL error occurred';
    const log = `ManagedIdentityV2\n${line}\n${line}\n${line}`;
    const stages = detectStages(log);
    const schannel = stages.find(s => s.stage === 'mtls_schannel');
    expect(schannel).toBeDefined();
    expect(schannel.matches.filter(m => m === line)).toHaveLength(1);
  });

  test('matching is case-insensitive', () => {
    const log = 'managedidentityv2\nschannel failure happened';
    const stages = detectStages(log);
    // 'schannel' (lowercase) should still match
    const schannel = stages.find(s => s.stage === 'mtls_schannel');
    expect(schannel).toBeDefined();
  });

  test('detects multiple stages in a single log', () => {
    const log = 'ManagedIdentityV2\nSCHANNEL failure\nIMDS unreachable at 169.254.169.254';
    const stages = detectStages(log);
    const stageNames = stages.map(s => s.stage);
    expect(stageNames).toContain('mtls_schannel');
    expect(stageNames).toContain('imds');
  });
});

// ---------------------------------------------------------------------------
// formatComment
// ---------------------------------------------------------------------------
describe('formatComment', () => {
  test('returns null when isMiV2 is false', () => {
    expect(formatComment({ isMiV2: false, stages: [] })).toBeNull();
  });

  test('returns null for null input', () => {
    expect(formatComment(null)).toBeNull();
  });

  test('includes the bot marker comment for update detection', () => {
    const result = formatComment({ isMiV2: true, stages: [] });
    expect(result).toContain('<!-- msal-log-triage-bot -->');
  });

  test('includes a heading for MSI v2 triage', () => {
    const result = formatComment({ isMiV2: true, stages: [] });
    expect(result).toContain('MSI v2 Automated Log Triage');
  });

  test('shows no-failure message when stage list is empty', () => {
    const result = formatComment({ isMiV2: true, stages: [] });
    expect(result).toContain('No specific failure patterns detected');
  });

  test('formats an error-severity stage with red emoji', () => {
    const stages = [{
      stage: 'mtls_schannel',
      label: 'mTLS / SCHANNEL',
      description: 'TLS failure',
      severity: 'error',
      matches: ['SCHANNEL error line'],
    }];
    const result = formatComment({ isMiV2: true, stages });
    expect(result).toContain('🔴');
    expect(result).toContain('mTLS / SCHANNEL');
    expect(result).toContain('SCHANNEL error line');
  });

  test('formats a warning-severity stage with yellow emoji', () => {
    const stages = [{
      stage: 'cert_cache',
      label: 'Certificate Cache',
      description: 'Cert not found',
      severity: 'warning',
      matches: ['certificate not found'],
    }];
    const result = formatComment({ isMiV2: true, stages });
    expect(result).toContain('🟡');
  });

  test('formats an info-severity stage with blue emoji', () => {
    const stages = [{
      stage: 'token_cache',
      label: 'Token Cache',
      description: 'Cache hit/miss',
      severity: 'info',
      matches: ['CacheHit: token found'],
    }];
    const result = formatComment({ isMiV2: true, stages });
    expect(result).toContain('🔵');
  });

  test('wraps matched lines in a collapsible details block', () => {
    const stages = [{
      stage: 'imds',
      label: 'IMDS',
      description: 'IMDS unreachable',
      severity: 'error',
      matches: ['Connection refused'],
    }];
    const result = formatComment({ isMiV2: true, stages });
    expect(result).toContain('<details>');
    expect(result).toContain('</details>');
  });
});

// ---------------------------------------------------------------------------
// analyze (integration)
// ---------------------------------------------------------------------------
describe('analyze', () => {
  test('returns isMiV2=false for a non-MSI v2 issue body', () => {
    const body = loadSample('non-miv2.log');
    const result = analyze(body);
    expect(result.isMiV2).toBe(false);
    expect(result.stages).toHaveLength(0);
    expect(result.comment).toBeNull();
  });

  test('returns isMiV2=false for an empty issue body', () => {
    const result = analyze('');
    expect(result.isMiV2).toBe(false);
  });

  test('returns isMiV2=false for null input', () => {
    const result = analyze(null);
    expect(result.isMiV2).toBe(false);
  });

  test('detects mTLS/SCHANNEL failure in issue body containing the log sample', () => {
    const body = `We are seeing errors with Managed Identity.\n\n\`\`\`log\n${loadSample('issue-5755-mtls-schannel.log')}\n\`\`\``;
    const result = analyze(body);
    expect(result.isMiV2).toBe(true);
    const schannel = result.stages.find(s => s.stage === 'mtls_schannel');
    expect(schannel).toBeDefined();
  });

  test('detects IMDS failure and returns correct error label', () => {
    const body = `Issue with MI v2:\n\`\`\`log\n${loadSample('imds-failure.log')}\n\`\`\``;
    const result = analyze(body);
    expect(result.isMiV2).toBe(true);
    expect(result.labels).toContain('msi-v2:has-failure');
  });

  test('includes base triage label for any MSI v2 issue', () => {
    const body = `ManagedIdentityV2 issue - no specific errors`;
    const result = analyze(body);
    expect(result.isMiV2).toBe(true);
    expect(result.labels).toContain('msi-v2:triage-run');
  });

  test('does not include has-failure label when no error-severity stages detected', () => {
    const body = `${loadSample('cache-hit-miss.log')}`;
    const result = analyze(body);
    expect(result.isMiV2).toBe(true);
    expect(result.labels).not.toContain('msi-v2:has-failure');
  });

  test('redacts JWT tokens before analysis so they do not appear in the comment', () => {
    const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const body = `ManagedIdentityV2 acquired token=${jwt}`;
    const result = analyze(body);
    expect(result.isMiV2).toBe(true);
    expect(result.comment).not.toContain('eyJhbGciOiJSUzI1NiJ9');
  });

  test('returns a non-null comment for MSI v2 issues', () => {
    const body = loadSample('issue-5755-mtls-schannel.log');
    const result = analyze(body);
    expect(result.comment).not.toBeNull();
    expect(result.comment).toContain('<!-- msal-log-triage-bot -->');
  });

  test('extracts and analyses log content from a code fence in the issue body', () => {
    const fencedBody = `User reports token failure.\n\n\`\`\`log\n${loadSample('imds-failure.log')}\n\`\`\`\nPlease help.`;
    const result = analyze(fencedBody);
    expect(result.isMiV2).toBe(true);
    expect(result.stages.length).toBeGreaterThan(0);
  });
});
