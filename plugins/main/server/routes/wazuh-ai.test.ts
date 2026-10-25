import { WazuhAiCtrl } from '../controllers/wazuh-ai';

/* eslint-disable @typescript-eslint/no-explicit-any, camelcase */
jest.mock('needle', () => jest.fn());

// Needle has no TypeScript declaration in this plugin.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const needle = require('needle') as jest.Mock;
const controller = new WazuhAiCtrl();
const alertIndex = 'wazuh-alerts-4.x-2026.10.24';
const alertId = 'synthetic-alert-id';
const source = {
  '@timestamp': '2026-10-24T10:00:00.000Z',
  timestamp: '2026-10-24T10:00:00.000Z',
  rule: {
    id: '1001',
    level: 8,
    description: 'Synthetic authentication failure',
    groups: ['authentication_failed'],
    mitre: { id: ['T1110'], tactic: ['Credential Access'] },
  },
  decoder: { name: 'sshd' },
  agent: { id: '007', name: 'private-hostname', ip: '192.0.2.20' },
  data: {
    srcip: '198.51.100.42',
    dstport: '22',
    authentication_result: 'failed',
    dstuser: 'private-user',
    password: 'synthetic-secret',
    arbitrary: 'private-alert-detail',
  },
  full_log: 'private raw log content',
  email: 'private@example.invalid',
};

const originalInternalToken = process.env.SOC_AI_INTERNAL_TOKEN;

const createContext = (username = 'analyst') => {
  const search = jest.fn().mockResolvedValue({
    body: { hits: { hits: [{ _source: source }] } },
  });
  return {
    wazuh: {
      security: {
        getCurrentUser: jest.fn().mockResolvedValue({ username }),
      },
    },
    wazuh_core: {
      configuration: {
        getSettingValue: jest.fn().mockResolvedValue('wazuh-alerts-*'),
      },
    },
    core: { opensearch: { client: { asCurrentUser: { search } } } },
    search,
  } as any;
};

const createResponse = () => ({
  ok: jest.fn(value => ({ statusCode: 200, ...value })),
  custom: jest.fn(value => value),
});

const createRequest = (username = 'analyst', body = {}) =>
  ({
    headers: { 'x-test-username': username },
    body: { index: alertIndex, id: alertId, ...body },
  } as any);

describe('POST /api/ai/analyze-alert controller authorization and privacy', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.SOC_AI_INTERNAL_TOKEN = 'synthetic-internal-token';
    needle.mockResolvedValue({
      statusCode: 200,
      body: { ok: true, analysis: 'Synthetic analysis result' },
    });
  });

  afterAll(() => {
    if (originalInternalToken === undefined) {
      delete process.env.SOC_AI_INTERNAL_TOKEN;
    } else {
      process.env.SOC_AI_INTERNAL_TOKEN = originalInternalToken;
    }
  });

  it('allows an analyst whose current OpenSearch user can search the alert', async () => {
    const context = createContext('soc-analyst');
    const response = createResponse();

    const result = await controller.analyzeAlert(
      context,
      createRequest('soc-analyst'),
      response as any,
    );

    expect(result).toEqual({
      statusCode: 200,
      body: { ok: true, analysis: 'Synthetic analysis result' },
    });
    expect(context.search).toHaveBeenCalledWith({
      index: alertIndex,
      body: {
        size: 1,
        // OpenSearch uses this API field name.
        // eslint-disable-next-line camelcase
        track_total_hits: false,
        query: { ids: { values: [alertId] } },
        _source: expect.arrayContaining([
          '@timestamp',
          'rule.id',
          'agent.id',
          'data.srcip',
        ]),
      },
    });
  });

  it('allows an administrator through the same current-user OpenSearch check', async () => {
    const context = createContext('admin');
    const response = createResponse();

    const result = await controller.analyzeAlert(
      context,
      createRequest('admin'),
      response as any,
    );

    expect(result.statusCode).toBe(200);
    expect(context.search).toHaveBeenCalledTimes(1);
  });

  it('rejects a request without an authenticated Wazuh user', async () => {
    const context = createContext();
    context.wazuh.security.getCurrentUser.mockResolvedValue(null);
    const response = createResponse();

    const result = await controller.analyzeAlert(
      context,
      createRequest(),
      response as any,
    );

    expect(result.statusCode).toBe(401);
    expect(context.search).not.toHaveBeenCalled();
    expect(needle).not.toHaveBeenCalled();
  });

  it('denies a forbidden OpenSearch search without calling the AI service', async () => {
    const context = createContext('restricted-user');
    context.search.mockRejectedValue({ meta: { statusCode: 403 } });
    const response = createResponse();

    const result = await controller.analyzeAlert(
      context,
      createRequest('restricted-user'),
      response as any,
    );

    expect(result).toEqual({
      statusCode: 403,
      body: { ok: false, error: 'Access to this alert is denied' },
    });
    expect(needle).not.toHaveBeenCalled();
  });

  it('does not disclose alerts hidden by document-level security', async () => {
    const context = createContext('scoped-analyst');
    context.search.mockResolvedValue({ body: { hits: { hits: [] } } });
    const response = createResponse();

    const result = await controller.analyzeAlert(
      context,
      createRequest('scoped-analyst'),
      response as any,
    );

    expect(result).toEqual({
      statusCode: 404,
      body: { ok: false, error: 'Alert is unavailable' },
    });
    expect(needle).not.toHaveBeenCalled();
  });

  it('forwards only allowlisted fields and ignores client-supplied alert content', async () => {
    const context = createContext();
    const response = createResponse();
    const request = createRequest('analyst', {
      alert: { full_log: 'client-injected-sensitive-content' },
    });

    await controller.analyzeAlert(context, request, response as any);

    const forwardedAlert = needle.mock.calls[0][2].alert;
    expect(forwardedAlert).toEqual({
      '@timestamp': source['@timestamp'],
      timestamp: source.timestamp,
      rule: source.rule,
      decoder: source.decoder,
      agent: { id: source.agent.id },
      data: {
        srcip: source.data.srcip,
        dstport: source.data.dstport,
        authentication_result: source.data.authentication_result,
      },
    });
    const forwardedJson = JSON.stringify(forwardedAlert);
    [
      'private-hostname',
      '192.0.2.20',
      'private-user',
      'synthetic-secret',
      'private-alert-detail',
      'private raw log content',
      'private@example.invalid',
      'client-injected-sensitive-content',
    ].forEach(value => expect(forwardedJson).not.toContain(value));
  });

  it('rejects an index outside the configured Wazuh alert pattern', async () => {
    const context = createContext();
    const response = createResponse();

    const result = await controller.analyzeAlert(
      context,
      createRequest('analyst', { index: 'other-index-2026.10.24' }),
      response as any,
    );

    expect(result.statusCode).toBe(400);
    expect(context.search).not.toHaveBeenCalled();
    expect(needle).not.toHaveBeenCalled();
  });

  it('generates a report from the current user selected record', async () => {
    const context = createContext('soc-analyst');
    const response = createResponse();
    needle.mockResolvedValue({
      statusCode: 200,
      body: {
        ok: true,
        status: 'ai_generated_unverified',
        evidence: {
          index: alertIndex,
          id: alertId,
          alert: { rule: source.rule },
        },
        report: 'AI-GENERATED DRAFT — UNVERIFIED',
      },
    });

    const result = await controller.generateReport(
      context,
      createRequest('soc-analyst', {
        analystNotes: 'Synthetic investigation context',
        alert: { full_log: 'client supplied content is ignored' },
      }),
      response as any,
    );

    expect(result).toEqual({
      statusCode: 200,
      body: {
        ok: true,
        status: 'ai_generated_unverified',
        evidence: {
          index: alertIndex,
          id: alertId,
          alert: { rule: source.rule },
        },
        report: 'AI-GENERATED DRAFT — UNVERIFIED',
      },
    });
    expect(context.search).toHaveBeenCalledWith(
      expect.objectContaining({
        index: alertIndex,
        body: expect.objectContaining({
          query: { ids: { values: [alertId] } },
        }),
      }),
    );
    expect(needle).toHaveBeenCalledWith(
      'post',
      'http://127.0.0.1:5000/api/ai/generate-report',
      {
        evidence: {
          index: alertIndex,
          id: alertId,
          alert: {
            '@timestamp': source['@timestamp'],
            timestamp: source.timestamp,
            rule: source.rule,
            decoder: source.decoder,
            agent: { id: source.agent.id },
            data: {
              srcip: source.data.srcip,
              dstport: source.data.dstport,
              authentication_result: source.data.authentication_result,
            },
          },
        },
        analyst_notes: 'Synthetic investigation context',
      },
      expect.objectContaining({ json: true }),
    );
  });

  it('rejects report requests from unauthenticated users', async () => {
    const context = createContext();
    context.wazuh.security.getCurrentUser.mockResolvedValue(null);
    const result = await controller.generateReport(
      context,
      createRequest(),
      createResponse() as any,
    );

    expect(result).toEqual({
      statusCode: 401,
      body: { ok: false, error: 'Authentication required' },
    });
    expect(context.search).not.toHaveBeenCalled();
    expect(needle).not.toHaveBeenCalled();
  });

  it('rejects an index outside the configured alert pattern for report generation', async () => {
    const context = createContext();
    const result = await controller.generateReport(
      context,
      createRequest('analyst', { index: 'other-index' }),
      createResponse() as any,
    );

    expect(result.statusCode).toBe(400);
    expect(context.search).not.toHaveBeenCalled();
    expect(needle).not.toHaveBeenCalled();
  });

  it('rejects a missing selected document ID without searching OpenSearch', async () => {
    const context = createContext();
    const result = await controller.generateReport(
      context,
      createRequest('analyst', { id: '' }),
      createResponse() as any,
    );

    expect(result).toEqual({
      statusCode: 400,
      body: { ok: false, error: 'A valid alert reference is required' },
    });
    expect(context.search).not.toHaveBeenCalled();
    expect(needle).not.toHaveBeenCalled();
  });

  it('returns a safe not-found response for missing selected documents', async () => {
    const context = createContext();
    context.search.mockResolvedValue({ body: { hits: { hits: [] } } });
    const result = await controller.generateReport(
      context,
      createRequest(),
      createResponse() as any,
    );

    expect(result).toEqual({
      statusCode: 404,
      body: { ok: false, error: 'Alert is unavailable' },
    });
    expect(needle).not.toHaveBeenCalled();
  });

  it('returns a safe denied response when OpenSearch forbids the search', async () => {
    const context = createContext();
    context.search.mockRejectedValue({ meta: { statusCode: 403 } });
    const result = await controller.generateReport(
      context,
      createRequest(),
      createResponse() as any,
    );

    expect(result).toEqual({
      statusCode: 403,
      body: { ok: false, error: 'Access to this alert is denied' },
    });
    expect(needle).not.toHaveBeenCalled();
  });

  it('rejects oversized records and notes before backend submission', async () => {
    const largeContext = createContext();
    largeContext.search.mockResolvedValue({
      body: {
        hits: {
          hits: [
            {
              _source: {
                ...source,
                rule: { ...source.rule, description: 'x'.repeat(300 * 1024) },
              },
            },
          ],
        },
      },
    });
    const largeResult = await controller.generateReport(
      largeContext,
      createRequest(),
      createResponse() as any,
    );
    expect(largeResult).toEqual({
      statusCode: 413,
      body: { ok: false, error: 'Alert payload is too large' },
    });
    expect(needle).not.toHaveBeenCalled();

    const notesContext = createContext();
    const notesResult = await controller.generateReport(
      notesContext,
      createRequest('analyst', { analystNotes: 'x'.repeat(4001) }),
      createResponse() as any,
    );
    expect(notesResult).toEqual({
      statusCode: 400,
      body: { ok: false, error: 'Analyst notes are invalid or too long' },
    });
    expect(notesContext.search).not.toHaveBeenCalled();
    expect(needle).not.toHaveBeenCalled();
  });

  it('does not expose backend failures or details to the browser', async () => {
    const context = createContext();
    needle.mockResolvedValue({
      statusCode: 503,
      body: { ok: false, error: 'private backend detail' },
    });
    const result = await controller.generateReport(
      context,
      createRequest(),
      createResponse() as any,
    );

    expect(result).toEqual({
      statusCode: 503,
      body: {
        ok: false,
        error: 'AI report generation is temporarily unavailable',
      },
    });
  });
});
