import axios from 'axios';
import { WazuhAiCtrl } from '../controllers/wazuh-ai';
import { WAZUH_FINDINGS_PATTERN } from '../../common/constants';

/* eslint-disable @typescript-eslint/no-explicit-any, camelcase */
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;
const controller = new WazuhAiCtrl();
const findingIndex = `${WAZUH_FINDINGS_PATTERN.replace('*', '')}-2026.10.24`;
const dataStreamFindingIndex = `.ds-${findingIndex}-000001`;
const findingId = 'synthetic-finding-id';
const source = {
  '@timestamp': '2026-10-24T10:00:00.000Z',
  wazuh: {
    agent: { id: '007', name: 'private-hostname', ip: '192.0.2.20' },
    rule: {
      id: '1001',
      level: 8,
      title: 'Synthetic authentication failure',
      private_context: 'private-rule-detail',
      mitre: {
        tactic: { id: ['TA0006'], name: ['Credential Access'] },
        technique: { id: ['T1110'], name: ['Brute Force'] },
        subtechnique: { id: ['T1110.001'], name: ['Password Guessing'] },
      },
    },
    integration: { category: 'authentication', name: 'synthetic-source' },
  },
  user: { name: 'private-user' },
  credentials: { password: 'synthetic-secret' },
  arbitrary: 'private-alert-detail',
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
    body: { index: findingIndex, id: findingId, ...body },
  } as any);

describe('POST /api/ai/analyze-alert controller authorization and privacy', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.SOC_AI_INTERNAL_TOKEN = 'synthetic-internal-token';
    mockedAxios.post.mockResolvedValue({
      status: 200,
      data: { ok: true, analysis: 'Synthetic analysis result' },
    } as any);
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
      index: findingIndex,
      body: {
        size: 1,
        // OpenSearch uses this API field name.
        // eslint-disable-next-line camelcase
        track_total_hits: false,
        query: { ids: { values: [findingId] } },
        _source: expect.arrayContaining([
          '@timestamp',
          'wazuh.agent.id',
          'wazuh.rule.id',
          'wazuh.rule.title',
          'wazuh.integration.category',
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

  it('allows a findings data-stream backing index', async () => {
    const context = createContext('soc-analyst');
    const response = createResponse();

    const result = await controller.analyzeAlert(
      context,
      createRequest('soc-analyst', { index: dataStreamFindingIndex }),
      response as any,
    );

    expect(result.statusCode).toBe(200);
    expect(context.search).toHaveBeenCalledWith(
      expect.objectContaining({ index: dataStreamFindingIndex }),
    );
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
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });

  it(
    'denies a user whose OpenSearch search is forbidden without calling the AI service',
    async () => {
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
      expect(mockedAxios.post).not.toHaveBeenCalled();
    },
  );

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
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });

  it('forwards only allowlisted fields and ignores client-supplied alert content', async () => {
    const context = createContext();
    const response = createResponse();
    const request = createRequest('analyst', {
      alert: { full_log: 'client-injected-sensitive-content' },
    });

    await controller.analyzeAlert(context, request, response as any);

    const forwardedAlert = mockedAxios.post.mock.calls[0][1].alert;
    expect(forwardedAlert).toEqual({
      '@timestamp': source['@timestamp'],
      wazuh: {
        agent: { id: source.wazuh.agent.id },
        rule: {
          id: source.wazuh.rule.id,
          level: source.wazuh.rule.level,
          title: source.wazuh.rule.title,
          mitre: source.wazuh.rule.mitre,
        },
        integration: source.wazuh.integration,
      },
    });
    const forwardedJson = JSON.stringify(forwardedAlert);
    [
      'private-hostname',
      '192.0.2.20',
      'private-user',
      'synthetic-secret',
      'private-alert-detail',
      'private-rule-detail',
      'private raw log content',
      'private@example.invalid',
      'client-injected-sensitive-content',
    ].forEach(value => expect(forwardedJson).not.toContain(value));
  });

  it.each([
    'other-index-2026.10.24',
    'wazuh-alerts-4.x-2026.10.24',
    'wazuh-findings-v5',
    'wazuh-findings-v5-',
    'wazuh-findings-v5security',
    'wazuh-findings-v5-security/',
    '.ds-wazuh-findings-v5',
    '.ds-wazuh-findings-v5-',
    '.ds-wazuh-findings-v5-security/',
  ])('rejects a non-findings index: %s', async index => {
    const context = createContext();
    const response = createResponse();

    const result = await controller.analyzeAlert(
      context,
      createRequest('analyst', { index }),
      response as any,
    );

    expect(result.statusCode).toBe(400);
    expect(context.search).not.toHaveBeenCalled();
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });
});
