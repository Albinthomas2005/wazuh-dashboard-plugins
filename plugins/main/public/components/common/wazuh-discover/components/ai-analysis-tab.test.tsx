import React from 'react';
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import '@testing-library/jest-dom';
import { WzRequest } from '../../../../react-services/wz-request';
import { AIAnalysisTab, buildMarkdownReport } from './ai-analysis-tab';

jest.mock('../../../../react-services/wz-request', () => ({
  WzRequest: {
    genericReq: jest.fn(),
  },
}));

const alertReference = { index: 'wazuh-alerts-4.x-2026.10.24', id: 'test-id' };
const secondAlertReference = {
  index: 'wazuh-alerts-4.x-2026.10.24',
  id: 'second-test-id',
};
const reportResult = {
  ok: true,
  status: 'ai_generated_unverified',
  evidence: {
    ...alertReference,
    alert: {
      '@timestamp': '2026-10-24T10:00:00.000Z',
      rule: { id: '1001', description: 'Synthetic login failure' },
    },
  },
  report: [
    'AI-GENERATED DRAFT — UNVERIFIED',
    '## Observed evidence',
    'Synthetic login failure',
    '## AI assessment (unverified)',
    'Requires analyst review',
  ].join('\n'),
};

const renderKeyedAnalysisTab = ({ index, id }: typeof alertReference) => (
  <AIAnalysisTab key={`${index}:${id}`} index={index} id={id} />
);

describe('AIAnalysisTab', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('requests analysis through the Wazuh server and displays it as text', async () => {
    const analysis = '<script>not executable</script>\nObserved facts';
    (WzRequest.genericReq as jest.Mock).mockResolvedValue({
      data: { ok: true, analysis },
    });

    const { container } = render(<AIAnalysisTab {...alertReference} />);
    fireEvent.click(screen.getByRole('button', { name: 'Analyze alert' }));

    await waitFor(() => {
      expect(container.querySelector('pre')?.textContent).toBe(analysis);
    });
    expect(document.querySelector('script')).toBeNull();
    expect(WzRequest.genericReq).toHaveBeenCalledWith(
      'POST',
      '/api/ai/analyze-alert',
      alertReference,
      { shouldRetry: false, checkCurrentApiIsUp: false },
    );
  });

  it('shows a loading state and prevents duplicate requests', () => {
    let resolveRequest: (value: unknown) => void = () => undefined;
    (WzRequest.genericReq as jest.Mock).mockImplementation(
      () =>
        new Promise(resolve => {
          resolveRequest = resolve;
        }),
    );

    render(<AIAnalysisTab {...alertReference} />);
    const button = screen.getByRole('button', { name: 'Analyze alert' });
    fireEvent.click(button);
    fireEvent.click(button);

    expect(screen.getByText('Analyzing alert…')).toBeInTheDocument();
    expect(button).toBeDisabled();
    expect(WzRequest.genericReq).toHaveBeenCalledTimes(1);

    act(() => {
      resolveRequest({ data: { ok: true, analysis: 'Done' } });
    });
  });

  it('shows a safe error without exposing request details', async () => {
    (WzRequest.genericReq as jest.Mock).mockRejectedValue(
      new Error('private URL or token detail'),
    );

    render(<AIAnalysisTab {...alertReference} />);
    fireEvent.click(screen.getByRole('button', { name: 'Analyze alert' }));

    expect(
      await screen.findByText(
        'AI analysis is unavailable. Check the backend connection and try again.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/private URL or token detail/)).toBeNull();
  });

  it('clears the previous alert analysis when the selected alert changes', async () => {
    (WzRequest.genericReq as jest.Mock).mockResolvedValueOnce({
      data: { ok: true, analysis: 'Alert A analysis' },
    });

    const { rerender } = render(renderKeyedAnalysisTab(alertReference));
    fireEvent.click(screen.getByRole('button', { name: 'Analyze alert' }));
    expect(await screen.findByText('Alert A analysis')).toBeInTheDocument();

    rerender(renderKeyedAnalysisTab(secondAlertReference));

    expect(screen.queryByText('Alert A analysis')).toBeNull();
    expect(
      screen.queryByText(
        'AI analysis is unavailable. Check the backend connection and try again.',
      ),
    ).toBeNull();
  });

  it('clears the previous alert error when the selected alert changes', async () => {
    (WzRequest.genericReq as jest.Mock).mockRejectedValueOnce(
      new Error('synthetic request failure'),
    );

    const { rerender } = render(renderKeyedAnalysisTab(alertReference));
    fireEvent.click(screen.getByRole('button', { name: 'Analyze alert' }));
    expect(
      await screen.findByText(
        'AI analysis is unavailable. Check the backend connection and try again.',
      ),
    ).toBeInTheDocument();

    rerender(renderKeyedAnalysisTab(secondAlertReference));

    expect(
      screen.queryByText(
        'AI analysis is unavailable. Check the backend connection and try again.',
      ),
    ).toBeNull();
    expect(screen.queryByText('Alert A analysis')).toBeNull();
  });

  it('does not show an old in-flight response after switching alerts', async () => {
    let resolveAlertA: (value: unknown) => void = () => undefined;
    (WzRequest.genericReq as jest.Mock)
      .mockImplementationOnce(
        () =>
          new Promise(resolve => {
            resolveAlertA = resolve;
          }),
      )
      .mockResolvedValueOnce({
        data: { ok: true, analysis: 'Alert B analysis' },
      });

    const { rerender } = render(renderKeyedAnalysisTab(alertReference));
    fireEvent.click(screen.getByRole('button', { name: 'Analyze alert' }));
    expect(screen.getByText('Analyzing alert…')).toBeInTheDocument();

    rerender(renderKeyedAnalysisTab(secondAlertReference));
    expect(screen.queryByText('Analyzing alert…')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Analyze alert' }));
    expect(await screen.findByText('Alert B analysis')).toBeInTheDocument();

    await act(async () => {
      resolveAlertA({ data: { ok: true, analysis: 'Alert A late analysis' } });
      await Promise.resolve();
    });

    expect(screen.getByText('Alert B analysis')).toBeInTheDocument();
    expect(screen.queryByText('Alert A late analysis')).toBeNull();
  });

  it('generates an unverified report from the selected record reference', async () => {
    (WzRequest.genericReq as jest.Mock).mockResolvedValue({
      data: reportResult,
    });

    render(<AIAnalysisTab {...alertReference} />);
    fireEvent.click(screen.getByRole('button', { name: 'Generate Report' }));

    expect(
      await screen.findByText(
        'AI-generated draft — unverified until reviewed by an analyst.',
      ),
    ).toBeInTheDocument();
    expect(WzRequest.genericReq).toHaveBeenCalledWith(
      'POST',
      '/api/ai/generate-report',
      { ...alertReference, analystNotes: '' },
      { shouldRetry: false, checkCurrentApiIsUp: false },
    );
    expect(
      screen.getByRole('textbox', {
        name: 'AI-generated report draft, unverified',
      }),
    ).toHaveValue(reportResult.report);
  });

  it('preserves analyst edits while the same selected record rerenders', async () => {
    (WzRequest.genericReq as jest.Mock)
      .mockResolvedValueOnce({ data: reportResult })
      .mockResolvedValueOnce({
        data: { ok: true, analysis: 'Synthetic analysis' },
      });

    render(<AIAnalysisTab {...alertReference} />);
    fireEvent.click(screen.getByRole('button', { name: 'Generate Report' }));

    const draft = await screen.findByRole('textbox', {
      name: 'AI-generated report draft, unverified',
    });
    fireEvent.change(draft, { target: { value: 'Analyst-edited draft' } });
    fireEvent.change(
      screen.getByRole('textbox', { name: 'Analyst-verified findings' }),
      {
        target: { value: 'Synthetic finding verified by analyst' },
      },
    );
    fireEvent.click(screen.getByRole('button', { name: 'Analyze alert' }));

    expect(await screen.findByText('Synthetic analysis')).toBeInTheDocument();
    expect(draft).toHaveValue('Analyst-edited draft');
    expect(
      screen.getByRole('textbox', { name: 'Analyst-verified findings' }),
    ).toHaveValue('Synthetic finding verified by analyst');
  });

  it('exports evidence, the edited draft, and analyst findings as distinct sections', async () => {
    const markdown = buildMarkdownReport(
      reportResult.evidence,
      'Edited synthetic report',
      'Verified synthetic finding',
    );

    expect(markdown).toContain('AI-generated and unverified');
    expect(markdown).toContain(
      '## Evidence summary (server-fetched, allowlisted, and privacy-filtered fields)',
    );
    expect(markdown).toContain('"id": "1001"');
    expect(markdown).toContain('## AI-generated report (unverified)');
    expect(markdown).toContain('Edited synthetic report');
    expect(markdown).toContain('## Analyst-verified findings');
    expect(markdown).toContain('Verified synthetic finding');
    const escapedEvidence = buildMarkdownReport(
      {
        ...reportResult.evidence,
        id: 'synthetic-id\n# forged heading',
        alert: { ['full_log']: '```\n# forged heading' },
      },
      'Synthetic report',
      '',
    );
    expect(escapedEvidence).not.toContain('```\n# forged heading');
    expect(escapedEvidence).not.toContain('synthetic-id\n# forged heading');

    const createObjectURL = jest.fn(() => 'blob:synthetic-report');
    const revokeObjectURL = jest.fn();
    Object.defineProperty(window.URL, 'createObjectURL', {
      configurable: true,
      value: createObjectURL,
    });
    Object.defineProperty(window.URL, 'revokeObjectURL', {
      configurable: true,
      value: revokeObjectURL,
    });
    const click = jest
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);

    (WzRequest.genericReq as jest.Mock).mockResolvedValue({
      data: reportResult,
    });
    render(<AIAnalysisTab {...alertReference} />);
    fireEvent.click(screen.getByRole('button', { name: 'Generate Report' }));
    await screen.findByRole('textbox', {
      name: 'AI-generated report draft, unverified',
    });
    fireEvent.change(
      screen.getByRole('textbox', {
        name: 'AI-generated report draft, unverified',
      }),
      { target: { value: 'Edited synthetic report' } },
    );
    fireEvent.change(
      screen.getByRole('textbox', { name: 'Analyst-verified findings' }),
      {
        target: { value: 'Verified synthetic finding' },
      },
    );
    fireEvent.click(
      screen.getByRole('button', {
        name: 'Export reviewed report as Markdown',
      }),
    );

    expect(createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
    expect(click).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:synthetic-report');
    click.mockRestore();
  });
});
