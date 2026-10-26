import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { WzRequest } from '../../react-services/wz-request';
import { AISocDashboard } from './index';

jest.mock('../../react-services/wz-request', () => ({
  WzRequest: {
    genericReq: jest.fn(),
  },
}));

jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useHistory: () => ({ push: jest.fn() }),
}));

describe('AISocDashboard', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  const enterAlertReference = () => {
    fireEvent.change(screen.getByRole('textbox', { name: 'Alert index' }), {
      target: { value: 'wazuh-alerts-4.x-2026.10.26' },
    });
    fireEvent.change(screen.getByRole('textbox', { name: 'Document ID' }), {
      target: { value: 'synthetic-alert-id' },
    });
  };

  it('requires an alert index and document ID before analysis', () => {
    render(<AISocDashboard />);

    expect(
      screen.getByRole('button', { name: 'Analyze alert' }),
    ).toBeDisabled();
    expect(
      screen.getByRole('button', { name: 'Generate report' }),
    ).toBeDisabled();
  });

  it('sends the selected record reference to the AI analysis endpoint', async () => {
    (WzRequest.genericReq as jest.Mock).mockResolvedValue({
      data: { ok: true, analysis: 'Synthetic alert analysis' },
    });

    render(<AISocDashboard />);
    enterAlertReference();
    fireEvent.click(screen.getByRole('button', { name: 'Analyze alert' }));

    expect(await screen.findByText('Synthetic alert analysis')).toBeInTheDocument();
    expect(WzRequest.genericReq).toHaveBeenCalledWith(
      'POST',
      '/api/ai/analyze-alert',
      {
        index: 'wazuh-alerts-4.x-2026.10.26',
        id: 'synthetic-alert-id',
      },
      { shouldRetry: false, checkCurrentApiIsUp: false },
    );
  });

  it('labels generated reports as unverified and allows editing the draft', async () => {
    (WzRequest.genericReq as jest.Mock).mockResolvedValue({
      data: {
        ok: true,
        status: 'ai_generated_unverified',
        evidence: {
          index: 'wazuh-alerts-4.x-2026.10.26',
          id: 'synthetic-alert-id',
        },
        report: 'Synthetic report draft',
      },
    });

    render(<AISocDashboard />);
    enterAlertReference();
    fireEvent.click(screen.getByRole('button', { name: 'Generate report' }));

    expect(
      await screen.findByText(
        'AI-generated draft — unverified until reviewed by an analyst.',
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('textbox', {
        name: 'AI-generated report draft, unverified',
      }),
    ).toHaveValue('Synthetic report draft');
  });

  it('shows a generic error instead of backend error details', async () => {
    (WzRequest.genericReq as jest.Mock).mockRejectedValue(
      new Error('private token or server detail'),
    );

    render(<AISocDashboard />);
    enterAlertReference();
    fireEvent.click(screen.getByRole('button', { name: 'Analyze alert' }));

    expect(
      await screen.findByText(
        'The AI service could not complete this request. Check the backend connection and try again.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/private token or server detail/)).toBeNull();
  });
});
