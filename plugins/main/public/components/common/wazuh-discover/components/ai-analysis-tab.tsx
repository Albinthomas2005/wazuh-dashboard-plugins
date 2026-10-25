import React, { useRef, useState } from 'react';
import {
  EuiButton,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiSpacer,
  EuiTextArea,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { WzRequest } from '../../../../react-services/wz-request';

interface AIAnalysisTabProps {
  index: string;
  id: string;
}

interface ReportEvidence {
  index: string;
  id: string;
  alert: Record<string, unknown>;
}

const escapeMarkdownInline = (value: string) =>
  value
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/[\r\n]/g, ' ');

export function buildMarkdownReport(
  evidence: ReportEvidence,
  report: string,
  analystFindings: string,
) {
  const evidenceJson = JSON.stringify(evidence.alert, null, 2).replace(
    /`/g,
    '\\u0060',
  );
  return [
    '# Wazuh investigation report draft',
    '',
    '**Status:** AI-generated and unverified until reviewed by an analyst.',
    `**Selected record:** \`${escapeMarkdownInline(
      evidence.index,
    )}\` / \`${escapeMarkdownInline(evidence.id)}\``,
    '',
    '## Evidence summary (server-fetched, allowlisted, and privacy-filtered fields)',
    '```json',
    evidenceJson,
    '```',
    '',
    '## AI-generated report (unverified)',
    report.trim(),
    '',
    '## Analyst-verified findings',
    analystFindings.trim() || 'Not yet verified by an analyst.',
    '',
  ].join('\n');
}

const AI_ANALYSIS_ERROR =
  'AI analysis is unavailable. Check the backend connection and try again.';

export const AIAnalysisTab = ({ index, id }: AIAnalysisTabProps) => {
  const [analysis, setAnalysis] = useState<string>();
  const [isLoading, setIsLoading] = useState(false);
  const [hasError, setHasError] = useState(false);
  const requestInFlight = useRef(false);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [reportError, setReportError] = useState(false);
  const [analystNotes, setAnalystNotes] = useState('');
  const [report, setReport] = useState<string>();
  const [reportDraft, setReportDraft] = useState('');
  const [analystFindings, setAnalystFindings] = useState('');
  const [reportEvidence, setReportEvidence] = useState<ReportEvidence>();

  const analyzeAlert = async () => {
    if (requestInFlight.current) {
      return;
    }

    requestInFlight.current = true;
    setIsLoading(true);
    setHasError(false);
    setAnalysis(undefined);

    try {
      const response = await WzRequest.genericReq(
        'POST',
        '/api/ai/analyze-alert',
        { index, id },
        { shouldRetry: false, checkCurrentApiIsUp: false },
      );
      const result = response?.data;

      if (
        result?.ok !== true ||
        typeof result.analysis !== 'string' ||
        !result.analysis.trim()
      ) {
        throw new Error('Invalid AI analysis response');
      }

      setAnalysis(result.analysis);
    } catch {
      setHasError(true);
    } finally {
      requestInFlight.current = false;
      setIsLoading(false);
    }
  };

  const generateReport = async () => {
    if (isGeneratingReport || report !== undefined) {
      return;
    }

    setIsGeneratingReport(true);
    setReportError(false);

    try {
      const response = await WzRequest.genericReq(
        'POST',
        '/api/ai/generate-report',
        { index, id, analystNotes },
        { shouldRetry: false, checkCurrentApiIsUp: false },
      );
      const result = response?.data;
      const evidence = result?.evidence;

      if (
        result?.ok !== true ||
        result.status !== 'ai_generated_unverified' ||
        typeof result.report !== 'string' ||
        !result.report.trim() ||
        evidence?.index !== index ||
        evidence?.id !== id ||
        !evidence.alert ||
        typeof evidence.alert !== 'object' ||
        Array.isArray(evidence.alert)
      ) {
        throw new Error('Invalid report response');
      }

      setReportEvidence(evidence as ReportEvidence);
      setReport(result.report);
      setReportDraft(result.report);
    } catch {
      setReportError(true);
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const exportReport = () => {
    if (!reportEvidence || reportDraft === undefined) {
      return;
    }

    const markdown = buildMarkdownReport(
      reportEvidence,
      reportDraft,
      analystFindings,
    );
    const objectUrl = window.URL.createObjectURL(
      new Blob([markdown], { type: 'text/markdown;charset=utf-8' }),
    );
    const link = document.createElement('a');
    const safeId = id.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
    link.href = objectUrl;
    link.download = `wazuh-investigation-${safeId || 'report'}.md`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(objectUrl);
  };

  return (
    <EuiFlexGroup direction='column' alignItems='flexStart' gutterSize='m'>
      <EuiFlexItem grow={false}>
        <EuiText size='s'>
          Request an AI explanation of this selected security alert.
        </EuiText>
        <EuiSpacer size='m' />
        <EuiButton
          onClick={analyzeAlert}
          isLoading={isLoading}
          isDisabled={isLoading}
        >
          Analyze alert
        </EuiButton>
      </EuiFlexItem>

      {isLoading && (
        <EuiFlexItem grow={false}>
          <EuiText size='s'>Analyzing alert…</EuiText>
        </EuiFlexItem>
      )}

      {hasError && (
        <EuiFlexItem>
          <EuiCallOut
            color='danger'
            iconType='alert'
            title={AI_ANALYSIS_ERROR}
          />
        </EuiFlexItem>
      )}

      {analysis !== undefined && (
        <EuiFlexItem>
          <EuiPanel paddingSize='m'>
            <EuiTitle size='s'>
              <h3>Analysis</h3>
            </EuiTitle>
            <EuiSpacer size='s' />
            <EuiText size='s'>
              <pre style={{ whiteSpace: 'pre-wrap' }}>{analysis}</pre>
            </EuiText>
          </EuiPanel>
        </EuiFlexItem>
      )}

      <EuiFlexItem grow={false}>
        <EuiSpacer size='m' />
        <EuiTitle size='s'>
          <h3>Investigation report</h3>
        </EuiTitle>
        <EuiText size='s'>
          Generate an unverified draft from the selected Wazuh record. No
          related records are queried.
        </EuiText>
        <EuiSpacer size='s' />
        <EuiTextArea
          aria-label='Optional analyst context'
          placeholder='Optional analyst context. Avoid secrets and personal data.'
          value={analystNotes}
          onChange={event => setAnalystNotes(event.target.value)}
          maxLength={4000}
          disabled={report !== undefined || isGeneratingReport}
          fullWidth
        />
        <EuiSpacer size='s' />
        <EuiButton
          onClick={generateReport}
          isLoading={isGeneratingReport}
          isDisabled={isGeneratingReport || report !== undefined}
        >
          {report === undefined ? 'Generate Report' : 'Report generated'}
        </EuiButton>
        {reportError && (
          <EuiCallOut
            color='danger'
            iconType='alert'
            title='Report generation is unavailable. Try again later.'
          />
        )}
      </EuiFlexItem>

      {reportEvidence && report !== undefined && (
        <EuiFlexItem>
          <EuiCallOut
            color='warning'
            iconType='alert'
            title='AI-generated draft — unverified until reviewed by an analyst.'
          >
            <p>
              Edits remain in this view only. Export the reviewed Markdown to
              keep a copy; the report is not saved by the backend.
            </p>
          </EuiCallOut>
          <EuiSpacer size='m' />
          <EuiPanel paddingSize='m'>
            <EuiTitle size='s'>
              <h4>
                Sanitized evidence summary supplied for the selected record
              </h4>
            </EuiTitle>
            <EuiSpacer size='s' />
            <EuiText size='s'>
              <pre style={{ whiteSpace: 'pre-wrap' }}>
                {JSON.stringify(reportEvidence.alert, null, 2)}
              </pre>
            </EuiText>
          </EuiPanel>
          <EuiSpacer size='m' />
          <EuiTextArea
            aria-label='AI-generated report draft, unverified'
            value={reportDraft}
            onChange={event => setReportDraft(event.target.value)}
            fullWidth
            rows={18}
          />
          <EuiSpacer size='m' />
          <EuiTextArea
            aria-label='Analyst-verified findings'
            placeholder='Enter findings you have verified against the evidence.'
            value={analystFindings}
            onChange={event => setAnalystFindings(event.target.value)}
            fullWidth
            rows={6}
          />
          <EuiSpacer size='s' />
          <EuiButton onClick={exportReport}>
            Export reviewed report as Markdown
          </EuiButton>
        </EuiFlexItem>
      )}
    </EuiFlexGroup>
  );
};
