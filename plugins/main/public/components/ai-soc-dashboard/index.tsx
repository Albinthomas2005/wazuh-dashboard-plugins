import React, { useState } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiCallOut,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiPage,
  EuiPageBody,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import { useHistory } from 'react-router-dom';
import { WzRequest } from '../../react-services/wz-request';

type CapabilityStatus = 'Available' | 'Planned';

const capabilities: {
  title: string;
  description: string;
  status: CapabilityStatus;
}[] = [
  {
    title: 'AI alert analysis',
    description:
      'Explain a selected Wazuh alert, summarize the evidence, and highlight investigation leads.',
    status: 'Available',
  },
  {
    title: 'AI investigation reports',
    description:
      'Generate an editable, unverified report draft from one selected alert record.',
    status: 'Available',
  },
  {
    title: 'Authentication investigation',
    description:
      'Correlate failed logins, suspicious source addresses, and unusual authentication patterns.',
    status: 'Planned',
  },
  {
    title: 'Threat hunting and correlation',
    description:
      'Connect related alerts into a timeline and map supported observations to MITRE ATT&CK.',
    status: 'Planned',
  },
  {
    title: 'File and malware investigation',
    description:
      'Help triage file-integrity changes, suspicious processes, and malware indicators.',
    status: 'Planned',
  },
  {
    title: 'Vulnerability and configuration review',
    description:
      'Prioritize detected vulnerabilities and configuration findings with analyst-facing explanations.',
    status: 'Planned',
  },
];

const AI_SOC_ERROR =
  'The AI service could not complete this request. Check the backend connection and try again.';

export const AISocDashboard: React.FC = () => {
  const history = useHistory();
  const [index, setIndex] = useState('');
  const [documentId, setDocumentId] = useState('');
  const [analystNotes, setAnalystNotes] = useState('');
  const [analysis, setAnalysis] = useState('');
  const [report, setReport] = useState('');
  const [error, setError] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);

  const hasRecordReference = Boolean(index.trim() && documentId.trim());
  const requestBody = {
    index: index.trim(),
    id: documentId.trim(),
  };

  const analyzeAlert = async () => {
    if (!hasRecordReference || isAnalyzing) {
      return;
    }

    setIsAnalyzing(true);
    setError('');
    setAnalysis('');
    try {
      const response = await WzRequest.genericReq(
        'POST',
        '/api/ai/analyze-alert',
        requestBody,
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
      setError(AI_SOC_ERROR);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const generateReport = async () => {
    if (!hasRecordReference || isGeneratingReport) {
      return;
    }

    setIsGeneratingReport(true);
    setError('');
    setReport('');
    try {
      const response = await WzRequest.genericReq(
        'POST',
        '/api/ai/generate-report',
        { ...requestBody, analystNotes: analystNotes.slice(0, 4000) },
        { shouldRetry: false, checkCurrentApiIsUp: false },
      );
      const result = response?.data;
      if (
        result?.ok !== true ||
        result.status !== 'ai_generated_unverified' ||
        typeof result.report !== 'string' ||
        !result.report.trim() ||
        result.evidence?.index !== requestBody.index ||
        result.evidence?.id !== requestBody.id
      ) {
        throw new Error('Invalid AI report response');
      }
      setReport(result.report);
    } catch {
      setError(AI_SOC_ERROR);
    } finally {
      setIsGeneratingReport(false);
    }
  };

  return (
    <EuiPage paddingSize='l'>
      <EuiPageBody>
        <EuiFlexGroup direction='column' gutterSize='l'>
          <EuiFlexItem>
            <EuiFlexGroup justifyContent='spaceBetween' alignItems='center'>
              <EuiFlexItem>
                <EuiTitle size='l'>
                  <h1>AI SOC Dashboard</h1>
                </EuiTitle>
                <EuiSpacer size='s' />
                <EuiText color='subdued'>
                  AI-assisted alert triage and investigation workflows for your
                  Wazuh security data.
                </EuiText>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButton
                  iconType='search'
                  onClick={() =>
                    history.push('/overview/?tab=general&tabView=dashboard')
                  }
                >
                  Open Threat Hunting
                </EuiButton>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiFlexItem>

          <EuiFlexItem>
            <EuiPanel paddingSize='l'>
              <EuiTitle size='m'>
                <h2>Start an AI investigation</h2>
              </EuiTitle>
              <EuiSpacer size='s' />
              <EuiText size='s' color='subdued'>
                Enter the index and document ID of a Wazuh alert. You can find
                these by opening an alert in Threat Hunting. The original alert
                is not modified.
              </EuiText>
              <EuiSpacer size='m' />
              <EuiFlexGroup>
                <EuiFlexItem>
                  <EuiFormRow label='Alert index' helpText='Example: wazuh-alerts-4.x-*'>
                    <EuiFieldText
                      value={index}
                      onChange={event => {
                        setIndex(event.target.value);
                        setAnalysis('');
                        setReport('');
                      }}
                      placeholder='Enter the exact alert index'
                      aria-label='Alert index'
                      fullWidth
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiFormRow label='Document ID' helpText='ID of the selected alert record'>
                    <EuiFieldText
                      value={documentId}
                      onChange={event => {
                        setDocumentId(event.target.value);
                        setAnalysis('');
                        setReport('');
                      }}
                      placeholder='Enter the alert document ID'
                      aria-label='Document ID'
                      fullWidth
                    />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
              <EuiFormRow
                label='Optional analyst context'
                helpText='Do not include passwords, API keys, or unnecessary personal data.'
              >
                <EuiTextArea
                  value={analystNotes}
                  onChange={event => setAnalystNotes(event.target.value)}
                  maxLength={4000}
                  rows={3}
                  placeholder='What have you observed so far? (optional)'
                  aria-label='Optional analyst context'
                  fullWidth
                />
              </EuiFormRow>
              <EuiSpacer size='m' />
              <EuiFlexGroup wrap>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    fill
                    iconType='sparkles'
                    onClick={analyzeAlert}
                    isLoading={isAnalyzing}
                    isDisabled={!hasRecordReference || isAnalyzing}
                  >
                    Analyze alert
                  </EuiButton>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton
                    iconType='document'
                    onClick={generateReport}
                    isLoading={isGeneratingReport}
                    isDisabled={!hasRecordReference || isGeneratingReport}
                  >
                    Generate report
                  </EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>
              {error && (
                <>
                  <EuiSpacer size='m' />
                  <EuiCallOut color='danger' iconType='alert' title={error} />
                </>
              )}
              {analysis && (
                <>
                  <EuiSpacer size='l' />
                  <EuiPanel color='subdued' paddingSize='m'>
                    <EuiTitle size='s'>
                      <h3>AI alert analysis</h3>
                    </EuiTitle>
                    <EuiSpacer size='s' />
                    <EuiText>
                      <pre style={{ whiteSpace: 'pre-wrap' }}>{analysis}</pre>
                    </EuiText>
                  </EuiPanel>
                </>
              )}
              {report && (
                <>
                  <EuiSpacer size='l' />
                  <EuiCallOut
                    color='warning'
                    iconType='alert'
                    title='AI-generated draft — unverified until reviewed by an analyst.'
                  />
                  <EuiSpacer size='s' />
                  <EuiTitle size='s'>
                    <h3>Investigation report draft</h3>
                  </EuiTitle>
                  <EuiTextArea
                    aria-label='AI-generated report draft, unverified'
                    value={report}
                    onChange={event => setReport(event.target.value)}
                    rows={18}
                    fullWidth
                  />
                </>
              )}
            </EuiPanel>
          </EuiFlexItem>

          <EuiFlexItem>
            <EuiTitle size='m'>
              <h2>AI capabilities</h2>
            </EuiTitle>
            <EuiSpacer size='s' />
            <EuiFlexGroup wrap>
              {capabilities.map(capability => (
                <EuiFlexItem key={capability.title} basis='30%'>
                  <EuiPanel paddingSize='m' hasBorder>
                    <EuiFlexGroup
                      alignItems='center'
                      justifyContent='spaceBetween'
                      gutterSize='s'
                    >
                      <EuiFlexItem>
                        <EuiTitle size='s'>
                          <h3>{capability.title}</h3>
                        </EuiTitle>
                      </EuiFlexItem>
                      <EuiFlexItem grow={false}>
                        <EuiBadge
                          color={
                            capability.status === 'Available'
                              ? 'success'
                              : 'hollow'
                          }
                        >
                          {capability.status}
                        </EuiBadge>
                      </EuiFlexItem>
                    </EuiFlexGroup>
                    <EuiSpacer size='s' />
                    <EuiText size='s'>{capability.description}</EuiText>
                  </EuiPanel>
                </EuiFlexItem>
              ))}
            </EuiFlexGroup>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiCallOut
              color='primary'
              iconType='info'
              title='Analyst review is required'
            >
              AI output is advisory. Validate every finding against the original
              Wazuh evidence before taking action. Generated reports are drafts,
              not verified incident conclusions.
            </EuiCallOut>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiPageBody>
    </EuiPage>
  );
};
