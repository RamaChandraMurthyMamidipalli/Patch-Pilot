import React, { useState } from 'react';
import {
  ShieldAlert,
  Flame,
  FileCheck2,
  BookOpen,
  Wrench,
  CheckCircle,
  XCircle,
  Copy,
  Check,
  ChevronRight,
  Sparkles,
  ExternalLink,
  Info
} from 'lucide-react';
import { Finding, TriageStatus, PatchResult } from '../../types';

interface FindingInspectorProps {
  finding: Finding;
  onTriageChange: (newStatus: TriageStatus) => void;
  onGeneratePatch: () => void;
  isGeneratingPatch: boolean;
}

export const FindingInspector: React.FC<FindingInspectorProps> = ({
  finding,
  onTriageChange,
  onGeneratePatch,
  isGeneratingPatch,
}) => {
  const [activeTab, setActiveTab] = useState<'attribution' | 'rag' | 'patch'>('attribution');
  const [copied, setCopied] = useState(false);

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      default: return 'badge-low';
    }
  };

  const handleCopyDiff = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const patch = finding.suggestedPatch;

  return (
    <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Finding Banner Header */}
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        gap: '16px',
        borderBottom: '1px solid var(--border-subtle)',
        paddingBottom: '18px',
      }}>
        <div style={{ maxWidth: '750px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px', flexWrap: 'wrap' }}>
            <span className={`badge ${getSeverityBadgeClass(finding.severity)}`}>
              {finding.severity}
            </span>
            <span className="badge" style={{ background: 'rgba(139, 92, 246, 0.15)', color: '#c084fc', border: '1px solid rgba(139, 92, 246, 0.3)' }}>
              {finding.cweId}
            </span>
            <span className="badge" style={{ background: 'rgba(255, 255, 255, 0.05)', color: 'var(--text-secondary)' }}>
              Rule: {finding.ruleId}
            </span>
            <span className="badge" style={{ background: 'rgba(6, 182, 212, 0.1)', color: '#38bdf8' }}>
              Line {finding.lineNumber}
            </span>
          </div>
          <h2 style={{ fontSize: '1.24rem', fontWeight: 700, color: '#f8fafc', lineHeight: '1.3' }}>
            {finding.title}
          </h2>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
            {finding.description}
          </p>
        </div>

        {/* Triage & Calibrated Risk Meter */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '10px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: 'rgba(239, 68, 68, 0.1)',
            padding: '6px 14px',
            borderRadius: 'var(--radius-md)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
          }}>
            <Flame size={16} color="#f87171" />
            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>Calibrated Risk:</span>
            <span style={{ fontSize: '0.94rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#f87171' }}>
              {(finding.confidence * 100).toFixed(0)}%
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Triage:</span>
            <select
              value={finding.triageStatus}
              onChange={(e) => onTriageChange(e.target.value as TriageStatus)}
              style={{
                background: 'var(--bg-tertiary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-muted)',
                borderRadius: 'var(--radius-sm)',
                padding: '4px 8px',
                fontSize: '0.78rem',
                outline: 'none',
              }}
            >
              <option value="open">Open (Unreviewed)</option>
              <option value="confirmed">Confirmed Risk</option>
              <option value="mitigated">Mitigated</option>
              <option value="false_positive">False Positive</option>
            </select>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-subtle)' }}>
        <button
          type="button"
          onClick={() => setActiveTab('attribution')}
          style={{
            padding: '10px 18px',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'attribution' ? '2px solid var(--cyan-primary)' : '2px solid transparent',
            color: activeTab === 'attribution' ? 'var(--cyan-primary)' : 'var(--text-muted)',
            fontWeight: 600,
            fontSize: '0.86rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            transition: 'all 0.2s ease',
          }}
        >
          <Flame size={16} />
          Line Attribution (Integrated Gradients)
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('rag')}
          style={{
            padding: '10px 18px',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'rag' ? '2px solid var(--cyan-primary)' : '2px solid transparent',
            color: activeTab === 'rag' ? 'var(--cyan-primary)' : 'var(--text-muted)',
            fontWeight: 600,
            fontSize: '0.86rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            transition: 'all 0.2s ease',
          }}
        >
          <BookOpen size={16} />
          Grounded Explanation (Hybrid RAG)
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('patch')}
          style={{
            padding: '10px 18px',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'patch' ? '2px solid var(--emerald-success)' : '2px solid transparent',
            color: activeTab === 'patch' ? 'var(--emerald-success)' : 'var(--text-muted)',
            fontWeight: 600,
            fontSize: '0.86rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            transition: 'all 0.2s ease',
          }}
        >
          <Wrench size={16} />
          Verified Remediation Studio
          {patch?.verified && (
            <span className="badge badge-verified" style={{ fontSize: '0.62rem', padding: '1px 6px' }}>
              PASS
            </span>
          )}
        </button>
      </div>

      {/* Tab 1: Line Attribution Heatmap */}
      {activeTab === 'attribution' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'rgba(255, 255, 255, 0.02)',
            padding: '8px 14px',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
            fontSize: '0.78rem',
            color: 'var(--text-secondary)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Info size={14} color="var(--cyan-primary)" />
              <span>Token saliency computed via Captum Integrated Gradients across UniXcoder layers.</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <span style={{ width: '10px', height: '10px', background: '#ef4444', borderRadius: '2px' }}></span>
                Critical (≥70%)
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <span style={{ width: '10px', height: '10px', background: '#f59e0b', borderRadius: '2px' }}></span>
                Moderate (30-69%)
              </span>
            </div>
          </div>

          {/* Code Viewer with Heatmap Bars */}
          <div style={{
            background: '#04060a',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--border-subtle)',
            overflow: 'hidden',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.84rem',
          }}>
            {finding.attributions.map((attr) => {
              const isHot = attr.attributionScore >= 0.7;
              const isWarm = attr.attributionScore >= 0.3 && attr.attributionScore < 0.7;
              const pct = (attr.attributionScore * 100).toFixed(0);

              return (
                <div
                  key={attr.lineNumber}
                  className={isHot ? 'attribution-hot' : isWarm ? 'attribution-warm' : ''}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '50px 70px 1fr',
                    alignItems: 'center',
                    padding: '3px 0',
                    borderBottom: '1px solid rgba(255,255,255,0.02)',
                  }}
                >
                  {/* Line Number */}
                  <span style={{ textAlign: 'right', paddingRight: '12px', color: 'var(--text-dim)', userSelect: 'none' }}>
                    {attr.lineNumber}
                  </span>

                  {/* Saliency Meter */}
                  <div style={{ padding: '0 8px' }}>
                    {attr.attributionScore > 0.05 ? (
                      <span style={{
                        fontSize: '0.68rem',
                        fontWeight: 700,
                        padding: '1px 5px',
                        borderRadius: '3px',
                        background: isHot ? 'rgba(239,68,68,0.25)' : 'rgba(245,158,11,0.2)',
                        color: isHot ? '#fca5a5' : '#fde68a',
                      }}>
                        {pct}%
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-dim)', fontSize: '0.68rem' }}>-</span>
                    )}
                  </div>

                  {/* Code Line */}
                  <pre style={{ margin: 0, padding: '2px 8px', color: isHot ? '#ffffff' : '#cbd5e1', overflowX: 'auto' }}>
                    {attr.lineContent}
                  </pre>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tab 2: Grounded Explanation (Hybrid RAG) */}
      {activeTab === 'rag' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {finding.explanation ? (
            <>
              {/* Vulnerability Mechanism */}
              <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                <h4 style={{ fontSize: '0.92rem', color: 'var(--cyan-primary)', marginBottom: '6px', fontWeight: 700 }}>
                  1. Vulnerability Mechanism
                </h4>
                <p style={{ fontSize: '0.84rem', color: '#e2e8f0', lineHeight: '1.6' }}>
                  {finding.explanation.vulnerabilityMechanism}
                </p>
              </div>

              {/* Exploitability Context */}
              <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                <h4 style={{ fontSize: '0.92rem', color: 'var(--amber-warning)', marginBottom: '6px', fontWeight: 700 }}>
                  2. Exploitability & Blast Radius
                </h4>
                <p style={{ fontSize: '0.84rem', color: '#e2e8f0', lineHeight: '1.6' }}>
                  {finding.explanation.exploitabilityContext}
                </p>
              </div>

              {/* Remediation Advice */}
              <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                <h4 style={{ fontSize: '0.92rem', color: 'var(--emerald-success)', marginBottom: '6px', fontWeight: 700 }}>
                  3. Recommended Defense Strategy
                </h4>
                <p style={{ fontSize: '0.84rem', color: '#e2e8f0', lineHeight: '1.6' }}>
                  {finding.explanation.remediationAdvice}
                </p>
              </div>

              {/* Verified Citations List */}
              <div>
                <h4 style={{ fontSize: '0.88rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '12px' }}>
                  Verified Knowledge Base Citations (Qdrant RAG + bge-reranker)
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {finding.explanation.citations.map((cite, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '14px',
                        borderRadius: 'var(--radius-md)',
                        background: 'rgba(15, 23, 42, 0.6)',
                        border: '1px solid var(--border-muted)',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span className="badge" style={{ background: 'rgba(139, 92, 246, 0.2)', color: '#c084fc' }}>
                            {cite.sourceType}
                          </span>
                          <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#f8fafc' }}>
                            {cite.source}
                          </span>
                        </div>
                        {cite.verified && (
                          <span className="badge badge-verified">
                            <CheckCircle size={12} />
                            Verified ({(cite.similarityScore * 100).toFixed(0)}% Match)
                          </span>
                        )}
                      </div>
                      <blockquote style={{
                        fontSize: '0.78rem',
                        fontStyle: 'italic',
                        color: 'var(--text-secondary)',
                        lineHeight: '1.5',
                        borderLeft: '2px solid var(--cyan-primary)',
                        paddingLeft: '10px',
                        margin: 0,
                      }}>
                        "{cite.quote}"
                      </blockquote>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <p style={{ color: 'var(--text-muted)', fontSize: '0.84rem' }}>No explanation generated yet.</p>
          )}
        </div>
      )}

      {/* Tab 3: Verified Remediation Studio */}
      {activeTab === 'patch' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {/* Patch Trigger & Loop Status */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc' }}>
                Bounded Verify-Repair Engine
              </h3>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Autonomous repair loop (max 2 retries) with multi-stage verification gates.
              </p>
            </div>

            <button
              type="button"
              className="btn btn-emerald"
              onClick={onGeneratePatch}
              disabled={isGeneratingPatch}
            >
              {isGeneratingPatch ? (
                <>
                  <div style={{
                    width: '14px',
                    height: '14px',
                    borderRadius: '50%',
                    border: '2px solid rgba(255,255,255,0.3)',
                    borderTopColor: '#fff',
                    animation: 'radarSweep 1s linear infinite',
                  }}></div>
                  Verifying Remediation...
                </>
              ) : (
                <>
                  <Sparkles size={16} />
                  Synthesize & Verify Patch
                </>
              )}
            </button>
          </div>

          {patch ? (
            <>
              {/* Verification Gates Checklist */}
              <div style={{
                background: 'rgba(16, 185, 129, 0.05)',
                border: '1px solid rgba(16, 185, 129, 0.25)',
                borderRadius: 'var(--radius-md)',
                padding: '16px',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                  <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#34d399', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Repair Verification Pipeline (Attempt #{patch.attemptNumber})
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '0.78rem', fontFamily: 'var(--font-mono)' }}>
                    <span>Before: <strong style={{ color: '#f87171' }}>{(patch.mlScoreBefore * 100).toFixed(0)}%</strong></span>
                    <ChevronRight size={14} color="var(--text-muted)" />
                    <span>After: <strong style={{ color: '#34d399' }}>{(patch.mlScoreAfter * 100).toFixed(0)}%</strong></span>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '10px' }}>
                  {patch.gates.map((g, i) => (
                    <div
                      key={i}
                      style={{
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: '8px',
                        background: 'rgba(0, 0, 0, 0.25)',
                        padding: '10px',
                        borderRadius: 'var(--radius-sm)',
                      }}
                    >
                      {g.passed ? (
                        <CheckCircle size={16} color="#10b981" style={{ marginTop: '2px', flexShrink: 0 }} />
                      ) : (
                        <XCircle size={16} color="#ef4444" style={{ marginTop: '2px', flexShrink: 0 }} />
                      )}
                      <div>
                        <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#f8fafc' }}>
                          {g.gate}
                        </div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                          {g.message}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Side-by-Side Unified Diff */}
              <div style={{
                background: '#04060a',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--border-subtle)',
                overflow: 'hidden',
              }}>
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 14px',
                  background: 'rgba(15, 23, 42, 0.7)',
                  borderBottom: '1px solid var(--border-subtle)',
                }}>
                  <span style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    unified.patch
                  </span>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{ padding: '3px 8px', fontSize: '0.72rem' }}
                    onClick={() => handleCopyDiff(patch.diff)}
                  >
                    {copied ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                    {copied ? 'Copied' : 'Copy Diff'}
                  </button>
                </div>

                <div style={{ padding: '12px', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', lineHeight: '1.5' }}>
                  {patch.diff.split('\n').map((line, idx) => {
                    const isAdd = line.startsWith('+');
                    const isDel = line.startsWith('-');
                    const isHeader = line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++');

                    return (
                      <div
                        key={idx}
                        className={isAdd ? 'diff-line-add' : isDel ? 'diff-line-del' : ''}
                        style={{
                          padding: '2px 8px',
                          color: isHeader ? 'var(--cyan-primary)' : isAdd ? '#6ee7b7' : isDel ? '#fca5a5' : '#94a3b8',
                        }}
                      >
                        {line}
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          ) : (
            <div style={{
              textAlign: 'center',
              padding: '30px',
              background: 'rgba(255, 255, 255, 0.02)',
              borderRadius: 'var(--radius-md)',
              border: '1px dashed var(--border-muted)',
            }}>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '12px' }}>
                No patch generated yet for this finding. Click above to trigger the bounded verify-repair loop.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
