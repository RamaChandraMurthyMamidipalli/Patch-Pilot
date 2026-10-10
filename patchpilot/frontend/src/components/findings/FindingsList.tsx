import React from 'react';
import { Finding } from '../../types';
import { ShieldAlert, AlertTriangle, AlertCircle, Info, ChevronRight } from 'lucide-react';

interface FindingsListProps {
  findings: Finding[];
  selectedFindingId: string;
  onSelectFinding: (id: string) => void;
}

export const FindingsList: React.FC<FindingsListProps> = ({
  findings,
  selectedFindingId,
  onSelectFinding,
}) => {
  const getSeverityIcon = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return <ShieldAlert size={16} color="#ef4444" />;
      case 'HIGH': return <AlertTriangle size={16} color="#f59e0b" />;
      case 'MEDIUM': return <AlertCircle size={16} color="#06b6d4" />;
      default: return <Info size={16} color="#94a3b8" />;
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h3 style={{ fontSize: '0.96rem', fontWeight: 700, color: '#f8fafc' }}>
          Triaged Vulnerabilities ({findings.length})
        </h3>
        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
          Ranked by Calibrated Risk
        </span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {findings.map((f) => {
          const isSelected = f.id === selectedFindingId;

          return (
            <div
              key={f.id}
              onClick={() => onSelectFinding(f.id)}
              style={{
                padding: '12px 14px',
                borderRadius: 'var(--radius-md)',
                background: isSelected ? 'rgba(6, 182, 212, 0.1)' : 'rgba(255, 255, 255, 0.02)',
                border: isSelected ? '1px solid var(--cyan-primary)' : '1px solid var(--border-subtle)',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {getSeverityIcon(f.severity)}
                  <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
                    {f.cweId}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{
                    fontSize: '0.72rem',
                    fontWeight: 700,
                    color: f.confidence >= 0.7 ? '#f87171' : '#fbbf24',
                    fontFamily: 'var(--font-mono)'
                  }}>
                    {(f.confidence * 100).toFixed(0)}%
                  </span>
                  <ChevronRight size={14} color={isSelected ? 'var(--cyan-primary)' : 'var(--text-dim)'} />
                </div>
              </div>

              <div style={{
                fontSize: '0.8rem',
                color: isSelected ? '#ffffff' : 'var(--text-secondary)',
                fontWeight: 600,
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}>
                {f.title}
              </div>

              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginTop: '8px',
                fontSize: '0.72rem',
                color: 'var(--text-dim)',
              }}>
                <span>Line {f.lineNumber}</span>
                <span className="badge" style={{
                  fontSize: '0.64rem',
                  padding: '1px 6px',
                  background: f.triageStatus === 'confirmed' ? 'rgba(239,68,68,0.15)' : 'rgba(255,255,255,0.05)',
                  color: f.triageStatus === 'confirmed' ? '#f87171' : 'var(--text-secondary)',
                }}>
                  {f.triageStatus}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
