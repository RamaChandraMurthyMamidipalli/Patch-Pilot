import React from 'react';
import { Shield, Cpu, Activity, Database, CheckCircle2 } from 'lucide-react';
import { SystemStats } from '../../types';

interface NavbarProps {
  stats: SystemStats;
  llmProvider: string;
}

export const Navbar: React.FC<NavbarProps> = ({ stats, llmProvider }) => {
  const budgetPercent = Math.min(100, Math.round((stats.llmBudgetUsedUsd / stats.llmBudgetCapUsd) * 100));

  return (
    <header className="navbar glass-panel" style={{
      margin: '16px 24px 0 24px',
      padding: '12px 24px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      position: 'sticky',
      top: '16px',
      zIndex: 50,
    }}>
      {/* Brand */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{
          width: '42px',
          height: '42px',
          borderRadius: '12px',
          background: 'linear-gradient(135deg, rgba(6, 182, 212, 0.2) 0%, rgba(139, 92, 246, 0.25) 100%)',
          border: '1px solid rgba(6, 182, 212, 0.4)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 15px rgba(6, 182, 212, 0.25)',
        }}>
          <Shield size={24} color="#06b6d4" />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{
              fontFamily: 'var(--font-heading)',
              fontSize: '1.28rem',
              fontWeight: 800,
              letterSpacing: '-0.02em',
              background: 'linear-gradient(90deg, #f8fafc 0%, #38bdf8 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}>
              PatchPilot
            </span>
            <span className="badge" style={{ background: 'rgba(6, 182, 212, 0.12)', color: '#38bdf8', fontSize: '0.65rem' }}>
              COPILOT v0.1
            </span>
          </div>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: 0 }}>
            Evidence-Grounded Vulnerability Triage & Remediation
          </p>
        </div>
      </div>

      {/* Active Engines / Guardrails Pill */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '18px' }}>
        <div style={{
          display: 'none',
          alignItems: 'center',
          gap: '12px',
          padding: '6px 14px',
          background: 'rgba(15, 23, 42, 0.6)',
          borderRadius: '9999px',
          border: '1px solid var(--border-subtle)',
          fontSize: '0.78rem',
        }} className="md-flex">
          <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#10b981' }}>
            <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10b981', boxShadow: '0 0 8px #10b981' }}></span>
            Bandit + Semgrep
          </span>
          <span style={{ color: 'var(--border-muted)' }}>|</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: '#38bdf8' }}>
            <Cpu size={13} /> UniXcoder + LightGBM
          </span>
          <span style={{ color: 'var(--border-muted)' }}>|</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: '#c084fc' }}>
            <Database size={13} /> Qdrant Hybrid RAG
          </span>
        </div>

        {/* Safety Guarantee */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: '5px 12px',
          background: 'rgba(16, 185, 129, 0.1)',
          border: '1px solid rgba(16, 185, 129, 0.3)',
          borderRadius: '9999px',
          fontSize: '0.75rem',
          color: '#34d399',
          fontWeight: 600,
        }}>
          <CheckCircle2 size={13} />
          <span>Defensive Only</span>
        </div>

        {/* LLM Provider & Budget Tracker */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          padding: '5px 14px',
          background: 'var(--bg-tertiary)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-subtle)',
        }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '10px' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                LLM: {llmProvider}
              </span>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                ${stats.llmBudgetUsedUsd.toFixed(2)} / ${stats.llmBudgetCapUsd.toFixed(2)}
              </span>
            </div>
            <div style={{
              width: '110px',
              height: '4px',
              background: 'rgba(255, 255, 255, 0.08)',
              borderRadius: '2px',
              marginTop: '4px',
              overflow: 'hidden',
            }}>
              <div style={{
                width: `${budgetPercent}%`,
                height: '100%',
                background: budgetPercent > 80 ? 'var(--crimson-threat)' : 'var(--cyan-primary)',
                transition: 'width 0.4s ease',
              }}></div>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
