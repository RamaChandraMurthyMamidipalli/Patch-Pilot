import React from 'react';
import { SystemStats } from '../../types';
import { ScanSearch, ShieldAlert, Wrench, Zap, Timer } from 'lucide-react';

interface MetricsBarProps {
  stats: SystemStats;
}

export const MetricsBar: React.FC<MetricsBarProps> = ({ stats }) => {
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
      gap: '16px',
      margin: '20px 24px 0 24px',
    }}>
      <div className="glass-panel" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{
          padding: '10px',
          borderRadius: '10px',
          background: 'rgba(6, 182, 212, 0.12)',
          color: 'var(--cyan-primary)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}>
          <ScanSearch size={22} />
        </div>
        <div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Total Scans Run
          </div>
          <div style={{ fontSize: '1.45rem', fontWeight: 700, fontFamily: 'var(--font-heading)', color: 'var(--text-primary)' }}>
            {stats.totalScans}
          </div>
        </div>
      </div>

      <div className="glass-panel" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{
          padding: '10px',
          borderRadius: '10px',
          background: 'rgba(239, 68, 68, 0.12)',
          color: 'var(--crimson-threat)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}>
          <ShieldAlert size={22} />
        </div>
        <div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Vulnerabilities Caught
          </div>
          <div style={{ fontSize: '1.45rem', fontWeight: 700, fontFamily: 'var(--font-heading)', color: '#f87171' }}>
            {stats.vulnerabilitiesDetected}
          </div>
        </div>
      </div>

      <div className="glass-panel" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{
          padding: '10px',
          borderRadius: '10px',
          background: 'rgba(16, 185, 129, 0.12)',
          color: 'var(--emerald-success)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}>
          <Wrench size={22} />
        </div>
        <div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Verified Patches
          </div>
          <div style={{ fontSize: '1.45rem', fontWeight: 700, fontFamily: 'var(--font-heading)', color: '#34d399' }}>
            {stats.patchesVerified}
          </div>
        </div>
      </div>

      <div className="glass-panel" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{
          padding: '10px',
          borderRadius: '10px',
          background: 'rgba(139, 92, 246, 0.12)',
          color: 'var(--purple-accent)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}>
          <Zap size={22} />
        </div>
        <div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Remediation Pass Rate
          </div>
          <div style={{ fontSize: '1.45rem', fontWeight: 700, fontFamily: 'var(--font-heading)', color: '#c084fc' }}>
            {stats.remediationRatePercent}%
          </div>
        </div>
      </div>

      <div className="glass-panel" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{
          padding: '10px',
          borderRadius: '10px',
          background: 'rgba(245, 158, 11, 0.12)',
          color: 'var(--amber-warning)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}>
          <Timer size={22} />
        </div>
        <div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Avg Triage Time
          </div>
          <div style={{ fontSize: '1.45rem', fontWeight: 700, fontFamily: 'var(--font-heading)', color: '#fbbf24' }}>
            {stats.avgScanDurationSec}s
          </div>
        </div>
      </div>
    </div>
  );
};
