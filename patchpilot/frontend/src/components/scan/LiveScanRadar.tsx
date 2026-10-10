import React from 'react';
import { ShieldCheck, Radar, Search, Cpu, CheckCircle2, Clock } from 'lucide-react';
import { ScanStage } from '../../types';

interface LiveScanRadarProps {
  stages: ScanStage[];
  currentProgress: number;
}

export const LiveScanRadar: React.FC<LiveScanRadarProps> = ({ stages, currentProgress }) => {
  return (
    <div className="glass-panel glass-panel-glow" style={{ padding: '24px', margin: '20px 0' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: '32px',
            height: '32px',
            borderRadius: '50%',
            background: 'rgba(6, 182, 212, 0.15)',
            border: '1px solid var(--cyan-primary)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            <Radar size={18} color="var(--cyan-primary)" className="radar-sweep" />
          </div>
          <div>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc' }}>
              Multi-Stage Analysis Radar
            </h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Executing AST parsing, SAST rules, UniXcoder embeddings, and calibrated ML fusion...
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '0.88rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--cyan-primary)' }}>
            {currentProgress}%
          </span>
          <div style={{
            width: '120px',
            height: '6px',
            background: 'rgba(255, 255, 255, 0.08)',
            borderRadius: '999px',
            overflow: 'hidden',
          }}>
            <div style={{
              width: `${currentProgress}%`,
              height: '100%',
              background: 'linear-gradient(90deg, #06b6d4, #10b981)',
              transition: 'width 0.3s ease',
            }}></div>
          </div>
        </div>
      </div>

      {/* Stages Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '12px',
      }}>
        {stages.map((stage) => {
          const isDone = stage.status === 'completed';
          const isRunning = stage.status === 'running';

          return (
            <div
              key={stage.id}
              style={{
                padding: '14px',
                borderRadius: 'var(--radius-md)',
                background: isRunning
                  ? 'rgba(6, 182, 212, 0.08)'
                  : isDone
                  ? 'rgba(16, 185, 129, 0.05)'
                  : 'rgba(255, 255, 255, 0.02)',
                border: isRunning
                  ? '1px solid var(--cyan-primary)'
                  : isDone
                  ? '1px solid rgba(16, 185, 129, 0.3)'
                  : '1px solid var(--border-subtle)',
                transition: 'all 0.25s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span style={{ fontSize: '0.8rem', fontWeight: 700, color: isRunning ? '#38bdf8' : isDone ? '#34d399' : 'var(--text-muted)' }}>
                  {stage.label}
                </span>
                {isDone ? (
                  <CheckCircle2 size={16} color="#10b981" />
                ) : isRunning ? (
                  <div style={{
                    width: '14px',
                    height: '14px',
                    borderRadius: '50%',
                    border: '2px solid rgba(6,182,212,0.3)',
                    borderTopColor: '#06b6d4',
                    animation: 'radarSweep 1s linear infinite',
                  }}></div>
                ) : (
                  <Clock size={15} color="var(--text-dim)" />
                )}
              </div>
              <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                {stage.description}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
};
