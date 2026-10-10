import React, { useRef } from 'react';
import { Play, Upload, RotateCcw, FileCode, ShieldAlert, Sparkles, Terminal } from 'lucide-react';
import {
  SAMPLE_VULNERABLE_CODE_SQLI,
  SAMPLE_VULNERABLE_CODE_CMD_INJECTION,
  SAMPLE_VULNERABLE_CODE_DESERIALIZATION,
} from '../../api/client';

interface ScanStudioProps {
  code: string;
  setCode: (code: string) => void;
  isScanning: boolean;
  onStartScan: () => void;
}

export const ScanStudio: React.FC<ScanStudioProps> = ({
  code,
  setCode,
  isScanning,
  onStartScan,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result as string;
        if (content) setCode(content);
      };
      reader.readAsText(file);
    }
  };

  const lineCount = code.split('\n').length;
  const charCount = code.length;

  return (
    <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Studio Header & Presets */}
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Terminal size={18} color="var(--cyan-primary)" />
          <h2 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            Python Security Analysis Studio
          </h2>
        </div>

        {/* Preset Selectors */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>Load Vectors:</span>
          <button
            type="button"
            className="btn btn-secondary"
            style={{ padding: '4px 10px', fontSize: '0.74rem' }}
            onClick={() => setCode(SAMPLE_VULNERABLE_CODE_SQLI)}
          >
            SQLi (CWE-89)
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            style={{ padding: '4px 10px', fontSize: '0.74rem' }}
            onClick={() => setCode(SAMPLE_VULNERABLE_CODE_CMD_INJECTION)}
          >
            Cmd Injection (CWE-78)
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            style={{ padding: '4px 10px', fontSize: '0.74rem' }}
            onClick={() => setCode(SAMPLE_VULNERABLE_CODE_DESERIALIZATION)}
          >
            Insecure Pickle (CWE-502)
          </button>
        </div>
      </div>

      {/* Editor Body */}
      <div style={{
        position: 'relative',
        background: '#04060a',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--border-subtle)',
        overflow: 'hidden',
      }}>
        {/* Editor bar */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '8px 14px',
          background: 'rgba(15, 23, 42, 0.7)',
          borderBottom: '1px solid var(--border-subtle)',
          fontSize: '0.75rem',
          color: 'var(--text-muted)',
          fontFamily: 'var(--font-mono)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileCode size={14} color="#38bdf8" />
            <span>payload.py</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <span>{lineCount} lines</span>
            <span>{charCount} chars</span>
          </div>
        </div>

        {/* Textarea code input */}
        <textarea
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="# Paste or upload Python source code here for security triage..."
          spellCheck={false}
          style={{
            width: '100%',
            height: '280px',
            background: 'transparent',
            color: '#e2e8f0',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.86rem',
            lineHeight: '1.6',
            padding: '14px',
            border: 'none',
            outline: 'none',
            resize: 'vertical',
            whiteSpace: 'pre',
            tabSize: 4,
          }}
        />
      </div>

      {/* Action Footer */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <input
            type="file"
            accept=".py"
            ref={fileInputRef}
            onChange={handleFileUpload}
            style={{ display: 'none' }}
          />
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload size={15} /> Upload .py
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setCode('')}
            title="Clear editor"
          >
            <RotateCcw size={15} /> Clear
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            type="button"
            className="btn btn-primary"
            onClick={onStartScan}
            disabled={isScanning || !code.trim()}
            style={{
              padding: '10px 24px',
              fontSize: '0.94rem',
              boxShadow: isScanning ? 'none' : '0 0 20px rgba(6, 182, 212, 0.4)',
            }}
          >
            {isScanning ? (
              <>
                <div style={{
                  width: '16px',
                  height: '16px',
                  borderRadius: '50%',
                  border: '2px solid rgba(255,255,255,0.3)',
                  borderTopColor: '#fff',
                  animation: 'radarSweep 1s linear infinite',
                }}></div>
                Scanning Codebase...
              </>
            ) : (
              <>
                <Play size={16} fill="#fff" />
                Run PatchPilot Scan
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
