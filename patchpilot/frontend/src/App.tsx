import React, { useState } from 'react';
import { Navbar } from './components/layout/Navbar';
import { MetricsBar } from './components/layout/MetricsBar';
import { ScanStudio } from './components/scan/ScanStudio';
import { LiveScanRadar } from './components/scan/LiveScanRadar';
import { FindingsList } from './components/findings/FindingsList';
import { FindingInspector } from './components/findings/FindingInspector';
import {
  INITIAL_DEMO_SCAN,
  INITIAL_SYSTEM_STATS,
  SAMPLE_VULNERABLE_CODE_SQLI,
  MOCK_FINDING_SQLI,
} from './api/client';
import { Finding, ScanStage, TriageStatus, PatchResult } from './types';

const INITIAL_STAGES: ScanStage[] = [
  { id: 'ast', label: '1. AST & Secret Redaction', description: 'AST parse verification & detect-secrets API token filtering', status: 'completed' },
  { id: 'sast', label: '2. Bandit & Semgrep SAST', description: 'Sandboxed subprocess rules with 30s timeout enforcement', status: 'completed' },
  { id: 'xai', label: '3. UniXcoder & Integrated Gradients', description: 'Semantic code representation and Captum token-level saliency', status: 'completed' },
  { id: 'ml', label: '4. LightGBM Calibrated Triager', description: 'Isotonic regression risk probability calculation', status: 'completed' },
];

export const App: React.FC = () => {
  const [code, setCode] = useState<string>(SAMPLE_VULNERABLE_CODE_SQLI);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(100);
  const [stages, setStages] = useState<ScanStage[]>(INITIAL_STAGES);
  const [findings, setFindings] = useState<Finding[]>([MOCK_FINDING_SQLI]);
  const [selectedFindingId, setSelectedFindingId] = useState<string>(MOCK_FINDING_SQLI.id);
  const [isGeneratingPatch, setIsGeneratingPatch] = useState<boolean>(false);
  const [stats, setStats] = useState(INITIAL_SYSTEM_STATS);

  const selectedFinding = findings.find((f) => f.id === selectedFindingId) || findings[0];

  const handleStartScan = () => {
    setIsScanning(true);
    setScanProgress(0);

    const resetStages: ScanStage[] = [
      { id: 'ast', label: '1. AST & Secret Redaction', description: 'AST parse verification & detect-secrets filtering', status: 'running' },
      { id: 'sast', label: '2. Bandit & Semgrep SAST', description: 'Sandboxed subprocess rules execution', status: 'pending' },
      { id: 'xai', label: '3. UniXcoder & Integrated Gradients', description: 'Semantic code representation & token saliency', status: 'pending' },
      { id: 'ml', label: '4. LightGBM Calibrated Triager', description: 'Isotonic regression risk probability calculation', status: 'pending' },
    ];
    setStages(resetStages);

    // Simulate multi-stage pipeline execution
    setTimeout(() => {
      setScanProgress(25);
      setStages((prev) => [
        { ...prev[0], status: 'completed' },
        { ...prev[1], status: 'running' },
        prev[2],
        prev[3],
      ]);
    }, 600);

    setTimeout(() => {
      setScanProgress(55);
      setStages((prev) => [
        prev[0],
        { ...prev[1], status: 'completed' },
        { ...prev[2], status: 'running' },
        prev[3],
      ]);
    }, 1300);

    setTimeout(() => {
      setScanProgress(85);
      setStages((prev) => [
        prev[0],
        prev[1],
        { ...prev[2], status: 'completed' },
        { ...prev[3], status: 'running' },
      ]);
    }, 2000);

    setTimeout(() => {
      setScanProgress(100);
      setStages((prev) => [
        prev[0],
        prev[1],
        prev[2],
        { ...prev[3], status: 'completed' },
      ]);
      setIsScanning(false);

      // Create finding based on scanned code content
      let newFinding: Finding;
      if (code.includes('ping') || code.includes('subprocess')) {
        newFinding = {
          id: 'find-cmd-01',
          scanId: 'scan-' + Date.now(),
          cweId: 'CWE-78',
          ruleId: 'bandit.B602.subprocess_popen_with_shell_equals_true',
          title: 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)',
          description: 'Subprocess execution with shell=True receiving unvalidated target parameter allows remote arbitrary command execution.',
          severity: 'CRITICAL',
          confidence: 0.98,
          analyzer: 'ensemble',
          lineNumber: 9,
          codeSnippet: 'result = subprocess.run(cmd, shell=True, capture_output=True, text=True)',
          triageStatus: 'open',
          attributions: [
            { lineNumber: 6, lineContent: 'def ping_host(target: str, count: int = 3):', attributionScore: 0.12, isPeak: false },
            { lineNumber: 7, lineContent: '    # VULNERABLE: shell=True with unvalidated user input', attributionScore: 0.05, isPeak: false },
            { lineNumber: 8, lineContent: '    cmd = f"ping -c {count} {target}"', attributionScore: 0.88, isPeak: true },
            { lineNumber: 9, lineContent: '    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)', attributionScore: 0.98, isPeak: true },
          ],
          explanation: {
            summary: 'Passing an untrusted target string into subprocess.run with shell=True triggers execution via the system shell (/bin/sh or cmd.exe), enabling command chaining with semicolons or backticks.',
            vulnerabilityMechanism: 'The shell parses metacharacters (&, ;, |, `). Supplying "8.8.8.8; cat /etc/passwd" executes both ping and cat.',
            exploitabilityContext: 'Critical severity. Remote unauthenticated endpoint directly exposes host shell capabilities.',
            remediationAdvice: 'Pass arguments as a list of strings and set shell=False (the safe default). Validate the IP address format strictly.',
            citations: [
              {
                source: 'CWE-78: OS Command Injection',
                sourceType: 'CWE',
                quote: 'The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements.',
                similarityScore: 0.97,
                verified: true,
              },
              {
                source: 'Python Security Documentation: Subprocess',
                sourceType: 'PEP',
                quote: 'Using shell=True can be a security hazard if combined with untrusted input. It is strongly recommended to use sequence arguments with shell=False.',
                similarityScore: 0.95,
                verified: true,
              }
            ]
          },
          suggestedPatch: {
            id: 'patch-cmd-01',
            findingId: 'find-cmd-01',
            diff: `--- diagnostics.py
+++ diagnostics.py
@@ -8,2 +8,3 @@
-    cmd = f"ping -c {count} {target}"
-    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
+    cmd = ["ping", "-c", str(count), target]
+    result = subprocess.run(cmd, shell=False, capture_output=True, text=True)`,
            patchedCode: '',
            attemptNumber: 1,
            verified: true,
            gates: [
              { gate: 'AST Syntax Parse', passed: true, message: 'ast.parse() executed successfully.' },
              { gate: 'Target SAST Rule Elimination', passed: true, message: 'Bandit B602 (subprocess shell=True) eliminated.' },
              { gate: 'Zero Regression Verification', passed: true, message: '0 new findings generated.' },
              { gate: 'Calibrated Risk Score Reduction', passed: true, message: 'Risk dropped from 0.98 to 0.01 (-99.0%).' },
            ],
            mlScoreBefore: 0.98,
            mlScoreAfter: 0.01,
            createdAt: new Date().toISOString(),
          }
        };
      } else if (code.includes('pickle')) {
        newFinding = {
          id: 'find-pickle-01',
          scanId: 'scan-' + Date.now(),
          cweId: 'CWE-502',
          ruleId: 'bandit.B301.pickle',
          title: 'Deserialization of Untrusted Data (Insecure Pickle Deserialization)',
          description: 'Deserializing user-controlled input with pickle.loads can invoke arbitrary Python callables, causing Remote Code Execution.',
          severity: 'CRITICAL',
          confidence: 0.99,
          analyzer: 'ensemble',
          lineNumber: 15,
          codeSnippet: 'session_data = pickle.loads(raw_bytes)',
          triageStatus: 'open',
          attributions: [
            { lineNumber: 13, lineContent: '    try:', attributionScore: 0.01, isPeak: false },
            { lineNumber: 14, lineContent: '        raw_bytes = base64.b64decode(auth_header)', attributionScore: 0.25, isPeak: false },
            { lineNumber: 15, lineContent: '        session_data = pickle.loads(raw_bytes)', attributionScore: 0.99, isPeak: true },
          ],
          explanation: {
            summary: 'The pickle module is not secure against erroneous or maliciously constructed data. Pickle byte streams can specify arbitrary callable functions executed upon unpickling (__reduce__).',
            vulnerabilityMechanism: 'Pickle bytecodes can instantiate classes and execute subprocess / system calls during object reconstruction.',
            exploitabilityContext: 'Critical remote exploitability. Any client who can provide an X-Session-Data header can achieve immediate host takeover.',
            remediationAdvice: 'Replace pickle with safe serialization formats like JSON, MessagePack, or use cryptographically signed payloads with itsdangerous/JWT.',
            citations: [
              {
                source: 'CWE-502: Deserialization of Untrusted Data',
                sourceType: 'CWE',
                quote: 'The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid, allowing arbitrary code execution.',
                similarityScore: 0.98,
                verified: true,
              },
              {
                source: 'Python Standard Library: pickle',
                sourceType: 'PEP',
                quote: 'Warning: The pickle module is not secure. Only unpickle data you trust. It is possible to construct malicious pickle data which will execute arbitrary code.',
                similarityScore: 0.96,
                verified: true,
              }
            ]
          },
          suggestedPatch: {
            id: 'patch-pickle-01',
            findingId: 'find-pickle-01',
            diff: `--- session.py
+++ session.py
@@ -1,2 +1,2 @@
-import pickle
+import json
@@ -15,1 +15,1 @@
-        session_data = pickle.loads(raw_bytes)
+        session_data = json.loads(raw_bytes.decode('utf-8'))`,
            patchedCode: '',
            attemptNumber: 1,
            verified: true,
            gates: [
              { gate: 'AST Syntax Parse', passed: true, message: 'ast.parse() executed successfully.' },
              { gate: 'Target SAST Rule Elimination', passed: true, message: 'Bandit B301 (pickle) eliminated.' },
              { gate: 'Zero Regression Verification', passed: true, message: '0 new findings detected.' },
              { gate: 'Calibrated Risk Score Reduction', passed: true, message: 'Risk dropped from 0.99 to 0.01.' },
            ],
            mlScoreBefore: 0.99,
            mlScoreAfter: 0.01,
            createdAt: new Date().toISOString(),
          }
        };
      } else {
        newFinding = MOCK_FINDING_SQLI;
      }

      setFindings([newFinding]);
      setSelectedFindingId(newFinding.id);
      setStats((prev) => ({
        ...prev,
        totalScans: prev.totalScans + 1,
        vulnerabilitiesDetected: prev.vulnerabilitiesDetected + 1,
      }));
    }, 2500);
  };

  const handleTriageChange = (newStatus: TriageStatus) => {
    setFindings((prev) =>
      prev.map((f) => (f.id === selectedFindingId ? { ...f, triageStatus: newStatus } : f))
    );
  };

  const handleGeneratePatch = () => {
    setIsGeneratingPatch(true);

    setTimeout(() => {
      setIsGeneratingPatch(false);
      setStats((prev) => ({
        ...prev,
        patchesVerified: prev.patchesVerified + 1,
      }));
    }, 1500);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Top Navigation */}
      <Navbar stats={stats} llmProvider="Gemini 2.0 Flash" />

      {/* Top Metrics Telemetry */}
      <MetricsBar stats={stats} />

      {/* Main Container */}
      <main style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1600px', margin: '0 auto', width: '100%' }}>
        {/* Python Code Input Studio */}
        <ScanStudio
          code={code}
          setCode={setCode}
          isScanning={isScanning}
          onStartScan={handleStartScan}
        />

        {/* Live Multi-Stage Radar (shown when scanning or after scan) */}
        <LiveScanRadar stages={stages} currentProgress={scanProgress} />

        {/* Findings & Triage Board */}
        {findings.length > 0 && (
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(320px, 1fr) minmax(650px, 2.5fr)',
            gap: '24px',
            alignItems: 'start',
          }}>
            {/* Left Findings List */}
            <FindingsList
              findings={findings}
              selectedFindingId={selectedFindingId}
              onSelectFinding={setSelectedFindingId}
            />

            {/* Right Detailed Finding Inspector */}
            <FindingInspector
              finding={selectedFinding}
              onTriageChange={handleTriageChange}
              onGeneratePatch={handleGeneratePatch}
              isGeneratingPatch={isGeneratingPatch}
            />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer style={{
        marginTop: 'auto',
        padding: '24px',
        textAlign: 'center',
        borderTop: '1px solid var(--border-subtle)',
        color: 'var(--text-muted)',
        fontSize: '0.78rem',
      }}>
        <p>
          PatchPilot Security Copilot • Defensive Only • Powered by Bandit, Semgrep, UniXcoder, LightGBM & Qdrant RAG
        </p>
      </footer>
    </div>
  );
};
export default App;
