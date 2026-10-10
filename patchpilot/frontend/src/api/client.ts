import { Scan, Finding, PatchResult, SystemStats } from '../types';

export const SAMPLE_VULNERABLE_CODE_SQLI = `import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("users.db")
    return conn

@app.route("/user/lookup", methods=["GET"])
def lookup_user():
    username = request.args.get("username", "")
    role = request.args.get("role", "guest")
    
    # VULNERABLE: Direct string formatting concatenation allows SQL Injection
    query = f"SELECT id, username, email FROM accounts WHERE username = '{username}' AND role = '{role}'"
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    
    return jsonify({"users": results})
`;

export const SAMPLE_VULNERABLE_CODE_CMD_INJECTION = `import os
import subprocess
from fastapi import FastAPI, HTTPException

app = FastAPI()

@app.post("/diagnostics/ping")
def ping_host(target: str, count: int = 3):
    # VULNERABLE: shell=True with unvalidated user input leads to Command Injection (CWE-78)
    cmd = f"ping -c {count} {target}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        raise HTTPException(status_code=400, detail="Ping failed")
        
    return {"output": result.stdout}
`;

export const SAMPLE_VULNERABLE_CODE_DESERIALIZATION = `import pickle
import base64
from flask import Flask, request, abort

app = Flask(__name__)

@app.route("/session/load", methods=["POST"])
def restore_session():
    auth_header = request.headers.get("X-Session-Data")
    if not auth_header:
        abort(401)
        
    try:
        # VULNERABLE: Insecure deserialization via pickle allows Remote Code Execution (CWE-502)
        raw_bytes = base64.b64decode(auth_header)
        session_data = pickle.loads(raw_bytes)
        return {"status": "authenticated", "user": session_data.get("user")}
    except Exception as e:
        return {"error": str(e)}, 400
`;

export const MOCK_FINDING_SQLI: Finding = {
  id: 'find-sqli-01',
  scanId: 'scan-demo-01',
  cweId: 'CWE-89',
  ruleId: 'bandit.B608.hardcoded_sql_expressions',
  title: 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
  description: 'Untrusted user input from request.args formatted directly into an SQL statement without parameterization or query binding.',
  severity: 'CRITICAL',
  confidence: 0.96,
  analyzer: 'ensemble',
  lineNumber: 16,
  lineEndNumber: 17,
  codeSnippet: `query = f"SELECT id, username, email FROM accounts WHERE username = '{username}' AND role = '{role}'"`,
  triageStatus: 'open',
  attributions: [
    { lineNumber: 11, lineContent: 'def lookup_user():', attributionScore: 0.05, isPeak: false },
    { lineNumber: 12, lineContent: '    username = request.args.get("username", "")', attributionScore: 0.32, isPeak: false },
    { lineNumber: 13, lineContent: '    role = request.args.get("role", "guest")', attributionScore: 0.28, isPeak: false },
    { lineNumber: 14, lineContent: '    ', attributionScore: 0.01, isPeak: false },
    { lineNumber: 15, lineContent: '    # VULNERABLE: Direct string formatting concatenation allows SQL Injection', attributionScore: 0.12, isPeak: false },
    { lineNumber: 16, lineContent: '    query = f"SELECT id, username, email FROM accounts WHERE username = \'{username}\' AND role = \'{role}\'"', attributionScore: 0.96, isPeak: true },
    { lineNumber: 17, lineContent: '    ', attributionScore: 0.01, isPeak: false },
    { lineNumber: 18, lineContent: '    conn = get_db()', attributionScore: 0.08, isPeak: false },
    { lineNumber: 19, lineContent: '    cursor = conn.cursor()', attributionScore: 0.14, isPeak: false },
    { lineNumber: 20, lineContent: '    cursor.execute(query)', attributionScore: 0.74, isPeak: true },
  ],
  explanation: {
    summary: 'The application constructs an SQL statement using an f-string interpolating raw user input. An adversary can inject SQL syntax to bypass authentication, dump databases, or drop tables.',
    vulnerabilityMechanism: 'String formatting evaluates user input as part of the query structure rather than data. Supplying "\' OR \'1\'=\'1" manipulates the boolean logic of the WHERE clause.',
    exploitabilityContext: 'High exploitability. Network reachable via standard GET endpoint without administrative authorization.',
    remediationAdvice: 'Refactor the query to use parameterized query placeholders (?) supplied as a tuple to cursor.execute(). Never concatenate untrusted strings into database queries.',
    citations: [
      {
        source: 'CWE-89: SQL Injection',
        sourceType: 'CWE',
        quote: 'The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream database component.',
        similarityScore: 0.96,
        verified: true,
      },
      {
        source: 'OWASP Top 10:2021-A03: Injection',
        sourceType: 'OWASP',
        quote: 'User-supplied data is not validated, filtered, or sanitized by the application. Dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter.',
        similarityScore: 0.94,
        verified: true,
      },
      {
        source: 'PEP 249: Python Database API Specification 2.0',
        sourceType: 'PEP',
        quote: 'Parameter style qmark uses question mark style, e.g. ...WHERE name=? and binds variables separately to prevent syntax interference.',
        similarityScore: 0.91,
        verified: true,
      }
    ]
  },
  suggestedPatch: {
    id: 'patch-sqli-01',
    findingId: 'find-sqli-01',
    diff: `--- accounts.py (original)
+++ accounts.py (remediated)
@@ -15,5 +15,5 @@
-    query = f"SELECT id, username, email FROM accounts WHERE username = '{username}' AND role = '{role}'"
+    query = "SELECT id, username, email FROM accounts WHERE username = ? AND role = ?"
     conn = get_db()
     cursor = conn.cursor()
-    cursor.execute(query)
+    cursor.execute(query, (username, role))`,
    patchedCode: `import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("users.db")
    return conn

@app.route("/user/lookup", methods=["GET"])
def lookup_user():
    username = request.args.get("username", "")
    role = request.args.get("role", "guest")
    
    # REMEDIATED: Parameterized SQL query prevents injection attacks
    query = "SELECT id, username, email FROM accounts WHERE username = ? AND role = ?"
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(query, (username, role))
    results = cursor.fetchall()
    conn.close()
    
    return jsonify({"users": results})
`,
    attemptNumber: 1,
    verified: true,
    gates: [
      { gate: 'AST Syntax Parse', passed: true, message: 'ast.parse() executed successfully without SyntaxError.' },
      { gate: 'Target SAST Rule Elimination', passed: true, message: 'Bandit B608 no longer detected on patched source.' },
      { gate: 'Zero Regression Verification', passed: true, message: '0 new High or Medium severity findings detected across all analyzers.' },
      { gate: 'Calibrated Risk Score Reduction', passed: true, message: 'LightGBM risk probability dropped from 0.96 to 0.02 (-97.9%).' },
    ],
    mlScoreBefore: 0.96,
    mlScoreAfter: 0.02,
    createdAt: new Date().toISOString(),
  }
};

export const INITIAL_DEMO_SCAN: Scan = {
  id: 'scan-demo-01',
  filename: 'user_service.py',
  sourceCode: SAMPLE_VULNERABLE_CODE_SQLI,
  status: 'completed',
  totalFindings: 1,
  criticalCount: 1,
  highCount: 0,
  mediumCount: 0,
  lowCount: 0,
  avgRiskScore: 0.96,
  createdAt: new Date().toISOString(),
  findings: [MOCK_FINDING_SQLI],
};

export const INITIAL_SYSTEM_STATS: SystemStats = {
  totalScans: 142,
  vulnerabilitiesDetected: 318,
  patchesVerified: 304,
  remediationRatePercent: 95.6,
  avgScanDurationSec: 3.4,
  llmBudgetUsedUsd: 1.18,
  llmBudgetCapUsd: 5.00,
};
