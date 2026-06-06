#!/usr/bin/env python3
"""
Solidity → Interactive HTML Audit Mind Map Generator (AI-Powered)
=================================================================
Three modes:
  raw      — No AI. Just extract and format. Fast.
  full     — AI translates EVERY function to plain-English logic. Slower but complete.
  filtered — AI filters high-risk functions only + deep exploit analysis. Smartest.

Usage:
    python3 solidity_mindmap.py <repo> [--mode raw|full|filtered] [--output file.html] [--api-key KEY] [--api-url URL] [--model MODEL]

Examples:
    # Raw mode (no AI, instant)
    python3 solidity_mindmap.py https://github.com/morpho-org/morpho-blue --mode raw

    # Full mode (AI explains every function)
    python3 solidity_mindmap.py ./morpho-blue --mode full

    # Filtered mode (AI picks high-risk + exploit analysis)
    python3 solidity_mindmap.py ./morpho-blue --mode filtered

    # Custom API
    python3 solidity_mindmap.py ./morpho-blue --mode full --api-url https://openrouter.ai/api/v1 --api-key sk-xxx --model anthropic/claude-sonnet-4
"""

import os
import re
import sys
import json
import time
import argparse
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from urllib.request import Request, urlopen
from urllib.error import HTTPError


# ============================================================
# SOLIDITY PARSER — Same as v1, full extraction
# ============================================================

class SolidityParser:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.contracts = []
        self.interfaces = []
        self.libraries = []
        self.constants = []
        self.imports = []

    def parse_all(self):
        sol_files = sorted(self.repo_path.rglob("*.sol"))
        skip = {'node_modules', '.git', '__pycache__', 'lib/', 'forge-std'}
        sol_files = [f for f in sol_files if not any(s in str(f) for s in skip)]

        for filepath in sol_files:
            try:
                content = filepath.read_text(encoding='utf-8', errors='ignore')
                rel_path = filepath.relative_to(self.repo_path)
                self._parse_file(content, str(rel_path))
            except Exception as e:
                print(f"  ⚠ Error parsing {filepath}: {e}", file=sys.stderr)

        return self._build_result()

    def _parse_file(self, content: str, filepath: str):
        content_clean = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
        content_clean = re.sub(r'/\*.*?\*/', lambda m: m.group().count('\n') * '\n', content_clean, flags=re.DOTALL)

        for m in re.finditer(r'import\s+(?:(?:"([^"]+)"|{[^}]+}\s+from\s+"([^"]+)"))', content):
            self.imports.append({'file': filepath, 'import': m.group(1) or m.group(2)})

        for m in re.finditer(r'(?:uint256|uint128|uint64|uint8|int256|bytes32|address|bool|string)\s+(?:public\s+)?(?:constant|immutable)\s+(\w+)\s*=\s*([^;]+);', content_clean):
            self.constants.append({'name': m.group(1), 'value': m.group(2).strip(), 'file': filepath})

        pattern = r'(contract|interface|library)\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{'
        for m in re.finditer(pattern, content_clean):
            kind, name = m.group(1), m.group(2)
            inheritance = [x.strip() for x in m.group(3).split(',')] if m.group(3) else []
            body = self._extract_braces(content_clean, m.end() - 1)

            item = {
                'name': name, 'kind': kind, 'inheritance': inheritance, 'file': filepath,
                'state_variables': self._extract_state_vars(body),
                'modifiers': self._extract_modifiers(body),
                'events': self._extract_events(body),
                'errors': self._extract_errors(body),
                'structs': self._extract_structs(body),
                'enums': self._extract_enums(body),
                'functions': self._extract_functions(body),
                'constructor': self._extract_constructor(body),
                'receive_eth': bool(re.search(r'receive\s*\(\s*\)', body)),
                'fallback': bool(re.search(r'fallback\s*\(\s*\)', body)),
            }

            if kind == 'contract': self.contracts.append(item)
            elif kind == 'interface': self.interfaces.append(item)
            elif kind == 'library': self.libraries.append(item)

    def _extract_braces(self, text, start):
        if start >= len(text) or text[start] != '{': return ''
        depth = 0
        for i in range(start, len(text)):
            if text[i] == '{': depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0: return text[start + 1:i]
        return text[start + 1:]

    def _extract_state_vars(self, body):
        vars_found = []
        for m in re.finditer(r'mapping\s*\([^)]+\)\s+(?:public\s+|internal\s+|private\s+)?(\w+)', body):
            vars_found.append({'type': 'mapping(...)', 'name': m.group(1), 'visibility': 'public'})
        pattern = r'((?:uint256|uint128|uint64|uint8|int256|bytes32|bytes|address|bool|string|[\w.]+)(?:\[\])?)\s+(public|internal|private|constant|immutable)?\s*(?:constant|immutable)?\s*(\w+)\s*(?:=\s*[^;]+)?\s*;'
        for m in re.finditer(pattern, body):
            vis = m.group(2) if m.group(2) in ('public', 'internal', 'private') else 'internal'
            vars_found.append({'type': m.group(1).strip(), 'name': m.group(3), 'visibility': vis})
        seen = set()
        unique = []
        for v in vars_found:
            if v['name'] not in seen:
                seen.add(v['name'])
                unique.append(v)
        return unique

    def _extract_modifiers(self, body):
        return [{'name': m.group(1), 'params': m.group(2) or ''} for m in re.finditer(r'modifier\s+(\w+)(?:\(([^)]*)\))?', body)]

    def _extract_events(self, body):
        return [{'name': m.group(1), 'raw': m.group(2).strip()} for m in re.finditer(r'event\s+(\w+)\s*\(([^)]*)\)', body)]

    def _extract_errors(self, body):
        return [{'name': m.group(1), 'raw': m.group(2).strip()} for m in re.finditer(r'error\s+(\w+)\s*\(([^)]*)\)', body)]

    def _extract_structs(self, body):
        structs = []
        for m in re.finditer(r'struct\s+(\w+)\s*\{', body):
            sb = self._extract_braces(body, m.end() - 1)
            fields = []
            for line in sb.split('\n'):
                line = line.strip().rstrip(';').strip()
                if line and not line.startswith('//'):
                    parts = line.split()
                    if len(parts) >= 2:
                        fields.append({'type': ' '.join(parts[:-1]), 'name': parts[-1]})
            structs.append({'name': m.group(1), 'fields': fields})
        return structs

    def _extract_enums(self, body):
        return [{'name': m.group(1), 'values': [v.strip() for v in m.group(2).split(',') if v.strip()]} for m in re.finditer(r'enum\s+(\w+)\s*\{([^}]*)\}', body)]

    def _extract_functions(self, body):
        funcs = []
        pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*((?:(?:external|public|internal|private|view|pure|payable|virtual|override|nonpayable)\s*)*)(?:returns\s*\(([^)]*)\))?\s*[^{]*\{'
        for m in re.finditer(pattern, body):
            name = m.group(1)
            raw_params = m.group(2).strip()
            mods_str = m.group(3).strip()
            raw_returns = m.group(4)

            visibility = 'internal'
            for v in ['external', 'public', 'internal', 'private']:
                if v in mods_str.split(): visibility = v; break
            mutability = 'nonpayable'
            for mv in ['view', 'pure', 'payable']:
                if mv in mods_str.split(): mutability = mv; break

            known = {'external', 'public', 'internal', 'private', 'view', 'pure', 'payable', 'virtual', 'override', 'nonpayable', 'returns'}
            custom_mods = [w.rstrip('(') for w in mods_str.split() if w.rstrip('(') not in known and w.rstrip('(')]

            func_body = self._extract_braces(body, m.end() - 1)
            calls = list(set(f"{c.group(1)}.{c.group(2)}" for c in re.finditer(r'(\w+)\.(\w+)\s*\(', func_body) if c.group(1) not in {'msg', 'block', 'tx', 'abi', 'type', 'this', 'super', 'require', 'assert', 'revert', 'emit', 'keccak256', 'sha256', 'ecrecover', 'selfdestruct', 'delegatecall', 'staticcall', 'call', 'transfer'}))

            funcs.append({
                'name': name, 'raw_params': raw_params, 'raw_returns': (raw_returns or '').strip(),
                'visibility': visibility, 'mutability': mutability,
                'is_virtual': 'virtual' in mods_str.split(), 'is_override': 'override' in mods_str,
                'custom_modifiers': custom_mods, 'calls': calls,
                'body_preview': func_body[:500] if func_body else ''
            })
        return funcs

    def _extract_constructor(self, body):
        m = re.search(r'constructor\s*\(([^)]*)\)', body)
        return {'raw_params': m.group(1).strip()} if m else None

    def _build_result(self):
        all_items = self.contracts + self.interfaces + self.libraries
        return {
            'repo_path': str(self.repo_path),
            'parsed_at': datetime.now().isoformat(),
            'stats': {
                'sol_files': len(set(c['file'] for c in all_items)),
                'contracts': len(self.contracts), 'interfaces': len(self.interfaces), 'libraries': len(self.libraries),
                'total_functions': sum(len(c['functions']) for c in all_items),
                'total_events': sum(len(c['events']) for c in all_items),
                'total_errors': sum(len(c['errors']) for c in all_items),
                'total_state_vars': sum(len(c['state_variables']) for c in all_items),
            },
            'contracts': self.contracts, 'interfaces': self.interfaces, 'libraries': self.libraries,
            'file_constants': self.constants,
        }


# ============================================================
# AI CLIENT — Calls OpenAI-compatible API
# ============================================================

class AIClient:
    def __init__(self, api_url: str, api_key: str, model: str):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.model = model
        self.call_count = 0
        self.total_tokens = 0

    def chat(self, system: str, user: str, max_tokens: int = 2000) -> str:
        """Make a chat completion API call."""
        self.call_count += 1
        url = f"{self.api_url}/chat/completions"
        payload = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "max_tokens": max_tokens,
            "temperature": 0.3
        }).encode('utf-8')

        req = Request(url, data=payload, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        })

        for attempt in range(3):
            try:
                with urlopen(req, timeout=60) as resp:
                    data = json.loads(resp.read().decode())
                    self.total_tokens += data.get('usage', {}).get('total_tokens', 0)
                    return data['choices'][0]['message']['content']
            except HTTPError as e:
                if e.code == 429:
                    wait = min(2 ** attempt * 5, 30)
                    print(f"  ⏳ Rate limited, waiting {wait}s...", file=sys.stderr)
                    time.sleep(wait)
                else:
                    body = e.read().decode() if e.readable() else ''
                    print(f"  ⚠ API error {e.code}: {body[:200]}", file=sys.stderr)
                    if attempt == 2: return f"[API Error: {e.code}]"
            except Exception as e:
                print(f"  ⚠ API error: {e}", file=sys.stderr)
                if attempt == 2: return f"[Error: {e}]"
            time.sleep(2)
        return "[Failed after retries]"


# ============================================================
# AI ANALYSIS — Full mode and Filtered mode
# ============================================================

def ai_analyze_full(client: AIClient, contract: dict) -> dict:
    """AI translates EVERY function to plain-English logic."""
    print(f"  🤖 AI analyzing {contract['name']} ({len(contract['functions'])} functions)...")

    # Build function list for AI
    fn_descriptions = []
    for i, fn in enumerate(contract['functions']):
        fn_descriptions.append(
            f"[{i}] function {fn['name']}({fn['raw_params']}) "
            f"{'external' if fn['visibility']=='external' else fn['visibility']} "
            f"{'payable' if fn['mutability']=='payable' else fn['mutability']} "
            f"{'virtual' if fn['is_virtual'] else ''} "
            f"returns({fn['raw_returns']}) "
            f"modifiers: {', '.join(fn['custom_modifiers'])} "
            f"calls: {', '.join(fn['calls']) if fn['calls'] else 'none'}"
        )

    # Include state vars and structs for context
    state_context = ""
    if contract['state_variables']:
        state_context = "\nState variables:\n" + "\n".join(
            f"  {sv['type']} {sv['name']} ({sv['visibility']})" for sv in contract['state_variables'][:30]
        )
    if contract['structs']:
        struct_lines = []
        for s in contract['structs']:
            fields = ', '.join(ft['type'] + ' ' + ft['name'] for ft in s['fields'])
            struct_lines.append(f"  struct {s['name']} {{ {fields} }}")
        state_context += "\nStructs:\n" + "\n".join(struct_lines)

    system_prompt = """You are a smart contract security auditor. For each function, provide a JSON analysis.

Return ONLY valid JSON array, no markdown, no explanation. Format:
[
  {
    "index": 0,
    "logic": "Plain English step-by-step logic of what this function does",
    "risk": "LOW|MEDIUM|HIGH|CRITICAL",
    "risk_reason": "Why this risk level",
    "attack_surface": "How an attacker could exploit this (if applicable)",
    "questions": ["Key audit questions for this function"]
  }
]

Guidelines:
- logic: Break down into numbered steps. No code syntax. Pure human language.
- risk: CRITICAL = funds at risk, HIGH = significant attack surface, MEDIUM = potential issues, LOW = safe/view/helper
- attack_surface: Specific exploit scenarios. Empty if LOW risk.
- questions: What an auditor should verify. 1-3 questions per function."""

    user_prompt = f"""Contract: {contract['name']}
Kind: {contract['kind']}
Inherits: {', '.join(contract['inheritance'])}
{state_context}

Functions:
{chr(10).join(fn_descriptions)}"""

    response = client.chat(system_prompt, user_prompt, max_tokens=4000)

    # Parse AI response
    try:
        # Try to extract JSON from response
        json_match = re.search(r'\[.*\]', response, re.DOTALL)
        if json_match:
            analyses = json.loads(json_match.group())
        else:
            analyses = json.loads(response)
    except json.JSONDecodeError:
        print(f"  ⚠ Failed to parse AI response for {contract['name']}", file=sys.stderr)
        analyses = []

    # Map analyses back to functions
    analysis_map = {}
    for a in analyses:
        idx = a.get('index', -1)
        if 0 <= idx < len(contract['functions']):
            analysis_map[idx] = a

    # Fill gaps
    for i in range(len(contract['functions'])):
        if i not in analysis_map:
            analysis_map[i] = {
                'index': i,
                'logic': f"Function: {contract['functions'][i]['name']}",
                'risk': 'LOW',
                'risk_reason': 'No analysis available',
                'attack_surface': '',
                'questions': []
            }

    return {
        'contract_name': contract['name'],
        'analyses': [analysis_map[i] for i in range(len(contract['functions']))]
    }


def ai_analyze_filtered(client: AIClient, contract: dict) -> dict:
    """AI filters high-risk functions and provides deep exploit analysis."""
    print(f"  🎯 AI filtering {contract['name']} ({len(contract['functions'])} functions)...")

    fn_descriptions = []
    for i, fn in enumerate(contract['functions']):
        fn_descriptions.append(
            f"[{i}] function {fn['name']}({fn['raw_params']}) "
            f"{fn['visibility']} {fn['mutability']} "
            f"calls: {', '.join(fn['calls']) if fn['calls'] else 'none'}"
        )

    state_context = ""
    if contract['state_variables']:
        state_context = "\nState variables:\n" + "\n".join(
            f"  {sv['type']} {sv['name']} ({sv['visibility']})" for sv in contract['state_variables'][:30]
        )

    system_prompt = """You are an elite smart contract security auditor. You only care about functions that matter for security.

Return ONLY valid JSON object, no markdown. Format:
{
  "high_risk_functions": [
    {
      "index": 0,
      "function_name": "withdraw",
      "risk": "CRITICAL",
      "logic": "Detailed step-by-step logic in plain English",
      "vulnerability": "Specific vulnerability name (e.g., Reentrancy, Oracle Manipulation)",
      "exploit_path": "Step-by-step attack scenario. How an attacker exploits this.",
      "exploit_difficulty": "EASY|MEDIUM|HARD",
      "exploit_impact": "What the attacker gains",
      "fix": "How to fix or mitigate",
      "questions": ["Specific audit questions"]
    }
  ],
  "low_risk_summary": "Brief note on why remaining functions are low risk",
  "overall_assessment": "Overall security assessment of this contract (2-3 sentences)"
}

Guidelines:
- ONLY include functions with MEDIUM, HIGH, or CRITICAL risk
- Skip view/pure/getter functions unless they have security implications
- Skip standard ERC20 functions (transfer, approve) unless overridden
- exploit_path: Be specific. Include transaction flow, flash loans, price manipulation, etc.
- Think like an attacker with unlimited capital and technical skill."""

    user_prompt = f"""Contract: {contract['name']}
Kind: {contract['kind']}
Inherits: {', '.join(contract['inheritance'])}
{state_context}

All functions:
{chr(10).join(fn_descriptions)}"""

    response = client.chat(system_prompt, user_prompt, max_tokens=4000)

    try:
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
        else:
            result = json.loads(response)
    except json.JSONDecodeError:
        print(f"  ⚠ Failed to parse AI response for {contract['name']}", file=sys.stderr)
        result = {'high_risk_functions': [], 'low_risk_summary': 'Parse error', 'overall_assessment': ''}

    result['contract_name'] = contract['name']
    return result


# ============================================================
# HTML GENERATOR
# ============================================================

def generate_html_raw(data: dict, repo_name: str) -> str:
    """Generate HTML without AI analysis (raw mode)."""
    return _generate_html(data, repo_name, mode='raw')


def generate_html_full(data: dict, repo_name: str, ai_results: list) -> str:
    """Generate HTML with AI analysis for every function."""
    return _generate_html(data, repo_name, mode='full', ai_results=ai_results)


def generate_html_filtered(data: dict, repo_name: str, ai_results: list) -> str:
    """Generate HTML with AI-filtered high-risk analysis only."""
    return _generate_html(data, repo_name, mode='filtered', ai_results=ai_results)


def _generate_html(data: dict, repo_name: str, mode: str = 'raw', ai_results: list = None) -> str:
    """Unified HTML generator for all modes."""
    stats = data['stats']
    ai_map = {}
    if ai_results:
        for r in ai_results:
            ai_map[r.get('contract_name', '')] = r

    all_items = data['contracts'] + data['interfaces'] + data['libraries']

    # Build sections
    sections_html = []
    for c in all_items:
        ai = ai_map.get(c['name'])
        sections_html.append(_build_section(c, mode, ai))

    # Cross-refs
    contract_names = {c['name'] for c in all_items}
    cross_calls = defaultdict(set)
    for c in all_items:
        for fn in c['functions']:
            for call in fn.get('calls', []):
                tc = call.split('.')[0]
                if tc in contract_names and tc != c['name']:
                    cross_calls[c['name']].add(call)

    cross_html = ''
    if cross_calls:
        cross_html = '<div class="cross-map" id="cross-refs"><h3>🔗 Cross-Contract Calls</h3>'
        for src, tgts in sorted(cross_calls.items()):
            for tgt in sorted(tgts):
                cross_html += f'<div class="cross-row"><span class="cross-from">{src}</span><span class="cross-arrow">→</span><span class="cross-to">{tgt}</span></div>'
        cross_html += '</div>'

    # Structs
    structs_html = ''
    has_structs = any(c['structs'] or c['enums'] for c in all_items)
    if has_structs:
        structs_html = '<div class="section" id="data-structures"><div class="section-header" onclick="toggleSection(this)"><span class="icon">🏗️</span><h2>Data Structures</h2><span class="arrow">▾</span></div><div class="section-body">'
        for c in all_items:
            if c['structs'] or c['enums']:
                structs_html += f'<div class="card"><div class="fn-name">📦 {c["name"]}</div>'
                for s in c['structs']:
                    structs_html += f'<div style="margin:8px 0"><span style="color:#e3b341;font-weight:600">struct {s["name"]}</span>'
                    for f in s['fields']:
                        structs_html += f'<div class="svar"><span class="type">{_esc(f["type"])}</span> <span class="name">{f["name"]}</span></div>'
                    structs_html += '</div>'
                for e in c['enums']:
                    structs_html += f'<div style="margin:8px 0"><span style="color:#3fb950;font-weight:600">enum {e["name"]}</span> <span style="color:#8b949e">{", ".join(e["values"])}</span></div>'
                structs_html += '</div>'
        structs_html += '</div></div>'

    # Glossary
    glossary_html = '<div class="glossary" id="glossary"><h2>📖 Contract Index</h2><div class="g-grid">'
    for c in all_items:
        glossary_html += f'<div class="g-item"><div class="g-name">{c["name"]}</div><div class="g-kind">{c["kind"]} — {len(c["functions"])} functions</div><div class="g-file">{c.get("file","")}</div></div>'
    glossary_html += '</div></div>'

    mode_label = {'raw': 'Raw Extraction', 'full': 'AI Full Analysis', 'filtered': 'AI Filtered (High-Risk Only)'}[mode]
    mode_badge = {'raw': '#3fb950', 'full': '#58a6ff', 'filtered': '#f0883e'}[mode]

    ai_stats = ''
    if ai_results:
        total_calls = sum(r.get('call_count', 0) for r in [ai_results[0]] if isinstance(r, dict)) if ai_results else 0
        ai_stats = f'<div style="margin-top:8px;font-size:12px;color:#484f58">AI calls: {sum(1 for _ in ai_results)} contract analyses</div>'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🧠 {repo_name} — Audit Mind Map ({mode_label})</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0e17;color:#e6edf3;min-height:100vh;overflow-x:hidden}}
nav{{position:fixed;top:0;left:0;right:0;background:rgba(10,14,23,0.95);backdrop-filter:blur(10px);border-bottom:1px solid #1c2333;z-index:100;padding:10px 20px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}}
nav .logo{{font-size:16px;font-weight:700;color:#58a6ff}}
nav a{{color:#8b949e;text-decoration:none;font-size:12px;padding:4px 8px;border-radius:6px;transition:all .2s}}
nav a:hover,nav a.active{{color:#fff;background:rgba(88,166,255,0.15)}}
.nav-right{{margin-left:auto;display:flex;gap:8px;align-items:center}}
.search-box{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:6px 12px;color:#e6edf3;font-size:13px;width:180px}}
.filter-btn{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:4px 10px;color:#8b949e;font-size:11px;cursor:pointer;transition:all .2s}}
.filter-btn:hover,.filter-btn.active{{background:rgba(88,166,255,0.15);color:#58a6ff;border-color:#1f6feb}}
main{{padding:70px 20px 40px;max-width:1600px;margin:0 auto}}
.hero{{text-align:center;padding:20px 0}}
.hero h1{{font-size:28px;background:linear-gradient(135deg,#58a6ff,#bc8cff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.hero p{{color:#8b949e;font-size:13px;margin-top:6px}}
.hero .stats{{display:flex;gap:14px;justify-content:center;margin-top:14px;flex-wrap:wrap}}
.hero .stat{{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:8px 14px;text-align:center}}
.hero .stat .num{{font-size:20px;font-weight:700;color:#58a6ff}}
.hero .stat .label{{font-size:10px;color:#484f58}}
.mode-badge{{display:inline-block;padding:3px 12px;border-radius:20px;font-size:12px;font-weight:600;margin-top:8px}}
.section{{margin:16px 0}}
.section-header{{display:flex;align-items:center;gap:10px;padding:12px 16px;background:#161b22;border:1px solid #21262d;border-radius:12px;cursor:pointer;user-select:none;transition:all .2s}}
.section-header:hover{{border-color:#30363d}}
.section-header h2{{font-size:14px;font-weight:600;flex:1}}
.section-header .badge{{padding:2px 8px;border-radius:12px;font-size:10px;font-weight:600}}
.section-header .count{{color:#484f58;font-size:11px}}
.section-header .arrow{{color:#484f58;font-size:12px;transition:transform .3s}}
.section-header.collapsed .arrow{{transform:rotate(-90deg)}}
.section-body{{padding:10px 0}}
.section-body.hidden{{display:none}}
.card{{background:#0d1117;border:1px solid #1c2333;border-radius:10px;padding:14px;margin-bottom:8px;transition:all .2s}}
.card:hover{{border-color:#30363d}}
.fn-name{{font-weight:700;font-size:13px;color:#e6edf3;margin-bottom:4px}}
.fn-meta{{font-size:11px;color:#484f58;display:flex;gap:8px;flex-wrap:wrap;align-items:center}}
.badge-vis{{display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:600}}
.b-ext{{background:rgba(88,166,255,0.15);color:#58a6ff}}
.b-pub{{background:rgba(63,185,80,0.15);color:#3fb950}}
.b-int{{background:rgba(227,179,65,0.15);color:#e3b341}}
.b-pri{{background:rgba(218,54,51,0.15);color:#f85149}}
.risk{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:700}}
.r-crit{{background:#da3633;color:#fff}}
.r-high{{background:#d29922;color:#000}}
.r-med{{background:#e3b341;color:#000}}
.r-low{{background:#3fb950;color:#000}}
.ai-logic{{background:rgba(88,166,255,0.05);border:1px solid rgba(88,166,255,0.1);border-radius:8px;padding:10px 14px;margin-top:8px;font-size:12px;line-height:1.7;color:#8b949e}}
.ai-logic .step{{display:block;padding:1px 0}}
.ai-logic .step::before{{content:"→ ";color:#30363d}}
.ai-exploit{{background:rgba(218,54,51,0.08);border:1px solid rgba(218,54,51,0.2);border-radius:8px;padding:10px 14px;margin-top:8px;font-size:12px}}
.ai-exploit .title{{color:#f85149;font-weight:700;margin-bottom:4px}}
.ai-exploit .body{{color:#ffa198;line-height:1.6}}
.ai-fix{{background:rgba(63,185,80,0.08);border:1px solid rgba(63,185,80,0.2);border-radius:8px;padding:10px 14px;margin-top:8px;font-size:12px;color:#7ee787}}
.ai-questions{{background:rgba(188,140,255,0.08);border:1px solid rgba(188,140,255,0.2);border-radius:8px;padding:10px 14px;margin-top:8px;font-size:12px;color:#d2a8ff}}
.ai-overall{{background:rgba(88,166,255,0.08);border:1px solid rgba(88,166,255,0.2);border-radius:10px;padding:14px;margin-top:10px;font-size:13px;color:#79c0ff;line-height:1.6}}
.svar{{display:flex;gap:8px;padding:2px 0;font-size:12px}}
.svar .type{{color:#79c0ff;min-width:100px}}
.svar .name{{color:#e6edf3}}
.params{{width:100%;border-collapse:collapse;margin:6px 0;font-size:11px;display:none}}
.params th{{text-align:left;color:#484f58;padding:3px 6px;border-bottom:1px solid #21262d}}
.params td{{padding:3px 6px;color:#8b949e}}
.ptype{{color:#79c0ff}}
.toggle-p{{color:#484f58;font-size:11px;cursor:pointer}}
.toggle-p:hover{{color:#58a6ff}}
.call-link{{display:inline-block;background:rgba(188,140,255,0.08);border:1px solid rgba(188,140,255,0.15);border-radius:4px;padding:1px 6px;margin:1px;font-size:10px;color:#d2a8ff}}
.cross-map{{background:#0d1117;border:1px solid #1c2333;border-radius:12px;padding:16px;margin:16px 0}}
.cross-map h3{{color:#d2a8ff;margin-bottom:10px}}
.cross-row{{display:flex;align-items:center;gap:8px;padding:4px 0;font-size:12px}}
.cross-from{{color:#58a6ff;font-weight:600;min-width:120px}}
.cross-arrow{{color:#484f58}}
.cross-to{{color:#d2a8ff}}
.glossary{{margin:24px 0;padding:20px;background:#0d1117;border:1px solid #1c2333;border-radius:12px}}
.glossary h2{{color:#58a6ff;margin-bottom:12px;font-size:16px}}
.g-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:6px}}
.g-item{{padding:8px 10px;background:#161b22;border-radius:6px;border-left:3px solid #21262d;font-size:12px}}
.g-name{{color:#79c0ff;font-weight:700}}
.g-kind{{color:#484f58;font-size:10px}}
.g-file{{color:#30363d;font-size:10px}}
.footer{{text-align:center;margin-top:30px;padding:16px;color:#21262d;font-size:11px}}
@media(max-width:768px){{nav{{gap:4px;padding:8px}}.search-box{{width:100px}}.hero h1{{font-size:20px}}}}
</style>
</head>
<body>
<nav>
  <div class="logo">🧠 {repo_name}</div>
  <a href="#contracts">Contracts</a>
  <a href="#interfaces">Interfaces</a>
  <a href="#libraries">Libraries</a>
  <a href="#cross-refs">Cross-Refs</a>
  <a href="#glossary">Index</a>
  <div class="nav-right">
    <button class="filter-btn active" onclick="filterVis('all')">All</button>
    <button class="filter-btn" onclick="filterVis('external')">Ext</button>
    <button class="filter-btn" onclick="filterVis('public')">Pub</button>
    <button class="filter-btn" onclick="filterVis('internal')">Int</button>
    <input type="text" class="search-box" placeholder="Search..." id="searchInput">
  </div>
</nav>
<main>
<div class="hero">
  <h1>🧠 {repo_name}</h1>
  <div class="mode-badge" style="background:{mode_badge}22;color:{mode_badge};border:1px solid {mode_badge}44">{mode_label}</div>
  <div class="stats">
    <div class="stat"><div class="num">{stats['sol_files']}</div><div class="label">Files</div></div>
    <div class="stat"><div class="num">{stats['contracts']}</div><div class="label">Contracts</div></div>
    <div class="stat"><div class="num">{stats['interfaces']}</div><div class="label">Interfaces</div></div>
    <div class="stat"><div class="num">{stats['libraries']}</div><div class="label">Libraries</div></div>
    <div class="stat"><div class="num">{stats['total_functions']}</div><div class="label">Functions</div></div>
    <div class="stat"><div class="num">{stats['total_state_vars']}</div><div class="label">State Vars</div></div>
    <div class="stat"><div class="num">{stats['total_events']}</div><div class="label">Events</div></div>
  </div>
  {ai_stats}
</div>
{"".join(sections_html)}
{cross_html}
{structs_html}
{glossary_html}
<div class="footer">
  <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")} — Solidity Mind Map v2.0 — Mode: {mode_label}</p>
</div>
</main>
<script>
function toggleSection(el){{el.classList.toggle('collapsed');const b=el.nextElementSibling;if(b)b.classList.toggle('hidden')}}
function filterVis(v){{document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));event.target.classList.add('active');document.querySelectorAll('.card').forEach(c=>{{if(v==='all'){{c.style.display='';return}}const el=c.querySelector('.badge-vis');c.style.display=el&&el.textContent.toLowerCase().includes(v)?'':'none'}})}}
document.getElementById('searchInput').addEventListener('input',e=>{{const q=e.target.value.toLowerCase();document.querySelectorAll('.card,.g-item').forEach(el=>{{el.style.display=el.textContent.toLowerCase().includes(q)||q===''?'':'none'}})}});
document.querySelectorAll('.toggle-p').forEach(el=>{{el.addEventListener('click',()=>{{const t=el.closest('.card').querySelector('.params');if(t){{t.style.display=t.style.display==='none'?'':'none';el.textContent=t.style.display==='none'?'[params]':'[hide]'}}}})}});
</script>
</body>
</html>'''


def _build_section(c: dict, mode: str, ai: dict = None) -> str:
    """Build HTML for one contract."""
    icon = {'contract': '📄', 'interface': '🔌', 'library': '📚'}.get(c['kind'], '📄')
    vis_class = {'contract': 'b-ext', 'interface': 'b-pub', 'library': 'b-int'}.get(c['kind'], 'b-ext')
    sid = c['name'].lower()
    inh = f" is {', '.join(c['inheritance'])}" if c['inheritance'] else ''

    ai_analyses = {}
    ai_filtered = None
    if ai:
        if mode == 'full' and 'analyses' in ai:
            for a in ai['analyses']:
                ai_analyses[a.get('index', -1)] = a
        elif mode == 'filtered':
            ai_filtered = ai

    html = f'<div class="section" id="{sid}"><div class="section-header" onclick="toggleSection(this)"><span class="icon">{icon}</span><h2>{c["name"]}{inh}</h2><span class="badge {vis_class}">{c["kind"]}</span><span class="count">F:{len(c["functions"])} S:{len(c["state_variables"])}</span><span class="arrow">▾</span></div><div class="section-body">'
    html += f'<div style="color:#484f58;font-size:10px;margin-bottom:8px">📁 {c["file"]}</div>'

    # AI Overall Assessment (filtered mode)
    if ai_filtered and ai_filtered.get('overall_assessment'):
        html += f'<div class="ai-overall"><strong>📋 Overall Assessment:</strong><br>{ai_filtered["overall_assessment"]}</div>'

    # Constructor
    if c.get('constructor'):
        html += f'<div class="card"><div class="fn-name">constructor({c["constructor"].get("raw_params","")})</div><div class="fn-meta"><span style="color:#f0883e">constructor</span></div></div>'

    # Receive/Fallback
    if c.get('receive_eth'):
        html += '<div class="card"><div class="fn-name">receive() external payable</div></div>'
    if c.get('fallback'):
        html += '<div class="card"><div class="fn-name">fallback() external payable</div></div>'

    # State vars
    if c['state_variables']:
        html += '<div class="card"><div class="fn-name">📦 State Variables</div><div style="padding:6px 0">'
        for sv in c['state_variables']:
            vc = {'public': 'b-pub', 'internal': 'b-int', 'private': 'b-pri'}.get(sv['visibility'], 'b-int')
            html += f'<div class="svar"><span class="type">{_esc(sv["type"])}</span><span class="name">{sv["name"]}</span><span class="badge-vis {vc}">{sv["visibility"]}</span></div>'
        html += '</div></div>'

    # Modifiers
    if c['modifiers']:
        html += '<div class="card"><div class="fn-name">🔒 Modifiers</div><div style="padding:6px 0">'
        for mod in c['modifiers']:
            html += f'<div style="font-size:12px;color:#d2a8ff;padding:2px 0">modifier {mod["name"]}({mod["params"]})</div>'
        html += '</div></div>'

    # Functions
    for i, fn in enumerate(c['functions']):
        vb = {'external': 'b-ext', 'public': 'b-pub', 'internal': 'b-int', 'private': 'b-pri'}.get(fn['visibility'], 'b-int')
        mut = fn['mutability'] if fn['mutability'] != 'nonpayable' else ''
        flags = []
        if fn['is_virtual']: flags.append('virtual')
        if fn['is_override']: flags.append('override')

        # Risk badge
        risk_html = ''
        nl = fn['name'].lower()
        if any(k in nl for k in ['liquidate', 'oracle', 'price']): risk_html = '<span class="risk r-crit">🔴</span>'
        elif any(k in nl for k in ['flash', 'borrow']): risk_html = '<span class="risk r-high">🟡</span>'
        elif any(k in nl for k in ['withdraw', 'set', 'admin', 'owner', 'enable', 'transfer']): risk_html = '<span class="risk r-med">🟡</span>'

        ai_analysis = ai_analyses.get(i)

        # Override risk with AI assessment
        if ai_analysis:
            ai_risk = ai_analysis.get('risk', '').upper()
            if ai_risk == 'CRITICAL': risk_html = '<span class="risk r-crit">🔴 CRITICAL</span>'
            elif ai_risk == 'HIGH': risk_html = '<span class="risk r-high">🟡 HIGH</span>'
            elif ai_risk == 'MEDIUM': risk_html = '<span class="risk r-med">🟡 MEDIUM</span>'
            elif ai_risk == 'LOW': risk_html = '<span class="risk r-low">🟢 LOW</span>'

        html += f'<div class="card" data-vis="{fn["visibility"]}"><div class="fn-name">{fn["name"]}({fn["raw_params"]}) {risk_html}</div><div class="fn-meta"><span class="badge-vis {vb}">{fn["visibility"]}</span>{"<span>" + mut + "</span>" if mut else ""}{"<span>" + " ".join(flags) + "</span>" if flags else ""}<span class="toggle-p">[params]</span></div>'

        # Params
        if fn['raw_params']:
            html += f'<table class="params"><tr><th>Param</th></tr><tr><td class="ptype">{_esc(fn["raw_params"])}</td></tr></table>'
        if fn['raw_returns']:
            html += f'<div style="font-size:11px;color:#3fb950">returns: {_esc(fn["raw_returns"])}</div>'

        # Calls
        if fn.get('calls'):
            html += '<div style="margin-top:4px;font-size:10px">🔗 ' + ' '.join(f'<span class="call-link">{c_}</span>' for c_ in fn['calls']) + '</div>'

        # AI FULL MODE: logic + risk + questions for every function
        if ai_analysis and mode == 'full':
            logic = ai_analysis.get('logic', '')
            if logic:
                steps = logic.split('\n') if '\n' in logic else [logic]
                html += '<div class="ai-logic">' + ''.join(f'<span class="step">{_esc(s.strip())}</span>' for s in steps if s.strip()) + '</div>'
            if ai_analysis.get('attack_surface'):
                html += f'<div class="ai-exploit"><div class="title">⚔ Attack Surface</div><div class="body">{_esc(ai_analysis["attack_surface"])}</div></div>'
            if ai_analysis.get('questions'):
                html += '<div class="ai-questions">❓ ' + '<br>'.join(f'• {_esc(q)}' for q in ai_analysis['questions']) + '</div>'

        html += '</div>'

    # AI FILTERED MODE: high-risk functions with deep analysis
    if ai_filtered and ai_filtered.get('high_risk_functions'):
        html += '<div class="card" style="border-color:#da363344"><div class="fn-name" style="color:#f85149">🎯 AI-Identified High-Risk Functions</div>'
        for hr in ai_filtered['high_risk_functions']:
            vuln = hr.get('vulnerability', 'Unknown')
            risk = hr.get('risk', 'HIGH')
            rc = {'CRITICAL': 'r-crit', 'HIGH': 'r-high', 'MEDIUM': 'r-med'}.get(risk, 'r-high')
            diff = hr.get('exploit_difficulty', '?')

            html += f'<div style="margin:12px 0;padding:12px;background:rgba(218,54,51,0.05);border-radius:8px">'
            html += f'<div style="font-weight:700;color:#f85149;font-size:13px">{hr.get("function_name", "?")}() <span class="risk {rc}">{risk}</span> <span style="font-size:11px;color:#ffa198">| {vuln} | Difficulty: {diff}</span></div>'

            logic = hr.get('logic', '')
            if logic:
                html += f'<div class="ai-logic"><strong style="color:#58a6ff">Logic:</strong><br>' + ''.join(f'<span class="step">{_esc(s.strip())}</span>' for s in logic.split('\n') if s.strip()) + '</div>'

            exploit = hr.get('exploit_path', '')
            if exploit:
                html += f'<div class="ai-exploit"><div class="title">⚔ Exploit Path</div><div class="body">{_esc(exploit)}</div></div>'

            impact = hr.get('exploit_impact', '')
            if impact:
                html += f'<div style="font-size:12px;color:#f0883e;margin-top:6px">💥 Impact: {_esc(impact)}</div>'

            fix = hr.get('fix', '')
            if fix:
                html += f'<div class="ai-fix">🔧 Fix: {_esc(fix)}</div>'

            qs = hr.get('questions', [])
            if qs:
                html += '<div class="ai-questions">❓ ' + '<br>'.join(f'• {_esc(q)}' for q in qs) + '</div>'

            html += '</div>'
        html += '</div>'

    if ai_filtered and ai_filtered.get('low_risk_summary'):
        html += f'<div class="card"><div class="fn-name" style="color:#3fb950">🟢 Remaining Functions</div><div style="font-size:12px;color:#8b949e;padding:6px 0">{_esc(ai_filtered["low_risk_summary"])}</div></div>'

    # Events
    if c['events']:
        html += '<div class="card"><div class="fn-name">📢 Events</div><div style="padding:6px 0">'
        for ev in c['events']:
            html += f'<div style="font-size:12px;color:#3fb950;padding:2px 0">event {ev["name"]}({ev["raw"]})</div>'
        html += '</div></div>'

    # Errors
    if c['errors']:
        html += '<div class="card"><div class="fn-name">❌ Custom Errors</div><div style="padding:6px 0">'
        for er in c['errors']:
            html += f'<div style="font-size:12px;color:#f85149;padding:2px 0">error {er["name"]}({er["raw"]})</div>'
        html += '</div></div>'

    html += '</div></div>'
    return html


def _esc(t: str) -> str:
    return t.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='Solidity → Interactive HTML Audit Mind Map')
    parser.add_argument('repo', help='GitHub URL or local path')
    parser.add_argument('--mode', choices=['raw', 'full', 'filtered'], default='raw', help='Output mode')
    parser.add_argument('--output', '-o', help='Output HTML file')
    parser.add_argument('--api-url', default=os.environ.get('MINDMAP_API_URL', 'https://openrouter.ai/api/v1'), help='OpenAI-compatible API URL')
    parser.add_argument('--api-key', default=os.environ.get('MINDMAP_API_KEY', os.environ.get('OPENROUTER_API_KEY', '')), help='API key')
    parser.add_argument('--model', default=os.environ.get('MINDMAP_MODEL', 'anthropic/claude-sonnet-4'), help='LLM model')
    args = parser.parse_args()

    # Clone if URL
    if args.repo.startswith('http'):
        repo_name = args.repo.split('/')[-1].replace('.git', '')
        tmp = tempfile.mkdtemp(prefix='sol_mm_')
        repo_path = os.path.join(tmp, repo_name)
        print(f"📥 Cloning {args.repo}...")
        subprocess.run(['git', 'clone', '--depth', '1', args.repo, repo_path], check=True, capture_output=True)
    else:
        repo_path = args.repo
        repo_name = Path(args.repo).name

    output = args.output or f"{repo_name}_AuditMindMap.html"

    # Parse
    print(f"🔍 Parsing {repo_path}...")
    parser = SolidityParser(repo_path)
    data = parser.parse_all()
    s = data['stats']
    print(f"📊 {s['sol_files']} files | {s['contracts']} contracts | {s['interfaces']} interfaces | {s['libraries']} libraries | {s['total_functions']} functions | {s['total_state_vars']} state vars")

    # AI analysis
    ai_results = []
    if args.mode in ('full', 'filtered'):
        if not args.api_key:
            print("❌ --api-key required for AI modes (or set MINDMAP_API_KEY / OPENROUTER_API_KEY env)")
            sys.exit(1)

        client = AIClient(args.api_url, args.api_key, args.model)
        all_items = data['contracts'] + data['interfaces'] + data['libraries']

        # Only analyze items with functions
        items_with_fns = [c for c in all_items if c['functions']]
        print(f"🤖 AI analyzing {len(items_with_fns)} contracts ({args.mode} mode)...")

        for i, c in enumerate(items_with_fns):
            print(f"  [{i+1}/{len(items_with_fns)}] {c['name']} ({len(c['functions'])} functions)")
            if args.mode == 'full':
                result = ai_analyze_full(client, c)
            else:
                result = ai_analyze_filtered(client, c)
            ai_results.append(result)
            time.sleep(1)  # Rate limit buffer

        print(f"✅ AI analysis complete. {client.call_count} API calls, {client.total_tokens} tokens used.")

    # Generate HTML
    print(f"📄 Generating HTML ({args.mode} mode)...")
    if args.mode == 'raw':
        html = generate_html_raw(data, repo_name)
    elif args.mode == 'full':
        html = generate_html_full(data, repo_name, ai_results)
    else:
        html = generate_html_filtered(data, repo_name, ai_results)

    Path(output).write_text(html, encoding='utf-8')
    print(f"✅ Saved to {output} ({len(html):,} bytes)")

    # Save JSON
    json_out = Path(output).with_suffix('.json')
    json_out.write_text(json.dumps({'data': data, 'ai_results': ai_results}, indent=2, default=str), encoding='utf-8')
    print(f"📊 JSON: {json_out}")


if __name__ == '__main__':
    main()
