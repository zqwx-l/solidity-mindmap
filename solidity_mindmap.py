#!/usr/bin/env python3
"""
Solidity → Interactive HTML Audit Mind Map Generator
=====================================================
Full detail extraction — NO filtering. Every function, state variable, event, error, struct, enum.

Usage:
    python3 solidity_mindmap.py <github_url_or_local_path> [output.html]

Examples:
    python3 solidity_mindmap.py https://github.com/morpho-org/morpho-blue
    python3 solidity_mindmap.py /root/audit-mindmap/morpho-blue
    python3 solidity_mindmap.py https://github.com/morpho-org/morpho-blue morpho_audit.html
"""

import os
import re
import sys
import json
import hashlib
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime
from collections import defaultdict


# ============================================================
# SOLIDITY PARSER — Full extraction, no filtering
# ============================================================

class SolidityParser:
    """Parse Solidity files and extract ALL contract information."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.contracts = []
        self.interfaces = []
        self.libraries = []
        self.structs = []
        self.enums = []
        self.events = []
        self.errors = []
        self.free_functions = []
        self.constants = []
        self.imports = []

    def parse_all(self):
        """Parse all .sol files in the repo."""
        sol_files = sorted(self.repo_path.rglob("*.sol"))
        # Skip node_modules, test, mock directories for cleaner output
        skip = {'node_modules', '.git', '__pycache__'}
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
        """Parse a single .sol file."""
        # Remove single-line comments
        content_clean = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
        # Remove multi-line comments (but preserve newlines for line counting)
        content_clean = re.sub(r'/\*.*?\*/', lambda m: m.group().count('\n') * '\n', content_clean, flags=re.DOTALL)

        # Extract imports
        for m in re.finditer(r'import\s+(?:(?:"([^"]+)"|{[^}]+}\s+from\s+"([^"]+)"))', content):
            self.imports.append({
                'file': filepath,
                'import': m.group(1) or m.group(2)
            })

        # Extract file-level constants
        for m in re.finditer(r'(?:uint256|uint128|uint64|uint8|int256|bytes32|address|bool|string)\s+(?:public\s+)?(?:constant|immutable)\s+(\w+)\s*=\s*([^;]+);', content_clean):
            self.constants.append({
                'name': m.group(1),
                'value': m.group(2).strip(),
                'file': filepath
            })

        # Extract contracts, interfaces, libraries
        pattern = r'(contract|interface|library)\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{'
        for m in re.finditer(pattern, content_clean):
            kind = m.group(1)
            name = m.group(2)
            inheritance = [x.strip() for x in m.group(3).split(',')] if m.group(3) else []

            # Find the body of this contract
            start = m.end()
            body = self._extract_braces(content_clean, start - 1)

            item = {
                'name': name,
                'kind': kind,
                'inheritance': inheritance,
                'file': filepath,
                'state_variables': self._extract_state_vars(body),
                'modifiers': self._extract_modifiers(body),
                'events': self._extract_events(body),
                'errors': self._extract_errors(body),
                'structs': self._extract_structs(body),
                'enums': self._extract_enums(body),
                'functions': self._extract_functions(body),
                'constructor': self._extract_constructor(body),
                'receive_eth': self._extract_receive_fallback(body, 'receive'),
                'fallback': self._extract_receive_fallback(body, 'fallback'),
            }

            if kind == 'contract':
                self.contracts.append(item)
            elif kind == 'interface':
                self.interfaces.append(item)
            elif kind == 'library':
                self.libraries.append(item)

    def _extract_braces(self, text: str, start: int) -> str:
        """Extract content between matching braces."""
        if start >= len(text) or text[start] != '{':
            return ''
        depth = 0
        for i in range(start, len(text)):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    return text[start + 1:i]
        return text[start + 1:]

    def _extract_state_vars(self, body: str) -> list:
        """Extract ALL state variables."""
        vars_found = []
        # Pattern: type [visibility] [constant|immutable] name [= value];
        pattern = r'(?:^|\n)\s*(mapping\([^)]+\)\s+(?:public|internal|private)?\s*(\w+))|(?:((?:uint256|uint128|uint64|uint8|int256|bytes32|bytes|address|bool|string|[\w.]+)(?:\[\])?))\s+(public|internal|private|constant|immutable)?\s*(?:constant|immutable)?\s*(\w+)\s*(?:=\s*[^;]+)?\s*;'
        for m in re.finditer(pattern, body):
            if m.group(2):  # mapping
                vars_found.append({
                    'type': m.group(1).strip(),
                    'name': m.group(2),
                    'visibility': 'public' if 'public' in m.group(1) else 'internal'
                })
            elif m.group(5):
                vis = m.group(4) if m.group(4) in ('public', 'internal', 'private') else 'internal'
                vars_found.append({
                    'type': m.group(3).strip(),
                    'name': m.group(5),
                    'visibility': vis
                })

        # Also catch mappings more broadly
        for m in re.finditer(r'mapping\s*\([^)]+\)\s+(?:public\s+|internal\s+|private\s+)?(\w+)', body):
            if not any(v['name'] == m.group(1) for v in vars_found):
                vars_found.append({
                    'type': 'mapping(...)',
                    'name': m.group(1),
                    'visibility': 'public'
                })

        return vars_found

    def _extract_modifiers(self, body: str) -> list:
        """Extract ALL modifiers."""
        mods = []
        for m in re.finditer(r'modifier\s+(\w+)(?:\(([^)]*)\))?\s*(?:override\s*(?:\([^)]*\))?\s*)?\{', body):
            mods.append({
                'name': m.group(1),
                'params': m.group(2) or ''
            })
        return mods

    def _extract_events(self, body: str) -> list:
        """Extract ALL events."""
        events = []
        for m in re.finditer(r'event\s+(\w+)\s*\(([^)]*)\)', body):
            params = self._parse_params(m.group(2))
            events.append({
                'name': m.group(1),
                'params': params,
                'raw': m.group(2).strip()
            })
        return events

    def _extract_errors(self, body: str) -> list:
        """Extract ALL custom errors."""
        errors = []
        for m in re.finditer(r'error\s+(\w+)\s*\(([^)]*)\)', body):
            errors.append({
                'name': m.group(1),
                'params': self._parse_params(m.group(2)),
                'raw': m.group(2).strip()
            })
        return errors

    def _extract_structs(self, body: str) -> list:
        """Extract ALL structs."""
        structs = []
        for m in re.finditer(r'struct\s+(\w+)\s*\{', body):
            struct_body = self._extract_braces(body, m.end() - 1)
            fields = []
            for line in struct_body.split('\n'):
                line = line.strip().rstrip(';').strip()
                if line and not line.startswith('//'):
                    parts = line.split()
                    if len(parts) >= 2:
                        fields.append({
                            'type': ' '.join(parts[:-1]),
                            'name': parts[-1]
                        })
            structs.append({
                'name': m.group(1),
                'fields': fields
            })
        return structs

    def _extract_enums(self, body: str) -> list:
        """Extract ALL enums."""
        enums = []
        for m in re.finditer(r'enum\s+(\w+)\s*\{([^}]*)\}', body):
            values = [v.strip() for v in m.group(2).split(',') if v.strip()]
            enums.append({
                'name': m.group(1),
                'values': values
            })
        return enums

    def _extract_functions(self, body: str) -> list:
        """Extract ALL functions — no filtering."""
        funcs = []
        # Match function definitions including modifiers
        pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*((?:(?:external|public|internal|private|view|pure|payable|virtual|override|nonpayable)\s*)*)(?:returns\s*\(([^)]*)\))?\s*[^{]*\{'
        for m in re.finditer(pattern, body):
            name = m.group(1)
            raw_params = m.group(2)
            modifiers_str = m.group(3).strip()
            raw_returns = m.group(4)

            params = self._parse_params(raw_params)
            returns = self._parse_params(raw_returns) if raw_returns else []

            # Determine visibility
            visibility = 'internal'
            for v in ['external', 'public', 'internal', 'private']:
                if v in modifiers_str.split():
                    visibility = v
                    break

            # Determine mutability
            mutability = 'nonpayable'
            for mv in ['view', 'pure', 'payable']:
                if mv in modifiers_str.split():
                    mutability = mv
                    break

            is_virtual = 'virtual' in modifiers_str.split()
            is_override = 'override' in modifiers_str

            # Extract custom modifiers (not visibility/mutability keywords)
            known = {'external', 'public', 'internal', 'private', 'view', 'pure',
                      'payable', 'virtual', 'override', 'nonpayable', 'returns'}
            custom_mods = []
            for word in modifiers_str.split():
                base = word.rstrip('(').strip()
                if base not in known and base:
                    custom_mods.append(base)

            # Extract function body for cross-call analysis
            func_start = m.end() - 1
            func_body = self._extract_braces(body, func_start)

            # Find external/internal calls
            calls = self._find_calls(func_body)

            funcs.append({
                'name': name,
                'params': params,
                'returns': returns,
                'visibility': visibility,
                'mutability': mutability,
                'is_virtual': is_virtual,
                'is_override': is_override,
                'custom_modifiers': custom_mods,
                'calls': calls,
                'raw_params': raw_params.strip(),
                'raw_returns': raw_returns.strip() if raw_returns else ''
            })

        return funcs

    def _extract_constructor(self, body: str) -> dict | None:
        """Extract constructor if present."""
        m = re.search(r'constructor\s*\(([^)]*)\)\s*[^{]*\{', body)
        if m:
            return {
                'params': self._parse_params(m.group(1)),
                'raw_params': m.group(1).strip()
            }
        return None

    def _extract_receive_fallback(self, body: str, kind: str) -> bool:
        """Check if receive() or fallback() exists."""
        return bool(re.search(rf'{kind}\s*\(\s*\)\s*(?:external\s+)?(?:payable\s+)?\{{', body))

    def _find_calls(self, body: str) -> list:
        """Find external/internal contract calls within function body."""
        calls = []
        # Pattern: ContractName.functionName or IContractName.functionName
        for m in re.finditer(r'(\w+)\.(\w+)\s*\(', body):
            contract = m.group(1)
            func = m.group(2)
            # Skip common non-contract calls
            skip = {'msg', 'block', 'tx', 'abi', 'type', 'this', 'super',
                     'require', 'assert', 'revert', 'emit', 'keccak256',
                     'sha256', 'ecrecover', 'ripemd160', 'selfdestruct',
                     'delegatecall', 'staticcall', 'call', 'transfer',
                     'balanceOf', 'approve', 'transferFrom', 'allowance'}
            if contract not in skip:
                calls.append(f"{contract}.{func}")
        return list(set(calls))

    def _parse_params(self, raw: str) -> list:
        """Parse function parameters into structured format."""
        if not raw or not raw.strip():
            return []
        params = []
        for p in raw.split(','):
            p = p.strip()
            if not p:
                continue
            parts = p.split()
            if len(parts) >= 2:
                name = parts[-1].lstrip('_')
                ptype = ' '.join(parts[:-1])
                params.append({'type': ptype, 'name': name})
            elif len(parts) == 1:
                params.append({'type': parts[0], 'name': ''})
        return params

    def _build_result(self) -> dict:
        """Build final result dictionary."""
        return {
            'repo_path': str(self.repo_path),
            'parsed_at': datetime.now().isoformat(),
            'stats': {
                'sol_files': len(set(c['file'] for c in self.contracts + self.interfaces + self.libraries)),
                'contracts': len(self.contracts),
                'interfaces': len(self.interfaces),
                'libraries': len(self.libraries),
                'total_functions': sum(len(c['functions']) for c in self.contracts + self.interfaces + self.libraries),
                'total_events': sum(len(c['events']) for c in self.contracts + self.interfaces + self.libraries),
                'total_errors': sum(len(c['errors']) for c in self.contracts + self.interfaces + self.libraries),
                'total_state_vars': sum(len(c['state_variables']) for c in self.contracts + self.libraries),
            },
            'contracts': self.contracts,
            'interfaces': self.interfaces,
            'libraries': self.libraries,
            'file_constants': self.constants,
        }


# ============================================================
# HTML GENERATOR — Interactive Mind Map
# ============================================================

def generate_html(data: dict, repo_name: str) -> str:
    """Generate full interactive HTML mind map from parsed data."""

    stats = data['stats']

    # Build contract sections
    sections_html = []

    # Contracts
    for c in data['contracts']:
        sections_html.append(_build_contract_section(c, 'contract'))

    # Interfaces
    for c in data['interfaces']:
        sections_html.append(_build_contract_section(c, 'interface'))

    # Libraries
    for c in data['libraries']:
        sections_html.append(_build_contract_section(c, 'library'))

    # Build cross-reference map
    all_contracts = data['contracts'] + data['interfaces'] + data['libraries']
    contract_names = {c['name'] for c in all_contracts}

    # Detect cross-contract calls
    cross_calls = defaultdict(set)
    for c in all_contracts:
        for fn in c['functions']:
            for call in fn.get('calls', []):
                target_contract = call.split('.')[0]
                if target_contract in contract_names and target_contract != c['name']:
                    cross_calls[c['name']].add(call)

    # Build cross-call section
    cross_html = _build_cross_call_section(cross_calls)

    # Build data structures section
    structs_html = _build_structs_section(data)

    # Build glossary
    glossary_html = _build_glossary(all_contracts)

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🧠 {repo_name} — Full Audit Mind Map</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0e17;color:#e6edf3;min-height:100vh;overflow-x:hidden}}

/* NAV */
nav{{position:fixed;top:0;left:0;right:0;background:rgba(10,14,23,0.95);backdrop-filter:blur(10px);border-bottom:1px solid #1c2333;z-index:100;padding:10px 20px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}}
nav .logo{{font-size:18px;font-weight:700;color:#58a6ff;white-space:nowrap}}
nav a{{color:#8b949e;text-decoration:none;font-size:12px;padding:4px 8px;border-radius:6px;transition:all .2s}}
nav a:hover,nav a.active{{color:#fff;background:rgba(88,166,255,0.15)}}
.nav-right{{margin-left:auto;display:flex;gap:8px;align-items:center}}
.search-box{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:6px 12px;color:#e6edf3;font-size:13px;width:200px}}
.filter-btn{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:4px 10px;color:#8b949e;font-size:11px;cursor:pointer;transition:all .2s}}
.filter-btn:hover,.filter-btn.active{{background:rgba(88,166,255,0.15);color:#58a6ff;border-color:#1f6feb}}

/* MAIN */
main{{padding:70px 20px 40px;max-width:1600px;margin:0 auto}}

/* HERO */
.hero{{text-align:center;padding:30px 0 20px}}
.hero h1{{font-size:32px;background:linear-gradient(135deg,#58a6ff,#bc8cff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}}
.hero p{{color:#8b949e;font-size:14px}}
.hero .stats{{display:flex;gap:16px;justify-content:center;margin-top:16px;flex-wrap:wrap}}
.hero .stat{{background:#161b22;border:1px solid #21262d;border-radius:12px;padding:10px 18px;text-align:center}}
.hero .stat .num{{font-size:22px;font-weight:700;color:#58a6ff}}
.hero .stat .label{{font-size:11px;color:#484f58;margin-top:2px}}

/* SECTION */
.section{{margin:20px 0}}
.section-header{{display:flex;align-items:center;gap:10px;padding:12px 18px;background:#161b22;border:1px solid #21262d;border-radius:12px;cursor:pointer;user-select:none;transition:all .2s}}
.section-header:hover{{border-color:#30363d;background:#1c2333}}
.section-header .icon{{font-size:18px}}
.section-header h2{{font-size:15px;font-weight:600;flex:1}}
.section-header .badge{{background:rgba(88,166,255,0.1);border:1px solid rgba(88,166,255,0.2);padding:2px 8px;border-radius:16px;font-size:10px;color:#58a6ff}}
.section-header .count{{color:#484f58;font-size:11px;margin-left:4px}}
.section-header .arrow{{color:#484f58;font-size:12px;transition:transform .3s}}
.section-header.collapsed .arrow{{transform:rotate(-90deg)}}
.section-body{{padding:12px 0}}
.section-body.hidden{{display:none}}

/* CARDS */
.card{{background:#0d1117;border:1px solid #1c2333;border-radius:12px;padding:16px;margin-bottom:10px;transition:all .2s}}
.card:hover{{border-color:#30363d}}
.card .fn-name{{font-weight:700;font-size:14px;color:#e6edf3;margin-bottom:4px}}
.card .fn-meta{{font-size:11px;color:#484f58;margin-bottom:8px;display:flex;gap:8px;flex-wrap:wrap}}
.card .fn-meta .vis{{color:#79c0ff}}
.card .fn-meta .mut{{color:#3fb950}}
.card .fn-meta .mod{{color:#d2a8ff}}

/* PARAMS table */
.params{{width:100%;border-collapse:collapse;margin:8px 0;font-size:12px}}
.params th{{text-align:left;color:#484f58;padding:4px 8px;border-bottom:1px solid #21262d;font-weight:500}}
.params td{{padding:4px 8px;color:#8b949e}}
.params .ptype{{color:#79c0ff}}
.params .pname{{color:#e6edf3}}

/* State vars */
.svar{{display:flex;gap:8px;padding:3px 0;font-size:12px}}
.svar .type{{color:#79c0ff;min-width:120px}}
.svar .name{{color:#e6edf3}}
.svar .vis{{color:#484f58;font-size:10px}}

/* Calls */
.call-link{{display:inline-block;background:rgba(188,140,255,0.08);border:1px solid rgba(188,140,255,0.15);border-radius:6px;padding:2px 8px;margin:2px;font-size:11px;color:#d2a8ff;cursor:pointer;transition:all .2s}}
.call-link:hover{{background:rgba(188,140,255,0.15);border-color:rgba(188,140,255,0.3)}}

/* Badges */
.badge-vis{{display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:600}}
.badge-ext{{background:rgba(88,166,255,0.15);color:#58a6ff}}
.badge-pub{{background:rgba(63,185,80,0.15);color:#3fb950}}
.badge-int{{background:rgba(227,179,65,0.15);color:#e3b341}}
.badge-pri{{background:rgba(218,54,51,0.15);color:#f85149}}

/* Risk badges */
.risk{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:700}}
.r-crit{{background:#da3633;color:#fff}}
.r-high{{background:#d29922;color:#000}}
.r-med{{background:#e3b341;color:#000}}
.r-low{{background:#3fb950;color:#000}}
.r-info{{background:#388bfd;color:#fff}}

/* CROSS CALLS */
.cross-map{{background:#0d1117;border:1px solid #1c2333;border-radius:14px;padding:20px;margin:20px 0}}
.cross-map h3{{color:#d2a8ff;margin-bottom:12px}}
.cross-row{{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:13px;flex-wrap:wrap}}
.cross-from{{color:#58a6ff;font-weight:600;min-width:140px}}
.cross-arrow{{color:#484f58}}
.cross-to{{color:#d2a8ff}}

/* GLOSSARY */
.glossary{{margin:30px 0;padding:24px;background:#0d1117;border:1px solid #1c2333;border-radius:14px}}
.glossary h2{{color:#58a6ff;margin-bottom:16px;font-size:18px}}
.g-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:8px}}
.g-item{{padding:8px 12px;background:#161b22;border-radius:8px;border-left:3px solid #21262d;font-size:12px}}
.g-item .g-name{{color:#79c0ff;font-weight:700}}
.g-item .g-kind{{color:#484f58;font-size:10px}}
.g-item .g-file{{color:#30363d;font-size:10px;margin-top:2px}}

/* FOOTER */
.footer{{text-align:center;margin-top:40px;padding:20px;color:#21262d;font-size:11px}}

/* RESPONSIVE */
@media(max-width:768px){{
  nav{{gap:6px;padding:8px 12px}}
  .search-box{{width:120px}}
  .hero h1{{font-size:22px}}
  .hero .stats{{gap:8px}}
  .hero .stat{{padding:8px 12px}}
}}

/* COLLAPSIBLE PARAMS */
.toggle-params{{color:#484f58;font-size:11px;cursor:pointer;margin-left:8px}}
.toggle-params:hover{{color:#58a6ff}}
</style>
</head>
<body>

<nav>
  <div class="logo">🧠 {repo_name}</div>
  <a href="#contracts">Contracts</a>
  <a href="#interfaces">Interfaces</a>
  <a href="#libraries">Libraries</a>
  <a href="#cross-refs">Cross-Refs</a>
  <a href="#data-structures">Structs</a>
  <a href="#glossary">Glossary</a>
  <div class="nav-right">
    <button class="filter-btn active" onclick="filterVis('all')">All</button>
    <button class="filter-btn" onclick="filterVis('external')">External</button>
    <button class="filter-btn" onclick="filterVis('public')">Public</button>
    <button class="filter-btn" onclick="filterVis('internal')">Internal</button>
    <input type="text" class="search-box" placeholder="Search..." id="searchInput">
  </div>
</nav>

<main>

<div class="hero">
  <h1>🧠 {repo_name} — Full Audit Mind Map</h1>
  <p>Every function, state variable, event, error, struct, enum — nothing filtered</p>
  <div class="stats">
    <div class="stat"><div class="num">{stats['sol_files']}</div><div class="label">Solidity Files</div></div>
    <div class="stat"><div class="num">{stats['contracts']}</div><div class="label">Contracts</div></div>
    <div class="stat"><div class="num">{stats['interfaces']}</div><div class="label">Interfaces</div></div>
    <div class="stat"><div class="num">{stats['libraries']}</div><div class="label">Libraries</div></div>
    <div class="stat"><div class="num">{stats['total_functions']}</div><div class="label">Functions</div></div>
    <div class="stat"><div class="num">{stats['total_state_vars']}</div><div class="label">State Vars</div></div>
    <div class="stat"><div class="num">{stats['total_events']}</div><div class="label">Events</div></div>
    <div class="stat"><div class="num">{stats['total_errors']}</div><div class="label">Errors</div></div>
  </div>
</div>

{"".join(sections_html)}

{cross_html}

{structs_html}

{glossary_html}

<div class="footer">
  <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")} — Solidity Mind Map Generator v1.0</p>
  <p>Full detail — no filtering — every function included</p>
</div>

</main>

<script>
// Toggle sections
function toggleSection(el){{
  el.classList.toggle('collapsed');
  const body=el.nextElementSibling;
  if(body)body.classList.toggle('hidden');
}}

// Filter by visibility
function filterVis(vis){{
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.card').forEach(card=>{{
    if(vis==='all'){{card.style.display='';return}}
    const visEl=card.querySelector('.vis');
    if(visEl&&visEl.textContent.toLowerCase().includes(vis))card.style.display='';
    else card.style.display='none';
  }});
}}

// Search
document.getElementById('searchInput').addEventListener('input',e=>{{
  const q=e.target.value.toLowerCase();
  document.querySelectorAll('.card').forEach(card=>{{
    card.style.display=card.textContent.toLowerCase().includes(q)||q===''?'':'none';
  }});
  document.querySelectorAll('.g-item').forEach(el=>{{
    el.style.display=el.textContent.toLowerCase().includes(q)||q===''?'':'none';
  }});
}});

// Nav active
const sections=document.querySelectorAll('.section');
const navLinks=document.querySelectorAll('nav a');
window.addEventListener('scroll',()=>{{
  let current='';
  sections.forEach(s=>{{if(s.getBoundingClientRect().top<200)current=s.id}});
  navLinks.forEach(a=>{{a.classList.toggle('active',a.getAttribute('href')==='#'+current)}});
}});

// Toggle params visibility
document.querySelectorAll('.toggle-params').forEach(el=>{{
  el.addEventListener('click',()=>{{
    const table=el.closest('.card').querySelector('.params');
    if(table){{table.style.display=table.style.display==='none'?'':'none';el.textContent=table.style.display==='none'?'[show params]':'[hide params]'}}
  }});
}});
</script>

</body>
</html>'''
    return html


def _build_contract_section(c: dict, kind: str) -> str:
    """Build HTML section for a single contract/interface/library."""
    icon = {'contract': '📄', 'interface': '🔌', 'library': '📚'}.get(kind, '📄')
    badge_class = {'contract': 'badge-ext', 'interface': 'badge-pub', 'library': 'badge-int'}.get(kind, 'badge-ext')
    section_id = c['name'].lower().replace(' ', '-')

    inheritance = f" is {', '.join(c['inheritance'])}" if c['inheritance'] else ""
    file_path = c.get('file', '')

    # Count items
    fn_count = len(c['functions'])
    sv_count = len(c['state_variables'])
    ev_count = len(c['events'])
    er_count = len(c['errors'])

    html = f'''
<div class="section" id="{section_id}">
  <div class="section-header" onclick="toggleSection(this)">
    <span class="icon">{icon}</span>
    <h2>{c['name']}{inheritance}</h2>
    <span class="badge">{kind}</span>
    <span class="count">F:{fn_count} S:{sv_count} E:{ev_count}</span>
    <span class="arrow">▾</span>
  </div>
  <div class="section-body">
    <div style="color:#484f58;font-size:11px;margin-bottom:10px;padding:0 4px">📁 {file_path}</div>
'''

    # Constructor
    if c.get('constructor'):
        ct = c['constructor']
        html += f'''
    <div class="card">
      <div class="fn-name">constructor({ct.get('raw_params', '')})</div>
      <div class="fn-meta"><span class="vis" style="color:#f0883e">constructor</span></div>
</div>
'''

    # Receive / Fallback
    if c.get('receive_eth'):
        html += '<div class="card"><div class="fn-name">receive() external payable</div><div class="fn-meta"><span class="vis" style="color:#f0883e">receive ETH</span></div></div>'
    if c.get('fallback'):
        html += '<div class="card"><div class="fn-name">fallback() external payable</div><div class="fn-meta"><span class="vis" style="color:#f0883e">fallback</span></div></div>'

    # State Variables
    if c['state_variables']:
        html += '''
    <div class="card">
      <div class="fn-name">📦 State Variables</div>
      <div style="padding:8px 0">'''
        for sv in c['state_variables']:
            vis_class = {'public': 'badge-pub', 'internal': 'badge-int', 'private': 'badge-pri'}.get(sv['visibility'], 'badge-int')
            html += f'<div class="svar"><span class="type">{_escape(sv["type"])}</span> <span class="name">{sv["name"]}</span> <span class="vis"><span class="badge-vis {vis_class}">{sv["visibility"]}</span></span></div>'
        html += '</div></div>'

    # Modifiers
    if c['modifiers']:
        html += '<div class="card"><div class="fn-name">🔒 Modifiers</div><div style="padding:8px 0">'
        for mod in c['modifiers']:
            html += f'<div style="font-size:12px;color:#d2a8ff;padding:2px 0">modifier {mod["name"]}({mod["params"]})</div>'
        html += '</div></div>'

    # Functions
    for fn in c['functions']:
        vis_badge = {
            'external': 'badge-ext',
            'public': 'badge-pub',
            'internal': 'badge-int',
            'private': 'badge-pri'
        }.get(fn['visibility'], 'badge-int')

        mut_text = fn['mutability'] if fn['mutability'] != 'nonpayable' else ''
        mods_text = ' '.join(fn.get('custom_modifiers', []))
        flags = []
        if fn['is_virtual']: flags.append('virtual')
        if fn['is_override']: flags.append('override')

        # Risk auto-detection hints
        risk_html = ''
        fn_name_lower = fn['name'].lower()
        if 'liquidate' in fn_name_lower:
            risk_html = '<span class="risk r-crit">🔴 LIQUIDATION</span>'
        elif 'oracle' in fn_name_lower or 'price' in fn_name_lower:
            risk_html = '<span class="risk r-crit">🔴 ORACLE</span>'
        elif 'flash' in fn_name_lower:
            risk_html = '<span class="risk r-high">🟡 FLASH</span>'
        elif 'withdraw' in fn_name_lower and fn['visibility'] in ('external', 'public'):
            risk_html = '<span class="risk r-med">🟡 WITHDRAW</span>'
        elif 'borrow' in fn_name_lower:
            risk_html = '<span class="risk r-high">🟡 BORROW</span>'
        elif 'owner' in fn_name_lower or 'admin' in fn_name_lower or 'set' in fn_name_lower:
            risk_html = '<span class="risk r-med">🟡 ADMIN</span>'

        html += f'''
    <div class="card" data-vis="{fn['visibility']}">
      <div class="fn-name">{fn["name"]}({fn["raw_params"]}) {risk_html}</div>
      <div class="fn-meta">
        <span class="vis"><span class="badge-vis {vis_badge}">{fn["visibility"]}</span></span>
        {"<span class='mut'>" + mut_text + "</span>" if mut_text else ''}
        {"<span class='mod'>" + mods_text + "</span>" if mods_text else ''}
        {"<span class='mod'>" + ' '.join(flags) + "</span>" if flags else ''}
        <span class="toggle-params">[show params]</span>
      </div>'''

        # Params table
        if fn['params']:
            html += '<table class="params" style="display:none"><tr><th>Type</th><th>Name</th></tr>'
            for p in fn['params']:
                html += f'<tr><td class="ptype">{_escape(p["type"])}</td><td class="pname">{p["name"]}</td></tr>'
            html += '</table>'

        # Returns
        if fn['returns']:
            html += '<div style="font-size:11px;color:#3fb950;margin-top:4px">returns: '
            html += ', '.join(f'{_escape(r["type"])} {r["name"]}' for r in fn['returns'])
            html += '</div>'

        # Cross-contract calls
        if fn.get('calls'):
            html += '<div style="margin-top:8px;font-size:11px">🔗 Calls: '
            for call in fn['calls']:
                html += f'<span class="call-link">{call}</span>'
            html += '</div>'

        html += '</div>'

    # Events
    if c['events']:
        html += '<div class="card"><div class="fn-name">📢 Events</div><div style="padding:8px 0">'
        for ev in c['events']:
            html += f'<div style="font-size:12px;color:#3fb950;padding:2px 0">event {ev["name"]}({ev["raw"]})</div>'
        html += '</div></div>'

    # Errors
    if c['errors']:
        html += '<div class="card"><div class="fn-name">❌ Errors</div><div style="padding:8px 0">'
        for er in c['errors']:
            html += f'<div style="font-size:12px;color:#f85149;padding:2px 0">error {er["name"]}({er["raw"]})</div>'
        html += '</div></div>'

    html += '</div></div>'
    return html


def _build_cross_call_section(cross_calls: dict) -> str:
    """Build cross-contract call reference section."""
    if not cross_calls:
        return ''

    html = '<div class="cross-map" id="cross-refs"><h3>🔗 Cross-Contract Calls</h3>'
    for source, targets in sorted(cross_calls.items()):
        for target in sorted(targets):
            html += f'<div class="cross-row"><span class="cross-from">{source}</span><span class="cross-arrow">→</span><span class="cross-to">{target}</span></div>'
    html += '</div>'
    return html


def _build_structs_section(data: dict) -> str:
    """Build data structures section."""
    all_items = data['contracts'] + data['interfaces'] + data['libraries']
    has_structs = any(c['structs'] for c in all_items)
    has_enums = any(c['enums'] for c in all_items)

    if not has_structs and not has_enums:
        return ''

    html = '<div class="section" id="data-structures"><div class="section-header" onclick="toggleSection(this)"><span class="icon">🏗️</span><h2>Data Structures (Structs & Enums)</h2><span class="arrow">▾</span></div><div class="section-body">'

    for c in all_items:
        if c['structs'] or c['enums']:
            html += f'<div class="card"><div class="fn-name">📦 {c["name"]}</div>'
            for s in c['structs']:
                html += f'<div style="margin:8px 0"><span style="color:#e3b341;font-size:12px;font-weight:600">struct {s["name"]}</span>'
                for field in s['fields']:
                    html += f'<div class="svar"><span class="type">{_escape(field["type"])}</span> <span class="name">{field["name"]}</span></div>'
                html += '</div>'
            for e in c['enums']:
                html += f'<div style="margin:8px 0"><span style="color:#3fb950;font-size:12px;font-weight:600">enum {e["name"]}</span>'
                html += f'<div style="font-size:12px;color:#8b949e;padding-left:16px">{", ".join(e["values"])}</div></div>'
            html += '</div>'

    html += '</div></div>'
    return html


def _build_glossary(all_contracts: list) -> str:
    """Build contract glossary."""
    html = '<div class="glossary" id="glossary"><h2>📖 Contract Glossary</h2><div class="g-grid">'
    for c in all_contracts:
        kind = c['kind']
        fn_count = len(c['functions'])
        html += f'''<div class="g-item">
          <div class="g-name">{c["name"]}</div>
          <div class="g-kind">{kind} — {fn_count} functions</div>
          <div class="g-file">{c.get("file", "")}</div>
        </div>'''
    html += '</div></div>'
    return html


def _escape(text: str) -> str:
    """HTML escape."""
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


# ============================================================
# MAIN
# ============================================================

def clone_repo(url: str, target: str) -> str:
    """Clone a GitHub repo."""
    print(f"📥 Cloning {url}...")
    subprocess.run(['git', 'clone', '--depth', '1', url, target], check=True, capture_output=True)
    return target


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    source = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    # Determine if URL or local path
    if source.startswith('http'):
        repo_name = source.split('/')[-1].replace('.git', '')
        tmp_dir = tempfile.mkdtemp(prefix='sol_mindmap_')
        repo_path = os.path.join(tmp_dir, repo_name)
        clone_repo(source, repo_path)
    else:
        repo_path = source
        repo_name = Path(source).name

    if not output:
        output = f"{repo_name}_AuditMindMap.html"

    print(f"🔍 Parsing Solidity files in {repo_path}...")
    parser = SolidityParser(repo_path)
    data = parser.parse_all()

    print(f"\n📊 Results:")
    print(f"   Solidity files: {data['stats']['sol_files']}")
    print(f"   Contracts: {data['stats']['contracts']}")
    print(f"   Interfaces: {data['stats']['interfaces']}")
    print(f"   Libraries: {data['stats']['libraries']}")
    print(f"   Functions: {data['stats']['total_functions']}")
    print(f"   State vars: {data['stats']['total_state_vars']}")
    print(f"   Events: {data['stats']['total_events']}")
    print(f"   Errors: {data['stats']['total_errors']}")

    print(f"\n📄 Generating HTML mind map...")
    html = generate_html(data, repo_name)

    output_path = Path(output)
    output_path.write_text(html, encoding='utf-8')
    print(f"✅ Saved to {output_path.absolute()} ({len(html):,} bytes)")

    # Also save JSON data
    json_path = output_path.with_suffix('.json')
    json_path.write_text(json.dumps(data, indent=2, default=str), encoding='utf-8')
    print(f"📊 JSON data saved to {json_path.absolute()}")


if __name__ == '__main__':
    main()
