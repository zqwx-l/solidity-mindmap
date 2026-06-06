# 🧠 Solidity Mind Map Generator

Convert any Solidity smart contract repository into an **interactive HTML audit mind map**.

Every function. Every state variable. Every event, error, struct, enum. **Nothing filtered.**

## Features

- **Full extraction** — no filtering, every function included
- **Interactive HTML** — filter by visibility, search, expand/collapse
- **Auto-risk detection** — highlights liquidation, oracle, flash loan, withdraw, borrow, admin functions
- **Cross-contract calls** — detects and maps inter-contract dependencies
- **Params table** — expandable parameter details for every function
- **Contract glossary** — searchable index of all contracts
- **Works with any repo** — GitHub URL or local path

## Usage

```bash
# From GitHub URL (auto clone)
python3 solidity_mindmap.py https://github.com/morpho-org/morpho-blue

# From local path
python3 solidity_mindmap.py /path/to/repo

# Custom output name
python3 solidity_mindmap.py https://github.com/morpho-org/morpho-blue morpho_audit.html
```

## Output

- `*_AuditMindMap.html` — Interactive mind map (open in browser)
- `*_AuditMindMap.json` — Raw extracted data (for further processing)

## Example Output (Morpho Blue)

| Metric | Count |
|--------|-------|
| Solidity Files | 57 |
| Contracts | 39 |
| Interfaces | 14 |
| Libraries | 14 |
| Functions | 359 |
| State Variables | 534 |
| Events | 19 |

## Dependencies

- Python 3.10+
- Git (for cloning repos)

No external packages required — uses only Python stdlib.

## How It Works

1. Clones repo (or reads local path)
2. Parses all `.sol` files using regex
3. Extracts: contracts, interfaces, libraries, functions, state variables, modifiers, events, errors, structs, enums, constructor, receive/fallback
4. Detects cross-contract calls
5. Generates interactive HTML with search, filter, and glossary

## License

MIT
