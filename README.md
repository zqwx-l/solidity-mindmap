# 🧠 Solidity Mind Map Generator (AI-Powered)

Convert any Solidity smart contract repository into an **interactive HTML audit mind map**.

## Three Modes

| Mode | Description | Speed |
|------|-------------|-------|
| `raw` | No AI. Extract everything, format as HTML. | ⚡ Instant |
| `full` | AI translates EVERY function to plain-English logic | 🐢 Slower |
| `filtered` | AI filters high-risk functions + deep exploit analysis | 🎯 Smartest |

## Usage

```bash
# Raw mode (no AI, instant)
python3 solidity_mindmap.py https://github.com/morpho-org/morpho-blue --mode raw

# Full mode (AI explains every function)
python3 solidity_mindmap.py ./morpho-blue --mode full --api-key sk-xxx

# Filtered mode (AI picks high-risk + exploit analysis)
python3 solidity_mindmap.py ./morpho-blue --mode filtered --api-key sk-xxx
```

## API Configuration

```bash
# Via command line
python3 solidity_mindmap.py ./repo --mode full --api-url https://openrouter.ai/api/v1 --api-key sk-xxx --model anthropic/claude-sonnet-4

# Via environment variables
export MINDMAP_API_URL=https://openrouter.ai/api/v1
export MINDMAP_API_KEY=sk-xxx
export MINDMAP_MODEL=anthropic/claude-sonnet-4
python3 solidity_mindmap.py ./repo --mode full
```

Works with any OpenAI-compatible API: OpenRouter, OpenAI, Anthropic (via proxy), local LLMs, etc.

## Output

- `*_AuditMindMap.html` — Interactive mind map (open in browser)
- `*_AuditMindMap.json` — Raw extracted data + AI analysis

## Features

- **Full extraction** — every function, state var, event, error, struct, enum
- **Interactive HTML** — filter by visibility, search, expand/collapse
- **Auto-risk detection** — highlights liquidation, oracle, flash loan functions
- **Cross-contract calls** — detects inter-contract dependencies
- **AI logic translation** — plain-English explanation of every function
- **AI exploit analysis** — attack vectors, difficulty, impact, fix
- **Works with any repo** — GitHub URL or local path

## Dependencies

- Python 3.10+
- Git (for cloning repos)
- API key (only for `full` and `filtered` modes)

## License

MIT
