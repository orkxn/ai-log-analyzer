# AI Log Analyzer

An AI-powered cybersecurity log analysis tool that detects threats, attacks, and suspicious activities in real-time using local LLM (Ollama).

![Node.js](https://img.shields.io/badge/Node.js-18+-green)
![Ollama](https://img.shields.io/badge/Ollama-llama3.2-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

- **Real-time AI Thinking** - Watch the AI analyze your logs in real-time with streaming output
- **Threat Detection** - Identifies SQL injection, XSS, brute force, data exfiltration, and more
- **Risk Assessment** - Severity levels (low/medium/high/critical) with confidence scores
- **Detailed Analysis** - Comprehensive explanations and actionable recommendations
- **IOC Extraction** - Automatically extracts IP addresses and threat indicators
- **Quick Tests** - Pre-built attack scenarios for testing
- **Modern UI** - Clean, dark-themed interface with smooth animations

## Screenshots

### Analysis Interface
- Paste any log entry and get instant AI-powered threat analysis
- Real-time streaming shows the AI's thinking process
- Results include severity, confidence, explanation, and recommendations

## Quick Start

### Prerequisites

1. **Node.js** (v18 or higher)
   ```bash
   node --version
   ```

2. **Ollama** with llama3.2 model
   ```bash
   # Install Ollama from https://ollama.ai
   ollama pull llama3.2
   ```

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR-USERNAME/ai-log-analyzer.git
   cd ai-log-analyzer
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start Ollama** (in a separate terminal)
   ```bash
   ollama serve
   ```

4. **Start the server**
   ```bash
   npm start
   ```

5. **Open in browser**
   ```
   http://localhost:3000
   ```

## Usage

### Web Interface

1. Open `http://localhost:3000` in your browser
2. Paste a log entry in the text area
3. Click "Analyze Log" or press `Ctrl + Enter`
4. Watch the AI thinking process in real-time
5. View detailed results with recommendations

### Quick Test Examples

Click any quick test button to analyze:

| Test | Description |
|------|-------------|
| Brute Force | Failed login attempts |
| SQL Injection | Database attack patterns |
| XSS Attack | Cross-site scripting |
| Data Exfil | Data exfiltration attempt |
| Normal Log | Safe activity for comparison |

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Check server and Ollama status |
| `/api/analyze` | POST | Analyze log (non-streaming) |
| `/api/analyze-stream` | POST | Analyze log with streaming |

#### Example API Request

```bash
curl -X POST http://localhost:3000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"log": "ERROR: Failed login attempt from 192.168.1.100"}'
```

#### Example Response

```json
{
  "type": "Brute Force Attack",
  "risk": "high",
  "confidence": 0.92,
  "isSuspicious": true,
  "explanation": "Multiple failed login attempts detected...",
  "suggestion": "1) Block the IP address immediately...",
  "indicators": ["failed login", "multiple attempts", "admin user"],
  "extractedIPs": ["192.168.1.100"]
}
```

## Project Structure

```
ai-log-analyzer/
├── public/
│   ├── index.html         # Main web interface
│   └── style.css          # Styles (if separate)
├── services/
│   ├── ollamaService.js   # AI integration with streaming
│   └── ruleEngine.js      # Pattern matching rules
├── server.js              # Express server with SSE
├── package.json
└── README.md
```

## Configuration

### Change AI Model

Edit `services/ollamaService.js`:

```javascript
const MODEL = 'llama3.2';  // Change to your preferred model
```

### Change Port

Set environment variable:

```bash
PORT=8080 npm start
```

## Tech Stack

- **Backend**: Node.js, Express.js
- **Frontend**: Vanilla HTML, CSS, JavaScript
- **AI**: Ollama (local LLM)
- **Streaming**: Server-Sent Events (SSE)

## Security Features

- Input validation and sanitization
- No external API calls (runs locally)
- Pattern-based pre-filtering with rule engine
- Detailed threat indicators extraction

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Ollama](https://ollama.ai) - Local LLM runtime
- [Express.js](https://expressjs.com) - Web framework
- [Inter Font](https://rsms.me/inter/) - Typography
- [JetBrains Mono](https://www.jetbrains.com/lp/mono/) - Monospace font

---

Made for the cybersecurity community
