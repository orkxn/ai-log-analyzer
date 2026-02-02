/**
 * server.js - Main Express Server
 * 
 * This is the entry point of your Log Analyzer API.
 * It sets up the Express server and defines the API endpoints.
 * 
 * To run: npm run dev
 * Then open: http://localhost:3000
 */

const express = require('express');
const cors = require('cors');
const path = require('path');

// Import our services
const { analyzeWithRules, extractIPs, extractPaths } = require('./services/ruleEngine');
const { analyzeLog, analyzeLogStream, checkOllama, MODEL } = require('./services/ollamaService');
const { validateAndCorrect } = require('./services/analysisValidator');

// Create Express app
const app = express();
const PORT = process.env.PORT || 3000;

// ==================== MIDDLEWARE ====================
// These run on every request

// Enable CORS (allows requests from other domains)
app.use(cors());

// Parse JSON request bodies
app.use(express.json());

// Serve static files from 'public' folder (our frontend)
app.use(express.static(path.join(__dirname, 'public')));

// ==================== API ENDPOINTS ====================

/**
 * Health check endpoint
 * GET /api/health
 * 
 * Use this to check if the server and Ollama are working
 */
app.get('/api/health', async (req, res) => {
    const ollamaStatus = await checkOllama();

    res.json({
        status: 'ok',
        server: 'running',
        ollama: ollamaStatus,
        model: MODEL
    });
});

/**
 * Main analysis endpoint
 * POST /api/analyze
 * 
 * This is the main endpoint that analyzes log entries.
 * 
 * Request body: { "log": "your log text here" }
 * Response: Analysis JSON
 */
app.post('/api/analyze', async (req, res) => {
    try {
        // Get the log from the request
        const { log } = req.body;

        // Validate input
        if (!log || typeof log !== 'string') {
            return res.status(400).json({
                error: 'Missing or invalid log parameter',
                hint: 'Send a JSON body with: { "log": "your log text" }'
            });
        }

        // Trim and check for empty log
        const logText = log.trim();
        if (logText.length === 0) {
            return res.status(400).json({
                error: 'Log cannot be empty'
            });
        }

        console.log(`\n[LOG] Analyzing: "${logText.substring(0, 50)}..."`);

        // Step 1: Quick analysis with rule engine
        const ruleResult = analyzeWithRules(logText);
        console.log(`[RULES] Rule engine: ${ruleResult.matchCount} pattern(s) matched`);

        // Step 2: Deep analysis with AI
        console.log('[AI] Sending to Ollama...');
        const aiResult = await analyzeLog(logText, ruleResult);

        // Handle Ollama errors
        if (!aiResult.success) {
            return res.status(503).json({
                error: 'AI analysis failed',
                details: aiResult.error,
                hint: aiResult.hint || 'Check if Ollama is running',
                ruleAnalysis: ruleResult.hasMatch ? ruleResult.primaryMatch : null
            });
        }

        // Step 3: Validate and correct AI output with deterministic rules
        console.log('[VALIDATE] Validating AI output...');
        const validated = validateAndCorrect(aiResult.analysis, logText);

        // Step 4: Build the response
        const response = {
            // Validated analysis (AI output corrected by rules)
            type: validated.type,
            risk: validated.risk,
            confidence: validated.confidence,
            explanation: validated.explanation,
            suggestion: validated.suggestion,
            isSuspicious: validated.isSuspicious,
            status: validated.status, // NEW: Determined by rules, not AI

            // Additional details
            indicators: validated.indicators,
            extractedIPs: extractIPs(logText),
            extractedPaths: extractPaths(logText),

            // Metadata
            _meta: {
                model: aiResult.model,
                ruleMatches: ruleResult.matchCount,
                quickMatch: ruleResult.hasMatch ? ruleResult.primaryMatch.name : null,
                validation: validated._meta // Shows adjustments made
            }
        };

        console.log(`[DONE] Analysis complete: ${response.type} | Status: ${response.status} | Risk: ${response.risk}`);
        if (validated._meta.adjustments.length > 0) {
            console.log(`   Adjustments: ${validated._meta.adjustments.join(', ')}`);
        }

        res.json(response);

    } catch (error) {
        console.error('[ERROR]', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
});

/**
 * Streaming analysis endpoint
 * POST /api/analyze-stream
 * 
 * This endpoint streams the AI's thinking process in real-time using SSE.
 */
app.post('/api/analyze-stream', async (req, res) => {
    try {
        const { log } = req.body;

        if (!log || typeof log !== 'string' || log.trim().length === 0) {
            return res.status(400).json({ error: 'Missing or invalid log parameter' });
        }

        const logText = log.trim();
        console.log(`\n[STREAM] Analyzing: "${logText.substring(0, 50)}..."`);

        // Set up SSE headers
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.flushHeaders();

        // Rule engine pre-analysis
        const ruleResult = analyzeWithRules(logText);

        // Send initial status
        res.write(`data: ${JSON.stringify({ type: 'status', message: 'Starting AI analysis...' })}\n\n`);

        // Stream AI response
        const stream = analyzeLogStream(logText, ruleResult);

        for await (const chunk of stream) {
            if (chunk.type === 'chunk') {
                res.write(`data: ${JSON.stringify({ type: 'thinking', content: chunk.content })}\n\n`);
            } else if (chunk.type === 'complete') {
                // Validate AI output with deterministic rules
                const validated = validateAndCorrect(chunk.analysis, logText);

                // Build final response (validated)
                const response = {
                    type: validated.type,
                    risk: validated.risk,
                    confidence: validated.confidence,
                    explanation: validated.explanation,
                    suggestion: validated.suggestion,
                    isSuspicious: validated.isSuspicious,
                    status: validated.status,
                    indicators: validated.indicators,
                    extractedIPs: extractIPs(logText),
                    extractedPaths: extractPaths(logText),
                    _meta: validated._meta
                };
                res.write(`data: ${JSON.stringify({ type: 'complete', result: response })}\n\n`);
            } else if (chunk.type === 'error') {
                res.write(`data: ${JSON.stringify({ type: 'error', error: chunk.error })}\n\n`);
            }
        }

        res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
        res.end();

    } catch (error) {
        console.error('[STREAM ERROR]', error);
        res.write(`data: ${JSON.stringify({ type: 'error', error: error.message })}\n\n`);
        res.end();
    }
});

// ==================== ERROR HANDLING ====================

// 404 handler for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({ error: 'API endpoint not found' });
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
    console.log('\n=== Log Analyzer API is running! ===');
    console.log(`Server: http://localhost:${PORT}`);
    console.log(`Model: ${MODEL}`);
    console.log('\nMake sure Ollama is running (ollama serve)');
    console.log('Open the URL in your browser to use the web interface\n');
});
