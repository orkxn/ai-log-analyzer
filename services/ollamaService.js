/**
 * ollamaService.js - Ollama AI Integration
 * 
 * This service connects to your local Ollama instance
 * and uses the llama3.2 model to analyze logs.
 * 
 * Make sure Ollama is running before starting the server!
 * You can check by running: ollama list
 */

const ollama = require('ollama');

// The model we're using - you can change this if you have a different one
const MODEL = 'llama3.2';

// System prompt for analysis
const SYSTEM_PROMPT = `You are a senior cybersecurity analyst and log forensics expert. Analyze log entries and provide comprehensive, detailed analysis.
                    
IMPORTANT: Always respond with valid JSON only, no other text. Use this exact format:
{
    "type": "The specific type of error, attack, or event (e.g., SQL Injection, Brute Force Attack, XSS, Authentication Failure, etc.)",
    "risk": "low|medium|high|critical",
    "confidence": 0.0 to 1.0 (your confidence in this assessment),
    "explanation": "Provide a DETAILED explanation including: 1) What exactly happened in this log entry, 2) Why this is suspicious or safe, 3) The technical mechanism of the attack/issue if applicable, 4) Potential impact if this is a real threat, 5) Any patterns or signatures you identified",
    "suggestion": "Provide DETAILED actionable recommendations including: 1) Immediate actions to take right now, 2) Short-term mitigation steps, 3) Long-term security improvements, 4) Specific tools or commands to use if applicable, 5) Prevention measures to avoid this in the future",
    "isSuspicious": true/false,
    "indicators": ["list", "of", "specific", "threat", "indicators", "found", "in", "the", "log"]
}

Be thorough and professional. Your explanation should be 3-5 sentences minimum. Your suggestion should include at least 3 specific actionable steps.`;

/**
 * Analyzes a log entry using AI (non-streaming)
 */
async function analyzeLog(logText, ruleHints = null) {
    try {
        const prompt = buildPrompt(logText, ruleHints);

        const response = await ollama.default.chat({
            model: MODEL,
            messages: [
                { role: 'system', content: SYSTEM_PROMPT },
                { role: 'user', content: prompt }
            ],
            format: 'json'
        });

        const analysis = parseAIResponse(response.message.content);
        return {
            success: true,
            analysis: analysis,
            model: MODEL
        };

    } catch (error) {
        console.error('Ollama error:', error.message);

        if (error.message.includes('ECONNREFUSED') || error.message.includes('fetch failed')) {
            return {
                success: false,
                error: 'Ollama is not running. Please start Ollama first!',
                hint: 'Run "ollama serve" in a terminal'
            };
        }

        return {
            success: false,
            error: error.message
        };
    }
}

/**
 * Analyzes a log entry using AI with streaming (shows thinking process)
 */
async function* analyzeLogStream(logText, ruleHints = null) {
    try {
        const prompt = buildPrompt(logText, ruleHints);

        const response = await ollama.default.chat({
            model: MODEL,
            messages: [
                { role: 'system', content: SYSTEM_PROMPT },
                { role: 'user', content: prompt }
            ],
            format: 'json',
            stream: true
        });

        let fullContent = '';

        for await (const chunk of response) {
            if (chunk.message && chunk.message.content) {
                fullContent += chunk.message.content;
                yield {
                    type: 'chunk',
                    content: chunk.message.content,
                    done: chunk.done || false
                };
            }
        }

        // Parse final result
        const analysis = parseAIResponse(fullContent);
        yield {
            type: 'complete',
            analysis: analysis,
            model: MODEL,
            success: true
        };

    } catch (error) {
        console.error('Ollama streaming error:', error.message);

        yield {
            type: 'error',
            success: false,
            error: error.message.includes('ECONNREFUSED') || error.message.includes('fetch failed')
                ? 'Ollama is not running. Please start Ollama first!'
                : error.message
        };
    }
}

/**
 * Builds the prompt for the AI
 */
function buildPrompt(logText, ruleHints) {
    let prompt = `Analyze this log entry:\n\n"${logText}"\n\n`;

    // Add hints from rule engine if available
    if (ruleHints && ruleHints.hasMatch) {
        prompt += `Initial pattern detection suggests: ${ruleHints.primaryMatch.name} (${ruleHints.primaryMatch.risk} risk)\n`;
        prompt += `Consider this in your analysis, but provide your own assessment.\n\n`;
    }

    prompt += `Provide your analysis as JSON with: type, risk, explanation, suggestion, isSuspicious, and indicators.`;

    return prompt;
}

/**
 * Parses the AI response into a structured object
 */
function parseAIResponse(content) {
    try {
        // Try to parse as JSON directly
        return JSON.parse(content);
    } catch (e) {
        // If parsing fails, try to extract JSON from the response
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
            try {
                return JSON.parse(jsonMatch[0]);
            } catch (e2) {
                // Return a fallback structure
                return {
                    type: "Unknown",
                    risk: "low",
                    confidence: 0.5,
                    explanation: content,
                    suggestion: "Manual review recommended",
                    isSuspicious: false,
                    indicators: []
                };
            }
        }

        // Complete fallback
        return {
            type: "Parse Error",
            risk: "low",
            confidence: 0.0,
            explanation: "Could not parse AI response",
            suggestion: "Try again or check the log format",
            isSuspicious: false,
            indicators: []
        };
    }
}

/**
 * Check if Ollama is available
 */
async function checkOllama() {
    try {
        const models = await ollama.default.list();
        const hasModel = models.models.some(m => m.name.includes(MODEL.split(':')[0]));
        return {
            available: true,
            hasModel: hasModel,
            models: models.models.map(m => m.name)
        };
    } catch (error) {
        return {
            available: false,
            error: error.message
        };
    }
}

module.exports = {
    analyzeLog,
    analyzeLogStream,
    checkOllama,
    MODEL
};
