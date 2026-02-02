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

// System prompt for analysis - STRICT to minimize false positives
const SYSTEM_PROMPT = `You are an expert cybersecurity analyst. Analyze log entries with EXTREME PRECISION. Your #1 priority is AVOIDING FALSE POSITIVES.

## ABSOLUTE RULES (NEVER BREAK THESE):

### RULE 1: LOGIN EVENTS - BE VERY CAREFUL
- A SINGLE failed login = NOT suspicious (users forget passwords)
- A SINGLE successful login = NOT suspicious (this is normal)
- 2-5 failed logins = NOT suspicious (users make typos)
- Even 5-10 failed logins = probably normal, mark as LOW risk at most
- BRUTE FORCE requires ALL of these conditions:
  * 10+ failed attempts
  * Same target account OR same source IP
  * Within 5 minutes or less
  * If ANY condition is missing, it is NOT brute force

### RULE 2: WHAT IS NEVER SUSPICIOUS
- "User X logged in successfully" = ALWAYS safe, risk: low
- "User X logged out" = ALWAYS safe, risk: low
- "Failed login for X" (single occurrence) = NOT suspicious, risk: low
- "Session expired" = ALWAYS safe
- "Invalid password" (single) = NOT suspicious
- "Account locked" = security feature working, NOT an attack
- "Password reset requested" = normal user action
- Any successful authentication = safe

### RULE 3: WHAT IS ACTUALLY SUSPICIOUS
Only flag as suspicious if you see CLEAR attack signatures:

SQL INJECTION - Must contain actual SQL syntax in wrong context:
- UNION SELECT, OR 1=1, DROP TABLE, INSERT INTO, DELETE FROM
- SQL comments: -- or /* */
- String terminators: ' or " followed by SQL keywords

XSS - Must contain script execution attempts:
- <script> tags
- javascript: protocol
- Event handlers: onerror=, onload=, onclick= with code

BRUTE FORCE - Must have ALL these indicators:
- "10+ failed attempts" or "multiple failed" with high count
- Short time window mentioned (minutes)
- Same source or same target

COMMAND INJECTION:
- Shell operators: ; | && \` $()
- System commands: cat, ls, rm, wget, curl in input

PATH TRAVERSAL:
- ../ or ..\ sequences
- Attempts to access /etc/passwd, /windows/system32, etc.

### RULE 4: RISK LEVELS
- LOW: Normal operations, informational logs, single errors
- MEDIUM: Unusual but not confirmed malicious (needs investigation)
- HIGH: Clear attack attempt with evidence
- CRITICAL: Successful breach or active data theft

### RULE 5: CONFIDENCE LEVELS
- 0.9+: Definitive attack signature present
- 0.7-0.89: Strong indicators but some uncertainty
- 0.5-0.69: Suspicious, needs more context
- Below 0.5: Probably normal, mark isSuspicious: false

## OUTPUT FORMAT (JSON only):
{
    "type": "Event type (be specific)",
    "risk": "low|medium|high|critical",
    "confidence": 0.0 to 1.0,
    "explanation": "Detailed analysis explaining your reasoning",
    "suggestion": "What to do (for safe events, say 'No action required - this is normal activity')",
    "isSuspicious": true/false,
    "indicators": [] // List specific indicators, empty [] if none
}

## EXAMPLES - LEARN FROM THESE:

LOG: "User admin logged in successfully from 192.168.1.50"
ANALYSIS: { "type": "Successful Login", "risk": "low", "confidence": 0.95, "isSuspicious": false, "indicators": [], "explanation": "Normal successful authentication event.", "suggestion": "No action required - this is normal activity." }

LOG: "Failed login attempt for user john from 10.0.0.1"
ANALYSIS: { "type": "Failed Login Attempt", "risk": "low", "confidence": 0.90, "isSuspicious": false, "indicators": [], "explanation": "Single failed login attempt. This is normal - users occasionally mistype passwords.", "suggestion": "No action required unless this becomes a pattern of many attempts." }

LOG: "3 failed login attempts for admin"
ANALYSIS: { "type": "Multiple Failed Logins", "risk": "low", "confidence": 0.85, "isSuspicious": false, "indicators": [], "explanation": "Three failed attempts is within normal range for a user who forgot their password.", "suggestion": "No immediate action needed. Monitor if count exceeds 10 in short period." }

LOG: "ALERT: 47 failed login attempts for 'root' from 203.0.113.50 in 2 minutes"
ANALYSIS: { "type": "Brute Force Attack", "risk": "critical", "confidence": 0.98, "isSuspicious": true, "indicators": ["47 attempts", "2 minute window", "targeting root", "external IP 203.0.113.50"], "explanation": "This is a brute force attack: 47 attempts in 2 minutes from external IP targeting privileged account.", "suggestion": "1) Block IP 203.0.113.50 immediately, 2) Check if any login succeeded, 3) Review root account for compromise." }

LOG: "GET /search?q=test"
ANALYSIS: { "type": "Normal HTTP Request", "risk": "low", "confidence": 0.95, "isSuspicious": false, "indicators": [], "explanation": "Standard search query with normal parameter.", "suggestion": "No action required." }

LOG: "GET /api/users?id=1' UNION SELECT * FROM passwords--"
ANALYSIS: { "type": "SQL Injection Attempt", "risk": "high", "confidence": 0.97, "isSuspicious": true, "indicators": ["UNION SELECT", "SQL comment --", "targeting passwords table"], "explanation": "Classic SQL injection attempt using UNION-based technique to extract password data.", "suggestion": "1) Block source IP, 2) Review WAF rules, 3) Check if query reached database." }

REMEMBER: When analyzing login events, your DEFAULT should be isSuspicious: false unless you see clear evidence of an attack (high volume + short time + same source/target).`;

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
