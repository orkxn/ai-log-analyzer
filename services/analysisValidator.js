/**
 * analysisValidator.js - Correlation-Based Attack Detection Engine (v7.0)
 * 
 * DESIGN PRINCIPLES:
 * 1. CORRELATION: Events analyzed in chains, not isolation
 * 2. SENSITIVE ASSETS: File categories with risk scores
 * 3. THRESHOLDS: Data exfiltration size limits
 * 4. CONFIDENCE LIMITS: No high confidence without verification
 * 5. CONSISTENCY: Suspicious explanation = not Safe
 */

// ==================== WHITELISTED DESTINATIONS ====================

const WHITELISTED_IPS = [
    // Internal ranges are auto-allowed
    // Add trusted external IPs here:
    // '8.8.8.8', '1.1.1.1'
];

const WHITELISTED_DOMAINS = [
    /cloudflare/i,
    /amazonaws/i,
    /azure/i,
    /googleapis/i
];

// ==================== KNOWN BASELINE WORKFLOWS ====================

const BASELINE_WORKFLOWS = {
    backup: {
        patterns: [/backup/i, /cron/i, /scheduled/i],
        allowedFiles: [/\.log$/, /\.bak$/, /archive/i],
        allowedDestinations: ['internal'],
        maxSizeMB: 500
    },
    cicd: {
        patterns: [/jenkins/i, /gitlab-runner/i, /github-actions/i],
        allowedCommands: ['npm', 'yarn', 'pip', 'docker', 'git'],
        allowedDestinations: ['internal', 'registry']
    },
    monitoring: {
        patterns: [/prometheus/i, /grafana/i, /datadog/i],
        allowedFiles: [/metrics/, /stats/],
        maxSizeMB: 10
    }
};

// ==================== SENSITIVE FILE CATEGORIES ====================

const SENSITIVE_FILES = {
    credentials: {
        patterns: [
            /\/etc\/shadow/i,
            /\/etc\/passwd/i,
            /\.ssh\/id_rsa/i,
            /\.aws\/credentials/i,
            /\.env\b/i,
            /secrets?\.(json|yml|yaml)/i,
            /credentials?\.(json|yml|xml)/i,
            /api[_-]?keys?\.(json|txt)/i
        ],
        riskScore: 100,
        category: 'CREDENTIALS'
    },
    customer_data: {
        patterns: [
            /customers?\.(csv|xlsx?|json|sql)/i,
            /users?\.(csv|xlsx?|json|sql)/i,
            /clients?\.(csv|xlsx?|json|sql)/i,
            /members?\.(csv|xlsx?|json|sql)/i,
            /contacts?\.(csv|xlsx?|json|sql)/i,
            /subscribers?\.(csv|xlsx?|json|sql)/i
        ],
        riskScore: 90,
        category: 'CUSTOMER_DATA'
    },
    financial: {
        patterns: [
            /payments?\.(csv|xlsx?|json|sql)/i,
            /transactions?\.(csv|xlsx?|json|sql)/i,
            /invoices?\.(csv|xlsx?|json|sql)/i,
            /billing\.(csv|xlsx?|json|sql)/i,
            /credit[_-]?cards?\.(csv|xlsx?|json|sql)/i,
            /accounts?\.(csv|xlsx?|json|sql)/i
        ],
        riskScore: 95,
        category: 'FINANCIAL'
    },
    database: {
        patterns: [
            /\.sql$/i,
            /dump\.(sql|gz|zip)/i,
            /backup\.(sql|gz)/i,
            /database\.(sql|json)/i,
            /db[_-]?export/i
        ],
        riskScore: 85,
        category: 'DATABASE'
    },
    config: {
        patterns: [
            /web\.config/i,
            /wp-config\.php/i,
            /\.htaccess/i,
            /nginx\.conf/i,
            /httpd\.conf/i,
            /settings\.(py|json|yml)/i
        ],
        riskScore: 70,
        category: 'CONFIG'
    }
};

// ==================== DATA EXFILTRATION THRESHOLDS ====================

const EXFIL_THRESHOLDS = {
    criticalSizeMB: 100,    // > 100MB = Critical
    highSizeMB: 50,         // > 50MB = High
    mediumSizeMB: 10,       // > 10MB = Medium
    minSuspiciousMB: 1      // > 1MB after sensitive file access = Suspicious
};

// ==================== CORRELATION CHAINS ====================

const CORRELATION_CHAINS = {
    data_exfiltration: {
        name: 'Data Exfiltration',
        stages: [
            { name: 'access', patterns: ['login', 'auth', 'session'] },
            { name: 'read', patterns: ['sensitive_file', 'database', 'customer_data'] },
            { name: 'exfil', patterns: ['outbound', 'transfer', 'curl', 'wget', 'nc'] }
        ],
        requiredStages: ['read', 'exfil'],
        severity: 'critical',
        status: 'Malicious'
    },
    credential_theft: {
        name: 'Credential Theft',
        stages: [
            { name: 'access', patterns: ['privilege', 'sudo', 'root'] },
            { name: 'read', patterns: ['shadow', 'passwd', 'credentials'] },
            { name: 'exfil', patterns: ['outbound', 'base64', 'curl'] }
        ],
        requiredStages: ['read'],
        severity: 'critical',
        status: 'Malicious'
    },
    lateral_movement: {
        name: 'Lateral Movement',
        stages: [
            { name: 'recon', patterns: ['scan', 'nmap', 'ping'] },
            { name: 'access', patterns: ['ssh', 'rdp', 'smb'] },
            { name: 'persist', patterns: ['cron', 'scheduled', 'startup'] }
        ],
        requiredStages: ['recon', 'access'],
        severity: 'high',
        status: 'Suspicious'
    }
};

// ==================== ATTACK PRIORITY ====================

const ATTACK_PRIORITY = {
    'Remote Code Execution': 100,
    'Command Injection': 95,
    'Data Exfiltration': 92,
    'Credential Theft': 90,
    'Privilege Escalation': 88,
    'Sensitive File Access': 85,
    'SQL Injection': 75,
    'Large Data Transfer': 70,
    'Brute Force Attack': 60,
    'Suspicious Activity': 30,
    'Normal Activity': 0
};

// ==================== SUSPICION KEYWORDS ====================

const SUSPICION_KEYWORDS = [
    'suspicious', 'unusual', 'anomal', 'unexpected', 'unauthorized',
    'malicious', 'attack', 'exploit', 'breach', 'compromise',
    'exfiltrat', 'injection', 'escalat', 'intrusion', 'threat'
];

// ==================== HARD RULES ====================

const HARD_RULES = {
    remote_script_execution: {
        patterns: [
            /curl\s+[^\|]+\|\s*(ba)?sh/i,
            /wget\s+[^\|]+\|\s*(ba)?sh/i,
            /bash\s+-c\s*["'].*curl/i
        ],
        type: 'Remote Code Execution',
        severity: 'critical',
        status: 'Malicious',
        explanation: 'CRITICAL: Remote script download and execution detected. This is a definitive RCE attack.',
        suggestion: 'IMMEDIATE ACTION: Isolate system, terminate process, block external URL, preserve logs.',
        priority: 100
    },
    reverse_shell: {
        patterns: [
            /nc\s+(-e|-c)\s+/i,
            /bash\s+-i\s+.*\/dev\/tcp/i,
            /\/dev\/tcp\/\d+\.\d+\.\d+\.\d+/i
        ],
        type: 'Remote Code Execution',
        severity: 'critical',
        status: 'Malicious',
        explanation: 'CRITICAL: Reverse shell detected. Attacker has remote command execution.',
        suggestion: 'IMMEDIATE ACTION: Disconnect from network, kill shell process, full forensic analysis.',
        priority: 100
    },
    credential_access: {
        patterns: [
            /cat\s+.*\/etc\/shadow/i,
            /\/etc\/shadow.*\|/i
        ],
        type: 'Credential Theft',
        severity: 'critical',
        status: 'Malicious',
        explanation: 'CRITICAL: Password hash file access detected. Credentials are compromised.',
        suggestion: 'IMMEDIATE ACTION: Force password reset for all users, check for exfiltration.',
        priority: 90
    }
};

// ==================== CRITICAL PATTERNS ====================

const CRITICAL_PATTERNS = {
    command_execution: {
        patterns: [
            /;\s*(cat|ls|rm|wget|curl|bash|sh|python|perl|php|nc)\s/i,
            /\|\s*(bash|sh|python|perl)\s/i,
            /exec\s*\(/i,
            /system\s*\(/i
        ],
        type: 'Command Injection',
        severity: 'critical',
        priority: 95
    },
    sensitive_file_generic: {
        patterns: [
            /\/etc\/shadow/i,
            /\/etc\/sudoers/i,
            /\.ssh\/id_rsa/i
        ],
        type: 'Sensitive File Access',
        severity: 'critical',
        priority: 85
    }
};

// ==================== HIGH PATTERNS ====================

const HIGH_PATTERNS = {
    sql_injection: {
        patterns: [
            /union\s+(all\s+)?select/i,
            /'\s*or\s*'?\d+\s*=\s*'?\d+/i,
            /drop\s+(table|database)/i,
            /;\s*--\s*$/
        ],
        type: 'SQL Injection',
        severity: 'high',
        priority: 75
    },
    path_traversal: {
        patterns: [/\.\.\//],
        type: 'Path Traversal',
        severity: 'high',
        priority: 65
    },
    brute_force: {
        patterns: [/(\d{2,})\s*(failed|unsuccessful)\s*(login|attempt)/i],
        type: 'Brute Force Attack',
        severity: 'high',
        priority: 60,
        requiresMinAttempts: 10
    }
};

// ==================== SEVERITY MAPPING ====================

const SEVERITY_STATUS_MAP = {
    critical: { status: 'Malicious', isSuspicious: true },
    high: { status: 'Suspicious', isSuspicious: true },
    medium: { status: 'Investigate', isSuspicious: false },
    low: { status: 'Safe', isSuspicious: false }
};

// ==================== MAIN FUNCTION ====================

function validateAndCorrect(aiAnalysis, originalLog) {
    const auditLog = {
        timestamp: new Date().toISOString(),
        phases: [],
        hardRuleTriggered: false
    };

    // ========== PHASE 1: HARD RULES ==========
    const hardRule = checkHardRules(originalLog);
    auditLog.phases.push({ phase: 'HARD_RULES', result: hardRule });
    if (hardRule.triggered) {
        auditLog.hardRuleTriggered = true;
        return generateOutput(hardRule, auditLog, aiAnalysis);
    }

    // ========== PHASE 2: EXTRACT CONTEXT ==========
    const context = extractContext(originalLog);
    auditLog.phases.push({ phase: 'CONTEXT', context });

    // ========== PHASE 3: DETECT SENSITIVE FILES ==========
    const sensitiveFiles = detectSensitiveFiles(originalLog);
    auditLog.phases.push({ phase: 'SENSITIVE_FILES', sensitiveFiles });

    // ========== PHASE 4: DETECT DATA TRANSFER SIZE ==========
    const dataTransfer = detectDataTransfer(originalLog);
    auditLog.phases.push({ phase: 'DATA_TRANSFER', dataTransfer });

    // ========== PHASE 5: DETECT PATTERNS ==========
    const patterns = detectPatterns(originalLog, context);
    auditLog.phases.push({ phase: 'PATTERNS', patterns });

    // ========== PHASE 6: CORRELATION ANALYSIS ==========
    const correlation = analyzeCorrelation(originalLog, sensitiveFiles, dataTransfer, patterns, context);
    auditLog.phases.push({ phase: 'CORRELATION', correlation });

    // ========== PHASE 7: CHECK BASELINE WORKFLOWS ==========
    const baseline = checkBaseline(originalLog, context, sensitiveFiles, dataTransfer);
    auditLog.phases.push({ phase: 'BASELINE', baseline });

    // ========== PHASE 8: CALCULATE RISK SCORE ==========
    const riskScore = calculateRiskScore(sensitiveFiles, dataTransfer, patterns, correlation, context, baseline);
    auditLog.phases.push({ phase: 'RISK_SCORE', riskScore });

    // ========== PHASE 9: DETERMINE SEVERITY (Rules only) ==========
    const severity = determineSeverity(riskScore, correlation, patterns, dataTransfer, sensitiveFiles);
    auditLog.phases.push({ phase: 'SEVERITY', severity });

    // ========== PHASE 10: CALCULATE CONFIDENCE (With limits) ==========
    const confidence = calculateConfidence(baseline, context, severity);
    auditLog.phases.push({ phase: 'CONFIDENCE', confidence });

    // ========== PHASE 11: VALIDATE AI EXPLANATION ==========
    const validatedAI = validateAIExplanation(aiAnalysis, severity);
    auditLog.phases.push({ phase: 'AI_VALIDATION', validatedAI });

    // ========== PHASE 12: ENFORCE CONSISTENCY ==========
    const finalDecision = enforceConsistency(severity, validatedAI, correlation, sensitiveFiles, dataTransfer, patterns, context);
    auditLog.phases.push({ phase: 'CONSISTENCY', finalDecision });

    return generateOutput(finalDecision, auditLog, aiAnalysis);
}

// ==================== PHASE 1: HARD RULES ====================

function checkHardRules(logText) {
    for (const [name, rule] of Object.entries(HARD_RULES)) {
        if (rule.patterns.some(p => p.test(logText))) {
            return {
                triggered: true,
                rule: name,
                type: rule.type,
                severity: rule.severity,
                status: rule.status,
                explanation: rule.explanation,
                suggestion: rule.suggestion,
                priority: rule.priority,
                indicators: [`HARD RULE: ${rule.type}`]
            };
        }
    }
    return { triggered: false };
}

// ==================== PHASE 2: CONTEXT ====================

function extractContext(logText) {
    const userMatch = logText.match(/user[:\s]+['"]?([a-zA-Z0-9_\-@.]+)['"]?/i);
    const user = userMatch ? userMatch[1] : null;

    const servicePatterns = [/^(svc|service|sys|daemon|cron|www-data|nginx|apache)$/i];
    const isServiceAccount = user ? servicePatterns.some(p => p.test(user)) : false;

    const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    const privateRegex = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/;
    const allIPs = [...new Set(logText.match(ipRegex) || [])];
    const externalIPs = allIPs.filter(ip => !privateRegex.test(ip));
    const whitelistedIPs = externalIPs.filter(ip => WHITELISTED_IPS.includes(ip));
    const unwhitelistedIPs = externalIPs.filter(ip => !WHITELISTED_IPS.includes(ip));

    const attemptCount = extractAttemptCount(logText);
    const hasSuccessfulAuth = /logged\s*in\s*successfully|authentication\s*success/i.test(logText);
    const hasFailedAuth = /failed\s*(login|auth)/i.test(logText);

    return {
        user,
        isServiceAccount,
        allIPs,
        externalIPs,
        whitelistedIPs,
        unwhitelistedIPs,
        hasUnwhitelistedExternal: unwhitelistedIPs.length > 0,
        attemptCount,
        hasSuccessfulAuth,
        hasFailedAuth
    };
}

// ==================== PHASE 3: SENSITIVE FILES ====================

function detectSensitiveFiles(logText) {
    const detected = [];
    let totalRiskScore = 0;
    let highestCategory = null;

    for (const [name, config] of Object.entries(SENSITIVE_FILES)) {
        const matches = config.patterns.filter(p => p.test(logText));
        if (matches.length > 0) {
            detected.push({
                name,
                category: config.category,
                riskScore: config.riskScore,
                matchCount: matches.length
            });
            totalRiskScore += config.riskScore;
            if (!highestCategory || config.riskScore > SENSITIVE_FILES[highestCategory]?.riskScore) {
                highestCategory = name;
            }
        }
    }

    return {
        detected,
        count: detected.length,
        totalRiskScore,
        highestCategory,
        hasCredentials: detected.some(d => d.category === 'CREDENTIALS'),
        hasCustomerData: detected.some(d => d.category === 'CUSTOMER_DATA'),
        hasFinancial: detected.some(d => d.category === 'FINANCIAL')
    };
}

// ==================== PHASE 4: DATA TRANSFER ====================

function detectDataTransfer(logText) {
    // Extract size patterns
    const sizePatterns = [
        { regex: /(\d+(?:\.\d+)?)\s*(GB|gigabyte)/i, multiplier: 1024 },
        { regex: /(\d+(?:\.\d+)?)\s*(MB|megabyte)/i, multiplier: 1 },
        { regex: /(\d+(?:\.\d+)?)\s*(KB|kilobyte)/i, multiplier: 0.001 },
        { regex: /size[:\s]+(\d+(?:\.\d+)?)\s*(MB|GB)/i, multiplier: 1 },
        { regex: /transfer[:\s]+(\d+(?:\.\d+)?)\s*(MB|GB)/i, multiplier: 1 }
    ];

    let sizeMB = 0;
    for (const { regex, multiplier } of sizePatterns) {
        const match = logText.match(regex);
        if (match) {
            const value = parseFloat(match[1]);
            const unit = match[2].toUpperCase();
            sizeMB = value * (unit.startsWith('G') ? 1024 : multiplier);
            break;
        }
    }

    // Detect outbound indicators
    const hasOutbound = /outbound|upload|transfer|POST|curl|wget|scp|ftp|exfil/i.test(logText);
    const hasLargeTransfer = sizeMB >= EXFIL_THRESHOLDS.minSuspiciousMB;

    let severity = 'none';
    if (sizeMB >= EXFIL_THRESHOLDS.criticalSizeMB) {
        severity = 'critical';
    } else if (sizeMB >= EXFIL_THRESHOLDS.highSizeMB) {
        severity = 'high';
    } else if (sizeMB >= EXFIL_THRESHOLDS.mediumSizeMB) {
        severity = 'medium';
    } else if (sizeMB >= EXFIL_THRESHOLDS.minSuspiciousMB) {
        severity = 'low';
    }

    return {
        sizeMB,
        hasOutbound,
        hasLargeTransfer,
        severity,
        isSuspicious: hasOutbound && hasLargeTransfer
    };
}

// ==================== PHASE 5: PATTERN DETECTION ====================

function detectPatterns(logText, context) {
    const findings = [];
    const categories = [];
    let highestSeverity = 'low';
    let highestPriority = 0;

    for (const [category, config] of Object.entries(CRITICAL_PATTERNS)) {
        if (config.patterns.some(p => p.test(logText))) {
            findings.push({ category, type: config.type, severity: 'critical', priority: config.priority });
            categories.push(category);
            highestSeverity = 'critical';
            if (config.priority > highestPriority) highestPriority = config.priority;
        }
    }

    for (const [category, config] of Object.entries(HIGH_PATTERNS)) {
        if (config.patterns.some(p => p.test(logText))) {
            if (config.requiresMinAttempts && context.attemptCount < config.requiresMinAttempts) continue;
            findings.push({ category, type: config.type, severity: 'high', priority: config.priority });
            categories.push(category);
            if (highestSeverity !== 'critical') highestSeverity = 'high';
            if (config.priority > highestPriority) highestPriority = config.priority;
        }
    }

    return { findings, categories, highestSeverity, highestPriority };
}

// ==================== PHASE 6: CORRELATION ====================

function analyzeCorrelation(logText, sensitiveFiles, dataTransfer, patterns, context) {
    const detectedChains = [];

    for (const [chainName, config] of Object.entries(CORRELATION_CHAINS)) {
        const stagesPresent = { access: false, read: false, exfil: false, recon: false, persist: false };

        // Check access stage
        if (context.hasSuccessfulAuth || /login|session|auth/i.test(logText)) {
            stagesPresent.access = true;
        }

        // Check read stage
        if (sensitiveFiles.count > 0 || /read|access|cat|view|dump/i.test(logText)) {
            stagesPresent.read = true;
        }

        // Check exfil stage
        if (dataTransfer.hasOutbound || context.hasUnwhitelistedExternal ||
            /curl|wget|nc|scp|ftp|upload|transfer|POST/i.test(logText)) {
            stagesPresent.exfil = true;
        }

        // Check if required stages are present
        const requiredMet = config.requiredStages.every(stage => stagesPresent[stage]);

        if (requiredMet) {
            detectedChains.push({
                name: chainName,
                displayName: config.name,
                severity: config.severity,
                status: config.status,
                stagesPresent
            });
        }
    }

    // Special case: Sensitive file + outbound = exfiltration
    const sensitiveWithExfil = sensitiveFiles.count > 0 &&
        (dataTransfer.hasOutbound || context.hasUnwhitelistedExternal);

    return {
        chains: detectedChains,
        hasChain: detectedChains.length > 0,
        primaryChain: detectedChains[0] || null,
        sensitiveWithExfil,
        isDataExfil: sensitiveWithExfil || detectedChains.some(c => c.name === 'data_exfiltration')
    };
}

// ==================== PHASE 7: BASELINE CHECK ====================

function checkBaseline(logText, context, sensitiveFiles, dataTransfer) {
    let matchedWorkflow = null;
    let isBaseline = false;

    for (const [name, config] of Object.entries(BASELINE_WORKFLOWS)) {
        const patternMatch = config.patterns.some(p => p.test(logText));
        if (!patternMatch) continue;

        let valid = true;

        // Check destination constraints
        if (config.allowedDestinations?.includes('internal') && context.hasUnwhitelistedExternal) {
            valid = false;
        }

        // Check size constraints
        if (config.maxSizeMB && dataTransfer.sizeMB > config.maxSizeMB) {
            valid = false;
        }

        // Check file constraints
        if (config.allowedFiles && sensitiveFiles.count > 0) {
            const hasDisallowedFiles = sensitiveFiles.detected.some(f =>
                !config.allowedFiles.some(af => af.test(f.name))
            );
            if (hasDisallowedFiles) valid = false;
        }

        if (valid) {
            matchedWorkflow = name;
            isBaseline = true;
            break;
        }
    }

    return {
        isBaseline,
        matchedWorkflow,
        allowsHighConfidence: isBaseline && !context.hasUnwhitelistedExternal
    };
}

// ==================== PHASE 8: RISK SCORE ====================

function calculateRiskScore(sensitiveFiles, dataTransfer, patterns, correlation, context, baseline) {
    let score = 0;

    // Sensitive file score
    score += sensitiveFiles.totalRiskScore;

    // Data transfer score
    if (dataTransfer.severity === 'critical') score += 80;
    else if (dataTransfer.severity === 'high') score += 60;
    else if (dataTransfer.severity === 'medium') score += 40;
    else if (dataTransfer.isSuspicious) score += 20;

    // Pattern score
    for (const finding of patterns.findings) {
        if (finding.severity === 'critical') score += 100;
        else if (finding.severity === 'high') score += 60;
        else score += 30;
    }

    // Correlation multiplier
    if (correlation.isDataExfil) score *= 1.5;
    if (correlation.hasChain) score *= 1.3;

    // External IP penalty
    if (context.hasUnwhitelistedExternal) score += 30;

    // Baseline reduction (but never below 50 if sensitive files accessed)
    if (baseline.isBaseline && sensitiveFiles.count === 0) {
        score *= 0.3;
    }

    return { score: Math.round(score), factors: { sensitiveFiles: sensitiveFiles.count, dataTransfer: dataTransfer.sizeMB } };
}

// ==================== PHASE 9: SEVERITY ====================

function determineSeverity(riskScore, correlation, patterns, dataTransfer, sensitiveFiles) {
    // Correlation chains force severity
    if (correlation.hasChain) {
        return {
            severity: correlation.primaryChain.severity,
            status: correlation.primaryChain.status,
            reason: `Attack chain: ${correlation.primaryChain.displayName}`
        };
    }

    // Sensitive files + exfil = critical
    if (correlation.sensitiveWithExfil) {
        return {
            severity: 'critical',
            status: 'Malicious',
            reason: 'Sensitive file access with outbound transfer'
        };
    }

    // Large transfer after sensitive access
    if (sensitiveFiles.count > 0 && dataTransfer.hasLargeTransfer) {
        return {
            severity: 'critical',
            status: 'Malicious',
            reason: 'Large data transfer following sensitive file access'
        };
    }

    // Pattern-based severity
    if (patterns.highestSeverity === 'critical') {
        return {
            severity: 'critical',
            status: 'Malicious',
            reason: `Critical pattern: ${patterns.findings[0]?.type}`
        };
    }

    // Risk score thresholds
    if (riskScore.score >= 150) {
        return { severity: 'critical', status: 'Malicious', reason: `Risk score: ${riskScore.score}` };
    }
    if (riskScore.score >= 80) {
        return { severity: 'high', status: 'Suspicious', reason: `Risk score: ${riskScore.score}` };
    }
    if (riskScore.score >= 40) {
        return { severity: 'medium', status: 'Investigate', reason: `Risk score: ${riskScore.score}` };
    }

    return { severity: 'low', status: 'Safe', reason: 'No significant risk detected' };
}

// ==================== PHASE 10: CONFIDENCE ====================

function calculateConfidence(baseline, context, severity) {
    let confidence = 0.70; // Default moderate confidence

    // Only allow high confidence with verification
    if (baseline.allowsHighConfidence) {
        confidence = 0.90;
    } else if (context.whitelistedIPs.length > 0 && context.unwhitelistedIPs.length === 0) {
        confidence = 0.85;
    }

    // Reduce confidence for unverified external activity
    if (context.hasUnwhitelistedExternal) {
        confidence = Math.min(confidence, 0.75);
    }

    // Critical findings increase confidence in detection
    if (severity.severity === 'critical') {
        confidence = Math.max(confidence, 0.90);
    }

    // Cap at 85% without verification
    if (!baseline.isBaseline && context.hasUnwhitelistedExternal) {
        confidence = Math.min(confidence, 0.85);
    }

    return { value: confidence, verified: baseline.isBaseline };
}

// ==================== PHASE 11: AI VALIDATION ====================

function validateAIExplanation(aiAnalysis, severity) {
    let explanation = aiAnalysis.explanation || '';

    // Detect suspicion in explanation
    const hasSuspicionWords = SUSPICION_KEYWORDS.some(kw =>
        explanation.toLowerCase().includes(kw)
    );

    // Force definitive language for dangerous findings
    if (severity.severity === 'critical' || severity.severity === 'high') {
        explanation = explanation
            .replace(/could be normal/gi, 'is not legitimate')
            .replace(/might be/gi, 'is')
            .replace(/possibly/gi, 'definitively');
    }

    return {
        explanation: explanation.trim() || generateExplanation(severity),
        hasSuspicionWords,
        original: aiAnalysis.explanation
    };
}

function generateExplanation(severity) {
    if (severity.severity === 'critical') {
        return `CRITICAL: ${severity.reason}. This requires immediate incident response.`;
    }
    if (severity.severity === 'high') {
        return `${severity.reason}. Investigation required.`;
    }
    if (severity.severity === 'medium') {
        return `${severity.reason}. Manual review recommended.`;
    }
    return 'Activity appears normal.';
}

// ==================== PHASE 12: CONSISTENCY ====================

function enforceConsistency(severity, validatedAI, correlation, sensitiveFiles, dataTransfer, patterns, context) {
    let { severity: sev, status } = severity;
    let explanation = validatedAI.explanation;
    const indicators = [];

    // RULE 1: Suspicious explanation cannot be Safe
    if (validatedAI.hasSuspicionWords && status === 'Safe') {
        status = 'Investigate';
        sev = 'medium';
        indicators.push('Escalated: Suspicious language in explanation');
    }

    // RULE 2: Critical = Malicious (always)
    if (sev === 'critical' && status !== 'Malicious') {
        status = 'Malicious';
    }

    // RULE 3: High = Suspicious (always)
    if (sev === 'high' && status === 'Safe') {
        status = 'Suspicious';
    }

    // RULE 4: Large transfer after sensitive = not Safe
    if (sensitiveFiles.count > 0 && dataTransfer.hasOutbound && status === 'Safe') {
        status = 'Investigate';
        sev = sev === 'low' ? 'medium' : sev;
        indicators.push('Sensitive file + outbound transfer');
    }

    // Add indicators
    if (sensitiveFiles.count > 0) {
        sensitiveFiles.detected.forEach(f => indicators.push(`${f.category}: ${f.name}`));
    }
    if (dataTransfer.sizeMB > 0) {
        indicators.push(`Data Transfer: ${dataTransfer.sizeMB.toFixed(1)} MB`);
    }
    if (correlation.hasChain) {
        indicators.push(`Attack Chain: ${correlation.primaryChain.displayName}`);
    }
    patterns.findings.forEach(f => indicators.push(`Pattern: ${f.type}`));
    if (context.hasUnwhitelistedExternal) {
        indicators.push(`External IP: ${context.unwhitelistedIPs.join(', ')}`);
    }

    // Determine type
    let type = 'Normal Activity';
    if (correlation.hasChain) {
        type = correlation.primaryChain.displayName;
    } else if (patterns.findings.length > 0) {
        type = patterns.findings[0].type;
    } else if (sensitiveFiles.count > 0 && dataTransfer.hasOutbound) {
        type = 'Data Exfiltration';
    } else if (sensitiveFiles.count > 0) {
        type = 'Sensitive File Access';
    }

    return {
        type,
        severity: sev,
        status,
        explanation,
        indicators,
        isSuspicious: sev !== 'low',
        priority: ATTACK_PRIORITY[type] || 0
    };
}

// ==================== OUTPUT ====================

function generateOutput(decision, auditLog, aiAnalysis) {
    let { severity, status } = decision;

    // Final consistency check
    if (severity === 'critical' && status !== 'Malicious') status = 'Malicious';
    if (status === 'Malicious' && severity !== 'critical') severity = 'critical';

    return {
        type: String(decision.type),
        risk: String(severity),
        confidence: decision.confidence?.value || 0.85,
        explanation: String(decision.explanation),
        suggestion: generateSuggestion(severity, status, decision.type),
        isSuspicious: Boolean(severity === 'critical' || severity === 'high'),
        indicators: (decision.indicators || []).filter(i => typeof i === 'string'),
        status: String(status),
        _meta: {
            validated: true,
            decisionSource: auditLog.hardRuleTriggered ? 'hard_rule' : 'rules',
            decisionSummary: auditLog.hardRuleTriggered
                ? 'HARD RULE: Non-negotiable security rule triggered.'
                : 'Correlation-based rule decision.',
            phases: auditLog.phases.map(p => p.phase),
            priority: decision.priority || 0,
            originalAI: aiAnalysis
        }
    };
}

function generateSuggestion(severity, status, type) {
    if (status === 'Malicious') {
        return `IMMEDIATE ACTION: ${type} confirmed. Isolate systems, preserve evidence, revoke credentials, begin incident response.`;
    }
    if (status === 'Suspicious') {
        return `Investigation required: ${type}. Review related events, check user history, preserve logs.`;
    }
    if (status === 'Investigate') {
        return 'Manual review recommended. Activity may be benign but warrants attention.';
    }
    return 'No action required.';
}

// ==================== HELPERS ====================

function extractAttemptCount(logText) {
    const match = logText.match(/(\d+)\s*(failed|unsuccessful)\s*(login|attempt)/i);
    if (match) {
        const num = parseInt(match[1]);
        if (num > 0 && num < 10000) return num;
    }
    return 0;
}

// ==================== EXPORTS ====================

module.exports = {
    validateAndCorrect,
    checkHardRules,
    detectSensitiveFiles,
    analyzeCorrelation,
    SENSITIVE_FILES,
    EXFIL_THRESHOLDS,
    CORRELATION_CHAINS
};
