/**
 * patterns.js - Known attack and error patterns
 * 
 * This file contains regex patterns to quickly detect common attack types
 * before sending to the AI for deeper analysis.
 * 
 * Each pattern has:
 * - name: The type of attack/error
 * - pattern: Regex to match
 * - risk: Risk level (low, medium, high, critical)
 * - description: What this pattern indicates
 */

const patterns = [
    // ==================== AUTHENTICATION ATTACKS ====================
    {
        name: "Brute Force Attack",
        pattern: /too many (login|authentication|sign.?in) attempts|failed login|invalid password|authentication fail/i,
        risk: "high",
        description: "Multiple failed login attempts detected, indicating a possible brute force attack"
    },
    {
        name: "Account Lockout",
        pattern: /account (locked|disabled|suspended)|too many attempts/i,
        risk: "medium",
        description: "Account has been locked due to suspicious activity"
    },

    // ==================== INJECTION ATTACKS ====================
    {
        name: "SQL Injection",
        pattern: /('|"|;|--|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b).*('|"|=|;)/i,
        risk: "critical",
        description: "SQL injection attempt detected - malicious SQL code in input"
    },
    {
        name: "XSS Attack",
        pattern: /<script|javascript:|on\w+\s*=|<iframe|<img.*onerror/i,
        risk: "high",
        description: "Cross-site scripting (XSS) attempt detected"
    },
    {
        name: "Command Injection",
        pattern: /;|\||`|\$\(|&&|\breturn\b|\bexec\b|\bsystem\b/i,
        risk: "critical",
        description: "Possible command injection attempt"
    },

    // ==================== NETWORK ATTACKS ====================
    {
        name: "DDoS/Rate Limiting",
        pattern: /rate limit|too many requests|connection limit|flood|ddos/i,
        risk: "high",
        description: "Possible denial of service or rate limiting triggered"
    },
    {
        name: "Port Scan",
        pattern: /port scan|connection refused|connection reset|multiple ports/i,
        risk: "medium",
        description: "Possible port scanning activity detected"
    },

    // ==================== FILE/PATH ATTACKS ====================
    {
        name: "Path Traversal",
        pattern: /\.\.\//i,
        risk: "high",
        description: "Directory traversal attempt to access unauthorized files"
    },
    {
        name: "File Inclusion",
        pattern: /include|require|file_get_contents|fopen/i,
        risk: "medium",
        description: "Possible file inclusion vulnerability exploitation"
    },

    // ==================== SYSTEM ERRORS ====================
    {
        name: "Database Error",
        pattern: /database (error|connection|timeout)|mysql|postgresql|mongodb|connection (refused|timeout|failed)/i,
        risk: "medium",
        description: "Database connectivity or query error"
    },
    {
        name: "Memory Error",
        pattern: /out of memory|memory (exceeded|limit|allocation)|heap|stack overflow/i,
        risk: "high",
        description: "System memory issue detected"
    },
    {
        name: "Permission Error",
        pattern: /permission denied|access denied|unauthorized|forbidden|403/i,
        risk: "medium",
        description: "Permission or access control error"
    },
    {
        name: "Timeout Error",
        pattern: /timeout|timed out|request timeout|gateway timeout|504/i,
        risk: "low",
        description: "Request or connection timeout"
    },
    {
        name: "Server Error",
        pattern: /internal server error|500|503|server (crash|down|error)/i,
        risk: "high",
        description: "Server-side error detected"
    }
];

module.exports = patterns;
