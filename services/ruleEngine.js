/**
 * ruleEngine.js - Pattern-based log analysis
 * 
 * This service quickly checks logs against known patterns
 * before sending to AI for deeper analysis.
 * 
 * Why use both rules AND AI?
 * - Rules are FAST and catch obvious patterns instantly
 * - AI provides deeper analysis and explanations
 * - Together they give the best results!
 */

const patterns = require('../config/patterns');

/**
 * Analyzes a log entry against known patterns
 * @param {string} logText - The log entry to analyze
 * @returns {object} - Analysis result with matched patterns
 */
function analyzeWithRules(logText) {
    const matches = [];

    // Check each pattern against the log
    for (const pattern of patterns) {
        if (pattern.pattern.test(logText)) {
            matches.push({
                name: pattern.name,
                risk: pattern.risk,
                description: pattern.description
            });
        }
    }

    // If we found matches, return the highest risk one
    if (matches.length > 0) {
        // Sort by risk level (critical > high > medium > low)
        const riskOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        matches.sort((a, b) => riskOrder[b.risk] - riskOrder[a.risk]);

        return {
            hasMatch: true,
            primaryMatch: matches[0],
            allMatches: matches,
            matchCount: matches.length
        };
    }

    // No patterns matched
    return {
        hasMatch: false,
        primaryMatch: null,
        allMatches: [],
        matchCount: 0
    };
}

/**
 * Extracts potential IP addresses from log text
 * @param {string} logText - The log entry
 * @returns {string[]} - Array of IP addresses found
 */
function extractIPs(logText) {
    const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    return logText.match(ipPattern) || [];
}

/**
 * Extracts potential file paths from log text
 * @param {string} logText - The log entry
 * @returns {string[]} - Array of file paths found
 */
function extractPaths(logText) {
    const pathPattern = /(?:\/[\w.-]+)+|(?:[A-Za-z]:\\[\w\\.-]+)/g;
    return logText.match(pathPattern) || [];
}

module.exports = {
    analyzeWithRules,
    extractIPs,
    extractPaths
};
