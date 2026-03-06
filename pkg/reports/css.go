package reports

const reportCSS = `
/* Varax Compliance Report Styles */
* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    color: #2d3748;
    background: #ffffff;
    line-height: 1.6;
    font-size: 14px;
}

.container {
    max-width: 960px;
    margin: 0 auto;
    padding: 40px 24px;
}

/* Header */
.header {
    border-bottom: 3px solid #1a365d;
    padding-bottom: 20px;
    margin-bottom: 32px;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
}

.logo {
    font-size: 28px;
    font-weight: 800;
    color: #1a365d;
    letter-spacing: 4px;
}

.header-meta {
    text-align: right;
    color: #718096;
    font-size: 13px;
}

/* Sections */
.section {
    margin-bottom: 36px;
}

.section-title {
    font-size: 20px;
    font-weight: 700;
    color: #1a365d;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 8px;
    margin-bottom: 16px;
}

/* Cover */
.cover {
    text-align: center;
    padding: 48px 0 32px;
    border-bottom: 2px solid #e2e8f0;
    margin-bottom: 36px;
}

.cover h1 {
    font-size: 32px;
    color: #1a365d;
    margin-bottom: 8px;
}

.cover .subtitle {
    font-size: 16px;
    color: #718096;
}

/* Score Gauge */
.score-gauge {
    display: flex;
    align-items: center;
    gap: 16px;
    margin: 16px 0;
}

.score-value {
    font-size: 48px;
    font-weight: 800;
    min-width: 100px;
}

.score-bar-container {
    flex: 1;
    height: 24px;
    background: #e2e8f0;
    border-radius: 12px;
    overflow: hidden;
}

.score-bar {
    height: 100%;
    border-radius: 12px;
    transition: width 0.3s;
}

.score-high .score-value { color: #38a169; }
.score-high .score-bar { background: #38a169; }
.score-medium .score-value { color: #d69e2e; }
.score-medium .score-bar { background: #d69e2e; }
.score-low .score-value { color: #e53e3e; }
.score-low .score-bar { background: #e53e3e; }

/* Summary Cards */
.summary-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin: 20px 0;
}

.summary-card {
    padding: 16px;
    border-radius: 8px;
    text-align: center;
    border: 1px solid #e2e8f0;
}

.summary-card .count {
    font-size: 32px;
    font-weight: 700;
}

.summary-card .label {
    font-size: 12px;
    color: #718096;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.card-pass { background: #f0fff4; border-color: #c6f6d5; }
.card-pass .count { color: #38a169; }
.card-fail { background: #fff5f5; border-color: #fed7d7; }
.card-fail .count { color: #e53e3e; }
.card-partial { background: #fffff0; border-color: #fefcbf; }
.card-partial .count { color: #d69e2e; }
.card-na { background: #f7fafc; border-color: #e2e8f0; }
.card-na .count { color: #a0aec0; }

/* Status Badges */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.status-pass { background: #c6f6d5; color: #276749; }
.status-fail { background: #fed7d7; color: #9b2c2c; }
.status-warn { background: #fefcbf; color: #975a16; }
.status-skip { background: #e2e8f0; color: #4a5568; }
.status-partial { background: #fefcbf; color: #975a16; }
.status-na { background: #e2e8f0; color: #718096; }

/* Severity Badges */
.severity-critical { background: #9b2c2c; color: #ffffff; }
.severity-high { background: #e53e3e; color: #ffffff; }
.severity-medium { background: #d69e2e; color: #ffffff; }
.severity-low { background: #3182ce; color: #ffffff; }
.severity-info { background: #a0aec0; color: #ffffff; }

/* Tables */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
    font-size: 13px;
}

thead th {
    background: #1a365d;
    color: #ffffff;
    padding: 10px 12px;
    text-align: left;
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

tbody td {
    padding: 8px 12px;
    border-bottom: 1px solid #e2e8f0;
}

tbody tr:nth-child(even) {
    background: #f7fafc;
}

tbody tr:hover {
    background: #edf2f7;
}

/* Control Cards */
.control-card {
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    margin-bottom: 20px;
    overflow: hidden;
}

.control-card-header {
    background: #f7fafc;
    padding: 14px 16px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #e2e8f0;
}

.control-card-header h3 {
    font-size: 15px;
    color: #1a365d;
}

.control-card-body {
    padding: 16px;
}

.control-description {
    color: #718096;
    font-size: 13px;
    margin-bottom: 12px;
}

/* Evidence Section */
.evidence-item {
    background: #f7fafc;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 12px;
    margin-bottom: 8px;
}

.evidence-category {
    font-weight: 600;
    color: #1a365d;
    font-size: 13px;
}

.evidence-data {
    background: #2d3748;
    color: #e2e8f0;
    padding: 12px;
    border-radius: 4px;
    font-family: "SF Mono", "Fira Code", "Fira Mono", Menlo, Consolas, monospace;
    font-size: 12px;
    overflow-x: auto;
    white-space: pre-wrap;
    margin-top: 8px;
}

/* History Bar Chart */
.history-chart {
    display: flex;
    align-items: flex-end;
    gap: 4px;
    height: 120px;
    padding: 8px 0;
}

.history-bar {
    flex: 1;
    border-radius: 3px 3px 0 0;
    min-width: 20px;
    position: relative;
}

.history-bar-label {
    position: absolute;
    bottom: -20px;
    left: 50%;
    transform: translateX(-50%);
    font-size: 10px;
    color: #718096;
}

/* Findings List */
.finding {
    padding: 12px 0;
    border-bottom: 1px solid #e2e8f0;
}

.finding:last-child {
    border-bottom: none;
}

.finding-header {
    display: flex;
    gap: 8px;
    align-items: center;
    margin-bottom: 4px;
}

.finding-id {
    font-weight: 600;
    color: #1a365d;
}

.finding-message {
    color: #4a5568;
    font-size: 13px;
}

/* Footer */
.footer {
    margin-top: 48px;
    padding-top: 16px;
    border-top: 1px solid #e2e8f0;
    color: #a0aec0;
    font-size: 12px;
    text-align: center;
}

.disclaimer {
    margin-top: 8px;
    font-style: italic;
}

/* Print Styles */
@media print {
    @page {
        margin: 20mm 15mm;
        size: A4;
    }

    body {
        font-size: 11px;
    }

    .container {
        max-width: 100%;
        padding: 0;
    }

    .section {
        page-break-inside: avoid;
    }

    .control-card {
        page-break-inside: avoid;
    }

    .cover {
        page-break-after: always;
    }

    .score-bar-container {
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }

    .badge, .summary-card, thead th {
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }

    tbody tr:nth-child(even) {
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }
}
`
