---
layout: default
title: Report Command — HunterX v6.0.0
keywords: HunterX Report Command, hunterx report, report generation, security reports
description: >-
  Generate professional security reports in various formats from scan results and assessment data.
---
# Report Command

The `report` command allows you to generate professional security reports from HunterX scan results, assessment data, and knowledge graph information. Reports can be generated in multiple formats including HTML, PDF, JSON, XML, and Markdown.

## Syntax

```bash
hunterx report [SUBCOMMAND] [OPTIONS]
```

## Subcommands

| Subcommand | Description |
|------------|-------------|
| `generate` | Generate a report from scan data |
| `list` | List available report templates |
| `info` | Show detailed information about a specific report template |
| `template` | Create, edit, or manage report templates |
| `export` | Export report data in various formats |
| `schedule` | Schedule automatic report generation |
| `email` | Send reports via email |
| `preview` | Preview a report before generating |
| `validate` | Validate report data and template compatibility |

## Examples

### Generate a Basic Report

```bash
hunterx report generate --input ./scans/20230815_143022/ --format html --output ./reports/scan-report.html
```

### Generate a PDF Report with Custom Template

```bash
hunterx report generate --input ./scans/20230815_143022/ --format pdf --template executive --output ./reports/executive-summary.pdf
```

### Generate a JSON Report for API Consumption

```bash
hunterx report generate --input ./scans/20230815_143022/ --format json --output ./reports/scan-data.json
```

### List Available Report Templates

```bash
hunterx report list
```

Sample output:
```
Available Report Templates:
  executive    : Executive summary for management
  technical    : Detailed technical report for security teams
  compliance   : Compliance-focused report (PCI DSS, HIPAA, etc.)
  penetration  : Full penetration test report
  vulnerability: Vulnerability assessment report
  custom       : User-defined custom template
```

### Get Template Information

```bash
hunterx report info --template technical
```

Sample output:
```
Template: technical
Description: Detailed technical report for security teams
Sections:
  - Executive Summary
  - Scope and Methodology
  - Asset Inventory
  - Vulnerability Findings
  - Exploitation Results
  - Risk Assessment
  - Remediation Recommendations
  - Appendices
Formats Supported: html, pdf, json, xml, md
Default Format: html
Required Data:
  - Scan results (JSON or XML)
  - Asset inventory
  - Vulnerability data
Optional Data:
  - Knowledge graph data
  - Agent logs
  - Workflow execution details
Customization Options:
  - logo: Path to logo image
  - cover_page: Include cover page (true/false)
  - toc: Include table of contents (true/false)
  - page_numbers: Include page numbers (true/false)
  - confidentiality: Confidentiality header/footer
  - version: Report version number
```

### Schedule Report Generation

```bash
hunterx report schedule --cron "0 0 * * 0" --input ./scans/weekly/ --format pdf --output ./reports/weekly-report.pdf
```

### Email a Report

```bash
hunterx report email --report ./reports/scan-report.html --to security-team@example.com --subject "Weekly Scan Report" --body "Please find attached the weekly security scan report."
```

### Preview a Report

```bash
hunterx report preview --input ./scans/20230815_143022/ --format html --template technical
```

## Common Options

| Option | Description |
|--------|-------------|
| `--input` | Path to scan results or assessment data |
| `--format` | Output format (html, pdf, json, xml, md) |
| `--output` | Output file path |
| `--template` | Report template to use (executive, technical, compliance, etc.) |
| `--title` | Report title |
| `--author` | Report author |
| `--date` | Report date (default: current date) |
| `--logo` | Path to logo image for header/footer |
| `--cover` | Include cover page (true/false) |
| `--toc` | Include table of contents (true/false) |
| `--section` | Include specific sections only (comma-separated) |
| `--exclude` | Exclude specific sections (comma-separated) |
| `--logo-width` | Logo width in pixels or percentage |
| `--font` | Font family for PDF reports |
| `--font-size` | Base font size for PDF reports |
| `--margin` | Page margins (top,right,bottom,left) |
| `--highlight` | Syntax highlighting for code blocks |
| `--theme` | Color theme (light, dark, corporate, etc.) |
| `--compress` | Compress output (for HTML/PDF) |
| `--password` | Password-protect PDF output |
| `--watermark` | Watermark text for PDF pages |
| `--compliance` | Compliance framework to align with (PCI, HIPAA, etc.) |
| `--cvss-version` | CVSS version to use for scoring (2.0, 3.0, 3.1) |
| `--max-vulns` | Maximum number of vulnerabilities to display per page |
| `--group-by` | Group findings by (host, severity, type, etc.) |
| `--sort-by` | Sort findings by (severity, cvss, host, etc.) |
| `--order` | Sort order (asc, desc) |

## Report Formats

### HTML
- Interactive table of contents
- Collapsible sections
- Searchable content
- Responsive design
- Export to PDF via browser print

### PDF
- Print-optimized layout
- Vector graphics for scalability
- Embedded fonts
- Password protection
- Watermarking support
- Table of contents with page numbers

### JSON
- Structured data for API consumption
- Machine-readable format
- Includes all raw data and metadata
- Easy to parse and process

### XML
- Structured data with schema validation
- Machine-readable format
- Compatible with legacy systems
- Extensible with custom namespaces

### Markdown
- Simple, readable format
- Easy to version control
- Can be converted to other formats
- Suitable for wiki or documentation systems

## Report Sections

Typical report sections include:

1. **Cover Page** (optional)
   - Title, date, author, client/logo
   - Confidentiality notice

2. **Table of Contents** (optional)
   - Auto-generated with page numbers

3. **Executive Summary**
   - High-level findings
   - Risk rating summary
   - Key recommendations
   - Business impact overview

4. **Scope and Methodology**
   - Engagement objectives
   - Testing methodology
   - Tools and techniques used
   - Limitations and assumptions

5. **Asset Inventory**
   - Discovered hosts, services, applications
   - OS and version detection
   - Cloud and container assets

6. **Vulnerability Findings**
   - Detailed vulnerability listings
   - CVE references and CVSS scores
   - Affected assets and locations
   - Proof of concept evidence

7. **Exploitation Results** (if applicable)
   - Successful exploitation attempts
   - Privilege escalation paths
   - Lateral movement chains
   - Data access achieved

8. **Risk Assessment**
   - Overall risk rating
   - Risk matrix visualization
   - Trend analysis (if historical data)
   - Business impact assessment

9. **Remediation Recommendations**
   - Prioritized remediation steps
   - Short-term and long-term fixes
   - Patch management guidance
   - Configuration hardening tips

10. **Appendices**
    - Detailed scan logs
    - Tool output and command lines
    - References and resources
    - Glossary of terms
    - Licensing information

## Typical Workflow

1. **Collect Data**: Run scans and assessments to generate input data
2. **Select Template**: Choose appropriate report template for audience
3. **Configure Options**: Set title, author, logo, sections, format, etc.
4. **Generate Report**: Create the report in desired format
5. **Review**: Preview and verify report contents
6. **Distribute**: Save, email, or upload report to stakeholders
7. **Archive**: Store report for compliance and historical tracking

## Related Commands

- `hunterx scan` - Generate data for reporting
- `hunterx knowledge-graph` - Export data for inclusion in reports
- `hunterx workflow` - Automate report generation as part of a workflow
- `hunterx agent` - Collect agent logs for inclusion in reports
- `hunterx reasoning` - Generate insights that can be included in reports

## Common Errors

- **Invalid Input Path**: Ensure the input directory or file exists and is readable
- **Unsupported Format**: Verify the requested format is supported (html, pdf, json, xml, md)
- **Template Not Found**: Check that the template name is correct and available
- **Missing Data**: Required data fields are missing from the input
- **Permission Denied**: Insufficient permissions to read input or write output
- **Format Conversion Error**: Missing dependencies for PDF generation (e.g., wkhtmltopdf)
- **Template Syntax Error**: Invalid template syntax or missing variables
- **Image Not Found**: Logo or image file not found or inaccessible
- **Encoding Issues**: Special characters causing encoding problems in output

## Best Practices

- Always validate input data before generating reports
- Use templates appropriate for the audience (executive vs technical)
- Include a clear methodology section for reproducibility
- Prioritize findings by risk and business impact
- Provide actionable remediation recommendations
- Keep reports concise but comprehensive
- Use visualizations (charts, graphs) to enhance understanding
- Ensure consistent branding with logos and color schemes
- Protect sensitive reports with passwords or encryption
- Schedule regular reports for ongoing monitoring
- Archive reports according to retention policies
- Validate generated reports for accuracy and completeness
