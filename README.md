# RuSure - Vulnerability Verification Tool

RuSure verifies SQL Injection and XSS vulnerabilities found by Burp Suite, reducing false positives through active, non-destructive testing.

## Features

- **SQL Injection Verification**: Union-based, Error-based, Boolean Blind, Time Blind, Stacked Queries
- **XSS Verification**: Reflected, Stored, and DOM-based XSS with screenshot capture
- **Custom Payload Support**: Upload your own SQLi and XSS payloads
- **Scan History**: Track all scans with detailed results
- **Full Request/Response Viewing**: See exactly what was sent and received

## Tech Stack

- **Backend**: Python/Flask
- **Frontend**: React/Vite
- **SQLi Scanner**: Custom Python script with multi-technique detection
- **XSS Scanner**: Playwright (Node.js)

## Installation

### Prerequisites

- Python 3.8+
- Node.js 16+ (LTS recommended)
- npm
- Git

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/YoussefFeki004/RuSure.git
cd RuSure

# Run the setup script (installs all dependencies)
./setup.sh

# Start the application
./start.sh
