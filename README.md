# PRODOT - Suspicious Process Monitor

PRODOT is a lightweight, cross-platform system monitoring tool designed to identify and score potentially suspicious processes. It provides a modern, real-time dashboard with heuristic-based threat analysis to help users maintain system security.

## 🚀 Features

- **Real-time Monitoring**: Continuous tracking of running processes using `psutil`.
- **Heuristic Scoring Engine**: Advanced analysis based on:
  - CPU and Memory consumption.
  - Execution from suspicious paths (e.g., `/tmp`, `.cache`, `AppData`).
  - Network connection patterns (external IP detection, high connection counts).
  - Suspicious naming conventions (non-vowel names, length obfuscation).
  - Process hierarchy analysis (unexpected parent-child relationships).
- **Modern GUI**: Responsive interface built with `customtkinter`.
- **Whitelist Support**: Configurable exclusion list for trusted system and user processes.
- **Efficient Performance**: Parallelized data collection using thread pools.

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- Git

### Setup
1. **Clone the repository**:
   ```bash
   git clone https://github.com/rpram143/PRODOT.git
   cd PRODOT
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## 🖥️ Usage

To start the monitor, run:
```bash
python main.py
```

- **Dashbord**: View currently active processes, their resources, and threat scores.
- **Details**: Click on any process to view detailed heuristic rule triggers.
- **Colors**:
  - `SAFE`: Low score, no suspicious activity detected.
  - `SUSPICIOUS`: Minor rule triggers.
  - `DANGEROUS`: Significant heuristic matches.
  - `CRITICAL`: High score, requires immediate attention.

## 📁 Project Structure

```text
PRODOT/
├── config/
│   └── whitelist.json    # Trusted process names
├── gui/
│   └── dashboard.py      # Main GUI implementation
├── monitor/
│   ├── collector.py      # Process data gathering
│   ├── heuristics.py     # Threat scoring engine
│   └── logger.py         # Suspicious activity logging
├── main.py               # Application entry point
└── requirements.txt      # Project dependencies
```

## ⚖️ License

Distributed under the MIT License. See `LICENSE` for more information (if applicable).
