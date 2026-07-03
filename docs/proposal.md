# VeriTrace Project Proposal

## Project Title

**VeriTrace: An Evidence Integrity Assessment Framework for Detecting Anti-Forensic Activity in Windows Systems**

---

# Project Overview

VeriTrace is an open-source Python-based Digital Forensics and Incident Response (DFIR) framework designed to improve the reliability of Windows forensic investigations through cross-artifact consistency analysis. Rather than treating individual forensic artifacts as independently trustworthy, VeriTrace correlates multiple Windows artifacts to identify inconsistencies that may indicate anti-forensic activity, evidence tampering, or artifact suppression.

---

# Security Problem

Digital forensic investigations depend on artifacts such as Windows Event Logs, Registry entries, Prefetch files, and file system metadata to reconstruct system activity. Attackers increasingly employ anti-forensic techniques—including timestomping, event log clearing, and artifact deletion—to conceal malicious activity and reduce investigator confidence in digital evidence.

Existing forensic tools excel at collecting and parsing artifacts; however, investigators must often manually determine whether evidence from multiple sources is consistent. This manual process is time-consuming and may overlook subtle inconsistencies.

---

# Research Question

**To what extent can cross-artifact consistency analysis improve the detection of anti-forensic activity in Windows systems?**

---

# Project Objectives

* Develop an open-source evidence integrity assessment framework.
* Correlate selected Windows forensic artifacts.
* Detect inconsistencies associated with common anti-forensic techniques.
* Produce repeatable and explainable investigation findings.
* Evaluate the framework using controlled forensic scenarios.

---

# Project Scope

## Included

* Windows Event Logs (EVTX)
* Windows Registry artifacts
* Windows Prefetch artifacts
* Cross-artifact consistency analysis
* HTML and JSON reporting

## Excluded

* Memory forensics
* Mobile device forensics
* Cloud forensics
* Linux and macOS artifacts
* Artificial Intelligence or Machine Learning
* Commercial forensic integrations

---

# Proposed Architecture

```
Windows Artifacts
        │
        ▼
 Artifact Parsers
        │
        ▼
 Normalization Engine
        │
        ▼
 Consistency Rule Engine
        │
        ▼
 Evidence Integrity Assessment
        │
        ▼
 Investigation Report
```

---

# Initial Detection Rules

### Rule 1

Compare MFT timestamps against supporting artifact timestamps to identify potential timestomping.

### Rule 2

Identify Windows Event Log clearing events and associated inconsistencies.

### Rule 3

Detect missing expected artifacts following documented execution activity.

---

# Technology Stack

Programming Language

* Python

Development Environment

* Visual Studio Code

Version Control

* GitHub

Testing Environment

* Windows 11 Virtual Machine

Output Formats

* HTML
* JSON
* CSV

---

# Expected Deliverables

* VeriTrace source code
* Documentation
* Detection rule engine
* Test datasets
* Evaluation results
* User guide
* Master's capstone report

---

# Success Criteria

The project will be considered successful if VeriTrace can:

* Detect timestamp manipulation.
* Detect Windows Event Log clearing.
* Detect artifact deletion or suppression.
* Produce repeatable investigation reports.
* Demonstrate effectiveness through controlled testing.

---

# Timeline

| Phase         | Description                            |
| ------------- | -------------------------------------- |
| Research      | Literature review and project planning |
| Design        | Architecture and rule development      |
| Development   | Python implementation                  |
| Testing       | Validation using forensic scenarios    |
| Evaluation    | Results analysis                       |
| Documentation | Final report and GitHub publication    |

---

# Future Enhancements

Potential future work includes:

* Support for additional Windows artifacts
* Timeline visualization
* Plugin architecture
* Linux and macOS support
* Integration with existing DFIR workflows
