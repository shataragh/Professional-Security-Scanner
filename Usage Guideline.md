## 💻 Usage & Execution Profiles

Run the framework by defining target parameters and selecting an execution profile tailored to your operational scope.

### Basic Scan
Execute a standard, non-intrusive baseline vulnerability sweep against the target:
```bash
python3 scanner.py -t http://target.com
```

### Aggressive Mode
Enable advanced scanning modules for deeper infrastructure and attack-surface discovery:
```bash
python3 scanner.py -t http://target.com -p aggressive
```

### Active Brute-Force (Hydra Integration)
Include active credential testing against discovered authentication interfaces using specialized user profiles:
```bash
python3 scanner.py -t http://target.com -p extreme --hydra --user admin
```

### Custom Configuration
Load a custom YAML file to enforce specific scanning constraints, custom headers, or rules of engagement:
```bash
python3 scanner.py -t http://target.com -c config.yaml
```

### Resume Interrupted Scan
Recover a terminated or interrupted session to pick up exactly where the previous scan left off:
```bash
python3 scanner.py -t http://target.com --resume
```

---

## 📊 Output & Reporting

The scanner automatically structures and outputs session results into multiple standard reporting formats located in the output directory:

* **HTML Report** – An executive-ready web dashboard featuring visual severity statistics, graphs, and remediation steps.
* **JSON Report** – Clean, machine-readable structured datasets built for direct SIEM, database, or CI/CD pipeline integration.
* **Markdown Report** – A clean, documentation-friendly format ready for engineering wikis or direct issue tracking updates.
* **Log Files** – Full, time-stamped terminal execution logs utilized for auditing, tracking, and technical debugging.
