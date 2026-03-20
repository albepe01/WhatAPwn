# WhatAPwn

**WhatAPwn** is a plug-and-play parallel fuzzing platform designed for automated vulnerability discovery on Intel ELF binaries.  
It enables scalable, reproducible fuzzing campaigns by orchestrating multiple fuzzers across different targets while integrating modern triaging and analysis pipelines.

---

## 🚀 Features

- Parallel fuzzing orchestration across multiple targets  
- Plug-and-play architecture for easy fuzzer integration  
- Support for:
  - AFL++
  - AFLGo
  - EcoFuzz  
- Automated crash triaging using:
  - ASAN
  - QEMU  
- Benchmarking support with real-world vulnerable targets (e.g. Fuzzing101)  
- Reproducible environments via Docker  
- Coverage-driven evaluation  

---

## 📁 Project Structure

```
WhatAPwn/
│── benchmarks/        # Benchmark targets (e.g., Fuzzing101)
│── fuzzers/           # Fuzzer integrations (AFL++, AFLGo, etc.)
│── runners/           # Execution logic for fuzzing campaigns
│── triage/            # Crash analysis and exploitability checks
│── qasan/             # ASAN/QEMU integration
│── Dockerfile         # Base environment
│── main.py            # Entry point
```

---

## ⚙️ Requirements

- Docker  
- Python 3.8+  
- Linux environment (WSL supported)
- XXD
- LLVM

---

## 🐳 Setup

Clone the repository:

```bash
git clone https://github.com/albepe01/WhatAPwn.git
cd WhatAPwn
```

Build the Docker image:

```bash
docker build -t whatapwn .
```

---

## ▶️ Usage

Run a fuzzing campaign:

```bash
python3 main.py --target <target_name> --fuzzer <fuzzer_name>
```

Example:

```bash
python3 main.py --target libexif --fuzzer aflpp
```

---

## 🧪 Benchmarks

The platform has been validated on real-world vulnerable targets from the **Fuzzing101** suite, including:

- Xpdf — CVE-2019-13288  
- libexif — CVE-2009-3895, CVE-2012-2836  

These results demonstrate the ability to **rediscover real-world vulnerabilities automatically**.

---

## 🔍 Crash Triage

WhatAPwn includes an automated triaging pipeline that:

- Replays crashes  
- Uses ASAN for memory error detection  
- Uses QEMU for instrumentation when needed  
- Evaluates crash exploitability  

---

## 🔌 Extending the Framework

Adding a new fuzzer is straightforward:

1. Create a new module in `fuzzers/`  
2. Implement the runner interface  
3. Register it in the orchestration pipeline  

---

## 📊 Future Work

- Support for non-ELF targets  
- Distributed fuzzing across multiple machines  
- Integration with symbolic execution tools  
- Enhanced exploitability classification  

---

## 🤝 Contributing

Contributions are welcome. Feel free to open issues or submit pull requests.

---
