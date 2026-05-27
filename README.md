# 🛡️ VibeGuard

VibeGuard is a real-time security tool designed to detect and remediate exposed API keys and secrets in your source files before they get pushed to production.

## 🚀 Installation for Users

To use VibeGuard globally on your machine, run these commands in your terminal:

1. **Clone the repository:**
```bash
   git clone [https://github.com/akroshub/Vibeguard.git](https://github.com/akroshub/Vibeguard.git)
   cd Vibeguard
2.Install and link globally:
npm install
npm link  
🖥️ How to Use Anywhere
Now open any other folder or project on your computer in your terminal and use the vsg command:

Scan for secrets:
vsg --scan
Safe test (Dry run)
vsg --scan --dry-run
Real-time monitoring:
vsg