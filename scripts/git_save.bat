@echo off
cd /d "%~dp0"
echo ==================================================
echo  SAVING WORK TO GIT
echo ==================================================

echo 1. Initializing Git Repository...
if not exist .git (
    git init
)

echo.
echo 2. Copying Documentation...
copy /Y "C:\Users\Meow\.gemini\antigravity\brain\d767a57b-1ee1-4029-b754-0d8a834530bf\task.md" "task.md"
copy /Y "C:\Users\Meow\.gemini\antigravity\brain\d767a57b-1ee1-4029-b754-0d8a834530bf\implementation_plan.md" "implementation_plan.md"

echo.
echo 3. Creating .gitignore...
(
echo __pycache__/
echo *.pyc
echo venv/
echo .vscode/
echo .idea/
echo *.log
echo !scan_log_*.txt
echo !devices_*.json
echo !forensics_*.json
) > .gitignore

echo.
echo 4. Committing changes...
git add .
git commit -m "Snapshot: Cync Explorer Tools & GUI (Post-Forensics)"

echo.
echo ==================================================
echo  DONE! Work saved.
echo ==================================================
pause
