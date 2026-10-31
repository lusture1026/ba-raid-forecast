@echo off
cd /d %~dp0
for %%f in (*.py) do py "%%f"
pause
