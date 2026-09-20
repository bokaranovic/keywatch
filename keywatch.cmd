@echo off
setlocal
python "%~dp0keywatch.py" %*
exit /b %ERRORLEVEL%
