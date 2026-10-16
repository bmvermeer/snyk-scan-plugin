@echo off
where python >nul 2>nul
if errorlevel 1 goto alt
python "%~dp0snyk_stub.py" %*
exit /b %errorlevel%
:alt
py -3 "%~dp0snyk_stub.py" %*
exit /b %errorlevel%
