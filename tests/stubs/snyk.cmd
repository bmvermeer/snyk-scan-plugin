@echo off
if defined SNYK_STUB_LOG echo %*>>"%SNYK_STUB_LOG%"
if "%~1"=="auth" goto auth
if not defined SNYK_STUB_AUTHED_FILE goto scan
if exist "%SNYK_STUB_AUTHED_FILE%" goto scan
echo Authentication required (SNYK-0005) 1>&2
exit /b 2
:scan
if defined SNYK_STUB_STDOUT echo %SNYK_STUB_STDOUT%
if defined SNYK_STUB_STDERR echo %SNYK_STUB_STDERR% 1>&2
if not defined SNYK_STUB_EXIT exit /b 0
exit /b %SNYK_STUB_EXIT%
:auth
if defined SNYK_STUB_AUTH_STDERR echo %SNYK_STUB_AUTH_STDERR% 1>&2
set CODE=0
if defined SNYK_STUB_AUTH_EXIT set CODE=%SNYK_STUB_AUTH_EXIT%
if not "%CODE%"=="0" exit /b %CODE%
if defined SNYK_STUB_AUTHED_FILE type nul > "%SNYK_STUB_AUTHED_FILE%"
exit /b 0
