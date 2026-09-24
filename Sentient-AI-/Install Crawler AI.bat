@echo off
:: Checks this PC for a Python 3.9+ (the py launcher first, then python on PATH) and runs
:: installer\bootstrap.py with any arguments passed through.
::
:: Why it exists: Explorer can double-click a .bat but a .py may open in an editor or the
:: Store instead, so this wrapper picks a working interpreter, explains how to install one
:: when there is none, and keeps the window open on errors. Kept CRLF and plain ASCII (see
:: .gitattributes) because cmd.exe mis-parses labels in LF-only files.
::
rem Crawler AI installer for Windows. Double-click this file in File Explorer:
rem it opens a local page in your browser that checks Docker Desktop, creates
rem your security keys, builds Crawler AI and opens it. Nothing to type.
rem
rem Downloaded as a ZIP? Windows may warn about a file from the internet
rem ("Windows protected your PC" or "Open File - Security Warning"). Choose
rem More info, then Run anyway (or Run). See installer\README.md.

setlocal
cd /d "%~dp0"
title Crawler AI installer
echo.
echo   Crawler AI installer
echo.

rem Prefer the py launcher (python.org installs), then python on PATH (the
rem Microsoft Store install). Either must be Python 3.9 or newer.
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
if not errorlevel 1 goto use_py
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
if not errorlevel 1 goto use_python
goto no_python

:use_py
py -3 installer\bootstrap.py %*
goto finished

:use_python
python installer\bootstrap.py %*
goto finished

:no_python
echo   This installer needs Python 3.9 or newer, and it isn't installed yet.
echo.
echo   Install it one of these two ways, then double-click
echo   "Install Crawler AI.bat" again:
echo.
echo     1. Microsoft Store: search for "Python 3.12" and click Get.
echo     2. python.org: https://www.python.org/downloads/
echo        In that installer, tick "Add python.exe to PATH" before Install Now.
echo.
echo   Opening the python.org download page for you...
start "" "https://www.python.org/downloads/"
echo.
pause
exit /b 1

:finished
rem Keep the window open if the installer stopped with an error, so the
rem message stays readable.
if errorlevel 1 pause
exit /b %errorlevel%
