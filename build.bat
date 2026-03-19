@echo off
pip install pyinstaller
pyinstaller --onefile --console --name lg-configure lg_configure.py
pyinstaller --onefile --console --name lg-daemon    lg_daemon.py
echo.
echo Done. Executables are in the dist\ folder.
