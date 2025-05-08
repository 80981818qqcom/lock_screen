@echo off
chcp 65001 > nul
call lockscreen_venv\Scripts\activate
python lock_screen.py
deactivate
