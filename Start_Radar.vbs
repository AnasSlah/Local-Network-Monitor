Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "cmd.exe /c cd C:\xampp\htdocs\network_monitor && python scanner.py", 0, False