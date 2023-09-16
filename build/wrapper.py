import os, sys, ctypes, platform
sys.path.insert(0, '..')
import scalpel
import psutil

def checkTerm():
    '''
    If the process is started by docuble clicking on the .exe file the father's process name will be the same as this instance.
    Otherwise if the process is started by cmd, Powershell or another script/program the father's name will not match with the instance
    The following list represents the chain of processes (origin/father/this process) created in different situations:
    Run from .py file: explorer.exe --> cmd/ps --> python
    Run from .exe file from terminal: cmd/ps --> scalpel.exe --> scalpel.exe
    Run from .exe file by double clicking: explorer.exe --> scalpel.exe --> scalpel.exe
    '''

    curr = os.getpid()
    parent = os.getppid()
    origin = psutil.Process(psutil.Process(parent).ppid())
    
    return psutil.Process(parent).name() != psutil.Process(curr).name() and origin != 'explorer.exe'

def preloadExe(args:list):
    fromTerm = checkTerm()
    appName = "scalpel.exe"

    if not args and not fromTerm:
        args = input("Specify the arguments to pass to the script and press ENTER\n").split()
    
    scalpel.Scan(appName, args).run()

    if not fromTerm:
        #Keep terminal open after execution ends
        input("Press ENTER to close...")

def preloadElf(args:list):
    appName = "scalpel"
    scalpel.Scan(appName, args).run()
 
if __name__ == '__main__':
    args = sys.argv[1:]
    
    if platform.system() == "Windows":
        preloadExe(args)
    else:
        preloadElf(args)