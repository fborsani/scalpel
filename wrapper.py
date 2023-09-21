import os, sys, ctypes, platform
import scalpel.scalpel
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

    curr = psutil.Process(os.getpid())
    parent = psutil.Process(os.getppid())
    origin = psutil.Process(parent.ppid())
        
    return curr.name() == parent.name() and  origin.name() != 'explorer.exe'

def preloadExe(args:list):
    fromTerm = checkTerm()
    appName = "scalpel.exe"

    if not fromTerm:
        args = input("Specify the arguments to pass to the script and press ENTER\n").split()
    
    try:
        scalpel.Scan(appName, args).run()
    except KeyboardInterrupt:
        print("Interrupt detected")
    except Exception as e:
        print(f"Unexpected error:\n{e.strerror}")
    finally:
        if not fromTerm:
            #Prevent terminal from closing
            input("Press ENTER to close...")

def preloadElf(args:list):
    print("WRAPPER ELF")
    appName = "scalpel"
    try:
        scalpel.Scan(appName, args).run()
        print("EXECUTION ENDED")
    except KeyboardInterrupt:
        print("Interrupt detected")
 
def main():
    args = sys.argv[1:]
    if platform.system() == "Windows":
        preloadExe(args)
    else:
        preloadElf(args)
main()