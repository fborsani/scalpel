import os, sys, ctypes, platform
import scalpel.scalpel as scalpel
import psutil

def check_term():
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

def preload_exe(args:list):
    from_term = check_term()
    app_name = "scalpel.exe"

    if not from_term:
        while(True):
            args = input("\n\nSpecify the arguments and press ENTER. Use -h to display the command list\n").split()
            try:
                scalpel.Scan(app_name, args).run()
            except KeyboardInterrupt:
                print("Interrupt detected")
            except Exception as e:
                print(f"Unexpected error:\n{e.strerror}")
            except SystemExit:
                #When argparse fails to parse the arguments or the user calls the script with the -h flag to display the help message argparse stops the execution
                #by invoking the exit command. 
                #We do not want to close the terminal when the program is being executed from the desktop so we capture and suppress the exception
                pass

    scalpel.Scan(app_name, args).run()

def preload_elf(args:list):
    app_name = "scalpel"
    try:
        scalpel.Scan(app_name, args).run()
    except KeyboardInterrupt:
        print("Interrupt detected")
 
def main():
    args = sys.argv[1:]
    if platform.system() == "Windows":
        preload_exe(args)
    else:
        preload_elf(args)
main()