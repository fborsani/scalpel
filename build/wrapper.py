import os, sys, ctypes
sys.path.insert(0, '..')
import scalpel
import psutil

def checkTerm():
    #If the process is started by docuble clicking on the .exe file the father's process name will be the same as this instance.
    #Otherwise if the process is started by cmd, Powershell or another script/program the father's name will not match with the instance

    curr = os.getpid()
    parent = os.getppid()
    origin = psutil.Process(psutil.Process(parent).ppid())
    
    return psutil.Process(parent).name() != psutil.Process(curr).name() and origin != 'explorer.exe'
 
if __name__ == '__main__':
    fromTerm = checkTerm()
    args = sys.argv[1:]
    
    if not args and not fromTerm:
        args = input("Specify the arguments to pass to the script and press ENTER\n").split()
    
    scalpel.Scan(args).run()

    if not fromTerm:
        #Keep terminal open after execution ends
        input("Press ENTER to close...")