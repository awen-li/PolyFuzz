import sys
import subprocess

if len (sys.argv) < 2:
    print ("\n*******************************************************")
    print ("python extract_log.py [command]")
    print ("\n*******************************************************\n")
    exit (0)

command   = sys.argv[1]

print ("[command]: %s" %command)

# execute the command
res = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)

while res.poll() == None:  
    log = res.stdout.read()
    
print ("\n*******************************************************")
print ("%s execution Done! ....." %command)
print ("\n*******************************************************\n")