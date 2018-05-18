#Docker Registry Cleaner

This is very small python2 util to cleanup docker images older than X days from a private docker registry
Please check if required libs are installed on your system:
```
sudo pip install -r requirements.txt
```

cleaner.py is easy to use:

```
./cleaner.py -h
 
usage: cleaner.py [-h] -r REGISTRY [-u USER] [-p PASSWD] [-d DAYS] [-D] [-v]
                  [-i WHITELIST]
Cleanup remote docker registry
optional arguments:
  -h, --help            show this help message and exit
  -r REGISTRY, --registry REGISTRY
                        Docker registry url
  -u USER, --user USER  Docker registry username
  -p PASSWD, --password PASSWD
                        Docker registry password
  -d DAYS, --days DAYS  Days after select an images as "old"
  -D, --dryrun          Dry run mode (do nothing, print list of deletion)
  -v, --verbose         Verbose logging
  -i WHITELIST, --include WHITELIST
                        Include pattern
```
In order to print which tag will be deleted with patterns: myproj and older than 30 days: (-v flag print verbose logs)

`./cleaner.py -r https://registry.domain.com:5000 -u USER -p PASSWORD -d 30 -i "myproj" -D`

In order to delete it remove the -D (dryrun) flag:

`./cleaner.py -r https://registry.domain.com:5000 -u USER -p PASSWORD -d 30 -i "myproj"`
