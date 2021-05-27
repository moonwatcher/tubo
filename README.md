tubo
====
tubo is a genomic data processing pipeline written for python 3.

Python dependencies: `pymongo`, `xmltodict` and `flask` 

Command line utilities: `picard` `bcl2fastq` `make` `mongodump` `mongoexport` `mongoimport` `mongorestore` `pheniqs` `rm` `rsync` `tar`  `pigz` `pixz` `pbzip2`

tubo requires a mongodb instance and several JSON config files. 
tubo refers to two environment variables called `TUBO_HOME` and `TUBO_SYSTEM_HOME`, defaulting to `~/.tubo` and `/usr/local/etc/tubo` respectively, 
in those it will look for the `repository.json`, `host.json` and `setting.json` configuration files with files found in `TUBO_HOME` taking precedence.

    usage: tubo [-h] [-S] [--host HOST] [-d] [--version] [-v LEVEL] ACTION ...

    Lior Galanti lior.galanti@nyu.edu NYU Center for Genomics & Systems Biology

    optional arguments:
      -h, --help            show this help message and exit
      -S, --submit          Submit job to queue
      --host HOST           local host name
      -d, --debug           only print commands without executing
      --version             show program's version number and exit
      -v LEVEL, --verbosity LEVEL
                            logging verbosity level

    pipeline operations:

      ACTION
        info                report medium information
        crawl               crawl resources
        copy                copy resource into location
        symlink             symlink resource to location
        move                move resource into location
        delete              delete resource
        tar                 create a compressed tar archive
        untar               extract a compressed tar archive
        get                 get documents
        drop                drop documents
        backup              create a BSON database snapshot
        restore             restore database from BSON snapshot
        basecall            convert BCL files to FASTQ
        demux               demultiplex reads
        filter              filter reads

repository.json
===============
```json
{
    "system": {
        "repository": "nyu"
    },
    "rule": {
        "rule/genealogy/profile": {
            "branch": [
                {
                    "apply": [
                        {
                            "property": "profile", 
                            "value": "unfiltered"
                        }
                    ],
                    "equal": {
                        "preset": "unfiltered"
                    }, 
                    "requires": [
                        "preset"
                    ]
                },
                {
                    "apply": [
                        {
                            "property": "profile", 
                            "value": "filtered"
                        }
                    ],
                    "equal": {
                        "preset": "filtered"
                    }, 
                    "requires": [
                        "preset"
                    ]
                }
            ]
        }, 
        "rule/genealogy/volume": null, 
        "rule/task/preset": null
    },
    "enumeration": {
        "temporary workspace": {
            "element": {
                "babylon": {
                    "host": "babylon.bio.nyu.edu", 
                    "path": "/volume/babylon/brooklyn/temp"
                }, 
                "aduae190": {
                    "host": "aduae190-lap.abudhabi.nyu.edu", 
                    "path": "/home/tubo/temp"
                },
                "albireo": {
                    "host": "albireo.bio.nyu.edu", 
                    "path": "/volume/albireo/waverly/temp"
                }
            }
        },
        "volume": {
            "element": {
                "alpha": {
                    "host": "babylon.bio.nyu.edu", 
                    "path": "/volume/babylon/brooklyn/alpha"
                }, 
                "beta": {
                    "host": "babylon.bio.nyu.edu", 
                    "path": "/volume/euphrates/toronto/beta"
                }, 
                "gamma": {
                    "host": "albireo.bio.nyu.edu", 
                    "path": "/volume/albireo/waverly/gamma"
                },
                "lambda": {
                    "host": "aduae190-lap.abudhabi.nyu.edu", 
                    "path": "/home/tubo/lambda"
                }
            }
        },
        "path homology": {
            "element": {
                "brooklyn on babylon": {
                    "alternate": "/export/data1", 
                    "host": "babylon.bio.nyu.edu", 
                    "path": "/volume/babylon/brooklyn"
                }, 
                "toronto on babylon": {
                    "alternate": "/mnt/gencore", 
                    "host": "babylon.bio.nyu.edu", 
                    "path": "/volume/euphrates/toronto"
                }, 
                "volume on albireo": {
                    "alternate": "/Volumes", 
                    "host": "albireo.bio.nyu.edu", 
                    "path": "/volume/albireo"
                }
            }
        }
    },
    "repository": {
        "nyu": {
            "mongodb": {
                "database": "tubo", 
                "host": "babylon.bio.nyu.edu", 
                "password": "hidden", 
                "username": "tubo"
            }
        }
    }
}
```

host.json
=========
```json
{
    "system": {
        "cores": 32, 
        "host": "babylon.bio.nyu.edu"
    },
    "rule": {
        "rule/genealogy/profile": null, 
        "rule/genealogy/volume": {
            "branch": [
                {
                    "apply": [
                        {
                            "property": "volume", 
                            "value": "alpha"
                        }
                    ]
                }
            ]
        }, 
        "rule/task/preset": null
    }
}
```

setting.json
============
Finally the setting.json file can be used to override login specific settings. For instance:

```json
{
    "system": {
        "interface": "development"
    },
    "enumeration": {
        "temporary workspace": {
            "element": {
                "localhost": {
                    "host": "localhost", 
                    "path": "~/.tubo/temp"
                }
            }
        },
        "volume": {
            "element": {
                "epsilon": {
                    "host": "localhost", 
                    "path": "~/.tubo/epsilon"
                }
            }
        }
    },
    "rule": {
        "rule/genealogy/profile": null, 
        "rule/genealogy/volume": {
            "branch": [
                {
                    "apply": [
                        {
                            "property": "volume", 
                            "value": "epsilon"
                        }
                    ]
                }
            ]
        }, 
        "rule/task/preset": null
    }
}
```

mongodb setup
=============

```
use admin
db.createUser(
  {
    user: "siteUserAdmin",
    pwd: "<admin password>",
    roles: [ { role: "userAdminAnyDatabase", db: "admin" } ]
  }
)

use tubo
db.createUser(
  {
    user: "tubo",
    pwd: "<tubo password>",
    roles: [ { role: "readWrite", db: "tubo" } ]
  }
)

use tubo
db.grantRolesToUser( "tubo", [ "readWrite" ] )
```