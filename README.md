BENCHPARSE 
-------

Quick and dirty script to parse benchmarks in XCCDF format and output valid Ansible tasks in YAML format. The output format is not configurable (yet!) without editing the Python source and it uses the format defined for the [ansible-lockdown][0] project benchmark roles.

Example output is included in the [examples](examples) folder.

## Instructions

- Install requirements (xmltodict)
    
    pip install -r requirements.txt

- Download SCAP content or other benchmarks with xccdf files. These can vary wildly and this script is only tested to work with STIGs and CIS. This script has not been tested with all the CIS or STIG content yet either.

- Run benchparse

```shell
    python benchparse.py -X /path/to/xcddf_file.xml -T STIG -P /path/to/output/
```

6. Optional Flags:
  *  -X, --xcddf Path to the XCDDF content you want to parse
  *  -P, --output-path Path to output the YAML files, should be a dir as multiple files will be written. Defaults to current working dir.
  *  -T, --benchmark-type The type of benchmark you are parsing, currently supports CIS or STIG as options. Defaults to CIS.









[0]:https://github.com/ansible/ansible-lockdown
