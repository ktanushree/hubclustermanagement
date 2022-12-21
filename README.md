# hubclustermanagement
Script to manage sites between hub clusters

#### Synopsis
This script can be used to delete a single site or a list of sites from a hubcluster. It also provide an action to append a site or a list of sites to a hub cluster.

Sites to be moved can be provided via the CLI or via a CSV file. If providing site names via a CSV file, make sure the column header is site_name



#### Requirements
* Active CloudGenix Account
* Python >=3.6
* Python modules:
    * CloudGenix Python SDK >= 6.1.1b1 - <https://github.com/CloudGenix/sdk-python>

#### License
MIT

#### Installation:
 - **Github:** Download files to a local directory, manually run `manageclusters.py`. 

### Examples of usage:
Delete a single site from a source cluster:
```
./manageclusters.py -CT CLI -S DCSiteName -CN ClusterName -SN Sitename -A delete
```
Delete sites from a source cluster via a CSV
```
./manageclusters.py -CT FILE -S DCSiteName -CN ClusterName -f csvfilename -A delete
```
Append a single site from a source cluster:
```
./manageclusters.py -CT CLI -S DCSiteName -CN ClusterName -SN Sitename -A append
```
Append sites from a source cluster via a CSV
```
./manageclusters.py -CT FILE -S DCSiteName -CN ClusterName -f csvfilename -A append
```


Use the -H hours to specify the time delta in hours for the event query.

Help Text:
```angular2
(base) M-Tanushree:hubclustermanagement tkamath$ ./manageclusters.py -h
usage: manageclusters.py [-h] [--controller CONTROLLER] [--email EMAIL] [--pass PASS] [--dcsitename DCSITENAME] [--conftype CONFTYPE] [--clustername CLUSTERNAME] [--sitename SITENAME] [--filename FILENAME] [--action ACTION]

Prisma SDWAN: Manage Sites between Hub Clusters.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod: https://api.elcapitan.cloudgenix.com

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of prompting
  --pass PASS, -P PASS  Use this Password instead of prompting

Cluster Config Info:
  Provide information on DC site Name, cluster name and element IDs or names to be assigned to the cluster.

  --dcsitename DCSITENAME, -S DCSITENAME
                        DC Site Name
  --conftype CONFTYPE, -CT CONFTYPE
                        Configuration Type. Allowed values: CLI or FILE
  --clustername CLUSTERNAME, -CN CLUSTERNAME
                        Cluster Name
  --sitename SITENAME, -SN SITENAME
                        Branch Site Name
  --filename FILENAME, -f FILENAME
                        CSV or excel file with Branch Site Names. Header: site_name
  --action ACTION, -A ACTION
                        Action on the cluster. Allowed values: delete or append
(base) M-Tanushree:hubclustermanagement tkamath$ 

```

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SDWAN Documentation at <https://docs.paloaltonetworks.com/prisma/prisma-sd-wan>
 
