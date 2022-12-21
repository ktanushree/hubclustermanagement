#!/usr/bin/env python
"""
Prisma SDWAN: Script to Manage Cluster post 6.1.1
tkamath@paloaltonetworks.com
"""
import cloudgenix
import pandas as pd
import os
import sys
import yaml
import argparse
import logging
import datetime


# Global Vars
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'Prisma SDWAN: Manage Sites between Hub Clusters'
CSVHEADER = ["site_name"]

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # will get caught below.
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None


#
# Global Dicts
#
site_id_name = {}
site_name_id = {}
dcsites = []
cluster_id_name = {}
cluster_name_id = {}
siteid_clusteridlist={}
siteid_clusternamelist = {}
cluster_id_peersites = {}
cluster_name_peersites = {}

DELETE = "delete"
APPEND = "append"


def createdicts(cgx_session, dcsiteid):
    # Get Sites
    resp = cgx_session.get.sites()
    if resp.cgx_status:
        sitelist = resp.cgx_content.get("items", None)

        for site in sitelist:
            site_id_name[site["id"]] = site["name"]
            site_name_id[site["name"]] = site["id"]

            if site["element_cluster_role"] == "HUB":
                dcsites.append(site["name"])

    else:
        print("ERR: Could not retrieve sites")
        cloudgenix.jd_detailed(resp)

    # Hub Clusters
    for dc in dcsites:
        siteid = site_name_id[dc]
        if siteid == dcsiteid:
            resp = cgx_session.get.hubclusters(site_id=siteid)
            if resp.cgx_status:
                clusters = resp.cgx_content.get("items", None)
                clusteridlist = []
                clusternamelist = []

                for cluster in clusters:
                    cluster_id_name[cluster['id']] = cluster['name']
                    cluster_name_id[cluster['name']] = cluster['id']
                    clusteridlist.append(cluster["id"])
                    clusternamelist.append(cluster["name"])
                    cluster_id_peersites[cluster["id"]] = cluster["peer_sites"]
                    cluster_name_peersites[cluster["name"]] = cluster["peer_sites"]

                siteid_clusteridlist[siteid] = clusteridlist
                siteid_clusternamelist[siteid] = clusternamelist

            else:
                print("ERR: Could not retrieve hubclusters for DC site ID {}".format(siteid))
                cloudgenix.jd_detailed(resp)

        else:
            continue

    return


def updatecluster(cgx_session, dcsiteid, cid, siteidlist, action):

    cname = cluster_id_name[cid]
    if action == DELETE:
        print("INFO: Updating Source Cluster. Action: Delete Site IDs")
        resp = cgx_session.get.hubclusters(site_id=dcsiteid, hubcluster_id=cid)
        if resp.cgx_status:
            clusterconf = resp.cgx_content
            peersites = clusterconf.get("peer_sites", None)
            if peersites is None:
                peersites = []
            print("\tDEBUG: Before peersites: {}".format(len(peersites)))
            for sid in siteidlist:
                if sid in peersites:
                    peersites.remove(sid)
                else:
                    print("\tWARN: Site {}[{}] not found in cluster {}".format(site_id_name[sid], sid, cname))

                print("\tDEBUG: After peersites: {}".format(len(peersites)))

            clusterconf["peer_sites"] = peersites
            print("INFO: Deleting site IDs from {} using payload: \n".format(cname))
            cloudgenix.jd_detailed(clusterconf)
            resp = cgx_session.put.hubclusters(site_id=dcsiteid, hubcluster_id=cid, data=clusterconf)
            if resp.cgx_status:
                print("INFO: Cluster {} Updated".format(cname))
            else:
                print("ERR: Could not delete site IDs from Source Cluster")
                cloudgenix.jd_detailed(resp)

                cgx_session.get.logout()
                sys.exit()

        else:
            print("ERR: Could not retrieve Hub Cluster {}".format(cname))
            cloudgenix.jd_detailed(resp)

    #
    # Update Site IDs in Dest Cluster
    #
    if action == APPEND:
        print("INFO: Updating Destination Cluster. Action: Add Site IDs")
        resp = cgx_session.get.hubclusters(site_id=dcsiteid, hubcluster_id=cid)
        if resp.cgx_status:
            clusterconf = resp.cgx_content
            peersites = clusterconf.get("peer_sites", None)
            if peersites is None:
                peersites = []

            print("\tDEBUG: Before peersites: {}".format(len(peersites)))
            for sid in siteidlist:
                if sid not in peersites:
                    peersites.append(sid)
                else:
                    print("\tWARN: Site {}[{}] already present in cluster {}".format(site_id_name[sid], sid, cname))

            print("\tDEBUG: After peersites: {}".format(len(peersites)))

            clusterconf["peer_sites"] = peersites
            print("INFO: Adding site IDs to {} using payload: \n".format(cname))
            cloudgenix.jd_detailed(clusterconf)
            resp = cgx_session.put.hubclusters(site_id=dcsiteid, hubcluster_id=cid, data=clusterconf)
            if resp.cgx_status:
                print("INFO: Destination Cluster {} Updated".format(cname))
            else:
                print("ERR: Could not delete site IDs from Destination Cluster")
                cloudgenix.jd_detailed(resp)
                cgx_session.get.logout()
                sys.exit()

        else:
            print("ERR: Could not retrieve Hub Cluster {}".format(cname))
            cloudgenix.jd_detailed(resp)

    return


def go():

    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default="https://api.elcapitan.cloudgenix.com")

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-P", help="Use this Password instead of prompting",
                             default=None)

    # Commandline for entering Site info
    site_group = parser.add_argument_group('Cluster Config Info',
                                           'Provide information on DC site Name, cluster name and element IDs or names to be assigned to the cluster.')

    site_group.add_argument("--dcsitename", "-S", help="DC Site Name", default=None)
    site_group.add_argument("--conftype", "-CT", help="Configuration Type. Allowed values: CLI or FILE", default=None)
    site_group.add_argument("--clustername", "-CN", help="Cluster Name", default=None)
    site_group.add_argument("--sitename", "-SN", help="Branch Site Name", default=None)
    site_group.add_argument("--filename", "-f", help="CSV or excel file with Branch Site Names. Header: site_name", default=None)
    site_group.add_argument("--action", "-A", help="Action on the cluster. Allowed values: delete or append", default=None)

    args = vars(parser.parse_args())

    ############################################################################
    # Parse and validate arguments
    ############################################################################
    dcsitename = args["dcsitename"]
    conftype = args['conftype']
    clustername = args["clustername"]
    filename = args["filename"]
    sitename = args["sitename"]
    action = args["action"]

    # Validate DC Site
    if dcsitename is None:
        print("ERR: Invalid DC Site Name. Please reenter the DC site name")
        sys.exit()

    if conftype in ["FILE", "CLI"]:
        if conftype == "FILE":
            if filename is None:
                print("ERR: Please enter the configuration file name")
                sys.exit()
            else:
                if not os.path.exists(filename):
                    print("ERR: Invalid file: {}. Please renter file location".format(filename))
                    sys.exit()
        else:
            # Validate Cluster & Site Name
            if sitename is None:
                print("ERR: Please provide a Branch site name")
                sys.exit()
    else:
        print("ERR: Invalid config type: {}. Please choose from: CLI or FILE".format(conftype))
        sys.exit()

    if (clustername is None):
        print("ERR: Please provide either a Source or Destination Cluster name")
        sys.exit()

    if action is None:
        print("ERR: Invalid action. Please choose from: delete or append")
        sys.exit()
    elif action not in [DELETE, APPEND]:
        print("ERR: Invalid action. Please choose from: delete or append")
        sys.exit()

    ############################################################################
    # Instantiate API & Login
    ############################################################################

    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=False)
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SDK_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # Create Dicts
    ############################################################################
    resp = cgx_session.get.sites()
    if resp.cgx_status:
        sitelist = resp.cgx_content.get("items", None)
        dcs = []
        dcsiteid = None
        for site in sitelist:
            if site["element_cluster_role"] == "HUB":
                dcs.append(site["name"])
                if site["name"] == dcsitename:
                    dcsiteid = site["id"]

        if dcsitename in dcs:
            print("INFO: DC Site {} found".format(dcsitename, dcsiteid))

        else:
            print("ERR: Invalid DC Site Name {}. No such site found".format(dcsitename))
            cgx_session.get.logout()
            sys.exit()

        createdicts(cgx_session, dcsiteid)

    else:
        print("ERR: Could not retrieve sites. Logging out.")
        cloudgenix.jd_detailed(resp)
        cgx_session.get.logout()
        sys.exit()

    ############################################################################
    # Validate Data
    ############################################################################
    #
    # Cluster Name
    #
    dcclusters = siteid_clusternamelist[dcsiteid]
    if clustername in dcclusters:
        print("INFO: Cluster {} found".format(clustername))
        cid = cluster_name_id[clustername]
    else:
        print("ERR: Cluster {} not found on DC {}[{}]".format(clustername, dcsitename, dcsiteid))
        cgx_session.get.logout()
        sys.exit()

    #
    # Site Names in File
    #
    if conftype == "FILE":
        print("INFO: Retrieving Site Names from {}".format(filename))

        sitedata = pd.read_csv(filename)
        cols = list(sitedata.columns)

        for item in CSVHEADER:
            if item in cols:
                continue
            else:
                print("ERR: Column {} not found. Please check Config file".format(item))
                cgx_session.get.logout()
                sys.exit()

        siteidlist = []
        for i, row in sitedata.iterrows():
            sname = row["site_name"]
            if sname in site_name_id.keys():
                siteidlist.append(site_name_id[sname])
            else:
                print("ERR[row: {}]: Site {} not found".format((i+1), sname))
                cgx_session.get.logout()
                sys.exit()

        if action == DELETE:
            print("INFO: Validating Site IDs retrieved from {} in Cluster {}".format(filename, clustername))
            clusterconfig = cluster_name_peersites[clustername]

            invalidlist = False
            for sid in siteidlist:
                if sid not in clusterconfig:
                    print("ERR: Site ID {} [{}] not found in {}".format(sid, site_id_name[sid], clustername))
                    invalidlist = True

                else:
                    continue

            if invalidlist:
                print("ERR: One or more siteIDs not configured on the cluster. Please fix configuration before moving sites".format(clustername))
                print("INFO: Logging out")
                cgx_session.get.logout()
                sys.exit()

            else:
                print("INFO: Data Validation Complete! Deleting site IDs from cluster {}".format(clustername))
                updatecluster(cgx_session, dcsiteid, cid, siteidlist, action)

        else:
            print("INFO: Appending site IDs to cluster {}".format(clustername))
            updatecluster(cgx_session, dcsiteid, cid, siteidlist, action)

    else:
        print("INFO: Updating using parameters via CLI")
        siteidlist = []
        if sitename in site_name_id.keys():
            siteidlist.append(site_name_id[sitename])
        else:
            print("ERR: Site {} not found".format(sitename))
            cgx_session.get.logout()
            sys.exit()

        updatecluster(cgx_session, dcsiteid, cid, siteidlist, action)

    ############################################################################
    # Logout to clear session
    ############################################################################
    print("INFO: Logging Out")
    cgx_session.get.logout()
    sys.exit()

if __name__ == "__main__":
    go()
