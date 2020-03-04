#!/usr/bin/python3

import json
import requests
import argparse
requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(description="Description for Palo Alto API Script")
parser.add_argument("--firstUsage", help="Example: --firstUsage True", required=False, default=False)
parser.add_argument("--update", help="Example: --update True", required=False, default=False)
parser.add_argument("--delete", help="Example: --delete True", required=False, default=False)
parser.add_argument("--server", help="Example: --server 192.168.1.1", required=True, default="")
parser.add_argument("--userToken", help="Example: --userToken LUFRPT0=", required=True, default="")
parser.add_argument("--blockedIP", help="Example: --blockedIP 1.2.3.4", required=False, default="")
parser.add_argument("--vsys", help="Example: --vsys vsys1", required=True, default="vsys1")
parser.add_argument("--commit", help="Example: --commit True", required=False, default="")
parser.add_argument("--protocol", help="Example: --protocol https", required=True, default="https")
parser.add_argument("--deletedIPName", help="Example: --deletedIPName BLOCKED_NMAP_SYN_1.1.1.1", required=False, default="")
parser.add_argument("--getIPS", help="Example: --getIPS True", required=False, default="")

argument = parser.parse_args()

SERVER = argument.protocol + "://" + argument.server
USER_TOKEN = argument.userToken
BLOCKED_IP = argument.blockedIP
VSYS = argument.vsys

BLOCKED_IP_NAME = "BLOCKED_" + BLOCKED_IP
FIREWALL_RULE_NAME = "BLOCKED_IPS"
BLOCKED_IP_GROUP_NAME = "Blocked_IP_Lists"


def detect_api_version():
    global API_VERSION
    request = requests.get(url=SERVER + "/restapi/9.0/", verify=False)
    if request.status_code == 404:
        API_VERSION = "v9.1"
    elif request.status_code == 401:
        API_VERSION = "9.0"
    return API_VERSION


def add_ip_object():
    API_VERSION = detect_api_version()
    if API_VERSION == "9.0":
        uri_suffix = "/restapi/" + API_VERSION + "/Objects/Addresses?location=vsys&vsys=" + VSYS + "&name=" + BLOCKED_IP_NAME + "&key=" + USER_TOKEN
        payload = {
            "entry": [
                {
                    "@name": BLOCKED_IP_NAME,
                    "@location": "shared",
                    "ip-netmask": BLOCKED_IP + "/32",
                    "description": BLOCKED_IP_NAME
                }
            ]
        }
        request = requests.post(url=SERVER + uri_suffix, data=json.dumps(payload), verify=False)
    elif API_VERSION == "v9.1":
        uri_suffix = "/restapi/" + API_VERSION + "/Policies/SecurityRules?location=vsys&vsys=" + VSYS + "&name=" + BLOCKED_IP_NAME
        payload = {
            "entry": [
                {
                    "@name": BLOCKED_IP_NAME,
                    "@location": "shared",
                    "ip-netmask": BLOCKED_IP + "/32",
                    "description": BLOCKED_IP_NAME
                }
            ]
        }

        headers = {'X-PAN-KEY': USER_TOKEN}
        request = requests.post(url=SERVER + uri_suffix, data=json.dumps(payload), headers=headers, verify=False)
    else:
        print ('No API Version detected.')


def add_ip_group():
    add_ip_object()
    API_VERSION = detect_api_version()
    if API_VERSION == "9.0":
        uri_suffix = "/restapi/" + API_VERSION + "/Objects/AddressGroups?location=vsys&vsys=" + VSYS + "&name=" + BLOCKED_IP_GROUP_NAME + "&key=" + USER_TOKEN
        payload = {
            "entry": [
                {
                    "@name": BLOCKED_IP_GROUP_NAME,
                    "description": BLOCKED_IP_GROUP_NAME,
                    "static": {
                        "member": [
                            BLOCKED_IP_NAME
                        ]
                    }
                }
            ]
        }
        request = requests.post(url=SERVER + uri_suffix, data=json.dumps(payload), verify=False)
        print (request.status_code)
    elif API_VERSION == "v9.1":
        uri_suffix = "/restapi/" + API_VERSION + "/Objects/AddressGroups?location=vsys&vsys=" + VSYS + "&name=" + BLOCKED_IP_GROUP_NAME
        payload = {
            "entry": [
                {
                    "@name": BLOCKED_IP_GROUP_NAME,
                    "description": BLOCKED_IP_GROUP_NAME,
                    "static": {
                        "member": [
                            BLOCKED_IP_NAME
                        ]
                    }
                }
            ]
        }

        headers = {'X-PAN-KEY': USER_TOKEN}
        request = requests.post(url=SERVER + uri_suffix, data=json.dumps(payload), headers=headers, verify=False)
    else:
        print ('No API Version detected.')


def get_ip_group_ip_list():
    API_VERSION = detect_api_version()
    uri_suffix = "/restapi/" + API_VERSION + "/Objects/AddressGroups?location=vsys&vsys=" + VSYS + "&key=" + USER_TOKEN
    response = requests.get(url=SERVER + uri_suffix, verify=False)
    json_data = response.json()
    # print json_data['result']['entry'][0]['@name']
    i = 0
    members_list = []
    for entry in json_data['result']['entry']:
        group_name = json_data['result']['entry'][i]['@name']

        if group_name == BLOCKED_IP_GROUP_NAME:
            for member in json_data['result']['entry'][i]['static']['member']:
                members_list.append(member)
        i += 1

    return members_list


def update_ip_group():
    add_ip_object()
    API_VERSION = detect_api_version()
    members = get_ip_group_ip_list()
    if API_VERSION == "9.0":
        uri_suffix = "/restapi/" + API_VERSION + "/Objects/AddressGroups?location=vsys&vsys=" + VSYS + "&name=" + BLOCKED_IP_GROUP_NAME + "&key=" + USER_TOKEN
        payload = {
            "entry": [
                {
                    "@name": BLOCKED_IP_GROUP_NAME,
                    "description": BLOCKED_IP_GROUP_NAME,
                    "static": {
                        "member": [
                            BLOCKED_IP_NAME, members
                        ]
                    }
                }
            ]
        }
        request = requests.put(url=SERVER + uri_suffix, data=json.dumps(payload), verify=False)
        print (request.status_code)
    elif API_VERSION == "v9.1":
        uri_suffix = "/restapi/" + API_VERSION + "/Objects/AddressGroups?location=vsys&vsys=" + VSYS + "&name=" + BLOCKED_IP_GROUP_NAME
        payload = {
            "entry": [
                {
                    "@name": BLOCKED_IP_GROUP_NAME,
                    "description": BLOCKED_IP_GROUP_NAME,
                    "static": {
                        "member": [
                            BLOCKED_IP_NAME, members
                        ]
                    }
                }
            ]
        }

        headers = {'X-PAN-KEY': USER_TOKEN}
        request = requests.put(url=SERVER + uri_suffix, data=json.dumps(payload), headers=headers, verify=False)
    else:
        print ('No API Version detected.')


def delete_ip_from_group():
    API_VERSION = detect_api_version()
    members = get_ip_group_ip_list()
    members.remove(argument.deletedIPName)
    if API_VERSION == "9.0":
        uri_suffix = "/restapi/" + API_VERSION + "/Objects/AddressGroups?location=vsys&vsys=" + VSYS + "&name=" + BLOCKED_IP_GROUP_NAME + "&key=" + USER_TOKEN
        payload = {
            "entry": [
                {
                    "@name": BLOCKED_IP_GROUP_NAME,
                    "description": BLOCKED_IP_GROUP_NAME,
                    "static": {
                        "member": [
                            members
                        ]
                    }
                }
            ]
        }
        request = requests.put(url=SERVER + uri_suffix, data=json.dumps(payload), verify=False)
        print (request.status_code)
    elif API_VERSION == "v9.1":
        uri_suffix = "/restapi/" + API_VERSION + "/Objects/AddressGroups?location=vsys&vsys=" + VSYS + "&name=" + BLOCKED_IP_GROUP_NAME
        payload = {
            "entry": [
                {
                    "@name": BLOCKED_IP_GROUP_NAME,
                    "description": BLOCKED_IP_GROUP_NAME,
                    "static": {
                        "member": [
                            members
                        ]
                    }
                }
            ]
        }

        headers = {'X-PAN-KEY': USER_TOKEN}
        request = requests.put(url=SERVER + uri_suffix, data=json.dumps(payload), headers=headers, verify=False)


def add_policy():
    API_VERSION = detect_api_version()
    if API_VERSION == "9.0":
        uri_suffix = "/restapi/" + API_VERSION + "/Policies/SecurityRules?location=vsys&vsys=" + VSYS + "&name=" + FIREWALL_RULE_NAME + "&key=" + USER_TOKEN
        payload = {
            "entry": [
                {
                    "@name": FIREWALL_RULE_NAME,
                    "@location": "vsys",
                    "@vsys": VSYS,
                    "to": {
                        "member": [
                            "any"
                        ]
                    },
                    "from": {
                        "member": [
                            "any"
                        ]
                    },
                    "source-user": {
                        "member": [
                            "any"
                        ]
                    },
                    "application": {
                        "member": [
                            "any"
                        ]
                    },
                    "service": {
                        "member": [
                            "any"
                        ]
                    },
                    "hip-profiles": {
                        "member": [
                            "any"
                        ]
                    },
                    "action": "deny",
                    "category": {
                        "member": [
                            "any"
                        ]
                    },
                    "source": {
                        "member": [
                            BLOCKED_IP_GROUP_NAME
                        ]
                    },
                    "destination": {
                        "member": [
                            "any"
                        ]
                    }
                }
            ]
        }
        request = requests.post(url=SERVER + uri_suffix, data=json.dumps(payload), verify=False)
    elif API_VERSION == "v9.1":
        uri_suffix = "/restapi/" + API_VERSION + "/Policies/SecurityRules?location=vsys&vsys=" + VSYS + "&name=" + FIREWALL_RULE_NAME
        payload = {
            "entry": [
                {
                    "@name": FIREWALL_RULE_NAME,
                    "@location": "vsys",
                    "@vsys": VSYS,
                    "to": {
                        "member": [
                            "any"
                        ]
                    },
                    "from": {
                        "member": [
                            "any"
                        ]
                    },
                    "source-user": {
                        "member": [
                            "any"
                        ]
                    },
                    "application": {
                        "member": [
                            "any"
                        ]
                    },
                    "service": {
                        "member": [
                            "any"
                        ]
                    },
                    "hip-profiles": {
                        "member": [
                            "any"
                        ]
                    },
                    "action": "deny",
                    "category": {
                        "member": [
                            "any"
                        ]
                    },
                    "source": {
                        "member": [
                            BLOCKED_IP_GROUP_NAME
                        ]
                    },
                    "destination": {
                        "member": [
                            "any"
                        ]
                    }
                }
            ]
        }

        headers = {'X-PAN-KEY': USER_TOKEN}
        request = requests.post(url=SERVER + uri_suffix, data=json.dumps(payload), headers=headers, verify=False)


def commit_changes():
    API_VERSION = detect_api_version()
    if API_VERSION == "9.0":
        uri_suffix = "/api/?type=commit&cmd=<commit></commit>&key=" + USER_TOKEN
        request = requests.get(url=SERVER + uri_suffix, verify=False)
    elif API_VERSION == "v9.1":
        uri_suffix = "/api/?type=commit&cmd=<commit></commit>"
        headers = {'X-PAN-KEY': USER_TOKEN}
        request = requests.get(url=SERVER + uri_suffix, headers=headers, verify=False)


def main():
    if argument.firstUsage:
        add_ip_group()
        add_policy()
    elif argument.update:
        update_ip_group()
    elif argument.delete:
        delete_ip_from_group()
    elif argument.commit:
        commit_changes()
    elif argument.getIPS:
        ip_list = get_ip_group_ip_list()
        print (ip_list)


main()
