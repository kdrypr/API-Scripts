#!/usr/bin/python3
#Author: BEAM TEKNOLOJI A.S.

import json
import requests
import argparse

requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(description="Description for Check Point API Script")
parser.add_argument("--firstUsage", help="Example: --firstUsage True", required=False, default=False)
parser.add_argument("--update", help="Example: --update True", required=False, default=False)
parser.add_argument("--delete", help="Example: --delete True", required=False, default=False)
parser.add_argument("--server", help="Example: --server 192.168.1.1", required=True, default="")
parser.add_argument("--user", help="Example: --user admin", required=True, default="")
parser.add_argument("--password", help="Example: --password testPass ", required=True, default="")
parser.add_argument("--blockedIP", help="Example: --blockedIP 1.2.3.4", required=False, default="")
parser.add_argument("--protocol", help="Example: --protocol https", required=True, default="https")
parser.add_argument("--deletedIPName", help="Example: --deletedIPName BLOCKED_NMAP_SYN_1.1.1.1", required=False,
                    default="")
parser.add_argument("--getIPS", help="Example: --getIPS True", required=False, default="")

argument = parser.parse_args()

SERVER = argument.protocol + "://" + argument.server
USER = argument.user
PASSWORD = argument.password
BASE_URL = "/web_api/"
BLOCKED_IP = argument.blockedIP
DELETED_IP_NAME = argument.deletedIPName

BLOCKED_IP_NAME = "BLOCKED_" + BLOCKED_IP
FIREWALL_RULE_NAME = "BLOCKED_IPS"
BLOCKED_IP_GROUP_NAME = "Blocked_IP_List"


def login():
    uri_suffix = "login"
    headers = {"Content-Type": "application/json"}
    payload = {"user": USER, "password": PASSWORD}
    request = requests.post(url=SERVER + BASE_URL + uri_suffix, data=json.dumps(payload), headers=headers, verify=False)
    return request.json()['sid']


SID = login()


def add_ip_object():
    uri_suffix = "add-network"
    headers = {
        "Content-Type": "application/json",
        "X-chkp-sid": SID
    }
    payload = {
        "name": BLOCKED_IP_NAME,
        "subnet": BLOCKED_IP,
        "subnet-mask": "255.255.255.255"
    }
    request = requests.post(url=SERVER + BASE_URL + uri_suffix, data=json.dumps(payload), headers=headers, verify=False)
    publish()
    return request


def create_ip_group_object():
    add_ip_object()
    uri_suffix = "add-group"
    headers = {
        "Content-Type": "application/json",
        "X-chkp-sid": SID
    }
    payload = {
        "name": BLOCKED_IP_GROUP_NAME,
        "members": BLOCKED_IP_NAME
    }
    request = requests.post(url=SERVER + BASE_URL + uri_suffix, data=json.dumps(payload), headers=headers, verify=False)
    publish()


def update_ip_group_object():
    add_ip_object()
    response_code = add_ip_object()
    if response_code.status_code == "400":
        uri_suffix = "set-group"
        headers = {
            "Content-Type": "application/json",
            "X-chkp-sid": SID
        }
        payload = {
            "name": BLOCKED_IP_GROUP_NAME,
            "members": {
                "add": BLOCKED_IP_NAME
            }
        }
        request = requests.post(url=SERVER + BASE_URL + uri_suffix, data=json.dumps(payload), headers=headers,
                                verify=False)
    else:
        add_ip_object()
        uri_suffix = "set-group"
        headers = {
            "Content-Type": "application/json",
            "X-chkp-sid": SID
        }
        payload = {
            "name": BLOCKED_IP_GROUP_NAME,
            "members": {
                "add": BLOCKED_IP_NAME
            }
        }
        request = requests.post(url=SERVER + BASE_URL + uri_suffix, data=json.dumps(payload), headers=headers,
                                verify=False)
        publish()


def remove_ip_from_group_object():
    uri_suffix = "set-group"
    headers = {
        "Content-Type": "application/json",
        "X-chkp-sid": SID
    }
    payload = {
        "name": BLOCKED_IP_GROUP_NAME,
        "members": {
            "remove": BLOCKED_IP_NAME
        }
    }
    request = requests.post(url=SERVER + BASE_URL + uri_suffix, data=json.dumps(payload), headers=headers, verify=False)
    publish()


def add_policy_with_ip_group_object():
    uri_suffix = "add-access-rule"
    headers = {
        "Content-Type": "application/json",
        "X-chkp-sid": SID
    }
    payload = {
        "layer": "Network",
        "position": 1,
        "name": FIREWALL_RULE_NAME,
        "source": BLOCKED_IP_GROUP_NAME,
        "action": "Drop"
    }
    request = requests.post(url=SERVER + BASE_URL + uri_suffix, data=json.dumps(payload), headers=headers, verify=False)
    publish()


def get_ips_from_group_object():
    uri_suffix = "show-group"
    headers = {
        "Content-Type": "application/json",
        "X-chkp-sid": SID
    }
    payload = {
        "name": BLOCKED_IP_GROUP_NAME
    }
    request = requests.post(url=SERVER + BASE_URL + uri_suffix, data=json.dumps(payload), headers=headers, verify=False)
    json_data = request.json()
    i = 0
    members_list = []
    try:
        for i in json_data['members']:
            members_list.append(i['name'])
    except:
        print ("Grup bulunamadi!")
    return members_list


def publish():
    uri_suffix = "publish"
    headers = {
        "Content-Type": "application/json",
        "X-chkp-sid": SID
    }
    payload = {}
    request = requests.post(url=SERVER + BASE_URL + uri_suffix, data=json.dumps(payload), headers=headers, verify=False)


def main():
    if argument.firstUsage:
        create_ip_group_object()
        add_policy_with_ip_group_object()
    elif argument.update:
        update_ip_group_object()
    elif argument.delete:
        remove_ip_from_group_object()
    elif argument.getIPS:
        ip_list = get_ips_from_group_object()
        print (ip_list)


main()
