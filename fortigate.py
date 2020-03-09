#!/usr/bin/python3
#Author: BEAM TEKNOLOJI A.S.

import json
import requests
import argparse

requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(description="Description for Fortigate API Script")
parser.add_argument("--firstUsage", help="Example: --firstUsage True", required=False, default=False)
parser.add_argument("--update", help="Example: --update True", required=False, default=False)
parser.add_argument("--delete", help="Example: --delete True", required=False, default=False)
parser.add_argument("--server", help="Example: --server 192.168.1.1", required=True, default="")
parser.add_argument("--user", help="Example: --user admin", required=True, default="")
parser.add_argument("--password", help="Example: --password bttm ", required=True, default="")
parser.add_argument("--blockedIP", help="Example: --blockedIP 1.2.3.4", required=False, default="")
parser.add_argument("--protocol", help="Example: --protocol https", required=True, default="https")
parser.add_argument("--deletedIPName", help="Example: --deletedIPName BLOCKED_1.1.1.1", required=False, default="")
parser.add_argument("--getIPS", help="Example: --getIPS True", required=False, default="")
parser.add_argument("--srcport", help="Example: --srcport port1", required=False, default="")
parser.add_argument("--dstport", help="Example: --dstport port2", required=False, default="")

argument = parser.parse_args()

SERVER = argument.protocol + "://" + argument.server
USER = argument.user
PASSWORD = argument.password
BASE_URL = "/api/v2/"
BLOCKED_IP = argument.blockedIP
SOURCE_PORT = argument.srcport
DESTINATION_PORT = argument.dstport
DELETED_IP_NAME = argument.deletedIPName

BLOCKED_IP_NAME = "BLOCKED_" + BLOCKED_IP
FIREWALL_RULE_NAME = "BLOCKED_IPS"
BLOCKED_IP_GROUP_NAME = "Blocked_IP_List"


def login():
    # create session.
    session = requests.session()
    url_suffix = '/logincheck'
    params = {
        'username': USER,
        'secretkey': PASSWORD,
        'ajax': 1
    }
    session.post(SERVER + url_suffix, data=params, verify=False)  # type: ignore
    # check for the csrf token in cookies we got, add it to headers of session,
    # or else we can't perform HTTP request that is not get.
    for cookie in session.cookies:
        if cookie.name == 'ccsrftoken':  # type: ignore
            csrftoken = cookie.value[1:-1]  # type: ignore
            session.headers.update({'X-CSRFTOKEN': csrftoken})
    return session


SESSION = login()


def http_request(method, url_suffix, params={}, data=None):
    res = SESSION.request(
        method,
        SERVER + BASE_URL + url_suffix,
        params=params,
        verify=False,
        data=data
    )

    if res.status_code not in {200}:
        print('[%d] - %s' % (res.status_code, res.reason))
    if method.upper() != 'GET':
        return res.status_code
    return res.json()


def create_policy_request():
    uri_suffix = 'cmdb/firewall/policy'

    payload = {
        'json': {
            "policyid": 0,
            "q_origin_key": 0,
            "name": FIREWALL_RULE_NAME,
            "srcintf": [
                {
                    "name": SOURCE_PORT,
                    "type": "physical",
                    "q_origin_key": SOURCE_PORT
                }
            ],
            "dstintf": [
                {
                    "name": DESTINATION_PORT,
                    "type": "physical",
                    "q_origin_key": DESTINATION_PORT
                }
            ],
            "srcaddr": [
                {
                    "name": BLOCKED_IP_GROUP_NAME,
                    "q_origin_key": BLOCKED_IP_GROUP_NAME
                }
            ],
            "dstaddr": [
                {
                    "name": "all",
                    "q_origin_key": "all"
                }
            ],
            "action": "deny",
            "status": "enable",
            "schedule": {
                "q_origin_key": "always",
                "name": "always"
            },
            "schedule-timeout": "disable",
            "service": [
                {
                    "name": "ALL",
                    "q_origin_key": "ALL"
                }
            ],
            "nat": "disable",
            "policyType": "policy"
        }
    }

    response = http_request('POST', uri_suffix, {}, json.dumps(payload))
    return response


def create_ip_address_object():
    uri_suffix = 'cmdb/firewall/address?datasource=1'

    payload = {"name": BLOCKED_IP_NAME, "subnet": BLOCKED_IP + "/32", "comment": "SOC Blocked"}
    response = http_request('POST', uri_suffix, {}, json.dumps(payload))
    return response


def create_ip_addresses_group():
    uri_suffix = 'cmdb/firewall/addrgrp?datasource=1'

    payload = {
        "name": BLOCKED_IP_GROUP_NAME,
        "q_origin_key": "",
        "member": [
            {
                "name": BLOCKED_IP_NAME,
                "q_origin_key": BLOCKED_IP_NAME
            }
        ],
        "comment": "SOC blocked IP lists"
    }

    response = http_request('POST', uri_suffix, {}, json.dumps(payload))


def get_address_groups_request():
    uri_suffix = 'cmdb/firewall/addrgrp/' + BLOCKED_IP_GROUP_NAME + "?datasource=1"
    response = http_request('GET', uri_suffix)
    return response.get('results')


def update_address_group():
    uri_suffix = 'cmdb/firewall/addrgrp/' + BLOCKED_IP_GROUP_NAME + "?datasource=1"
    address_groups = get_address_groups_request()
    for address_group in address_groups:
        members = address_group.get('member')
        members_list = []
        for member in members:
            members_list.append(member.get('name'))

    new_member = []
    for i in members_list:
        item = {"name": i, "q_origin_key": i}
        new_member.append(item)

    new_item = {"name": BLOCKED_IP_NAME, "q_origin_key": BLOCKED_IP_NAME}
    new_member.append(new_item)

    payload = {
        "name": BLOCKED_IP_GROUP_NAME,
        "q_origin_key": "",
        "member": new_member,
        "comment": "SOC blocked IP lists"
    }

    response = http_request('PUT', uri_suffix, {}, json.dumps(payload))


def delete_ip_from_group():
    uri_suffix = 'cmdb/firewall/addrgrp/' + BLOCKED_IP_GROUP_NAME + "?datasource=1"
    address_groups = get_address_groups_request()
    for address_group in address_groups:
        members = address_group.get('member')
        members_list = []
        for member in members:
            members_list.append(member.get('name'))

    new_member = []
    for i in members_list:
        if i != DELETED_IP_NAME:
            item = {"name": i, "q_origin_key": i}
            new_member.append(item)

    payload = {
        "name": BLOCKED_IP_GROUP_NAME,
        "q_origin_key": "",
        "member": new_member,
        "comment": "SOC blocked IP lists"
    }

    response = http_request('PUT', uri_suffix, {}, json.dumps(payload))


def get_ips_from_group():
    try:
        uri_suffix = 'cmdb/firewall/addrgrp/' + BLOCKED_IP_GROUP_NAME + "?datasource=1"
        address_groups = get_address_groups_request()
        for address_group in address_groups:
            members = address_group.get('member')
            members_list = []
            for member in members:
                members_list.append(member.get('name'))

        new_member = []
        for i in members_list:
            item = i
            new_member.append(item)

        print (new_member)
    except:
        return


def logout(session):
    url_suffix = '/logout'
    session.get(SERVER + url_suffix, verify=False)


def main():
    if argument.firstUsage:
        create_ip_address_object()
        create_ip_addresses_group()
        create_policy_request()
        logout(SESSION)
    elif argument.update:
        create_ip_address_object()
        update_address_group()
        logout(SESSION)
    elif argument.delete:
        delete_ip_from_group()
        logout(SESSION)
    elif argument.getIPS:
        get_ips_from_group()


main()
