#!/usr/bin/env python3

import requests
import json
import base64
import csv
import yaml
import logging
import re


def loggingConfig():
    logging.basicConfig(filename="contrast.log",
                        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", encoding="utf-8", level=logging.DEBUG)


def loadContrastConfig(yaml_file):
    with open(yaml_file) as stream:
        try:
            config = yaml.safe_load(stream)
            if not isValidContrastConfig(config):
                raise yaml.YAMLError("Invalid Contrast Configuration")
        except yaml.YAMLError as ye:
            logging.error(ye)
    return config


def isValidContrastConfig(config):
    logging.debug("Validating Contrast Config")
    if not isValidUrl(config.get("api").get("url")):
        return False
    if not isValidApiKey(config.get("api").get("api_key")):
        return False
    if not isValidServiceKey(config.get("api").get("service_key")):
        return False
    if not isValidUserName(config.get("api").get("user_name")):
        return False
    if not isValidOrganizationId(config.get("api").get("organization_id")):
        return False
    return True


def isValidUrl(url):
    if url == None:
        return False
    url_regex = ("((http|https)://)(www.)?" +
                 "[a-zA-Z0-9@:%._\\+~#?&//=]" +
                 "{2,256}\\.[a-z]" +
                 "{2,6}\\b([-a-zA-Z0-9@:%" +
                 "._\\+~#?&//=]*)")
    if re.search(url_regex, url):
        logging.debug("Valid api.url")
        return True
    else:
        logging.error("Invalid api.url")
        return False


def isValidApiKey(api_key):
    if api_key == None:
        return False
    if len(api_key) == 32:
        logging.debug("Valid api.api_key")
        return True
    else:
        logging.debug("Invalid api.api_key")
        return False


def isValidServiceKey(service_key):
    if service_key == None:
        return False
    if len(service_key) == 16:
        logging.debug("Valid api.service_key")
        return True
    else:
        logging.debug("Invalid api.service_key")
        return False


def isValidUserName(user_name):
    if user_name == None:
        return False
    email_regex = "^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$"
    if re.search(email_regex, user_name):
        logging.debug("Valid api.user_name")
        return True
    else:
        logging.error("Invalid api.user_name")
        return False


def isValidOrganizationId(organization_id):
    if organization_id == None:
        return False
    organization_id_regex = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    if len(organization_id) != 36:
        logging.debug("Invalid api.organization_id")
        return False
    if not re.search(organization_id_regex, organization_id):
        logging.debug("Invalid api.organization_id")
        return False
    else:
        logging.debug("Valid api.organization_id")
        return True


def createSession(api):
    session = requests.Session()
    session.headers.update({
        'Authorization': createAuthorizationHeader(api.get("user_name"), api.get("service_key")),
        'API-Key': api.get("api_key"),
        'Accept': 'application/json'
    })
    return session


def createAuthorizationHeader(user_name, service_key):
    unencodedAuthorization = user_name + ":" + service_key
    return base64.b64encode(str.encode(unencodedAuthorization))


def getVulnTypeFilters(api):
    session = createSession(api)
    contrast_url = api.get("url")
    organization_id = api.get("organization_id")
    vulntype_url = f"{contrast_url}/api/ng/{organization_id}/orgtraces/filter/vulntype/listing"

    with open("vulntype.json", "r") as f:
        vulntype_payload = json.load(f)

    response = session.post(vulntype_url, json=vulntype_payload)
    filters = response.json().get('filters')

    return filters


def getVulnerabilityMappings(filters):
    vulnerability_mappings = []

    with open("assess_to_protect_map.json", "r") as f:
        assess_to_protect_map = json.load(f)

    for filter in filters:
        keycode = filter.get('keycode')
        label = filter.get('label')
        count = filter.get('count')

        vulnerability_mapping = dict()

        vulnerability_mapping['assess_rule_name'] = label
        vulnerability_mapping['assess_rule_uuid'] = keycode
        vulnerability_mapping['vulnerability_count'] = count

        if keycode in assess_to_protect_map.keys():
            vulnerability_mapping['protect_rule_available'] = True
            vulnerability_mapping['protect_rule_uuid'] = assess_to_protect_map.get(
                keycode).get('protect_rule')
        else:
            vulnerability_mapping['protect_rule_available'] = False
            vulnerability_mapping['protect_rule_uuid'] = "None"

        vulnerability_mappings.append(vulnerability_mapping)

    return vulnerability_mappings


def getProtectionStatuses(filters):
    protection_statuses = []

    protection = {
        "status": "protection",
        "count": 0
    }

    no_protection = {
        "status": "no_protection",
        "count": 0
    }

    beta_protection = {
        "status": "beta_protection",
        "count": 0
    }

    with open("assess_to_protect_map.json", "r") as f:
        assess_to_protect_map = json.load(f)

    for filter in filters:
        keycode = filter.get('keycode')
        count = filter.get('count')

        if keycode in assess_to_protect_map.keys():
            protect_rule_status = assess_to_protect_map.get(
                keycode).get('protect_rule_status')
            if protect_rule_status == 'protection':
                protection['count'] = protection.get('count') + count
            elif protect_rule_status == 'beta_protection':
                beta_protection['count'] = beta_protection.get('count') + count
            else:
                logging.error("Unknown rule status:" + protect_rule_status)
        else:
            no_protection['count'] = no_protection.get('count') + count

    protection_statuses.append(protection)
    protection_statuses.append(no_protection)
    protection_statuses.append(beta_protection)

    return protection_statuses


def writeVulnerabilityMappingsToCSV(vulnerability_mappings):
    with open('protect_vulnerability_mapping.csv', 'w', newline='') as csvfile:
        fieldnames = ['assess_rule_name', 'assess_rule_uuid',
                      'vulnerability_count', 'protect_rule_available', 'protect_rule_uuid']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for vulnerability_mapping in vulnerability_mappings:
            writer.writerow(vulnerability_mapping)


def writeProtectionStatusesToCSV(protection_statuses):
    with open('protection_statuses.csv', 'w', newline='') as csvfile:
        fieldnames = ['status', 'count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for protection_status in protection_statuses:
            writer.writerow(protection_status)


def run():
    loggingConfig()
    config = loadContrastConfig("contrast_security.yaml")
    api = config.get("api")

    filters = getVulnTypeFilters(api)

    vulnerability_mappings = getVulnerabilityMappings(filters)
    protection_statuses = getProtectionStatuses(filters)

    writeVulnerabilityMappingsToCSV(vulnerability_mappings)
    writeProtectionStatusesToCSV(protection_statuses)


if __name__ == "__main__":
    run()
