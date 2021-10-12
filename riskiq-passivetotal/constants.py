"""
   Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end
"""

OPTIONS_MAPPING = {
    "Email": "email",
    "Domain": "domain",
    "Name": "name",
    "Organization": "organization",
    "Address": "address",
    "Phone": "phone",
    "Name Server": "nameserver"
}

PARAM_ENDPOINT_MAPPING = {
    "Get Enrichment Data": "/pt/v2/enrichment",
    "Get Malware Data": "/pt/v2/enrichment/malware",
    "Get OSINT Data": "/pt/v2/enrichment/osint",
    "Get SubDomains Data": "/pt/v2/enrichment/subdomains"
}