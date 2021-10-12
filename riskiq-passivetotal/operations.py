"""
   Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end
"""

import datetime
import requests
from connectors.core.connector import ConnectorError, get_logger
from .constants import *

logger = get_logger('riskiq-passivetotal')

def parse_datetime(input_date):
    try:
        if input_date:
            tmp_date = input_date.replace('T', ' ').split('.')
            return tmp_date
        else:
            return None
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))

def get_str_input(params, key):
    logger.info("Getting value for key {}".format(key))
    ret_val = params.get(key, None)
    if isinstance(ret_val, bytes):
        ret_val = ret_val.decode('utf-8')
    return ret_val


def get_config_params(config, endpoint):
    url = config.get('url')
    if not url.startswith('https://') and not url.startswith('http://'):
        url = ('https://{}'.format(url)).strip('/')
    username = config.get('username')
    api_key = config.get('api_key')
    auth = (username, api_key)
    verify_ssl = config.get('verify_ssl')
    return url+endpoint, auth, verify_ssl



def make_api_call(config, method, endpoint, param):
    try:
        url, auth, verify_ssl = get_config_params(config, endpoint)
        payload = {
            "Content-Type": "application/json"
        }
        logger.info('executing {0}'.format(url))
        if method == 'GET':
            response = requests.get(url, auth=auth, headers=payload, params=param, verify=verify_ssl)
        else:
            response = requests.post(url, auth=auth, headers=payload, data=param, verify=verify_ssl)
        if response.ok:
            logger.info('successfully got response from url= {0}, status code is= {1}'.format(url, response.status_code))
            if 'json' in str(response.headers):
                return response.json()
            else:
                return response.content
        else:
            logger.error(str(response.content))
            raise ConnectorError(str(response.content))
    except requests.exceptions.SSLError:
        raise ConnectorError('SSL certificate validation failed')
    except requests.exceptions.ConnectTimeout:
        raise ConnectorError('The request timed out while trying to connect to the server')
    except requests.exceptions.ReadTimeout:
        raise ConnectorError('The server did not send any data in the allotted amount of time')
    except requests.exceptions.ConnectionError:
        raise ConnectorError('Invalid endpoint or credentials')
    except Exception as err:
        raise ConnectorError(str(err))


def get_reputation(config, params):
    try:
        endpoint = '/pt/v2/reputation'
        res = make_api_call(config, 'GET', endpoint, params)
        return res
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_components(config, params):
    try:
        if params.pop('search_by', None) == 'Get Addresses By Component Name':
            endpoint = '/pt/v2/components/{name}/addresses'.format(name=params.pop('name'))
        else:
            endpoint = '/pt/v2/components/{name}/hosts'.format(name=params.pop('name'))
        param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
        res = make_api_call(config, 'GET', endpoint, param_dict)
        return res
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))

def get_trackers(config, params):
    try:
        endpoint = '/pt/v2/host-attributes/trackers'
        params['start'] = parse_datetime(params.get('start'))
        params['end'] = parse_datetime(params.get('end'))
        param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
        res = make_api_call(config, 'GET', endpoint, param_dict)
        return res
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))

def get_cookies(config, params):
    try:
        endpoint = '/pt/v2/host-attributes/cookies'
        param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
        res = make_api_call(config, 'GET', endpoint, param_dict)
        return res
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_alerts(config, params):
    try:
        endpoint = '/pt/v2/monitor'
        params['start'] = parse_datetime(params.get('start'))
        params['end'] = parse_datetime(params.get('end'))
        param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
        res = make_api_call(config, 'GET', endpoint, param_dict)
        return res
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_services(config, params):
    try:
        endpoint = '/pt/v2/services'
        res = make_api_call(config, 'GET', endpoint, params)
        return res
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_enrichment_data(config, params):
    try:
        endpoint = PARAM_ENDPOINT_MAPPING.get(params.get('query_for'), '/pt/v2/enrichment')
        res = make_api_call(config, 'GET', endpoint, params)
        return res
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_whois_data(config, params):
    try:
        endpoint = '/pt/v2/whois'
        param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
        res = make_api_call(config, 'GET', endpoint, param_dict)
        return res
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def search_whois_data(config, params):
    try:
        endpoint = '/pt/v2/whois/search'
        params['field'] = OPTIONS_MAPPING.get(params.get('field'))
        res = make_api_call(config, 'GET', endpoint, params)
        return res
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))

def get_passive_dns(config, params):
    try:
        endpoint = '/pt/v2/dns/passive'
        params['start'] = parse_datetime(params.get('start'))
        params['end'] = parse_datetime(params.get('end'))
        param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
        res = make_api_call(config, 'GET', endpoint, param_dict)
        return res
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))

def _check_health(config):
    try:
        endpoint = '/pt/v2/account'
        res = make_api_call(config, 'GET', endpoint, {})
        if res:
            return True
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


operations = {
    'get_reputation': get_reputation, #not included in license level
    'get_components': get_components,
    'get_trackers': get_trackers,  #search is disabled for account level
    'get_cookies': get_cookies,    #search is disabled for account level
    'get_alerts': get_alerts,
    'get_services': get_services,
    'get_enrichment_data': get_enrichment_data,
    'get_whois_data': get_whois_data,
    'search_whois_data': search_whois_data,
    'get_passive_dns': get_passive_dns
}
