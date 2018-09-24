# --- Description ---
# Script to set all L2/L3 domains to maintenance mode
#
# --- Author ---
# Chow Lip Khin <lipkhin.chow@nokia.com>
#
# --- Version ---
# 20180920 - 1.0
#
# --- Requirements ---
# 1. Python 2.7
# 2. Nuage VSPK 5.0+ (pip install vspk)
#
# --- Usage ---
# run 'python nuage_maintenance_mode.py -h' for an overview
#
# --- Examples ---
# 1. 'python nuage_maintenance_mode.py -e'		# Enable maintenance mode for all L2/L3 domains
# 2. 'python nuage_maintenance_mode.py -x'		# Disable maintenance mode for all L2/L3 domains

import argparse
import logging
import urllib3
import sys
import csv
import re
from colorama import init, Fore
from vspk import v5_0 as vspk
from vspk.utils import set_log_level

def setup_logging(args):
	debug = args.debug
	verbose = args.verbose
	if debug:
		set_log_level(logging.DEBUG)
	elif verbose:
		set_log_level(logging.INFO)
	else:
		set_log_level(logging.ERROR)

def colour(colour, text):
	return getattr(Fore, colour) + text + Fore.RESET
	
def parse_payload(payload_file):
	parsed_payload = {}
	temp_dict = {}
	temp_list = []
	keys = []
	after_start = False
	try:
		with open(payload_file) as csvfile:
			reader = csv.reader(csvfile)
			for row in reader:
				if row[0] and not re.search('^#',row[0].strip()):
					if row[0] == "key_start":
						section_key = row[1].strip()
						parsed_payload[section_key] = {}
						after_start = True
						continue
					if after_start:
						keys = row
						after_start = False
						continue
					if row[0] == "key_end":
						parsed_payload[section_key.strip()] = temp_list
						temp_list = []
						temp_dict = {}
						continue
					for i in range(0, len(keys)):
						temp_dict[keys[i].strip()]=row[i].strip()
					temp_list.append(temp_dict.copy())
		return parsed_payload
	except IOError:
		print "%s - Error opening the file \'%s\'" % (colour('RED', '[ERROR]'), payload_file)
		sys.exit()

def nuage_connect(nuage_username, nuage_password, nuage_enterprise, nuage_host, nuage_port):
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	try:
		nc = None
		print 'Connecting to Nuage server \'%s:%s\' with username \'%s\'...' % (nuage_host, nuage_port, nuage_username),
		nc = vspk.NUVSDSession(username=nuage_username, password=nuage_password, enterprise=nuage_enterprise, api_url="https://%s:%s" % (nuage_host, nuage_port))
		nc.start()
		print '%s' % colour('GREEN', '[CONNECTED]')
		return nc
	except:
		print '%s - Could not connect' % colour('RED', '[ERROR]')
		sys.exit()

def get_nuage_entity(parent, nuage_type, search_query, single_entity=False):
	if single_entity:
		entity = parent.fetcher_for_rest_name(nuage_type.lower()).get_first(filter=search_query)
	else:
		entity = parent.fetcher_for_rest_name(nuage_type.lower()).get(filter=search_query)
	return entity

def get_args():
	parser = argparse.ArgumentParser(description="Script to set all L2/L3 domains to maintenance mode")
	parser.add_argument('-e', '--enable', required=False, help='enable maintenance mode for all L2/L3 domains', dest='enable_maintenance_mode', action='store_true')
	parser.add_argument('-x', '--disable', required=False, help='disable maintenance mode for all L2/L3 domains', dest='disable_maintenance_mode', action='store_true')
	parser.add_argument('-v', '--verbose', required=False, help='enable verbose output', dest='verbose', action='store_true')
	parser.add_argument('-d', '--debug', required=False, help='enable debug output', dest='debug', action='store_true')
	parser.add_argument('-f', '--payload_file', required=False, help='name of the payload file to be used in this script (default: payload.csv)', dest='payload_file', action='store', default='payload.csv')
	args = parser.parse_args()
	return args
				
def main():
	init()
	args = get_args()
	setup_logging(args)
	payload = parse_payload(args.payload_file)
	nuage_username = payload['nuage_login'][0]['nuage_username']
	nuage_password = payload['nuage_login'][0]['nuage_password']
	nuage_enterprise = payload['nuage_login'][0]['nuage_enterprise']
	nuage_host = payload['nuage_login'][0]['nuage_host']
	nuage_port = payload['nuage_login'][0]['nuage_port']

	if args.enable_maintenance_mode or args.disable_maintenance_mode:
		nc = nuage_connect(nuage_username, nuage_password, nuage_enterprise, nuage_host, nuage_port)
		if nc is None:
			sys.exit()
		
		if args.disable_maintenance_mode:
			enterprises = get_nuage_entity(nc.user, 'Enterprise', '', False)
			for enterprise in enterprises:
				print '\n' + enterprise.name
				domains = get_nuage_entity(enterprise, 'Domain', '', False)
				for domain in domains:
					print 'Disabling maintenance mode for L3 domain \'%s\'...' % domain.name,
					domain.maintenance_mode = 'DISABLED'
					domain.save()
					print '%s' % colour('GREEN', '[DONE]')
				l2domains = get_nuage_entity(enterprise, 'L2Domain', '', False)
				for l2domain in l2domains:
					print 'Disabling maintenance mode for L2 domain \'%s\'...' % l2domain.name,
					l2domain.maintenance_mode = 'DISABLED'
					l2domain.save()
					print '%s' % colour('GREEN', '[DONE]')
				
		elif args.enable_maintenance_mode:
			enterprises = get_nuage_entity(nc.user, 'Enterprise', '', False)
			for enterprise in enterprises:
				print '\n' + enterprise.name
				domains = get_nuage_entity(enterprise, 'Domain', '', False)
				for domain in domains:	
					print 'Enabling maintenance mode for L3 domain \'%s\'...' % domain.name,
					domain.maintenance_mode = 'ENABLED'
					domain.save()
					print '%s' % colour('GREEN', '[DONE]')
				l2domains = get_nuage_entity(enterprise, 'L2Domain', '', False)
				for l2domain in l2domains:
					print 'Enabling maintenance mode for L2 domain \'%s\'...' % l2domain.name,
					l2domain.maintenance_mode = 'ENABLED'
					l2domain.save()
					print '%s' % colour('GREEN', '[DONE]')
				
	else:
		print '%s - No executable arguments passed. Use the -h option for help.' % colour('RED', '[ERROR]')
	
if __name__ == '__main__':
	main()
