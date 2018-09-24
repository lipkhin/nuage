# --- Description ---
# Script to create L2/L3 domains for CBIS infrastructure deployment
#
# --- Author ---
# Chow Lip Khin <lipkhin.chow@nokia.com>
#
# --- Version ---
# 20180910 - 1.0
#
# --- Requirements ---
# 1. Python 2.7
# 2. Nuage VSPK 5.0+ (pip install vspk)
#
# --- Usage ---
# run 'python nuage_cbis_buid.py -h' for an overview
#
# --- Examples ---
# 1. 'python nuage_cbis_buid.py -a'			# Execute all functions
# 2. 'python nuage_cbis_buid.py -G -g -e'	# Execute platform infrastructure configuration
# 3. 'python nuage_cbis_buid.py -L -l'		# Execute L3 domain configuration
# 4. 'python nuage_cbis_buid.py -N -n'		# Execute L2 domain configuration
# 5. 'python nuage_cbis_buid.py -b'			# Add bridge vport to L2/L3 domains

import argparse
import logging
import urllib3
import sys
import csv
import re
from colorama import init, Fore
from vspk import v5_0 as vspk
from vspk.utils import set_log_level

vlan_description = {
	# vlan_id : vlan_description
	'0' : 'Provisioning',
	'514' : 'Internal API',
	'515' : 'Storage',
	'516' : 'CBIS Tenant',
	'517' : 'Storage Management',
	'512' : 'CBIS External',
	'600' : 'VNF MANO'
}

l3domain_data = [
	# l3domain_name, l3domain_description, zone_name, subnet_name, subnet_address, subnet_netmask, subnet_gateway, l3domain_template_name
	('L3-A0212_VIM', 'CBIS External', 'CBIS-External', 'CBIS-External', '172.21.84.128', '255.255.255.224', '172.21.84.129', 'CBIS-Infra-L3-Template')
]

l2domain_data = [
	# l2domain_name, l2domain_description, l2domain_template_name
	('L2-A0212TTES11_CBIS_Provisioning', 'PSI CBIS_Provisioning VLAN # 0', 'CBIS-Infra-L2-Template'),
	('L2-A0212TTES11_CBIS_Internal_API', 'PSI CBIS_Internal_API VLAN # 514', 'CBIS-Infra-L2-Template'),
	('L2-A0212TTES11_CBIS_Storage', 'PSI CBIS_Storage VLAN # 515', 'CBIS-Infra-L2-Template'),
	('L2-A0212TTES11_CBIS_Tenant', 'PSI CBIS_Tenant VLAN # 516', 'CBIS-Infra-L2-Template'),
	('L2-A0212TTES11_CBIS_Storage_mgmt', 'PSI CBIS_Storage_mgmt VLAN # 517', 'CBIS-Infra-L2-Template')
]

vlan_l3domain = {
	# vlan_id : subnet_name
	'512' : 'CBIS-External'
}

vlan_l2domain = {
	# vlan_id : l2domain_name
	'0' : 'L2-A0212TTES11_CBIS_Provisioning',
	'514' : 'L2-A0212TTES11_CBIS_Internal_API',
	'515' : 'L2-A0212TTES11_CBIS_Storage',
	'516' : 'L2-A0212TTES11_CBIS_Tenant',
	'517' : 'L2-A0212TTES11_CBIS_Storage_mgmt'
}

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

def create_gateway_template(parent, gateway_template_data, port_template_data):
	print '\n### Create Platform Gateway Template ###'
	for data in gateway_template_data:
		gateway_template_name = data['gateway_template_name']
		gateway_personality = data['gateway_personality']
		print 'Creating platform gateway template \'%s\' (personality: %s)...' % (gateway_template_name, gateway_personality),
		gateway_template = get_nuage_entity(parent, 'GatewayTemplate', 'name == "%s"' % gateway_template_name, True)
		if gateway_template is None:
			try:
				gateway_template = vspk.NUGatewayTemplate(name=gateway_template_name, personality=gateway_personality)
				parent.create_child(gateway_template)
				print '%s' % colour('GREEN', '[DONE]')
				add_port_to_gateway_template(gateway_template, port_template_data)
			except:
				print '%s - Unable to create child (GatewayTemplate)' % colour('RED', '[ERROR]')
		else:
			print '%s - Gateway template name exists' % colour('RED', '[ERROR]')

def add_port_to_gateway_template(parent, port_template_data):
	for data in port_template_data:
		if data['gateway_template_name'] == parent.name:
			port_name = data['port_name']
			port_description = data['port_description']
			port_type = data['port_type']
			vlan_range = data['vlan_range']
			vlan_list = data['vlan_list']
			print '  Adding port \'%s\' to gateway template \'%s\'...' % (port_name, parent.name),
			port_template = get_nuage_entity(parent, 'PortTemplate', 'name == "%s"' % port_name, True)
			if port_template is None:
				try:
					port_template = vspk.NUPortTemplate(name=port_name, description=port_description, physical_name=port_name, port_type=port_type, vlan_range=vlan_range)
					parent.create_child(port_template)
					print '%s' % colour('GREEN', '[DONE]')
					if vlan_list:
						add_vlan_to_port_template(port_template, port_name, vlan_list)
				except:
					print '%s - Unable to create child (PortTemplate)' % colour('RED', '[ERROR]')
			else:
				print '%s - Port template name exists' % colour('RED', '[ERROR]')
					
def add_vlan_to_port_template(parent, port_name, vlan_list):			
	for vlan_id in vlan_list.split(','):
		print '    Adding VLAN # %s to port \'%s\'...' % (vlan_id, port_name),
		vlan_template = get_nuage_entity(parent, 'VLANTemplate', 'name == "%s"' % vlan_id, True)
		if vlan_template is None:
			try:
				vlan_template = vspk.NUVLANTemplate(value=vlan_id, description=vlan_description[vlan_id])
				parent.create_child(vlan_template)
				print '%s' % colour('GREEN', '[DONE]')
			except:
				print '%s - Unable to create child (VLANTemplate)' % colour('RED', '[ERROR]')
		else:
			print '%s - VLAN template exists' % colour('RED', '[ERROR]')
			
def instantiate_gateway(parent, gateway_data):
	print '\n### Instantiate Gateways ###'
	for data in gateway_data:
		gateway_name = data['gateway_name']
		gateway_description = data['gateway_description']
		gateway_system_id = data['gateway_system_id']
		gateway_template_name = data['gateway_template_name']
		if gateway_template_name:
			print 'Instantiating gateway \'%s\' with template \'%s\'...' % (gateway_name, gateway_template_name),
		else:
			print 'Instantiating gateway \'%s\'...' % (gateway_name),
		gateway = get_nuage_entity(parent, 'Gateway', 'systemID == "%s"' % gateway_system_id, True)
		if gateway is None:
			try:
				if gateway_template_name:
					gateway_template = get_nuage_entity(parent, 'GatewayTemplate', 'name == "%s"' % gateway_template_name, True)
					gateway = vspk.NUGateway(name=gateway_name, description=gateway_description, system_id=gateway_system_id, template_id=gateway_template.id)
				else:
					gateway = vspk.NUGateway(name=gateway_name, description=gateway_description, system_id=gateway_system_id)
				parent.create_child(gateway)
				print '%s' % colour('GREEN', '[DONE]')
			except:
				print '%s - Unable to create child (Gateway)' % colour('RED', '[ERROR]')
		else:
			if gateway.pending is True:
				print '%s - Gateway exists in pending state' % colour('RED', '[ERROR]')
				print 'Deleting pending gateway \'%s\'...' % (gateway.name),
				try:
					gateway.pending = False
					gateway.save()
					gateway.delete()
					print '%s' % colour('GREEN', '[DONE]')
				except:
					print '%s - Unable to delete pending gateway' % colour('RED', '[ERROR]')
					
				if gateway_template_name:
					print 'Instantiating gateway \'%s\' with template \'%s\'...' % (gateway_name, gateway_template_name),
				else:
					print 'Instantiating gateway \'%s\'...' % (gateway_name),
				try:
					if gateway_template_name:
						gateway_template = get_nuage_entity(parent, 'GatewayTemplate', 'name == "%s"' % gateway_template_name, True)
						gateway = vspk.NUGateway(name=gateway_name, description=gateway_description, system_id=gateway_system_id, template_id=gateway_template.id)
					else:
						gateway = vspk.NUGateway(name=gateway_name, description=gateway_description, system_id=gateway_system_id)
					parent.create_child(gateway)
					print '%s' % colour('GREEN', '[DONE]')
				except:
					print '%s - Unable to create child (Gateway)' % colour('RED', '[ERROR]')
						
			else:
				print '%s - Gateway exists' % colour('RED', '[ERROR]')
				
def attach_enterprise_permission(parent, gateway_list, enterprise_id):
	print '\n### Attach Enterprise Permission ###'
	for data in gateway_list:
		gateway_name = data['gateway_name']
		gateway = get_nuage_entity(parent, 'Gateway', 'name == "%s"' % gateway_name, True)
		if gateway is None:
			return 1
		print '\n' + gateway.name
		ports = get_nuage_entity(gateway, 'Port', '', False)
		for port in ports:
			vlans = get_nuage_entity(port, 'VLAN', '', False)
			for vlan in vlans:
				print 'Adding enterprise permission to port \'%s\' VLAN # %s...' % (port.name, vlan.value),
				enterprisepermission = get_nuage_entity(vlan, 'EnterprisePermission', '', True)
				if enterprisepermission is None:
					try:
						enterprisepermission = vspk.NUEnterprisePermission(permitted_action='USE', permitted_entity_id=enterprise_id)
						vlan.create_child(enterprisepermission)
						print '%s' % colour('GREEN', '[DONE]')
					except:
						print '%s - Unable to create child (EnterprisePermission)' % colour('RED', '[ERROR]')
				else:
					existing_enterprise = get_nuage_entity(parent, 'Enterprise', 'ID == "%s"' % enterprisepermission.permitted_entity_id, True)
					print '%s - Entity already assigned to \'%s\'' % (colour('RED', '[ERROR]'), existing_enterprise.name)

def create_l3domain_template(parent, l3domain_data):
	print '\n### Create L3 Domain Template ###'
	for (l3domain_name, l3domain_description, zone_name, subnet_name, subnet_address, subnet_netmask, subnet_gateway, l3domain_template_name) in l3domain_data:
		l3domain_template = get_nuage_entity(parent, 'DomainTemplate', 'name == "%s"' % l3domain_template_name, True)
		if l3domain_template is None:
			print 'Creating L3 domain template \'%s\'...' % (l3domain_template_name),
			try:
				l3domain_template = vspk.NUDomainTemplate(name=l3domain_template_name)
				parent.create_child(l3domain_template)
				print '%s' % colour('GREEN', '[DONE]')
			except:
				print '%s - Unable to create child (DomainTemplate)' % colour('RED', '[ERROR]')

def instantiate_l3domain(parent, l3domain_data):
	print '\n### Instantiate L3 Domain ###'
	for (l3domain_name, l3domain_description, zone_name, subnet_name, subnet_address, subnet_netmask, subnet_gateway, l3domain_template_name) in l3domain_data:
		print 'Instantiating L3 domain \'%s\'...' % (l3domain_name),
		l3domain = get_nuage_entity(parent, 'Domain', 'name == "%s"' % l3domain_name, True)
		if l3domain is None:
			try:
				l3domain_template = get_nuage_entity(parent, 'DomainTemplate', 'name == "%s"' % l3domain_template_name, True)
				l3domain = vspk.NUDomain(name=l3domain_name, description=l3domain_description, template_id=l3domain_template.id)
				parent.create_child(l3domain)
				print '%s' % colour('GREEN', '[DONE]')
				# add zone to L3 domain
				add_zone_to_l3domain(l3domain, zone_name, subnet_name, subnet_address, subnet_netmask, subnet_gateway)
			except:
				print '%s - Unable to create child (Domain)' % colour('RED', '[ERROR]')
		else:
			print '%s - L3 domain name exists' % colour('RED', '[ERROR]')
	
def add_zone_to_l3domain(parent, zone_name, subnet_name, subnet_address, subnet_netmask, subnet_gateway):
	print '  Adding zone \'%s\' to L3 domain \'%s\'...' % (zone_name, parent.name),
	zone = get_nuage_entity(parent, 'Zone', 'name == "%s"' % zone_name, True)
	if zone is None:
		try:
			zone = vspk.NUZone(name=zone_name)
			parent.create_child(zone)
			print '%s' % colour('GREEN', '[DONE]')
			add_subnet_to_zone(zone, subnet_name, subnet_address, subnet_netmask, subnet_gateway)
		except:
			print '%s - Unable to create child (Zone)' % colour('RED', '[ERROR]')
	else:
		print '%s - Zone name exists' % colour('RED', '[ERROR]')
		
def add_subnet_to_zone(parent, subnet_name, subnet_address, subnet_netmask, subnet_gateway):
	print '    Adding subnet \'%s\' to zone \'%s\'...' % (subnet_name, parent.name),
	subnet = get_nuage_entity(parent, 'Subnet', 'name == "%s"' % subnet_name, True)
	if subnet is None:
		try:
			subnet = vspk.NUSubnet(name=subnet_name, address=subnet_address, netmask=subnet_netmask, gateway=subnet_gateway)
			parent.create_child(subnet)
			print '%s' % colour('GREEN', '[DONE]')
		except:
			print '%s - Unable to create child (Subnet)' % colour('RED', '[ERROR]')
	else:
		print '%s - Subnet name exists' % colour('RED', '[ERROR]')

def create_l2domain_template(parent, l2domain_data):
	print '\n### Create L2 Domain Template ###'
	for (l2domain_name, l2domain_description, l2domain_template_name) in l2domain_data:
		l2domain_template = get_nuage_entity(parent, 'L2DomainTemplate', 'name == "%s"' % l2domain_template_name, True)
		if l2domain_template is None:
			print 'Creating L2 domain template \'%s\'...' % (l2domain_template_name),
			try:
				l2domain_template = vspk.NUL2DomainTemplate(name=l2domain_template_name)
				parent.create_child(l2domain_template)
				print '%s' % colour('GREEN', '[DONE]')
			except:
				print '%s - Unable to create child (L2DomainTemplate)' % colour('RED', '[ERROR]')

def instantiate_l2domain(parent, l2domain_data):
	print '\n### Instantiate L2 Domain ###'
	for (l2domain_name, l2domain_description, l2domain_template_name) in l2domain_data:
		print 'Instantiating L2 domain \'%s\'...' % (l2domain_name),
		l2domain = get_nuage_entity(parent, 'L2Domain', 'name == "%s"' % l2domain_name, True)
		if l2domain is None:
			try:
				l2domain_template = get_nuage_entity(parent, 'L2DomainTemplate', 'name == "%s"' % l2domain_template_name, True)
				l2domain = vspk.NUL2Domain(name=l2domain_name, description=l2domain_description, template_id=l2domain_template.id)
				parent.create_child(l2domain)
				print '%s' % colour('GREEN', '[DONE]')
			except:
				print '%s - Unable to create child (L2Domain)' % colour('RED', '[ERROR]')
		else:
			print '%s - L2 domain name exists' % colour('RED', '[ERROR]')

def add_bridge_vport(parent, gateway_data):
	print '\n### Add Bridge vPort to L2/L3 Domain ###'
	for (gateway_name, gateway_description, gateway_type, gateway_system_id, gateway_template_name) in gateway_data:
		if gateway_type == 'Leaf':
			gateway = get_nuage_entity(parent, 'Gateway', 'name == "%s"' % gateway_name, True)
			if gateway is None:
				return 1
			print '\n' + gateway.name
			ports = get_nuage_entity(gateway, 'Port', '', False)
			for port in ports:
				vlans = get_nuage_entity(port, 'VLAN', '', False)
				for vlan in vlans:
					if str(vlan.value) in vlan_l2domain:
						l2domain = get_nuage_entity(parent, 'L2Domain', 'name == "%s"' % vlan_l2domain[str(vlan.value)], True)
						if l2domain:
							print 'Adding bridge vport (port \'%s\' VLAN # %s) to L2 domain \'%s\'...' % (port.name, vlan.value, l2domain.name),
							vport_name = gateway.name + '_' + port.physical_name.replace('/','_')
							vport = get_nuage_entity(l2domain, 'VPort', 'name == "%s"' % vport_name, True)
							if vport is None:
								try:
									vport = vspk.NUVPort(name=vport_name, address_spoofing='ENABLED', type='BRIDGE', vlanid=vlan.id) 
									l2domain.create_child(vport)
									bridge_interface = vspk.NUBridgeInterface(name=vport_name)
									vport.create_child(bridge_interface)
									print '%s' % colour('GREEN', '[DONE]')
								except:
									print '%s - Unable to create child (VPort)' % colour('RED', '[ERROR]')
							else:
								print '%s - VPort name exists' % colour('RED', '[ERROR]')
					elif str(vlan.value) in vlan_l3domain:
						subnet = get_nuage_entity(parent, 'Subnet', 'name == "%s"' % vlan_l3domain[str(vlan.value)], True)
						if subnet:
							print 'Adding bridge vport (port \'%s\' VLAN # %s) to L3 domain subnet \'%s\'...' % (port.name, vlan.value, subnet.name),
							vport_name = gateway.name + '_' + port.physical_name.replace('/','_')
							vport = get_nuage_entity(subnet, 'VPort', 'name == "%s"' % vport_name, True)
							if vport is None:
								try:
									vport = vspk.NUVPort(name=vport_name, address_spoofing='ENABLED', type='BRIDGE', vlanid=vlan.id) 
									subnet.create_child(vport)
									bridge_interface = vspk.NUBridgeInterface(name=vport_name)
									vport.create_child(bridge_interface)
									print '%s' % colour('GREEN', '[DONE]')
								except:
									print '%s - Unable to create child (VPort)' % colour('RED', '[ERROR]')
							else:
								print '%s - VPort name exists' % colour('RED', '[ERROR]')

def get_args():
	parser = argparse.ArgumentParser(description="Script to create L2/L3 domains for CBIS infra deployment")
	parser.add_argument('-a', '--all', required=False, help='execute all functions', dest='all', action='store_true')
	parser.add_argument('-G', '--gateway-tpl', required=False, help='create gateway template', dest='gateway_tpl', action='store_true')
	parser.add_argument('-g', '--gateway', required=False, help='instantiate gateway', dest='gateway', action='store_true')
	parser.add_argument('-e', '--ent-permission', required=False, help='attach enterprise permission', dest='ent_permission', action='store_true')
	parser.add_argument('-L', '--l3domain-tpl', required=False, help='create L3 domain template', dest='l3domain_tpl', action='store_true')
	parser.add_argument('-l', '--l3domain', required=False, help='instantiate L3 domain', dest='l3domain', action='store_true')
	parser.add_argument('-N', '--l2domain-tpl', required=False, help='create L2 domain template', dest='l2domain_tpl', action='store_true')
	parser.add_argument('-n', '--l2domain', required=False, help='instantiate L2 domain', dest='l2domain', action='store_true')
	parser.add_argument('-b', '--bridge-vport', required=False, help='create bridge vport', dest='bridge_vport', action='store_true')
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
	nuage_org = payload['nuage_org'][0]['org_name']

	if args.all or args.gateway_tpl or args.gateway or args.ent_permission or args.l3domain_tpl or args.l3domain or args.l2domain_tpl or args.l2domain or args.bridge_vport:
		nc = nuage_connect(nuage_username, nuage_password, nuage_enterprise, nuage_host, nuage_port)
		if nc is None:
			sys.exit()

		enterprise = get_nuage_entity(nc.user, 'Enterprise', 'name == "%s"' % nuage_org, True)
		if enterprise is None:
			print '%s - Unknown organization \'%s\'' % (colour('RED', '[ERROR]'), nuage_org)
			sys.exit()
		"""
		# Platform infrastructure configuration
		if args.all or args.gateway_tpl:
			create_gateway_template(nc.user, payload['gateway_template_data'], payload['port_template_data'])
		if args.all or args.gateway:
			instantiate_gateway(nc.user, payload['gateway_data'])
		if args.all or args.ent_permission:
			attach_enterprise_permission(nc.user, payload['gateway_list'], enterprise.id)
		
		# L3 domain configuration
		if args.all or args.l3domain_tpl:
			create_l3domain_template(enterprise, payload['l3domain_template_data'])
		if args.all or args.l3domain:
			instantiate_l3domain(enterprise, l3domain_data)
		
		# L2 domain configuration
		if args.all or args.l2domain_tpl:
			create_l2domain_template(enterprise, l2domain_data)
		if args.all or args.l2domain:
			instantiate_l2domain(enterprise, l2domain_data)
		
		# Add bridge vport to L2/L3 domains
		if args.all or args.bridge_vport:
			add_bridge_vport(nc.user, gateway_data)
		"""
	else:
		print '%s - No executable arguments passed. Use the -h option for help.' % colour('RED', '[ERROR]')
	
if __name__ == '__main__':
	main()
