import logging
import urllib3
from vspk import v5_0 as vspk
from vspk.utils import set_log_level

nuage_username = 'csproot'
nuage_password = 'csproot'
nuage_enterprise = 'csp'
nuage_host = '10.243.16.8'
nuage_port = '443'

def nuage_connect(nuage_username, nuage_password, nuage_enterprise, nuage_host, nuage_port):
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	try:
		nc = None
		print 'Connecting to Nuage server \'%s:%s\' with username \'%s\'...' % (nuage_host, nuage_port, nuage_username),
		nc = vspk.NUVSDSession(username=nuage_username, password=nuage_password, enterprise=nuage_enterprise, api_url="https://%s:%s" % (nuage_host, nuage_port))
		nc.start()
		print '[CONNECTED]'
		return nc
	except:
		print '[ERROR: Could not connect]'

def get_nuage_entity(parent, nuage_type, search_query, single_entity=False):
	if single_entity:
		entity = parent.fetcher_for_rest_name(nuage_type.lower()).get_first(filter=search_query)
	else:
		entity = parent.fetcher_for_rest_name(nuage_type.lower()).get(filter=search_query)
	return entity

def main():
	set_log_level(logging.ERROR)
	nc = nuage_connect(nuage_username, nuage_password, nuage_enterprise, nuage_host, nuage_port)
	
	delete_pending_list = []
	vsp = get_nuage_entity(nc.user, 'VSP', '', True)
	
	print 'Searching for VMs in \'DELETE_PENDING\' state...'
	vscs = get_nuage_entity(vsp, 'VSC', '', False)
	for vsc in vscs:
		vrss = get_nuage_entity(vsc, 'VRS', '', False)
		for vrs in vrss:
			vms = get_nuage_entity(vrs, 'VM', '', False)
			for vm in vms:
				if vm.status == 'DELETE_PENDING':
					if vm.id not in delete_pending_list:
						delete_pending_list.append(vm.id)
						print '%s,%s,%s,%s,%s,%s,%s' % (vm.enterprise_name, vm.name, vm.status, vm.reason_type, vm.delete_expiry, vm.delete_mode, vm.id)
	
	print '\nTotal number of VMs in \'DELETE_PENDING\' state: %s\n' % len(delete_pending_list)
	
	if delete_pending_list:
		delete = raw_input("Delete all VMs above? [y/n]: ")
		if delete.lower() == 'y' or delete.lower() == 'yes':
			for vm_id in delete_pending_list:
				vm = vspk.NUVM(id=vm_id)
				vm.fetch()
				print 'Deleting VM \'%s\'...' % vm.name,
				vm.delete()
				print '[DONE]'

if __name__ == '__main__':
	main()