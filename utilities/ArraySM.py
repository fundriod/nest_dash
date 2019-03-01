#!/usr/bin/env python3
import logging
import random
import itertools
import argparse
import time
import log_handler
from ArrayCM import ssh as ssh
from ArrayCM import rest as rest
from ArrayCM import GenericError
from ArrayGM import GetObj
from pprint import pprint as pp
# from collections import defaultdict

#
logging.LIST = 35  # between WARNING and ERROR
logging.addLevelName(logging.LIST, 'LIST')
log = logging.getLogger()
# log.addHandler(log_handler.StreamHandler())
# log.addHandler(log_handler.FileHandler())
setattr(log, 'list', lambda message, *args: log._log(logging.LIST, message, args))
# log.setLevel('INFO')


class SetObj(GetObj):
    def __init__(self, hostname, username, password):
        GetObj.__init__(self, hostname, username, password)
    #     # self._hostname = hostname
    #     # self._username = username
    #     # self._password = password

    #
    #
    def set_vol_create(self, vol_prefix="nVol", vol_suffix="nap", vol_size="1", vol_count=1, vol_pool="default",
                      vol_dedup="off", vol_perfpolicy="default", vol_initiatorgrp="nap-dummy"):

        vol_size = 1024*int(vol_size)
        pool_list = GetObj.get_poollist(self, pool_regex="")
        pool = [each.pool_name for each in pool_list if vol_pool in each.pool_name]
        policy_list = GetObj.get_perfpolicy(self, policy_arg=vol_perfpolicy)
        initiator_list = GetObj.get_initiatorlist(self, client_regex="")
        print(initiator_list)
        initiator = [each.name for each in initiator_list if vol_initiatorgrp in each.name]
        pp("=======================")
        print(initiator)
        # todo add create_initiator
        created_vols = list()
        for vol in range(int(vol_count)):
            vol_name = vol_prefix+str(vol)+vol_suffix
            try:
                this_pool = random.choice(pool)
                output = ssh(hostname=self._hostname, username=self._username, password=self._password,
                             command="vol --create %s --size %s --pool %s --perfpolicy '%s' --dedupe_enabled %s "
                                     "--initiatorgrp %s " % (vol_name, vol_size, this_pool,
                                                             random.choice(policy_list), vol_dedup, initiator[0]))
            except GenericError as e:
                log.error(e)
            else:
                if output['error']:
                    log.error("%s >> CREATE: vol create %s - failed with error %s"
                              % (self._hostname, str(vol_name+':/'+this_pool), output['error']))
                else:
                    created_vols.append(str(vol_name+':/'+this_pool))
                    log.info("%s >> CREATE: vol create %s - successful!"
                             % (self._hostname, str(vol_name+':/'+this_pool)))

        log.list("%s >> LIST: %s vol created %s" % (self._hostname, len(created_vols), ', '.join(created_vols)))
        return created_vols

    #
    #
    def set_vol_delete(self, vol_regex=None, *args):
        deleted_vols = []
        all_vols = GetObj.rest_vollist(self, vol_regex=vol_regex)
        if all_vols:
            # vol_list = [(each.name, each.path.split(':')[0]) for each in all_vols]
            vol_list = [each for each in all_vols if each.acl is None and each.volcoll_name == '']
            pp(vol_list)
            time.sleep(30)
        else:
            return None
        for vol in vol_list:
            try:
                dissoc = ssh(hostname=self._hostname, username=self._username, password=self._password,
                             command="vol --dissoc %s --pool %s --force " % (vol.name, vol.pool_name))
                offline = ssh(hostname=self._hostname, username=self._username, password=self._password,
                              command="vol --offline %s  --pool %s --force" % (vol.name, vol.pool_name))
                if offline['error']:
                    log.error("%s >> vol offline %s - failed with error %s" % (self._hostname, vol.name, dissoc['error']))
                else:
                    log.info("%s >> vol offline %s - successful!" % (self._hostname, vol.name))
            except GenericError as e:
                log.error(e)
            else:
                delete = ssh(hostname=self._hostname, username=self._username, password=self._password,
                             command="vol --delete %s  --pool %s" % (vol.name, vol.pool_name))
                if delete['error']:
                    log.error("%s >> DELETE: vol delete %s - failed with error: %s"
                              % (self._hostname, vol.full_name, delete['error']))
                else:
                    log.info("%s >> DELETE: vol delete %s - successful!" % (self._hostname, vol.full_name))

                    deleted_vols.append(vol.full_name)

        log.list("%s >> LIST: %s vol deleted %s " % (self._hostname, len(deleted_vols), ', '.join(deleted_vols)))
        return deleted_vols

    #
    #
    def set_clone_create(self, vol_regex="nap", snap_regex="nSnap", clone_prefix="nClone", clone_count=1, read_only='no'):
        all_vols = GetObj.get_vollist(self, vol_regex=vol_regex)
        all_clones_created = list()
        # pp(all_vols)
        if all_vols:
            for vol in all_vols:
                vol_all_snaps = GetObj.get_snaplist(self, vol_regex=vol.name, snap_regex=snap_regex)

                # pp(vol_all_snaps)
                if vol_all_snaps:
                    for snap in vol_all_snaps:
                        while int(clone_count) > 0:
                            # pp(snap)
                            # pp(vol)
                            clone_name = clone_prefix+'.'+str(clone_count)+'-'+vol.name+vol.path.split(':')[0]+'-'+snap.snap_name
                            try:
                                clone = ssh(hostname=self._hostname, username=self._username, password=self._password,
                                            command="vol --clone %s --snapname %s --pool %s --clonename "
                                                    "%s --readonly=%s" % (vol.name, snap.snap_name,
                                                                          vol.path.split(':')[0],  clone_name,
                                                                          read_only.lower()))
                            except GenericError as e:
                                log.error(e)
                            else:
                                if clone['error']:
                                    log.error("%s >> CLONE_CREATE: clone create %s - failed with error: %s"
                                              % (self._hostname, clone_name, clone['error']))
                                else:
                                    log.info("%s >> CLONE_CREATE: clone create of %s - successful! %s"
                                             % (self._hostname, clone_name, clone['info']))
                                    all_clones_created.append(clone_name)
                                    clone_count -= 1

        return all_clones_created

    #
    #
    def set_snap_create(self, vol_regex="nap", snap_prefix="nSnap", writable_snap="No", snap_count=1,
                       snap_suffix="sNap"):

        all_created_snap = list()

        all_vols = GetObj.get_vollist(self, vol_regex=vol_regex)
        if all_vols:
            vol_list = [(each.name, each.path.split(':')[0]) for each in all_vols]
            for vol, pool in vol_list:
                created_snap = list()
                for snap_number in range(int(snap_count)):
                    snap_name = ("%s.%s-%s.%s" % (snap_prefix, vol, snap_number, snap_suffix))
                    try:
                        if writable_snap.lower() == "yes":
                            _create = ssh(hostname=self._hostname, username=self._username, password=self._password,
                                          command="vol --snap %s --snapname %s --start_online --allow_writes --pool %s"
                                                  % (vol, snap_name, pool))
                        else:
                            _create = ssh(hostname=self._hostname, username=self._username, password=self._password,
                                          command="vol --snap %s --snapname %s --pool %s" % (vol, snap_name, pool))
                    except GenericError as e:
                        log.error(e)
                    else:
                        if _create['error']:
                            log.error("%s >> CREATE: snap create %s on vol %s - failed with error: %s" %
                                      (self._hostname, snap_name, str(vol+':/'+pool), _create['error']))
                        else:
                            log.info("%s >> CREATE: snap create %s on vol %s - successful!" %
                                     (self._hostname, str(vol+':/'+pool), snap_name))
                            created_snap.append(snap_name)
                if created_snap:
                    log.list("%s >> LIST: %s snap created on vol %s: %s"
                             % (self._hostname, len(created_snap), str(vol+':/'+pool), ', '.join(created_snap)))

                    all_created_snap.append({str(vol+':/'+pool): created_snap})

        return all_created_snap

    #
    #
    def set_snap_delete(self, vol_regex=None, snap_regex=None):

        all_deleted_snap = list()

        all_snaps = GetObj.get_snaplist(self, vol_regex=vol_regex, snap_regex=snap_regex)
        if all_snaps:
            snap_list = [(each.vol_name, each.snap_name, each.path.split(':')[0]) for each in all_snaps]

            for vol, snap, pool in snap_list:
                    try:
                        delete = ssh(hostname=self._hostname, username=self._username, password=self._password,
                                     command="snap --delete %s --vol %s --pool %s" % (snap, vol, pool))
                    except GenericError as e:
                        log.error(e)
                    else:
                        if delete['error']:
                            log.error("%s >> DELETE: snap delete %s on vol %s - failed with error: %s" %
                                      (self._hostname, snap, str(vol+':/'+pool), delete['error']))
                        else:
                            log.info("%s >> DELETE: snap delete %s on vol %s - successful!"
                                     % (self._hostname, snap, str(vol+':/'+pool)))
                            all_deleted_snap.append((str(vol+':/'+pool), snap))
        log.list("%s >> LIST: %s snap deleted %s " %
                 (self._hostname, len(all_deleted_snap), ', '.join([item[0]+' '+item[1] for item in all_deleted_snap])))
        return all_deleted_snap

    #
    # completely migrated to rest calls
    #
    def set_volcoll_add(self, vol_regex=None, volcoll_regex=None, sync_repl=False, *args):

        volcoll_list = GetObj.rest_volcolllist(self, volcoll_regex=volcoll_regex)
        vol_list = GetObj.rest_vollist(self, vol_regex=vol_regex)

        all_vols = list()  # all volumes with new volcoll added by this function
        qualified_vols = list()  # all volumes that can be added to volcolls
        sync_repl_volcolls = list()  # all volcoll with sync-repl enabled

        if vol_list and volcoll_list:
            qualified_vols = [vol for vol in vol_list if vol.volcoll_name == '']
            sync_repl_volcolls = [volcoll for volcoll in volcoll_list if volcoll.replication_type == 'synchronous']
            normal_volcolls = [volcoll for volcoll in volcoll_list if volcoll.replication_type != 'synchronous']
            log.list("Filtered qualified volumes %s" % str([vol.full_name for vol in qualified_vols]))
            log.list("Filtered synchronous volcolls %s" % str([volcoll.full_name for volcoll in sync_repl_volcolls]))
            # todo Add support for non sync-repl vols

        else:
            log.warning("%s >> VOLCOLL ADD: No volume with regex:'%s' or volcoll with regex:'%s' found to work on." %
                        (self._hostname, vol_regex, volcoll_regex))
            time.sleep(5)

        if sync_repl is not False and len(sync_repl_volcolls) != 0 and len(qualified_vols) != 0:
            for vol in qualified_vols:
                valid_volcolls = [vc for vc in sync_repl_volcolls if vc.replication_partner != vol.pool_name]
                # todo change to compare with pool id.
                if len(valid_volcolls) != 0:
                    final_volcoll = random.choice(valid_volcolls)

                    log.info("%s >> VOLCOLL ADD: Valid volcoll for vol: %s is: %s with repl_partner as: %s" %
                             (self._hostname, vol.full_name, final_volcoll.full_name,
                              final_volcoll.replication_partner))
                    # time.sleep(10)
                    try:

                        data = '{"id":"%s","volcoll_id":"%s"}' % (vol.vol_id, final_volcoll.volcoll_id)

                        endpoint = 'volumes/%s' % vol.vol_id
                        response = rest(hostname=self._hostname, username=self._username, password=self._password,
                                        endpoint=endpoint, action='PUT', in_data=data)

                    except GenericError as e:
                        log.error(e)

                    else:
                        if response and 'messages' in response:
                            log.error("%s >> VOLCOLL ADD: vol add of %s on volcoll %s - failed with error: %s" %
                                      (self._hostname, vol.full_name, final_volcoll.full_name,
                                       response['messages'][0]['text']))
                        else:
                            log.info("%s >> VOLCOLL ADD: vol add of %s on volcoll %s - successful!"
                                     % (self._hostname, vol.full_name, final_volcoll.full_name))
                            all_vols.append(vol.full_name)

                else:
                    log.warning("%s >> VOLCOLL ADD: No qualified sync-repl enabled volcoll found for volume %s." %
                                (self._hostname, vol.full_name))
                    time.sleep(5)
        else:
            log.warning("%s >> VOLCOLL ADD: No qualified volume or volcoll found to work on." % self._hostname)
            time.sleep(5)
        return all_vols if len(all_vols) > 0 else []

    #
    # completely migrated to rest calls
    #
    def set_volcoll_remove(self, vol_regex=None, dummy=None, delete_downstream=False, *args):

        all_list = GetObj.rest_vollist(self, vol_regex=vol_regex)
        if all_list is not None:
            vol_list = [vol for vol in all_list if vol.volcoll_name != '' and vol.repl_role != 'synchronous_downstream']
            downstream_vols = [vol for vol in all_list if vol.repl_role == 'synchronous_downstream']

            # pp(downstream_vols)

            all_vols = list()
            if len(vol_list) == 0:
                log.warning("%s >> VOLCOLL REMOVE: No valid volume with string - '%s' found with associated volcoll."
                            % (self._hostname, vol_regex))
                return []  # return empty list
            log.list("%s Filtered volumes to remove volcoll %s" % (len(vol_list),
                                                                   str([vol.full_name for vol in vol_list])))
            for vol in vol_list:
                try:
                    # vol_pool = vol.path.split(':')[0]

                    data = '{"id":"%s","volcoll_id":""}' % vol.vol_id
                    # pp(data)
                    endpoint = 'volumes/%s' % vol.vol_id
                    response = rest(hostname=self._hostname, username=self._username, password=self._password,
                                    endpoint=endpoint, action='PUT', in_data=data)

                    time.sleep(5)  # sleep to re-sync the config

                except GenericError as e:
                    log.error(e)

                else:
                    if response and 'messages' in response:
                        log.error("%s >> VOLCOLL REMOVE: vol %s - failed with error: %s" %
                                  (self._hostname, vol.full_name, response['messages'][0]['text']))
                        pp(response)
                    else:
                        log.info("%s >> VOLCOLL REMOVE: vol %s - successful!"
                                 % (self._hostname, vol.full_name))
                        all_vols.append(vol.full_name)

            time.sleep(15)  # let vol --dissoc take effect and vol goes offline

            if delete_downstream is not False:
                for vol in downstream_vols:
                    out = GetObj.rest_vollist(self, vol_regex=vol.name)
                    # pp(out)
                    # time.sleep(5)
                    delete_ok = [del_ok for del_ok in out if del_ok.acl is None and del_ok.volcoll_name == '' and
                                 del_ok.state == 'offline']
                    log.list("Filtered downstream volume to delete %s" % str([vol.full_name for vol in delete_ok]))
                    time.sleep(5)
                    for each in delete_ok:

                        endpoint = 'volumes/%s' % each.vol_id
                        delete = rest(hostname=self._hostname, username=self._username, password=self._password,
                                      endpoint=endpoint, action='DELETE', in_data='{}')

                        if delete and 'messages' in delete:
                            log.error("%s >> DELETE DOWNSTREAM: vol %s - failed with error: %s" %
                                      (self._hostname, each.full_name, delete['messages'][0]['text']))
                        else:
                            log.info("%s >> DELETE DOWNSTREAM: vol %s - successful!"
                                     % (self._hostname, each.full_name))

            return all_vols
        else:
            log.warning("%s >> VOLCOLL REMOVE: No volume exists with string - '%s' found on array."
                        % (self._hostname, vol_regex))

    #
    # completely migrated to rest calls
    #
    def set_volcoll_handover(self, volcoll_regex=None, partner_regex=None, *args):

        volcoll_list = GetObj.rest_volcolllist(self, volcoll_regex=volcoll_regex)
        partners_list = GetObj.rest_partnerlist(self, partner_regex=partner_regex)

        volcoll_list = [vc for vc in volcoll_list if vc.replication_partner != '']
        all_handover_volcolls = list()

        for volcoll in volcoll_list:
            if len(partners_list) != 0:
                replication_partner_id = [_id.repl_id for _id in partners_list if _id.full_name ==
                                          volcoll.replication_partner]
                data = '{"id":"%s","replication_partner_id":"%s"}' % (volcoll.volcoll_id,
                                                                      replication_partner_id[0].strip())
                try:

                        endpoint = 'volume_collections/%s/actions/handover' % volcoll.volcoll_id
                        response = rest(hostname=self._hostname, username=self._username, password=self._password,
                                        endpoint=endpoint, action='POST', in_data=data)
                        # pp(response)
                        # time.sleep(30)

                except GenericError as e:
                    log.error(e)
                else:
                    if response and response['messages']:
                        log.error("%s >> HANDOVER: volcoll %s handover to partner %s - failed with error: %s" %
                                  (self._hostname, volcoll.full_name, volcoll.replication_partner,
                                   response['messages'][0]['text']))
                    else:
                        log.info("%s >> HANDOVER: volcoll %s handover to partner %s - successful!"
                                 % (self._hostname, volcoll.full_name, volcoll.replication_partner))

                        all_handover_volcolls.append(volcoll.full_name)

        return all_handover_volcolls if len(all_handover_volcolls) > 0 else []

    #
    #
    def set_vol_move(self, vol_regex=None, pool_regex=None):
        vol_list = GetObj.get_vollist(self, vol_regex=vol_regex)
        all_pool_list = GetObj.get_poollist(self, pool_regex=pool_regex)
        pool_list = [item.pool_name for item in all_pool_list]
        all_moved_vols = list()
        if vol_list and pool_list:
            for vol in vol_list:
                
                try:
                    vol_pool = vol.path.split(':')[0]
                    dest_pool = random.choice(pool_list)
                    out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                              command="vol --move %s --pool %s --dest_pool %s"
                                      % (vol.name, vol_pool, dest_pool))
                except GenericError as e:
                    log.error(e)
                else:
                    if out['error']:
                        log.error("%s >> VOLMOVE: vol move of %s to pool %s - failed with error: %s" %
                                  (self._hostname, vol.name, dest_pool, out['error']))
                    else:
                        log.info("%s >> VOLMOVE: vol move of %s to pool %s - successful! %s"
                                 % (self._hostname, vol.name+':/'+vol_pool, dest_pool, out['info']))
                        all_moved_vols.append(str(vol.name+':/'+vol_pool))
        return all_moved_vols

    #
    #
    def set_nsproc_flag(self, array_regex=None, proc_state=None):
        proc_list = GetObj.get_nsproc(self, array_regex=array_regex, proc_state=proc_state)
        if proc_list:
            flagged_process = [item for item in proc_list if int(item.num_restarts) != 1]
            return flagged_process
        else:
            return []

    #
    # completely migrated to rest calls
    #
    def set_failover(self, array_regex=None, *args):
        array_list = GetObj.rest_arraylist(self, array_regex=array_regex)
        if array_list:
            ctrlr_list = GetObj.rest_ctrlrlist(self, array_regex=array_regex)
            healthy = [ctrlr for ctrlr in ctrlr_list if ctrlr.state == 'active']
            pp('healthy ctrlr')
            pp(healthy)
            for ctrlr in healthy:
                endpoint = 'arrays/%s/actions/failover' % ctrlr.array_id
                response = rest(hostname=self._hostname, username=self._username, password=self._password,
                                endpoint=endpoint, action='POST', in_data='{}')
                log.info("%s >> FAILOVER: %s : %s" %
                         (self._hostname, ctrlr.hostname, response['messages'][0]['text']))
                # pp(response)
                time.sleep(60)

    #
    # WIP migrated to rest calls
    #
    def set_reboot(self, array_regex=None, *args):
        array_list = GetObj.rest_arraylist(self, array_regex=array_regex)
        pp(array_list)
        array = random.choice(array_list)
        pp(array)
        # if array_list:
        #     for array in random.choice(array_list):
        #         pp(array)
                # endpoint = 'arrays/%s/actions/reboot' % ctrlr.array_id
                # response = rest(hostname=self._hostname, username=self._username, password=self._password,
                #                 endpoint=endpoint, action='POST', in_data='{}')
                # log.info("%s >> FAILOVER: %s : %s" %
                #          (self._hostname, ctrlr.hostname, response['messages'][0]['text']))
                # pp(response)
                # time.sleep(60)

    #
    # completely migrated to rest calls
    #
    def set_migrate(self, *args):
        group_list = GetObj.rest_groupinfo(self,)
        if group_list:
            endpoint = 'groups/%s/actions/check_migrate' % group_list[0].id
            check_migrate = rest(hostname=self._hostname, username=self._username, password=self._password,
                                 endpoint=endpoint, action='POST', in_data='{}')
            retry = 1
            while check_migrate != {} and retry <= 5:
                log.error("%s >> GROUP MIGRATE: %s migrate check failed with error: %s \n. ** Retry %s in 20 sec **" %
                          (self._hostname, group_list[0].leader_array_name, check_migrate['messages'][0]['text'], retry))
                time.sleep(20)
                check_migrate = rest(hostname=self._hostname, username=self._username, password=self._password,
                                     endpoint=endpoint, action='POST', in_data='{}')
                retry = retry + 1
                pp(check_migrate)

            if not check_migrate:
                log.info("%s >> GROUP MIGRATE: %s migrate check - successful!"
                         % (self._hostname, group_list[0].leader_array_name))
                try:
                    endpoint = 'groups/%s/actions/migrate' % group_list[0].id
                    response = rest(hostname=self._hostname, username=self._username, password=self._password,
                                    endpoint=endpoint, action='POST', in_data='{}')

                except GenericError as e:
                    log.error(e)

                else:
                    if response and response['messages']:
                        log.error("%s >> GROUP MIGRATE: %s migrate failed with error: %s" %
                                  (self._hostname, group_list[0].leader_array_name,
                                   response['messages'][0]['text']))
                    else:
                        log.info("%s >> GROUP MIGRATE:  %s migrate to partner - successful!"
                                 % (self._hostname, group_list[0].leader_array_name))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='Array Set Module',
                                     description='SetMod to execute operation on (group leader) using ssh/rest')

    parser.add_argument("action", choices=["set_reboot", "set_migrate", "set_failover", "set_nsproc_flag", "set_vol_move",
                                           "set_volcoll_handover", "set_volcoll_remove", "set_volcoll_add",
                                           "set_snap_delete", "set_snap_create", "set_clone_create", "set_vol_delete",
                                           "set_vol_create"],
                        help="""


                        """)

    parser.add_argument('-n', '--hostname', default=None, type=str, required=True,
                        help=' FQN of array to connect !! REQUIRED ARGUMENT !! DEFAULT: None')

    parser.add_argument('-u', '--username', default='admin', type=str, required=False,
                        help=' Username of given array, DEFAULT: admin')

    parser.add_argument('-p', '--password', default='admin', type=str, required=False,
                        help=' Password of given user, DEFAULT: admin')

    parser.add_argument('-l', '--log_level', default='WARNING', type=str, required=False,
                        help=' Stdout log level, DEFAULT: WARNING (options: DEBUG,INFO,WARNING,ERROR,CRITICAL)')

    parser.add_argument('-r', '--regex_csv', default=',', type=str, required=False,
                        help=' Flexible CSV regex, DEFAULT: ,')

    args = parser.parse_args()

    #
    # setting logger only if called direct.
    log.addHandler(log_handler.StreamHandler())
    log.setLevel(args.log_level.upper())

    obj = SetObj(hostname=args.hostname, username=args.username, password=args.password)


    def run_func(action=args.action):
        inst = getattr(obj, action)
        return inst(*args.regex_csv.split(','))


    pp(run_func())

# vol_prefix="nVol", vol_suffix="nap", vol_size="1", vol_count=1, vol_pool="default",
#                      vol_dedup="off", vol_perfpolicy="default", vol_initiatorgrp="nap-dummy"
#
#
#
#
# a = SetObj(hostname="sjc-array1016", username='admin', password='admin')
#
#
# #
# # pp(a.set_vol_create(vol_count=10, vol_suffix="srt", vol_prefix='sit', vol_size='200',
# # vol_initiatorgrp='a11-alpha2', vol_perfpolicy="", vol_pool="-"))
# # pp(a.set_snapcreate(snap_count=200, vol_regex='phy'))
# # time.sleep(15)
# # pp(a.set_voldelete(vol_regex='^nVol\|nap$'))
# # pp(a.set_snapdelete(vol_regex="^nVol\|nap$"))
# # while True:
#     #     pp(a.set_snap_create(vol_regex='srt'))
#     # pp(a.set_clone_create(vol_regex='srt', snap_regex=''))
#
#     # time.sleep(300)
#     #pp(a.set_volcoll_handover(volcoll_regex="-"))
#     #pp('sleep 300')
#     #time.sleep(300)
#     #pp(a.set_handover())
#     # pp(a.set_volcoll_remove(vol_regex=""))i
#     #pp('sleep 300')
#     #time.sleep(300)
#
#     # pp(a.set_failover(array_regex='sjc'))
#     # pp('sleep 1800')
#     # time.sleep(1800)
# pp(a.set_volcoll_add(vol_regex='sit', volcoll_regex="", sync_repl=True))
# # pp(a.set_volcoll_remove(vol_regex='sit0', delete_downstream=True))
# # pp(a.set_vol_move(vol_regex='nVol99', pool_regex=""))
# # pp(a.set_nsproc_flag(array_regex='', proc_state=''))
