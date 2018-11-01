import logging
import random
import itertools
import argparse
import time
import log_handler
from ArrayCM import ssh as ssh
from ArrayCM import GenericError
from ArrayGM import GetObj
from pprint import pprint as pp
# from collections import defaultdict

#
logging.LIST = 35  # between WARNING and ERROR
logging.addLevelName(logging.LIST, 'LIST')
log = logging.getLogger()
log.addHandler(log_handler.StreamHandler())
# log.addHandler(log_handler.FileHandler())
setattr(log, 'list', lambda message, *args: log._log(logging.LIST, message, args))
log.setLevel('INFO')


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
        initiator = [each.name for each in initiator_list if vol_initiatorgrp in each.name]
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
    def set_vol_delete(self, vol_regex=None):
        deleted_vols = []
        all_vols = GetObj.get_vollist(self, vol_regex=vol_regex)
        if all_vols:
            vol_list = [(each.name, each.path.split(':')[0]) for each in all_vols]
            # pp(vol_list)
        else:
            return None
        for vol, pool in vol_list:
            try:
                dissoc = ssh(hostname=self._hostname, username=self._username, password=self._password,
                             command="vol --dissoc %s --pool %s --force " % (vol, pool))
                offline = ssh(hostname=self._hostname, username=self._username, password=self._password,
                              command="vol --offline %s  --pool %s --force" % (vol, pool))
                if offline['error']:
                    log.error("%s >> vol offline %s - failed with error %s" % (self._hostname, vol, dissoc['error']))
                else:
                    log.info("%s >> vol offline %s - successful!" % (self._hostname, vol))
            except GenericError as e:
                log.error(e)
            else:
                delete = ssh(hostname=self._hostname, username=self._username, password=self._password,
                             command="vol --delete %s  --pool %s --force" % (vol, pool))
                if delete['error']:
                    log.error("%s >> DELETE: vol delete %s - failed with error: %s"
                              % (self._hostname, str(vol+':/'+pool), delete['error']))
                else:
                    log.info("%s >> DELETE: vol delete %s - successful!" % (self._hostname, str(vol+':/'+pool)))

                    deleted_vols.append(vol + ':/' + pool)

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
    #
    def set_volcoll_add(self, vol_regex=None, volcoll_regex=None):
        volcoll_list = GetObj.get_volcolllist(self, volcoll_regex=volcoll_regex)
        vol_list = GetObj.get_vollist(self, vol_regex=vol_regex)
        all_vols = list()  # all volumes with new volcoll added by this function

        if vol_list and volcoll_list:
            for vol in vol_list:
                vol_pool = vol.path.split(':')[0]
                volcolls = [vc for vc in volcoll_list if vc.replication_type == 'synchronous'
                            and vc.replication_partner != vol_pool
                            and vc.replication_partner != '']
                rand_volcoll = random.choice(volcolls)

                try:
                    out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                              command="vol --assoc %s --pool %s --volcoll %s "
                                      % (vol.name, vol_pool, rand_volcoll.volcoll_name))
                except GenericError as e:
                    log.error(e)

                else:
                    if out['error']:
                        log.error("%s >> ADD: volcoll add of %s on volcoll %s - failed with error: %s" %
                                  (self._hostname, str(vol.name+':/'+vol_pool), rand_volcoll.volcoll_name, out['error']))
                    else:
                        log.info("%s >> ADD: volcoll add of %s on volcoll %s - successful!"
                                 % (self._hostname, str(vol.name+':/'+vol_pool), rand_volcoll.volcoll_name))
                        all_vols.append(vol.name+':/'+vol_pool)

        return all_vols.append if len(all_vols) > 0 else []

    #
    #
    def set_volcoll_remove(self, vol_regex=None, *args):
        vol_list = GetObj.get_vollist(self, vol_regex=vol_regex)
        all_vols = list()

        if vol_list is None:
            return []  # return empty list
        for vol in vol_list:
            try:
                vol_pool = vol.path.split(':')[0]
                out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                          command="vol --dissoc %s --pool %s" % (vol.name, vol_pool))
            except GenericError as e:
                log.error(e)
            else:
                if out['error']:
                    log.error("%s >> REMOVE: volcoll remove of %s - failed with error: %s" %
                              (self._hostname, str(vol.name + ':/' + vol_pool), out['error']))
                else:
                    log.info("%s >> REMOVE: volcoll remove of %s - successful!" %
                             (self._hostname, str(vol.name + ':/' + vol_pool)))
                    all_vols.append(vol.name+':/'+vol_pool)

        return all_vols

    #
    #
    def set_volcoll_handover(self, volcoll_regex=None):
        volcoll_list = GetObj.get_volcolllist(self, volcoll_regex=volcoll_regex)
        volcoll_list = [vol for vol in volcoll_list if vol.replication_partner != '' and vol.upstream_vollist]
        all_handovervols = list()
        for volcoll in volcoll_list:
            try:
                out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                          command="volcoll --handover %s --partner %s"
                                  % (volcoll.volcoll_name, volcoll.replication_partner))
            except GenericError as e:
                log.error(e)
            else:
                if out['error']:
                    log.error("%s >> HANDOVER: volcoll %s handover to partner %s - failed with error: %s" %
                              (self._hostname, volcoll.volcoll_name, volcoll.replication_partner, out['error']))
                else:
                    log.info("%s >> HANDOVER: volcoll %s handover to partner %s - successful!"
                             % (self._hostname, volcoll.volcoll_name, volcoll.replication_partner))
                    all_handovervols.append(volcoll.upstream_vollist)
        return list(itertools.chain(*all_handovervols)) if len(all_handovervols) > 0 else []

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




# vol_prefix="nVol", vol_suffix="nap", vol_size="1", vol_count=1, vol_pool="default",
#                      vol_dedup="off", vol_perfpolicy="default", vol_initiatorgrp="nap-dummy"
#
#
#
#
a = SetObj(hostname="sjc-array1038", username='admin', password='admin')


#
# pp(a.set_volcreate(vol_count=20, vol_suffix="sync-repl", vol_prefix='test', vol_size='20',
# vol_initiatorgrp='system-tc58', vol_perfpolicy="",vol_pool="" ))
# pp(a.set_snapcreate(snap_count=200, vol_regex='test'))
# time.sleep(15)
# pp(a.set_snapdelete(vol_regex="^nVol\|nap$"))
# pp(a.set_voldelete(vol_regex='^nVol\|nap$'))
# while True:
#     pp(a.set_volcolladd(vol_regex='test', volcoll_regex=""))
#     pp(a.set_handover(volcoll_regex=""))
#     pp(a.set_volcollremove(vol_regex=""))
#     time.sleep(300)

pp(a.set_vol_move(vol_regex='nVol99', pool_regex=""))
# pp(a.set_snap_create(vol_regex='nVol98'))
# pp(a.set_clone_create(vol_regex='nVol98', snap_regex=''))
# pp(a.set_nsproc_flag(array_regex='', proc_state=''))