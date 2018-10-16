#!/usr/bin/env python3

import logging
import collections
import itertools
import argparse
import log_handler
from ArrayCM import ssh as ssh
from pprint import pprint as pp


log = logging.getLogger()


class GenericError(Exception):
    def __init__(self, *args):
        # super().__init__(msg)
        self.args = args

    def __str__(self):
        # lof.error("host: {!r} exc: {!r} reason: {})".format(self.args[0], self.args[1], self.args[2]))
        return "GenericError(host: {!r} exc: {!r} reason: {})".format(self.args[0], self.args[1], self.args[2])


class GetObj:

    def __init__(self, hostname, username, password):
        self._hostname = hostname
        self._username = username
        self._password = password

    #
    #
    def get_vollist(self, vol_regex=None, *args):

        try:
            out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                      command="vol --list | sed '1,/--+--/d'| grep -i '%s' | awk '{print $1, $2, $3, $5, $8}'"
                              % vol_regex)

        except GenericError as e:
            raise e

        else:
            volume = collections.namedtuple('vol', ['name', 'size', 'online', 'usage', 'path'])
            volume.__new__.__defaults__ = (None,)
            if out['data']:
                vollist = [volume(*item.split()) for item in out['data']]
                return vollist

        finally:
            log.info("test line to check logger")
            log.debug("ran successfully")

    #
    #
    def get_snaplist(self, vol_regex=None, snap_regex=None, *args):
        # print("vol_regex:%s" % vol_regex)
        # print("snap_regex:%s" % snap_regex)

        try:
            out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                      command="snap --list --all | sed '1,/--+--/d'| grep -i '%s' | "
                              "awk '{print $1, $2, $3, $4, $5, $7}'" % vol_regex)
        except GenericError as e:
            raise e

        else:
            snap = collections.namedtuple('snap', ['vol_name', 'snap_name', 'size', 'online', 'status', 'path'])
            snap.__new__.__defaults__ = (None,)
            if out['data']:
                snaplist = [snap(*item.split()) for item in out['data']]

                if snap_regex and snap_regex != '':
                    return list(filter(lambda each: snap_regex in each.snap_name, snaplist))

                else:
                    return snaplist

        finally:
            log.debug("ran successfully")

    #
    #
    def get_initiatorlist(self, client_regex=None, *args):

        try:
            out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                      command="initiatorgrp --list | sed '1,/--+--/d'| grep -i '%s' | awk '{print $1, $2, $3}'"
                              % client_regex)

        except GenericError as e:
            raise e

        else:
            initiator = collections.namedtuple('initiator', ['name', 'init_count', 'sub_count'])
            initiator.__new__.__defaults__ = (None,)
            if out['data']:
                initiatorlist = [initiator(*item.split()) for item in out['data']]
                return initiatorlist
        finally:

            log.debug("ran successfully")

    #
    #
    def get_poollist(self, pool_regex=None, *args):

        try:
            out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                      command="pool --list | sed '1,/--+--/d'| grep -i '%s' | awk '{print $1, $2, $3, $4 }'"
                              % pool_regex)
        except GenericError as e:
            raise e
        else:
            pool = collections.namedtuple('pool', ['pool_name', 'capacity', 'usage', 'array'])
            pool.__new__.__defaults__ = (None,)
            if out['data']:
                poollist = [pool(*item.split()) for item in out['data']]
                return poollist
        finally:

            log.debug("ran successfully")

    #
    #
    def get_volcolllist(self, volcoll_regex=None, *args):

        try:
            out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                      command="volcoll --list | sed '1,/--+--/d'| grep -i '%s' | awk '{print $1, $2, $3}'"
                              % volcoll_regex)
        except GenericError as e:
            raise e
        else:
            volcoll = collections.namedtuple('volcoll', ['volcoll_name', 'app_sync', 'owned_by'])
            volcoll.__new__.__defaults__ = (None,)
            if out['data']:
                volcolllist = [volcoll(*item.split()) for item in out['data']]
                return volcolllist
        finally:

            log.debug("ran successfully")

    #
    #
    def get_arraylist(self, array_regex=None, *args):
        try:
            out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                      command="array --list | sed '1,/--+--/d'| grep -i '%s' | awk '{print $1, $2, $3, $4, $5}'"
                              % array_regex)
        except GenericError as e:
            raise e
        else:
            array = collections.namedtuple('array', ['array_name', 'serial', 'model', 'version', 'status'])
            array.__new__.__defaults__ = (None,)
            if out['data']:
                arraylist = [array(*item.split()) for item in out['data']]
                return arraylist
        finally:
            log.debug("ran successfully")

    #
    #
    def get_disklist(self, array_regex=None, disk_regex=None, *args):
        disklist = []
        arrays = GetObj.get_arraylist(self, array_regex=array_regex)

        if arrays is None:
            log.error("get_arraylist: No valid array return with string: %s from host : %s" % (array_regex,
                      self._hostname))
            return None
        for array in arrays:
            try:
                out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                          command="disk --list --array %s | sed '1,/--+--/d' | grep -i '%s'"
                                  % (array.array_name, disk_regex))
            except GenericError as e:
                raise e
            else:
                disk = collections.namedtuple('disk', ['slot', 'serial', 'type', 'size', 'state', 'raid', 'shelf',
                                                       'location'])
                disk.__new__.__defaults__ = (None,)
                if out['data']:
                    disklist.append(list(disk(*item.replace('in use', 'in-use').split()) for item in
                                         out['data'] if "in use" in item))

        return list(itertools.chain(*disklist))

    #
    #
    def get_iplist(self, array_regex=None, *args):
        try:
            out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                      command="ip --list | grep eth | grep '%s'" % array_regex)
        except GenericError as e:
            raise e
        else:
            ip = collections.namedtuple('ip', ['ip', 'nic', 'status', 'type', 'array', 'controller'])
            ip.__new__.__defaults__ = (None,)
            if out['data']:
                iplist = [ip(*item.split()) for item in out['data']]
                return iplist

    #
    #
    def get_ctrlrlist(self, array_regex=None, *args):
        ctrlrlist = []
        arrays = GetObj.get_arraylist(self, array_regex=array_regex)
        if arrays is None:
            log.error("get_arraylist: No valid array return with string: %s from host : %s" %
                      (array_regex, self._hostname))
            return None
        for array in arrays:
            try:
                out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                          command="ctrlr --list --array '%s' | sed '1,/--+--/d'" % array.array_name)
            except GenericError as e:
                raise e
            else:
                ctrlr = collections.namedtuple('ctrlr', ['name', 'state', 'hostname', 'supp_ip', 'power_status',
                                                         'fan_status', 'temp_status'])
                ctrlr.__new__.__defaults__ = (None,)
                if out['data']:
                    ctrlrlist.append(list(ctrlr(*item.split()) for item in out['data']))
        return list(itertools.chain(*ctrlrlist))

    #
    #
    def get_groupinfo(self, field_arg=None, *args):
        try:
            out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                      command="group --info | grep -i '%s'" % field_arg)
        except GenericError as e:
                raise e
        else:
            group_dict = [(item.split(':')[0], item.strip().split(':')[1].strip()) for item in out['data']]
            return group_dict
        finally:
            log.debug("ran successfully")

    #
    #
    def get_perfpolicy(self, policy_arg=None, *args):
        try:
            out = ssh(hostname=self._hostname, username=self._username, password=self._password,
                      command="perfpolicy --list | sed '1,/--+--/d' | cut -d  ' ' -f 1-4 | grep -i '%s'" % policy_arg)
        except GenericError as e:
                raise e
        else:
            group_dict = [item.strip() for item in out['data']]
            return group_dict
        finally:
            log.debug("ran successfully")


if __name__ == "__main__":

    #
    # setting logger only if called direct.
    log.addHandler(log_handler.StreamHandler())
    log.addHandler(log_handler.FileHandler())
    log.setLevel('INFO')
    parser = argparse.ArgumentParser(prog='Array Get Module',
                                     description='OpMod to execute operation on (group leader) using ssh')

    parser.add_argument("action", choices=["get_vollist", "get_snaplist", "get_initiatorlist", "get_poollist",
                                           "get_volcolllist", "get_arraylist", "get_arraylist", "get_disklist",
                                           "get_iplist", "get_ctrlrlist", "get_groupinfo", "get_perfpolicy"],
                        help="""
                        get_vollist --regex_csv vol_regex,
                        get_snaplist --regex_csv vol_regex,snap_regex,
                        get_initiatorlist --regex_csv client_regex,
                        get_poollist --regex_csv pool_regex,
                        get_volcolllist --regex_csv volcoll_regex,
                        get_arraylist --regex_csv array_regex,
                        get_disklist --regex_csv array_regex, disk_regex,
                        get_iplist --regex_csv array_regex,
                        get_ctrlrlist --regex_csv array_regex,
                        get_groupinfo --regex_csv field_arg
                        get_perfpolicy --regex_csv policy_arg
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
                        help=' SSH command to execute, DEFAULT: ,')

    args = parser.parse_args()
    log.setLevel(args.log_level.upper())
    obj = GetObj(hostname=args.hostname, username=args.username, password=args.password)

    def run_func(action=args.action):
        inst = getattr(obj, action)
        return inst(*args.regex_csv.split(','))
    pp(run_func())


