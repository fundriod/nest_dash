#!/usr/bin/env python3
import os
import paramiko
import logging
import requests
import socket
import argparse
import sys
import log_handler
from pprint import pprint as pp

log = logging.getLogger()
requests.packages.urllib3.disable_warnings()


class GenericError(Exception):
    def __init__(self, *args):
        # super().__init__(msg)
        self.args = args

    def __str__(self):
        # lof.error("host: {!r} exc: {!r} reason: {})".format(self.args[0], self.args[1], self.args[2]))
        return "GenericError(host: {!r} exc: {!r} reason: {})".format(self.args[0], self.args[1], self.args[2])


def ssh(hostname=None, command=None, username=None, password=None,):
    assert hostname and command and username and password, "ArrayCM.ssh requires valid args"

    _ssh = paramiko.SSHClient()
    _ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())

    if hostname:  # TODO check hostname validation
        try:
            log.debug('_cli_ SSHClient: {!r} SSH_stdin: {!r}'.format(hostname, command))
            _ssh.connect(hostname=hostname, username=username, password=password)
        except(TimeoutError, paramiko.ssh_exception.AuthenticationException, socket.error) as e:
            raise GenericError(hostname, command, e)
        else:
            std_in, std_out, std_err = _ssh.exec_command(command)
            std_in.flush()
            _output = std_out.readlines()
            stdret = std_err.readlines()
            out_info = None
            out_error = None
            out_unknown = None
            if stdret:
                if (stdret[0]).split(':')[0] == 'INFO':
                    out_info = stdret
                elif (stdret[0]).split(':')[0] == 'ERROR':
                    out_error = stdret
                else:
                    out_unknown = stdret

            log.debug('_cli_ SSHClient: {!r} SSH_stdout:\n{}'.format(hostname, ''.join(_output)))
            log.info("SSH:: {} with command: {} - executed successfully".format(hostname, command))
            return dict(host=hostname, data=_output, info=out_info, error=out_error, unknown=out_unknown)
        finally:
            _ssh.close()


def wip_ssh_pass(hostname=None, command=None, username=None, password=None,):
    _ssh = paramiko.SSHClient()
    _ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())

    if hostname:  # todo check hostname validation
        try:
            log.debug('_cli_ SSHClient: {!r} SSH_stdin: {!r}'.format(hostname, command))
            _ssh.connect(hostname=hostname, username=username, password=password)
        except(TimeoutError, paramiko.ssh_exception.AuthenticationException, socket.error) as e:
            raise GenericError(hostname, command, e)
        else:
            # to make it work with interactive ssh session
            stdin, stdout, stderr = _ssh.exec_command(command)
            stdin.flush()
            stdin.write("\n")
            stdin.write("date")
            stdin.flush()
            output = stdout.readlines()
            log.debug('_cli_ SSHClient: {!r} SSH_stdout:\n{}'.format(hostname, ''.join(output)))
            log.info("SSH_PASS:: {} with command: {} - executed successfully".format(hostname, command))
            return dict(host=hostname, data=output)


def rest(hostname=None, endpoint=None, username=None, password=None, action=None):
    assert hostname and endpoint and username and password, "ArrayCM.rest requires valid args"

    def request(url=None, headers=None, json=None, verify=False, verb=action):
        # pp(verb)
        if verb.upper() == 'GET':
            log.debug('_rest_get_ url: {!r} header: {!r} json: {!r}'.format(url, headers, json))
            # return requests.post(url, json=json, headers=headers, verify=verify)
            return requests.get(url, json=json, headers=headers, verify=verify)
        elif verb.upper() == 'POST':
            log.debug('_rest_post_ url: {!r} header: {!r} json: {!r}'.format(url, headers, json))
            # return requests.get(url, json=json, headers=headers, verify=verify)
            return requests.post(url, json=json, headers=headers, verify=verify)
        else:
            log.error('_rest_invalid url: {!r} json: {!r} - failed with no request verb'.format(url, json))
            return False

    def get_token():
        url = 'https://{}:5392/v1/tokens'.format(hostname)
        data = dict(data={"username": username, "password": password})
        try:
            # response = request(url=url, json=data)
            response = requests.post(url, json=data, verify=False)
        except (TimeoutError, requests.exceptions.ConnectionError) as e:
            raise GenericError(hostname, endpoint, e)
        else:
            token = (response.json()['data']['session_token'])
            log.debug('_rest_ url: {!r} json: {!r} token: {!r} - executed successfully.'.format(url, data, token))

            return token

    def end_point():
        url = "https://{}:5392/v1/{}".format(hostname, endpoint)
        header = {'X-Auth-Token': get_token()}
        log.debug('_rest_ url: {!r} endpoint: {!r}'.format(url, endpoint))
        response = request(url=url, headers=header, json={"operationType": "fetch"}, verb=action)
        # pp(response)
        if response.status_code == 200 or 202:
            log.info("REST:: {} with endpoint: {} - executed successfully".format(hostname, endpoint))
        return response.json()

    return end_point()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='ArrayCM', description='Connection method to connect an array (group leader)'
                                                                 ' using ssh or rest')

    parser.add_argument("action", choices=["ssh", "rest", "ssh_pass"], help="Action to be preformed")

    parser.add_argument('-n', '--hostname', default=None, type=str, required=True,
                        help=' FQN of array to connect !! REQUIRED ARGUMENT !! DEFAULT: None')

    parser.add_argument('-u', '--username', default='admin', type=str, required=False,
                        help=' Username of given array, DEFAULT: admin')

    parser.add_argument('-p', '--password', default='admin', type=str, required=False,
                        help=' Password of given user, DEFAULT: admin')

    parser.add_argument('-l', '--log_level', default='ERROR', type=str, required=False,
                        help=' Stdout log level, DEFAULT: ERROR (options: DEBUG,INFO,WARNING,ERROR,CRITICAL)')

    parser.add_argument('-c', '--command', default='version', type=str, required=False,
                        help=' SSH command to execute, DEFAULT: version')

    parser.add_argument('-e', '--endpoint', default='groups', type=str, required=False,
                        help=' REST endpoint to execute, DEFAULT: groups')
    parser.add_argument('-v', '--verb', default='GET', type=str, required=False,
                        help=' REST verb to execute (GET or POST), DEFAULT: GET')

    args = parser.parse_args()

    #
    # setting logger only if called direct.
    log.addHandler(log_handler.StreamHandler())
    log.setLevel(args.log_level.upper())

    if args.action == "ssh":
        try:
            output = ssh(hostname=args.hostname, command=args.command, username=args.username,
                         password=args.password)
        except GenericError as e:
            log.error(e)
        else:
            pp(output)
    elif args.action == "rest":
        try:
            output = rest(hostname=args.hostname, endpoint=args.endpoint, username=args.username,
                          password=args.password, action=args.verb)
        except GenericError as e:
            log.error(e)
        else:
            pp(output)

    if args.action == "ssh_pass":
        print('function implementation not completed.')
        sys.exit(0)
        # pp(ssh_pass(hostname=args.hostname, command=args.command, username=args.username,
        #           password=args.password))

