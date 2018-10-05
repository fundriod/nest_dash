import os
import paramiko
import logging
import requests
import socket


log = logging.getLogger()
requests.packages.urllib3.disable_warnings()


class GenericError(Exception):
    def __init__(self, *args):
        # super().__init__(msg)
        self.args = args

    def __str__(self):
        return "GenericError(host: {!r} exc: {!r} reason: {})".format(self.args[0], self.args[1], self.args[2])


def ssh(hostname=None, command="array --list", username="root", password="admin",):
    _ssh = paramiko.SSHClient()
    _ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())

    if hostname:  # todo check hostname
        try:
            log.debug('_cli_ SSHClient: {!r} SSH_stdin: {!r}'.format(hostname, command))
            _ssh.connect(hostname=hostname, username=username, password=password)
        except(TimeoutError, paramiko.ssh_exception.AuthenticationException, socket.error) as e:
            raise GenericError(hostname, command, e)
        else:
            std_in, std_out, std_err = _ssh.exec_command(command)
            std_in.flush()
            output = std_out.readlines()
            log.debug('_cli_ SSHClient: {!r} SSH_stdout:\n{}'.format(hostname, ''.join(output)))
            log.info("SSH: {} with command: {} - executed successfully".format(hostname, command))
            return dict(host=hostname, data=output)


def rest(hostname=None, endpoint=None, username="admin", password="admin"):

    def request(url=None, headers=None, json=None, verify=False):
        if headers is not None:
            log.debug('_rest_ url: {!r} header: {!r} json: {!r}'.format(url, headers, json))
            # return requests.post(url, json=json, headers=headers, verify=verify)
            return requests.get(url, json=json, headers=headers, verify=verify)
        else:
            log.debug('_rest_ url: {!r} json: {!r}'.format(url, json))
            return requests.post(url, json=json, verify=verify)

    def get_token():
        url = 'https://{}:5392/v1/tokens'.format(hostname)
        json = dict(data={"username": username, "password": password})
        try:
            response = request(url=url, json=json)
        except requests.exceptions.ConnectionError as e:
            raise GenericError(hostname, endpoint, e)
        else:
            token = (response.json()['data']['session_token'])
            return token

    def end_point():
        # url = "https://{}:5392/v1/{}".format(hostname, endpoint)
        url = "https://{}:5392/v1/{}".format(hostname, endpoint)
        header = {'X-Auth-Token': get_token()}
        log.debug('_rest_ url: {!r} endpoint: {!r}'.format(url, endpoint))
        response = request(url=url, headers=header, json={"operationType": "fetch"})
        #requests.post(url, json={"operationType": "fetch"}, headers=head, verify=False)
        if response.status_code == 200:
            log.info("REST: {} with endpoint: {} - executed successfully".format(hostname, endpoint))
        return response.json()

    return end_point()