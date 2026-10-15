#!/usr/bin/env python3
"""Open SGX EPC, drop all root privilege, then run an OS-free native trial.

This development launcher is not a production authentication service.
--unseal reads the original encrypted BIOS container into a sealed RAM FD.
--tls also uses the bounded Linux sensor transport to test a TLS handshake.
--capture additionally verifies one source image and logs only metadata.
No VM disk or network connection is used. All image data stays in RAM.
"""
import argparse
import ctypes
import os
from pathlib import Path
import resource
import pwd
import signal
import socket
import sys
import time

from fprint_protocol import error_metadata

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent


def drop_privileges():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(38, 1, 0, 0, 0):
        raise OSError(ctypes.get_errno(), 'PR_SET_NO_NEW_PRIVS')
    os.initgroups(pwd.getpwuid(1000).pw_name, 1000)
    os.setresgid(1000, 1000, 1000)
    os.setresuid(1000, 1000, 1000)
    runtime = {}
    for line in Path('/proc/self/status').read_text().splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            runtime[key] = value.strip()
    if any(runtime[k].split() != ['1000'] * 4 for k in ('Uid', 'Gid')):
        raise RuntimeError('Privilege drop failed')
    if any(int(runtime[k], 16) for k in ('CapPrm', 'CapEff', 'CapAmb')):
        raise RuntimeError('Capabilities remain after privilege drop')
    print('launcher_privileges_dropped=1 capabilities=0', flush=True)


def runner_arguments(epc_fd, sealed_fd, transport_fd=-1, capture=False):
    intel = PROJECT / 'sgx-vm/intel/Intel_SGX_DCAP_for_Windows/psw/WindowsServer2019_Windows10'
    args = [str(HERE / 'kvm_runner'), str(epc_fd), str(HERE / 'intel-le.plan'),
            str(intel / 'le_prod_css.bin'), str(HERE / 'goodix.plan'),
            str(PROJECT / 'windows-driver-1.1.151.18/extracted/source/sgx_white_list_cert.bin'),
            str(sealed_fd), str(transport_fd), str(int(capture))]
    return args


def reap_worker(pid, deadline):
    """Closing RPC stops the worker; its own 30-second alarm also bounds it.

    No signal capability is needed across the child's UID change. A child
    exceeding this extra grace period is a fatal backend error, allowing
    systemd's existing cgroup cleanup to run rather than leaving an orphan.
    """
    while True:
        exited, status = os.waitpid(pid, os.WNOHANG)
        if exited:
            return os.waitstatus_to_exitcode(status)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError('Native SGX worker exceeded its own deadline after RPC closure')
        time.sleep(min(remaining, 0.05))


def run_tls_trial(epc_fd, sealed_fd, capture=False, image_consumer=None,
                  report=None, worker_log_fd=None, runner_factory=None,
                  allow_sensor_identity=False):
    from transport_server import serve_transport
    sys.path.insert(0, str(PROJECT / 'sgx-vm'))
    from tls_bridge import TlsBridge

    if report is None:
        report = lambda message: print(message, flush=True)
    bridge = parent = child = None
    pid = -1
    worker_deadline = None
    result = 1
    try:
        if type(allow_sensor_identity) is not bool or (allow_sensor_identity and capture is not True):
            raise ValueError('Sensor identity requires the explicit baseline capture path')
        bridge_options = {'allow_capture': capture, 'image_consumer': image_consumer}
        if allow_sensor_identity:
            bridge_options['original_engine_baseline'] = True
        bridge = TlsBridge(report, **bridge_options)
        parent, child = socket.socketpair()
        child.set_inheritable(True)
        factory = runner_arguments if runner_factory is None else runner_factory
        args = factory(epc_fd, sealed_fd, child.fileno(), capture)
        pid = os.fork()
        if pid == 0:
            try:
                parent.close()
                if worker_log_fd is not None:
                    os.dup2(worker_log_fd, 1)
                    os.dup2(worker_log_fd, 2)
                drop_privileges()
                os.execve(args[0], args, {'PATH': '/usr/bin'})
            except BaseException:
                os._exit(1)
        worker_deadline = time.monotonic() + (125 if allow_sensor_identity else 35)
        child.close()
        os.close(epc_fd)
        epc_fd = -1
        os.close(sealed_fd)
        sealed_fd = -1
        transport_options = {'allow_capture': capture}
        if allow_sensor_identity:
            transport_options['allow_sensor_identity'] = True
        count = serve_transport(parent, bridge,
                                time.monotonic() + (120 if allow_sensor_identity else 45),
                                **transport_options)
        report('native_sensor_rpc_requests=' + str(count))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            exited, status = os.waitpid(pid, os.WNOHANG)
            if exited:
                result = os.waitstatus_to_exitcode(status)
                pid = -1
                break
            time.sleep(0.05)
    except BaseException as error:
        report(error_metadata(error, prefix='native_sgx_operation_error='))
        raise
    finally:
        if parent is not None:
            parent.close()
        if child is not None:
            child.close()
        try:
            if pid > 0:
                result = reap_worker(pid, worker_deadline)
                report('native_sgx_worker_exit=' + str(result) + ' aborted=1')
        finally:
            try:
                if bridge is not None:
                    bridge.close()
            finally:
                for fd in (epc_fd, sealed_fd):
                    if fd >= 0:
                        os.close(fd)
    report('native_sgx_worker_exit=' + str(result) + ' sensor_transport_closed=1')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unseal', action='store_true')
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--capture', action='store_true')
    options = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('PKEXEC_UID') != '1000':
        raise SystemExit('Start through pkexec as the UID1000 desktop owner for the root-only SGX device')
    for name, expected in (('sys_vendor', 'HUAWEI'), ('product_name', 'MACHC-WAX9')):
        if Path('/sys/class/dmi/id', name).read_text().strip() != expected:
            raise SystemExit('Unexpected computer')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    epc_fd = os.open('/dev/sgx_vepc', os.O_RDWR | os.O_CLOEXEC)
    os.set_inheritable(epc_fd, True)
    sealed_fd = -1
    if options.unseal or options.tls or options.capture:
        from sealed_input import create_sealed_input
        sealed_fd = create_sealed_input()
    if options.tls or options.capture:
        raise SystemExit(run_tls_trial(epc_fd, sealed_fd, capture=options.capture))
    args = runner_arguments(epc_fd, sealed_fd)
    drop_privileges()
    os.execve(args[0], args, {'PATH': '/usr/bin'})


if __name__ == '__main__':
    main()
