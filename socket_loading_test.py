#!/usr/bin/python3


from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from os import urandom
from tcpmitm.connector import Connector, make_connector_args, simple_packet_forwarding
from tcpmitm.sloppiness import make_sloppy_args
from tcpmitm.utils import add_all_args
from threading import Condition


class DataManager:
    def __init__(self, array_size, n_times):
        self._array_size = array_size
        self._n_times = n_times
        self._gen_array = lambda: bytearray(urandom(self._array_size))

        self._checked_bytes, self._checked_blocks, self._check_failed = 0, 0, None
        self._array_cond, self._array = Condition(), None

    def __enter__(self):
        self._executor = ThreadPoolExecutor(max_workers=self._n_times)
        if self._n_times:
            print("Generating block...")
            self._future = self._executor.submit(self._gen_array)
        return self

    def __exit__(self, *exc_info):
        self._executor.shutdown()

    def data_to_send(self):

        # with ThreadPoolExecutor(max_workers=self._n_times) as e:
        #     array_generators = as_completed(
        #         e.submit(lambda: bytearray(urandom(self._array_size)))
        #         for _ in range(self._n_times)
        #     )

        for i in range(self._n_times):
            with self._array_cond:
                while self._array and not self._check_failed:
                    self._array_cond.wait()

                if self._check_failed:
                    raise self._check_failed

                # self._array = next(array_generators).result()
                self._array = self._future.result()
                self._future = self._executor.submit(self._gen_array) \
                    if i + 1 < self._n_times else None
                self._array_cond.notify()
            yield self._array

    def report(self, chunk):
        with self._array_cond:
            while not self._array:
                self._array_cond.wait()

            st, end = self._checked_bytes, self._checked_bytes + len(chunk)
            try:
                assert end <= self._array_size, "reported message is too long"
                assert_msg = "checking bytes [{}: {}] failed".format(st, end)
                assert chunk == self._array[st: end], assert_msg
            except AssertionError as e:
                self._check_failed = e
                self._array_cond.notify()
                raise e

            self._checked_bytes += len(chunk)
            block, percent = self._checked_blocks, 100 * self._checked_bytes / self._array_size
            if self._checked_bytes == self._array_size:
                self._checked_blocks += 1
                self._checked_bytes = 0
                self._array = None
                self._array_cond.notify()

                if self._checked_blocks == self._n_times:
                    return block, percent, "All completed!"
            return block, percent


def server_routine(server_conn, data_manager):
    prev_block_num = 0
    with server_conn as conn:
        while True:
            data = conn.recv(65000)
            if not data:
                continue

            block_num, progress_percent, *completed = data_manager.report(data)
            progress_percent = int(progress_percent // 1)

            if prev_block_num < block_num:
                print("")
                prev_block_num = block_num
            report_msg = " " * 50 + "\r" + "Check progress: block #{}, {}%\r"
            print(report_msg.format(block_num + 1, progress_percent), end="")

            if completed:
                print("\nEverything've been asserted!")
                break


def client_routine(client_conn, data_manager):
    with client_conn as conn:
        for data in data_manager.data_to_send():
            conn.send(data)


if __name__ == "__main__":
    desc = "Module tests tcp mitm's work on high loads"
    parser = ArgumentParser(description=desc)
    args, _, check_and_break = add_all_args(parser,
                                            make_connector_args,
                                            make_sloppy_args)

    server_port, middle_port = args.server_port, args.middle_port

    with DataManager(array_size=200000000, n_times=10) as data_manager:
        connector = Connector(server_port, middle_port)
        connector.connect(
            partial(server_routine,
                    server_conn=connector.server,
                    data_manager=data_manager),
            partial(simple_packet_forwarding,
                    mitm=connector.mitm,
                    processing=check_and_break),
            partial(client_routine,
                    client_conn=connector.client,
                    data_manager=data_manager)
        )
