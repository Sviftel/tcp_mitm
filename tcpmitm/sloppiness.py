from functools import partial
from time import sleep


def check_and_break(pkt, breaker):
    if breaker is None or not breaker.time_to_mess_up(pkt):
        return pkt
    return breaker.mess_up(pkt)


class FinDelayer:
    """adds a delay if got FIN packet"""
    def __init__(self, sleep_duration):
        self._flag = "delay_fins"
        self._dur = sleep_duration

    def time_to_mess_up(self, pkt):
        return pkt["TCP"].flags & 0x01

    def mess_up(self, pkt):
        sleep(self._dur)
        return pkt


def make_sloppy_args(parser):
    group = parser.add_mutually_exclusive_group()
    breakers = [FinDelayer(0.3)]

    for breaker in breakers:
        group.add_argument("--" + breaker._flag,
                           action="store_true",
                           default=False,
                           help=breaker.__doc__)

    parsed_args = yield

    dict_args = vars(parsed_args)
    for breaker in breakers:
        if dict_args[breaker._flag]:
            return partial(check_and_break, breaker=breaker)

    return partial(check_and_break, breaker=None)
