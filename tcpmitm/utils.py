from threading import Lock, Thread
from queue import Queue


def add_all_args(parser, *args_makers):
    args_evaluators = []
    for make_args in args_makers:
        g = make_args(parser)
        next(g)
        args_evaluators.append(g)

    parsed_args = parser.parse_args()

    evaluated = [parsed_args]
    for eval_args in args_evaluators:
        try:
            evaluated.append(eval_args.send(parsed_args))
        except StopIteration as e:
            evaluated.append(e.value)

    return evaluated


class LockedValue:
    def __init__(self, v):
        self._lock = Lock()
        self._v = v

    def set(self, v):
        with self._lock:
            self._v = v

    def get(self):
        with self._lock:
            return self._v

    def __bool__(self):
        return bool(self.get())


def select_from_functions(*producers):
    combined = Queue()

    def listen_and_forward(src, produce):
        while True:
            try:
                item = produce()
            except Exception as e:
                item = e
            combined.put((src, item))

    for src, produce in producers:
        t = Thread(target=listen_and_forward, args=(src, produce))
        t.daemon = True
        t.start()

    while True:
        src, item = combined.get()
        combined.task_done()
        yield src, item
