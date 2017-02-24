
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
