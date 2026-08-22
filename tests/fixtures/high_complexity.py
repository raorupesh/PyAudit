def classify(value, a, b, c, d, e, f, g, h, i, j):
    if value == a:
        return "a"
    elif value == b:
        return "b"
    elif value == c:
        return "c"
    elif value == d:
        return "d"
    elif value == e:
        return "e"
    elif value == f:
        return "f"
    elif value == g:
        return "g"
    elif value == h:
        return "h"
    elif value == i:
        return "i"
    elif value == j:
        return "j"
    elif value < 0:
        return "negative"
    else:
        return "unknown"


def simple(x):
    return x + 1
