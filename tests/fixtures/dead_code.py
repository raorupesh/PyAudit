def used_function():
    return 42


def unused_function():
    return "nobody calls me"


class Foo:
    def used_method(self):
        return 1

    def unused_method(self):
        return 2


unused_variable = "dead"

print(used_function())
Foo().used_method()
