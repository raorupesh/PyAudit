import subprocess


def run_command(user_input):
    subprocess.call(user_input, shell=True)


def evaluate(expr):
    return eval(expr)


PASSWORD = "hardcoded-secret-123"
