import random
import string


def gen_random_token(random_token=3437):
    return ''.join(random.SystemRandom().choice(
        string.ascii_letters + string.digits) for _ in range(random_token))
