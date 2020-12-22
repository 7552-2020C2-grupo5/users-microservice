import random
import string


def generate_random_password(length):
    s = string.ascii_lowercase + string.digits
    return ''.join(random.choice(s) for i in range(length))
