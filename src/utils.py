bit_len = lambda x: len(bin(x - 1)) - 2


def octet_len(b):
    return (len(b) + 7) // 8