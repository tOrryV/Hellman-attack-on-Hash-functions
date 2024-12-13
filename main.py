import random
import hashlib
from concurrent.futures import ThreadPoolExecutor


def R(x, r):
    return x + r


def get_sha512(byts):
    return hashlib.sha512(byts).digest()


def generate_bits(bits):
    return random.randbytes(bits // 8)


def gen_pre_table(K, L, padding, n, n_bytes, r=None):
    if r is None:
        r = generate_bits(padding)
    X = {}

    for _ in range(K):
        x0 = generate_bits(n)
        key = x0
        for _ in range(L):
            key = get_sha512(R(key, r))[-n_bytes:]
        X[key] = x0

    return [X, r]


def gen_pre_tables_parallel(K, L, padding, n, n_bytes):
    r = generate_bits(padding)
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(
            lambda _: gen_pre_table(K, L, padding, n, n_bytes, r), range(K)
        ))
    return results


def find_preimage(L, table, hash_val, n_bytes):
    y = hash_val
    r = table[1]

    found = -1
    for j in range(L):
        if y in table[0]:
            found = j
            break

        y = get_sha512(R(y, r))[-n_bytes:]

    if found != -1:
        x = table[0][y]
        for _ in range(L - found - 1):
            x = get_sha512(R(x, r))[-n_bytes:]
        return R(x, r)

    return None


def find_preimage_parallel(L, tables, hash_val, n_bytes):
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(
            lambda table: find_preimage(L, table, hash_val, n_bytes),
            tables
        ))
    return [result for result in results]


def attack_1_once(K, L, padding, n, n_bytes):
    value_for_hash = generate_bits(256)
    hash_value = get_sha512(value_for_hash)
    table = gen_pre_table(K, L, padding, n, n_bytes)
    preimage = find_preimage(L, table, hash_value[-n_bytes:], n_bytes)

    print(f'Generated vector: {value_for_hash.hex()}')
    if preimage:
        preimage_hash = get_sha512(preimage)
        print(f"Original hash value: {hash_value[:-n_bytes].hex()} {hash_value[-n_bytes:].hex()}\n"
              f"Preimage: {preimage.hex()}\n"
              f"Preimage hash: {preimage_hash[:-n_bytes].hex()} {preimage_hash[-n_bytes:].hex()}")

        if preimage_hash[-n_bytes:] == hash_value[-n_bytes:]:
            print("Preimage successfully found!")
        else:
            print("Preimage not found!")
    else:
        print("Preimage not found!")


def attack_1_multy(N, K, L, padding, n, n_bytes):
    result = {}
    for k in K:
        for l in L:
            table = gen_pre_table(k, l, padding, n, n_bytes)
            success = 0
            not_found = 0
            for _ in range(N):
                value_for_hash = generate_bits(256)
                hash_value = get_sha512(value_for_hash)
                preimage = find_preimage(l, table, hash_value[-n_bytes:], n_bytes)

                if preimage:
                    preimage_hash = get_sha512(preimage)

                    if preimage_hash[-n_bytes:] == hash_value[-n_bytes:]:
                        success += 1
                    else:
                        not_found += 1
                else:
                    not_found += 1
            result[(k, l)] = (success, not_found)

    return result


def attack_2_once(K, L, padding, n, n_bytes):
    value_for_hash = generate_bits(256)
    hash_value = get_sha512(value_for_hash)
    tables = gen_pre_tables_parallel(K, L, padding, n, n_bytes)
    preimages = find_preimage_parallel(L, tables, hash_value[-n_bytes:], n_bytes)

    print(f'Generated vector: {value_for_hash.hex()}')

    if not preimages:
        print("No valid preimage found in all tables!")
        return False

    for preimage in preimages:
        if preimage:
            preimage_hash = get_sha512(preimage)
            if preimage_hash[-n_bytes:] == hash_value[-n_bytes:]:
                print(f"Original hash value: {hash_value[:-n_bytes].hex()} {hash_value[-n_bytes:].hex()}\n"
                      f"Preimage: {preimage.hex()}\n"
                      f"Preimage hash: {preimage_hash[:-n_bytes].hex()} {preimage_hash[-n_bytes:].hex()}\n"
                      f"Preimage successfully found!")
                return True

    print("Preimage not found!")


def attack_2_multy(N, K, L, padding, n, n_bytes):
    result = {}
    for k in K:
        for l in L:
            tables = gen_pre_tables_parallel(k, l, padding, n, n_bytes)
            success = 0
            not_found = 0
            for _ in range(N):
                value_for_hash = generate_bits(256)
                hash_value = get_sha512(value_for_hash)
                preimages = find_preimage_parallel(l, tables, hash_value[-n_bytes:], n_bytes)
                not_found += 1
                for preimage in preimages:
                    if preimage:
                        preimage_hash = get_sha512(preimage)

                        if preimage_hash[-n_bytes:] == hash_value[-n_bytes:]:
                            success += 1
                            not_found -= 1
                            break
            result[(k, l)] = (success, not_found)

    return result


def main():
    N = 10000
    # n = 16
    n = 32
    n_bytes = n // 8

    # K = [2**10, 2**12, 2**14]
    # L = [2**5, 2**6, 2**7]
    K = [2 ** 20, 2 ** 22, 2 ** 24]
    L = [2 ** 10, 2 ** 12, 2 ** 14]

    padding = 128 - n

    attack = int(input(f'Choose attack:\n\t1. Attack 1 once\n\t2. Attack 1 multy\n\t'
                       f'3. Attack 2 once\n\t4. Attack 2 multy\n'))

    match attack:
        case 1:
            attack_1_once(K[0], L[0], padding, n, n_bytes)
        case 2:
            stats = attack_1_multy(N, K, L, padding, n, n_bytes)
            for key, value in stats.items():
                percent_of_succ = round(value[0] / N * 100, 2)
                percent_of_fail = round(100 - percent_of_succ, 2)
                print(f'K: {key[0]}, L: {key[1]} => success: {value[0]}, fail: {value[1]}, Percent of success found '
                      f'preimage: {percent_of_succ}%, Percent of not found preimage: {percent_of_fail}%')
        case 3:
            attack_2_once(K[0], L[0], padding, n, n_bytes)
        case 4:
            stats = attack_2_multy(N, K, L, padding, n, n_bytes)
            for key, value in stats.items():
                percent_of_succ = round(value[0] / N * 100, 2)
                percent_of_fail = round(100 - percent_of_succ, 2)
                print(f'K: {key[0]}, L: {key[1]} => success: {value[0]}, fail: {value[1]}, Percent of success found '
                      f'preimage: {percent_of_succ}%, Percent of not found preimage: {percent_of_fail}%')
        case _:
            exit(f'Invalid input')


if __name__ == '__main__':
    main()
