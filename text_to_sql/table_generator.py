import pandas as pd
import numpy as np
import string
from pprint import pprint

ALPHABET = np.array(list(string.ascii_lowercase))
N_CHARS = 7


def generate_bools(n_samples):
    return np.random.choice(a=[False, True], size=n_samples)


def generate_ints(n_samples):
    return np.random.randint(0, 100, size=n_samples)


def generate_strings(n_samples):
    return [''.join(word).capitalize() for word in np.random.choice(ALPHABET, size=(n_samples, N_CHARS))]


def generate_table(table_name, n_samples, col_value_generators):
    pprint({col_name: col_value_generator(n_samples) for col_name, col_value_generator in col_value_generators.items()})
    df = pd.DataFrame({col_name: TYPE_TO_GENERATOR[col_value_type](n_samples)
                       for col_name, col_value_type in col_value_generators.items()})
    df.to_csv(f'out/{table_name}.csv', encoding='utf-8', sep='\t', index=False)


TYPE_TO_GENERATOR = {
    str: generate_strings,
    int: generate_ints,
    bool: generate_bools
}
if __name__ == "__main__":
    generate_table(table_name="employee",
                   n_samples=10,
                   col_value_generators={
                       "name": str,
                       "email": str,
                       "age": int,
                   })

    generate_table(table_name="user",
                   n_samples=10,
                   col_value_generators={
                       "id": str,
                       "name": str,
                       "email": str,
                       "age": int,
                       "manager": str
                   })

    generate_table(table_name="city",
                   n_samples=20,
                   col_value_generators={
                       "name": str,
                       "zipcode": int
                   })
