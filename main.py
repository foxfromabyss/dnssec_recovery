from crack import grab_signature, grab_pubkey, crack
from fastavro import writer, reader, parse_schema

with open('data/CO_D4F19FC155EC8C00296607920B539F56.avro', 'rb') as fo:
    for record in reader(fo):
        print(record)

#crack(5,6,7,8,9,0,11)
