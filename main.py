from crack import grab_signature, grab_pubkey, crack
from fastavro import writer, reader, parse_schema
import json

file_name = 'data/CO_D4F19FC155EC8C00296607920B539F56.avro'
with open(file_name, 'rb') as fo:
    for record in reader(fo):
        # should group records together and then reprocess them?
        print(record)

#crack(5,6,7,8,9,0,11)
