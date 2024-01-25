def convert_string_to_hex(input_string):
    chunks = [input_string[i:i+2] for i in range(0, len(input_string), 2)]

    hex_chunks = [f"0x{chunk.upper()}" for chunk in chunks]

    formatted_output = ', '.join(hex_chunks)
    return formatted_output









vectors =[{
    "name": "aes-192",
    "key": "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "plain": "6bc1bee22e409f96e93d7e117393172a",
    "cipher": "1abc932417521ca24f2b0459fe7e6e0b",
    "iv": "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
},
{
    "name": "aes-256",
    "key": "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "plain": "6bc1bee22e409f96e93d7e117393172a",
    "cipher": "601ec313775789a5b7a7f504bbf3d228",
    "iv": "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
},
{
"name": "aes-192-eax",
"key": "ca2d0660cdb59d6cf4d62033dd218f767c2a57a53a0cb2fa",
"plain": "596f757220706c61696e746578742068657265",
"cipher": "f17e3bb7c7107119f3c5aa483712a11d87a992",
"iv": "997b4927457a3f4c9dfec0614f1ee0d7",
"tag": "e9cf8de264941101c455b182a6f16959"
},
{
    "name": "aes-192-eax #2",
    "key": "83ecb7d1b9eabd00afac068171ee2957184798382b02406b",
"plain": "48656c6c6f20576f726c64",
"cipher": "dd9d22154bdf63874cf3cd58066ed78b",
"iv": "ffeba48517c2c16c9e8f6e05d68fc3d7",
"tag": "0381200733df8b33f81b5759f5c45240"
}
]


for item in vectors:
    print(f"---------------------------- {item.get('name')} ----------------------------")
    for arg in item:
        if (arg != "name"):
            print(f"{arg}: {item.get(arg)}")
            print(convert_string_to_hex(item.get(arg)))
            print()
