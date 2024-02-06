import requests

url = "http://192.168.178.180/getdata"

try:
    response = requests.get(url)
    if response.status_code == 200:
        data = response.text
        print("Data retrieved successfully")
    else:
        print("Failed to retrieve data.")
except requests.exceptions.RequestException as e:
    print(f"Error connecting to the server: {e}")



parts = data.split("AES-")
parts = ["AES-" + part for part in parts[1:]]


def write_encryption_nums(input):
    encrpytion_nums = [x.strip().replace("e", "") for x in input.split(" ") if "e" in x]
    with open("output.csv", "a") as fl:
        fl.write(f"{input.split(" ")[0]}-Encrpytion,")
        fl.write(",".join(encrpytion_nums))
        fl.write("\n")

def write_decryption_nums(input):
    decrpytion_nums = [x.strip().replace("d", "") for x in input.split(" ") if "d" in x]
    with open("output.csv", "a") as fl:
        fl.write(f"{input.split(" ")[0]}-Decrpytion,")
        fl.write(",".join(decrpytion_nums))
        fl.write("\n")


def write_csv(input):
    with open("output.csv", "w") as fl:
        fl.write("Method,")
        for i in range(1,101):
            if(i == 100):
                fl.write(f"{i}")
            else:
                fl.write(f"{i},")
        fl.write("\n")
    for part in input:
        write_encryption_nums(part)
        write_decryption_nums(part)

write_csv(parts)




