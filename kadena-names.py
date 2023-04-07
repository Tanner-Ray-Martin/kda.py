import requests

"""
Convert Name to Address
"""

name = "tanner.kda"

url = f"https://www.kadenanames.com/api/v1/address/{name}"

resp = requests.get(url)

target_address = resp.json()["address"]

"""
Convert Address to Name
"""

address = "k:72deb03afaf4573497d92ccb3c06d500c04b755c4e152eb0b92629686b55e155"

url = f"https://www.kadenanames.com/api/v1/name/{address}"

resp = requests.get(url)

target_name = resp.json()["name"]

print(target_address, target_name)
