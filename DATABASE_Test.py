import pymongo
from Crypto.Hash import SHA256

username = "A_username"
password = 'A_password'
byte_password = bytes(password, 'utf-8')
hash_password = SHA256.new(data=byte_password).hexdigest()

client = pymongo.MongoClient('mongodb+srv://SeChatUsername:SeChatLover%23123@cbs-01.1swurq8.mongodb.net/')

dblist = client.list_database_names()
if "SeChat" in dblist:
    print("The database exists.")

SeChat = client['SeChat']
UserData = SeChat["UserData"]
myquery = { "user_username": { "$eq": username },"user_password": { "$eq": hash_password } }

user1_data = UserData.find(myquery)
for x in user1_data:
  print(x)