#!/usr/bin/env python3

import mysql.connector

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="Oracle123!"
)

mycursor = mydb.cursor()

mycursor.execute("SHOW DATABASES")

for x in mycursor:
  print(x)