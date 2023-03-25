from flask import Flask
from flask import render_template
from flask import request
import sqlite3
import json
import plotly.graph_objects as go
import pandas as pd



#crear la bd (tablas)
con= sqlite3.connect('')

#leer datos proporcionados
alertas= pd.read_csv('alerts.csv')
d= open("devices.json")
dispositivos= json.load(d)


cur=con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS devices(id TEXT, ip TEXT, localizacion TEXT,responsable_id TEXT, analisis_id TEXT)")
cur.execute("CREATE TABLE IF NOT EXISTS alerts(timestamp TEXT, sid INTEGER, msg TEXT,clasificacion TEXT, prioridad INTEGER, protocolo TEXT, origen INTEGER, destino INTEGER, puerto INTEGER  )")
cur.execute("CREATE TABLE IF NOT EXISTS responsable(nombre TEXT PRIMARY_KEY, telefono TEXT, rol TEXT)")
cur.execute("CREATE TABLE IF NOT EXISTS analisis(id INTEGER PRIMARY_KEY, puertos_abiertos TEXT, servicios INTEGER, servicios_inseguros INTEGER, vulnerabilidades_detectadas INTEGER)")

cur.execute("INSERT INTO responsable VALUES ('admin', '656445552','Administracion de sistemas')")
cur.execute("INSERT INTO responsable VALUES ('Paco Garcia', '640220120','Direccion')")
cur.execute("INSERT INTO responsable VALUES ('Luis Sanchez', 'None','Desarrollador')")
cur.execute("INSERT INTO responsable VALUES ('admin', '656445552','Administracion de sistemas')")
cur.execute("INSERT INTO responsable VALUES ('admiin', 'None','None')")
cur.execute("INSERT INTO responsable VALUES ('admin', '656445552','Administracion de sistemas')")
cur.execute("INSERT INTO responsable VALUES ('admin','656445552','Administracion de sistemas')")



con.commit()





#EJERCICIO 2 - Consultas
df_dispositivos = pd.read_sql_query("SELECT * from devices", con)

numDispositivos = df_dispositivos['id'].nunique()
print(numDispositivos)