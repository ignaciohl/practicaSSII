from flask import Flask
from flask import render_template
from flask import request
import sqlite3
import json
import plotly.graph_objects as go
import pandas as pd



#crear la bd (tablas)
con= sqlite3.connect()
cur=con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS devices(id TEXT, ip TEXT, localizacion TEXT,responsable_id TEXT, analisis_id TEXT)")
cur.execute("CREATE TABLE IF NOT EXISTS alerts(timestamp TEXT, sid INTEGER, msg TEXT,clasificacion TEXT, prioridad INTEGER, protocolo TEXT, origen INTEGER, destino INTEGER, puerto INTEGER  )")

#leer datos proporcionados
alertas= pd.read_csv('alerts.csv')
d= open("devices.json")
dispositivos= json.load(d)

con.commit()

#EJERCICIO 2 - Consultas
numDispositivos = df_devices['id'].nunique()
