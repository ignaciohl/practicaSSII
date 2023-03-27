from flask import Flask
from flask import render_template
from flask import request
import sqlite3
import json
import plotly.graph_objects as go
import pandas as pd



#crear la bd (tablas)
con= sqlite3.connect('practica.db')

#leer datos proporcionados
df_alertas= pd.read_csv('alerts.csv')
d= open("devices.json")
dispositivos= json.load(d)


cur=con.cursor()



cur.execute("CREATE TABLE IF NOT EXISTS responsable(nombre TEXT PRIMARY_KEY, telefono TEXT, rol TEXT)")
cur.execute("CREATE TABLE IF NOT EXISTS analisis(id INTEGER PRIMARY_KEY, puertos_abiertos TEXT, numPuertosAbiertos INTEGER, servicios INTEGER, servicios_inseguros INTEGER, vulnerabilidades_detectadas INTEGER)")
cur.execute("CREATE TABLE IF NOT EXISTS devices(id TEXT, ip TEXT, localizacion TEXT,responsable_id TEXT, analisis_id INTEGER, FOREIGN KEY(responsable_id) REFERENCES responsable(nombre), FOREIGN KEY(analisis_id) REFERENCES analisis(id))")
cur.execute("CREATE TABLE IF NOT EXISTS alerts(timestamp TEXT, sid INTEGER, msg TEXT,clasificacion TEXT, prioridad INTEGER, protocolo TEXT, origen INTEGER, destino INTEGER, puerto INTEGER  )")


'''
## datos tabla responsable
cur.execute("INSERT INTO responsable VALUES ('admin', '656445552','Administracion de sistemas')")
cur.execute("INSERT INTO responsable VALUES ('Paco Garcia', '640220120','Direccion')")
cur.execute("INSERT INTO responsable VALUES ('Luis Sanchez', 'None','Desarrollador')")
cur.execute("INSERT INTO responsable VALUES ('admin', '656445552','Administracion de sistemas')")
cur.execute("INSERT INTO responsable VALUES ('admiin', 'None','None')")
cur.execute("INSERT INTO responsable VALUES ('admin', '656445552','Administracion de sistemas')")
cur.execute("INSERT INTO responsable VALUES ('admin','656445552','Administracion de sistemas')")

# datos tabla analisis
cur.execute("INSERT INTO analisis VALUES(1, '80/TCP, 443/TCP, 3306/TCP, 40000/UDP', 4, 3, 0, 15)")
cur.execute("INSERT INTO analisis VALUES(2, 'None', 0, 0, 0, 4)")
cur.execute("INSERT INTO analisis VALUES(3, '1194/UDP, 8080/TCP,8080/UDP, 40000/UDP',4, 1, 1, 52)")
cur.execute("INSERT INTO analisis VALUES(4, '443/UDP, 80/TCP',2, 1, 0,3)")
cur.execute("INSERT INTO analisis VALUES(5, '80/TCP, 67/UDP, 68/UDP', 3, 2, 2, 12)")
cur.execute("INSERT INTO analisis VALUES(6, '8080/TCP, 3306/TCP, 3306/UDP', 3,2, 0, 2)")
cur.execute("INSERT INTO analisis VALUES(7, '80/TCP, 443/TCP, 9200/TCP, 9300/TCP, 5601/TCP', 5,3, 2, 21)")

# datos tabla devices
cur.execute("INSERT INTO devices VALUES('web', '172.18.0.0', 'None','admin', 1)")
cur.execute("INSERT INTO devices VALUES('paco_pc', '172.17.0.0', 'Barcelona','Paco Garcia', 2)")
cur.execute("INSERT INTO devices VALUES('luis_pc', '172.19.0.0', 'Madrid','Luis Sanchez', 3)")
cur.execute("INSERT INTO devices VALUES('router1', '172.1.0.0', 'None','admin', 4)")
cur.execute("INSERT INTO devices VALUES('dhcp_server', '172.1.0.1', 'Madrid','admiin', 5)")
cur.execute("INSERT INTO devices VALUES('mysql_db', '172.18.0.1', 'None','admin', 6)")
cur.execute("INSERT INTO devices VALUES('ELK', '172.18.0.2', 'None','admin', 7)")
'''


con.commit()



#EJERCICIO 2 - Consultas
df_dispositivos = pd.read_sql_query("SELECT * from devices", con)
df_analisis=pd.read_sql_query("SELECT * FROM analisis",con)
numDispositivos = df_dispositivos['id'].nunique()
print("Número de dispositivos: " +str(numDispositivos))
## hasta aquí bien, numDispositivos 7


numAlertas= len(df_alertas)
print("Número de alertas: " + str(numAlertas))
# numAlertas = 200225


mediaPuertos=df_analisis['numPuertosAbiertos'].mean()
desvPuertos=df_analisis['numPuertosAbiertos'].std()
print("Media de puertos: " + str(mediaPuertos))
print("Desviacion estándar: " + str(desvPuertos))
# media puertos: 3.0
# desv estándar puertos abiertos: 1.632993161855452



mediaServiciosInseguros=df_analisis['servicios_inseguros'].mean()
desvServiciosInseguros=df_analisis['servicios_inseguros'].std()
print("Media servicios inseguros detectados: " + str(mediaServiciosInseguros))
print("Desviacion estandar número de servicios inseguros detectados" + str(desvServiciosInseguros))

#Media servicios inseguros detectados: 0.7142857142857143
#Desviacion estandar número de servicios inseguros detectados0.9511897312113418


mediaVulner=df_analisis['vulnerabilidades_detectadas'].mean()
desvVulner=df_analisis['vulnerabilidades_detectadas'].std()
print("Media vulnerabilidades detectadas: " + str(mediaVulner))
print("Desviacion estandar del número de vulnerabilidades detectadas: " + str(desvVulner))
#Media vulnerabilidades detectadas: 15.571428571428571
#Desviacion estandar del número de vulnerabilidades detectadas: 17.539072028446878

minPuertos=df_analisis['numPuertosAbiertos'].min()
maxPuertos=df_analisis['numPuertosAbiertos'].max()
print("Valor mínimo del total de puertos abiertos: " + str(minPuertos))
print("Valor máximo del total de puertos abiertos: " + str(maxPuertos))
# Valor mínimo del total de puertos abiertos: 0
# Valor máximo del total de puertos abiertos: 5

minVulner=df_analisis['vulnerabilidades_detectadas'].min()
maxVulner=df_analisis['vulnerabilidades_detectadas'].max()
print("Valor mínimo del numero de vulnerabilidades detectadas: " + str(minVulner))
print("Valor máximo del numero de vulnerabilidades detectadas: " + str(maxVulner))
#Valor mínimo del numero de vulnerabilidades detectadas: 2
#Valor máximo del numero de vulnerabilidades detectadas: 52



