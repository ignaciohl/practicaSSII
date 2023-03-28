from flask import Flask
from flask import render_template
from flask import request
import sqlite3
import json
#import plotly.graph_objects as go
#import matplotlib.pyplot as plt
import pandas as pd
#import statistics



#crear la bd (tablas)
con= sqlite3.connect('practica.db')

#leer datos proporcionados
df_alertas= pd.read_csv('alerts.csv')
d= open("devices.json")
dispositivos= json.load(d)


cur=con.cursor()



cur.execute("CREATE TABLE IF NOT EXISTS responsable(nombre TEXT PRIMARY_KEY, telefono TEXT, rol TEXT)")
cur.execute("CREATE TABLE IF NOT EXISTS analisis(id TEXT PRIMARY_KEY, puertos_abiertos TEXT, numPuertosAbiertos TEXT, servicios TEXT, servicios_inseguros TEXT, vulnerabilidades_detectadas INTEGER)")
cur.execute("CREATE TABLE IF NOT EXISTS devices(id TEXT, ip TEXT, localizacion TEXT,responsable_id TEXT, analisis_id TEXT, FOREIGN KEY(responsable_id) REFERENCES responsable(nombre), FOREIGN KEY(analisis_id) REFERENCES analisis(id))")
cur.execute("CREATE TABLE IF NOT EXISTS alerts(timestamp TEXT, sid TEXT, msg TEXT,clasificacion TEXT, prioridad TEXT, protocolo TEXT, origen TEXT, destino TEXT, puerto TEXT  )")

#datos tabla alerts
df_alertas.to_sql('alerts',con,if_exists='replace',index=False)

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


'''
#Ejercicio 3
df_tabla3=pd.read_sql_query("SELECT * FROM alerts JOIN devices ON (alerts.origen = devices.ip) JOIN analisis ON devices.analisis_id = analisis.id", con)
for i in range(1,4):
    prioridad=df_tabla3.loc[df_tabla3['prioridad']==i]
    print("Numero de observaciones:", str(len(prioridad)))
    print("Numero de valores ausentes:", str(len(prioridad.loc[prioridad['localizacion']=='None'])))
    print("Mediana:", prioridad['vulnerabilidades_detectadas'].median())
    print("Media:",prioridad['vulnerabilidades_detectadas'].mean())
    print("Varianza:", prioridad['vulnerabilidades_detectadas'].var())
    print("Minimo",prioridad['vulnerabilidades_detectadas'].min())
    print("Maximo:",prioridad['vulnerabilidades_detectadas'].max())

for i in range(7,9):
    fecha=df_tabla3.loc[(pd.to_datetime(df_tabla3['timestamp']).dt.month==i)]
    print("Numero de observaciones", str(len(fecha)))
    print("Numero de valores ausentes", str(len(fecha.loc[fecha['localizacion']=='None'])))
    print("Mediana:",fecha['vulnerabilidades_detectadas'].median())
    print("Media:", fecha['vulnerabilidades_detectadas'].mean())
    print("Varianza:", fecha['vulnerabilidades_detectadas'].var())
    print("Minimo", fecha['vulnerabilidades_detectadas'].min())
    print("Maximo:", fecha['vulnerabilidades_detectadas'].max())

#Ejercicio 4

apartadoIp = df_alertas[df_alertas['prioridad']==1]
apartadoIp = apartadoIp.groupby('origen')['sid'].count().reset_index(name='IP')
apartadoIp.sort_values(by=['IP'],ascending=False, inplace=True)
apartadoIp.head(10).plot(kind='bar',color='green')
plt.title('IP mas problematicas')
plt.xlabel('IP')
plt.ylabel('numero de alertas')
plt.show()

timeAlerts = df_alertas.groupby('timestamp')['timestamp'].count().reset_index(name='Alertas en el tiempo')
timeAlerts['timestamp'] = pd.to_datetime(timeAlerts['timestamp'])
timeAlerts = timeAlerts.set_index('timestamp')
timeAlerts.plot(kind='line',color='green')
plt.xlabel('Fecha')
plt.ylabel('Alertas')
plt.title('Numero de alertas en el tiempo')
plt.show()

alertasCateg= df_alertas.groupby('clasificacion')['sid'].count()
alertasCateg=alertasCateg.sort_values(ascending=False)
alertasCateg.plot(kind='bar',color='green')
plt.title('Alertas por categoria')
plt.xlabel('Categoria')
plt.ylabel('Numero de alertas')
plt.show()

#No funciona bien
df_tabla4 = pd.read_sql_query("SELECT devices.id as id_dev, SUM(servicios_inseguros + vulnerabilidades_detectadas) as total_vulnerabilidades FROM analisis JOIN devices ON analisis.id=devices.analisis_id",con)
plt.bar(df_tabla4['id_dev'],df_tabla4['total_vulnerabilidades'],color='green')
plt.title('titulo')
plt.xlabel('x')
plt.ylabel('y')
plt.show()

'''



