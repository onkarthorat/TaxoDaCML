from sklearn.pipeline import make_pipeline
from sklearn.externals import joblib
# from sklearn.preprocessing import StandardScaler, MinMaxScaler, QuantileTransformer
import keras

scaler_4lm = joblib.load('models/scaler_4lm.mod')
model_level1 = joblib.load('models/level1.mod')

model_level2 = joblib.load('models/level2.mod')

model_level3l = joblib.load('models/level3l.mod')
model_level3r = joblib.load('models/level3r_dt.mod')

# model_level4ll = joblib.load('/content/drive/MyDrive/models/level4ll.mod')
model_level4lr = joblib.load('models/level4lr.mod')
model_level4rr = joblib.load('models/level4rr.mod')
model_level4lm = keras.models.load_model('models/model_4LM.h5')

import numpy as np
import pandas as pd

level1_features = [' Destination Port',
 ' Protocol',
 ' Fwd Packet Length Min',
 ' Fwd Packet Length Mean',
 'Fwd Packets/s',
 ' Min Packet Length',
 ' Packet Length Mean',
 ' URG Flag Count',
 ' Down/Up Ratio',
 ' Average Packet Size',
 ' Avg Fwd Segment Size',
 ' Inbound']

level2_features = [' Protocol',
 ' Fwd Packet Length Max',
 ' Fwd Packet Length Min',
 ' Fwd Packet Length Mean',
 ' Min Packet Length',
 ' Max Packet Length',
 ' Packet Length Mean',
 ' ACK Flag Count',
 ' Average Packet Size',
 ' Avg Fwd Segment Size',
 'Init_Win_bytes_forward']

level3l_features = [' Source Port',
            ' Fwd Packet Length Mean',
            ' Fwd Packet Length Max',
            ' Fwd Packet Length Min',
            ' Min Packet Length',
            ' Max Packet Length',
            ' Packet Length Mean',
            ' Average Packet Size',
            ' Avg Fwd Segment Size']

level3r_features = [' Protocol',
            ' Fwd Packet Length Mean',
            ' Fwd Packet Length Max',
            ' Fwd Packet Length Min',
            ' Min Packet Length',
            ' Max Packet Length',
            ' Packet Length Mean',
            ' ACK Flag Count',
            ' Average Packet Size',
            ' Avg Fwd Segment Size',
            'Init_Win_bytes_forward']


level4lm_features = [' Source Port',
		 ' Protocol',
		 'Total Length of Fwd Packets',
		 ' Fwd Packet Length Max',
		 ' Fwd Packet Length Min',
		 ' Fwd Packet Length Mean',
		 ' Bwd Packet Length Min',
		 ' Fwd Header Length',
		 'Fwd Packets/s',
		 ' Min Packet Length',
		 ' Max Packet Length',
		 ' Packet Length Mean',
		 ' ACK Flag Count',
		 ' Down/Up Ratio',
		 ' Average Packet Size',
		 ' Avg Fwd Segment Size',
		' Fwd Header Length.1',
		 ' Subflow Fwd Bytes',
		 'Init_Win_bytes_forward',
		 ' act_data_pkt_fwd',
		 ' min_seg_size_forward']   



level4lr_features = [' Source Port',
             ' Flow IAT Mean',
             ' Flow IAT Std',
             ' Flow IAT Max',
             ' Fwd IAT Mean',
             ' Fwd IAT Std',
             ' Fwd IAT Max',
             'Fwd Packets/s',
             ' Total Fwd Packets',
             'Total Length of Fwd Packets',
             ' Average Packet Size',
             'Subflow Fwd Packets',
             ' Subflow Fwd Bytes',
             ' act_data_pkt_fwd']


level4rr_features = [' Protocol',
 ' Fwd Packet Length Max',
 ' Max Packet Length',
 ' ACK Flag Count',
 'Init_Win_bytes_forward'] 


 
def final_predict(X):
  y_pred = []
  level1_preds = []
  level2_preds = []
  level3_preds = []
  level4_preds = []

  for i in range(len(X)):
    if i % 1000 == 0:
      print(i)
    x = X.iloc[i]
    x1 = x[level1_features].values
    #####transform x1
    level1_pred = model_level1.predict(x1.reshape(1,-1))[0]

    if level1_pred == 0:     #benign
      y_pred.append(0)
      level1_preds.append('BENIGN')
      level2_preds.append('NA')
      level3_preds.append('NA')
      level4_preds.append('NA')

    else:           #attack
      level1_preds.append('ATTACK')
      x2 = x[level2_features].values
      #transform x2

      level2_pred = model_level2.predict(x2.reshape(1,-1))[0]

      if level2_pred == 0:      #REFLECTION
        level2_preds.append('REFLECTION')
        x3 = x[level3l_features].values
        #transform x3

        level3_pred = model_level3l.predict(x3.reshape(1,-1))[0]

        if level3_pred == 0:        #TCP/UDP REFLECTION

          level3_preds.append('TCP/UDP REFLECTION')
          # x = x.values
          
          x4 = x[level4lm_features].values
          x4 = scaler_4lm.transform(x4.reshape(1,-1))
          
          level4_pred = np.argmax(model_level4lm.predict(x4.reshape(1,-1)))

          if level4_pred == 0:        #DNS

            level4_preds.append('DNS')
            y_pred.append(7)       #dns

          elif level4_pred == 1:        #LDAP

            level4_preds.append('LDAP')
            y_pred.append(1)       #ldap    

          elif level4_pred == 2:        #NETBIOS

            level4_preds.append('NETBIOS')
            y_pred.append(3)       #netbios       

          elif level4_pred == 3:        #SNMP

            level4_preds.append('SNMP')
            y_pred.append(9)       #snmp

          else:             #portmap
            level4_preds.append('PORTMAP')
            y_pred.append(4)         #portmap

        else:

          level3_preds.append('UDP REFLECTION')

          x4 = x[level4lr_features].values
          #transform x4

          level4_pred = model_level4lr.predict(x4.reshape(1,-1))[0]

          if level4_pred == 1:          #NTP

            level4_preds.append('NTP')
            y_pred.append(8)         #ntp

          elif level4_pred == 0:                       #TFTP

            level4_preds.append('TFTP')
            y_pred.append(10)         #tftp
          
          else:

            level4_preds.append('MSSQL')
            y_pred.append(2)

      else:                   #EXPLOITATION

        level2_preds.append('EXPLOITATION')
        x3 = x[level3r_features].values
        #transform x3

        level3_pred = model_level3r.predict(x3.reshape(1,-1))[0]
        
        if level3_pred == 0:        #TCP    SYN

          level3_preds.append('TCP EXPLOITATION')
          level4_preds.append('SYN')
          y_pred.append(5)     #syn

        else:

          level3_preds.append('UDP EXPLOITATION')

          x4 = x[level4rr_features].values
          #transform x4

          level4_pred = model_level4rr.predict(x4.reshape(1,-1))[0]

          if level4_pred == 1:          #UDP Flood

            level4_preds.append('UDP-FLOOD')
            y_pred.append(6)       #udpflood

          else:                 #UDP Lag

            level4_preds.append('UDP-Lag')
            y_pred.append(11)         #udplag

  y_pred_arr = np.array(y_pred)
  return y_pred_arr, level1_preds, level2_preds, level3_preds, level4_preds


path = input("Provide the path of input csv file: ")
data = pd.read_csv(path)

y_pred, level1_preds, level2_preds, level3_preds, level4_preds = final_predict(data)

print(level1_preds + " ---> " + level2_preds + " ---> " + level3_preds + " ----> " + level4_preds)



