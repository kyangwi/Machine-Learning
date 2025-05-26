import  os
import pickle
import pandas as pd
import streamlit as st
from androguard.core.bytecodes.apk import APK
from androguard.core.analysis.analysis import Analysis
from androguard.core.bytecodes.dvm import DalvikVMFormat


def conver_apk_to_permission(apk_path):
      a = APK(apk_path)
      print(a)
      # Extract permissions
      permissions = a.get_permissions()
      # Extract API calls
      def get_api_calls(dvm):
          calls = set()
          for method in dvm.get_methods():
              for ins in method.get_instructions():
                  if ins.get_op_value() == 0x6e:  # Invoke-virtual (0x6e)
                      method_name = ins.get_output().split(',')[1].strip()
                      calls.add(method_name)
          return calls
      # Load the DalvikVMFormat
      d = DalvikVMFormat(a.get_dex())
      api_calls = get_api_calls(d)
      apk_permissions=[]
      # Print permissions and API calls
      print("Permissions:")
      for permission in permissions:
          apk_permissions.append(f'{permission}')
          print(permission)

      # Define the list of permissions with the last part of the permission string
      permissions_list = [
          'SEND_SMS', 'READ_PHONE_STATE', 'getDeviceId', 'transact', 'getCanonicalName',
          'getLine1Number', 'chmod', 'GET_ACCOUNTS', 'getResource', 'URLDecoder',
          'INTERNET', 'SmsManager', 'ClassLoader', 'getSubscriberId',
          'getClass', 'registerReceiver', 'WRITE_HISTORY_BOOKMARKS',
          'exec', 'BOOT_COMPLETED', 'unregisterReceiver',
          'cast', 'loadLibrary', 'gsm.SmsManager', 'PackageInfo',
          'READ_SMS', 'onServiceConnected', 'init', 'WRITE_EXTERNAL_STORAGE', 'bindService', 'Binder'
      ]
      # Initialize a dictionary with permission names as keys and values as 0
      permissions_dict = {permission: 0 for permission in permissions_list}
      # Function to check and update permissions
      def check_and_update_permissions(apk_permissions, permissions_dict):
          for permission in apk_permissions:
              # Extract the last part of the permission string
              print(permission)
              last_part = permission.split('.')[-1]
              if last_part in permissions_dict:
                  permissions_dict[last_part] = 1

      # Replace 'apk_permissions' with the actual permissions extracted from the APK
      # You should have 'apk_permissions' as a list of permissions extracted using androguard
      # For this example, I'll use a few permissions as if they were extracted
      # Check and update permissions
      check_and_update_permissions(apk_permissions, permissions_dict)
      # Create a DataFrame with a single row
      df = pd.DataFrame([permissions_dict])
      old_columns = [
              'SEND_SMS', 'READ_PHONE_STATE', 'getDeviceId', 'transact', 'getCanonicalName',
              'getLine1Number', 'chmod', 'GET_ACCOUNTS', 'getResource', 'URLDecoder',
              'INTERNET', 'SmsManager', 'ClassLoader', 'getSubscriberId',
              'getClass', 'registerReceiver', 'WRITE_HISTORY_BOOKMARKS',
              'exec', 'BOOT_COMPLETED', 'unregisterReceiver',
              'cast', 'loadLibrary', 'gsm.SmsManager', 'PackageInfo',
              'READ_SMS', 'onServiceConnected', 'init', 'WRITE_EXTERNAL_STORAGE', 'bindService', 'Binder']
    
      new_columns= [
              'SEND_SMS', 'READ_PHONE_STATE', 'TelephonyManager.getDeviceId', 'transact', 'Ljava.lang.Class.getCanonicalName',
              'TelephonyManager.getLine1Number', 'chmod', 'GET_ACCOUNTS', 'Ljava.lang.Class.getResource', 'Ljava.net.URLDecoder',
              'INTERNET', 'android.telephony.SmsManager', 'ClassLoader', 'TelephonyManager.getSubscriberId',
              'Ljava.lang.Object.getClass', 'Landroid.content.Context.registerReceiver', 'WRITE_HISTORY_BOOKMARKS',
              'Runtime.exec', 'android.intent.action.BOOT_COMPLETED', 'Landroid.content.Context.unregisterReceiver',
              'Ljava.lang.Class.cast', 'System.loadLibrary', 'android.telephony.gsm.SmsManager', 'android.content.pm.PackageInfo',
              'READ_SMS', 'onServiceConnected', 'HttpGet.init', 'WRITE_EXTERNAL_STORAGE', 'bindService', 'android.os.Binder'
          ]
 
      column_mapping = dict(zip(old_columns, new_columns))
      df.rename(columns=column_mapping, inplace=True)
      return df

def main():
    st.set_page_config(page_title="AudioChat Transcriber", layout="wide")
    st.title('Android malware detection using Machine learning')

    apk_file = st.file_uploader('Uppload your mobile application',type=['apk'])

    if apk_file is not None:
        if not os.path.exists('upploaded_apk'):
            os.makedirs('Upploaded_apk')

        # APK path
        apk_folder = './upploaded_apk/apk.apk'

        # write binary apk file to loacal disc
        with open(apk_folder, 'wb') as file:
            file.write(apk_file.read())  # Use apk_file.read() to get the contents as bytes

  
        # extracting android premissions and then converting them into a dataframe
        new_df=conver_apk_to_permission(apk_folder)

        # print(new_df)
        new_df.to_csv('Android_permissioins.csv',index=False)
        # dataframe = pd.read_csv('./Android_permissioins.csv')
        st.success("Permission metrics extracted successfully!")

        st.text(f'{new_df.head()}')
        with open("./model.pkl", "rb") as model_file:
            loaded_model = pickle.load(model_file)

        try:
            preds = loaded_model.predict(new_df)
            if preds[0] == 0 :
                st.success(f"Benign applications")
            if preds[0] == 1:
                st.error(f"Malware detected")

        except Exception as e:
            
            print(e)


    

if __name__ == "__main__":
    main()