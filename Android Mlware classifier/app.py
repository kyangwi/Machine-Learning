import re
from flask import Flask, render_template, request, jsonify
import pickle
import os
import tempfile
import pandas as pd
from androguard.core.bytecodes.apk import APK
from androguard.core.analysis.analysis import Analysis
from androguard.core.bytecodes.dvm import DalvikVMFormat

# Load the pickled model
with open('model.pkl', 'rb') as file:
    model = pickle.load(file)

app = Flask(__name__, static_folder='static')
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

@app.route('/')
def admin():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    uploaded_file = request.files['fileInput']
    if uploaded_file:
        result = process_file(uploaded_file)  # Process the uploaded file
        return render_template('index.html', result=result)
    else:
        return render_template('index.html', result=None)



def process_file(file):
    # Save the uploaded file to a temporary location
    temp_dir = tempfile.mkdtemp()
    temp_file_path = os.path.join(temp_dir, file.filename)
    file.save(temp_file_path)

    # Extract permissions and API calls from the APK file
    df = convert_apk_to_permission(temp_file_path)

    # Use the model for predictions
    result = model.predict(df)

    # Remove the temporary file
    os.remove(temp_file_path)
    os.rmdir(temp_dir)

    if result[0] == 0:
        return "Benign application"
    elif result[0] == 1:
        return "Malware detected"


def convert_apk_to_permission(apk_file):
    a = APK(apk_file)

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
    apk_permissions = []

    for permission in permissions:
        apk_permissions.append(f'{permission}')

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
            last_part = permission.split('.')[-1]
            if last_part in permissions_dict:
                permissions_dict[last_part] = 1

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
        'READ_SMS', 'onServiceConnected', 'init', 'WRITE_EXTERNAL_STORAGE', 'bindService', 'Binder'
    ]

    new_columns = [
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

if __name__ == '__main__':
    app.run(debug=True)
