import os
import json
import numpy as np
import datetime
from fastapi import FastAPI, Request
from secml.array import CArray
from secml_malware.attack.blackbox.c_wrapper_phi import CEnd2EndWrapperPhi, CEmberWrapperPhi, CRemoteWrapperPhi
from secml_malware.models import MalConv, CClassifierEnd2EndMalware, CClassifierEmber, CClassifierRemote
from secml_malware.utils.is_valid_url import isValidUrl
import ember
import asyncio
import time

app = FastAPI()

files = []
X_train = None
y_train = None
next_fine_tuning = 0
i = 0

classifier = os.getenv("classifier")
labeling_service = os.getenv("labeling_service")
apiKeys = os.getenv("apiKeys")
training_samples = os.getenv("training_samples")
fine_tuning = os.getenv("fine_tuning", "false").lower() == "true"
samples_for_fine_tuning = os.getenv("samples_for_fine_tuning")
load_pretrained_model = os.getenv("load_pretrained_model", "true").lower() == "true"



print(f"Classfier passed: {classifier}")

net = None
if classifier == "malconv":
    print("Loading Malconv model...")
    net = CClassifierEnd2EndMalware(MalConv())
    net.load_pretrained_model()
    net = CEnd2EndWrapperPhi(net)
    print("Malconv model loading complete.")

elif classifier == "emberGBDT":
    if load_pretrained_model:
        print("Loading Ember GBDT pretrained model")
        net = CClassifierEmber(tree_path="ember2018/ember_model_2018.txt")
        net = CEmberWrapperPhi(net)
        print("Ember GBDT pretrained model loading complete.")
    else: 
        print("Loading Ember dataset..")
        if int(training_samples) > 200000:
            subset = "train"
        else:
            subset = "test"
        X_train, y_train = ember.read_vectorized_features(
            "ember2018/",
            subset=subset,
            feature_version=2
        )
        X_train = X_train[y_train != -1].astype(dtype='float64')
        y_train = y_train[y_train != -1]
        
        random_indices = np.random.choice(len(X_train), int(training_samples), replace=False)        
        X_train = X_train[random_indices]
        y_train = y_train[random_indices]

        print("Ember dataset loading complete.")
        print("shape X_train: ", X_train.shape)
        print("shape y_train: ", y_train.shape) 
        
        print("Loading Ember GBDT model...")
        net = CClassifierEmber(X=X_train, y=y_train)
        net = CEmberWrapperPhi(net)
        print("Ember GBDT model loading complete.")
else:
    raise ValueError("Classifier not specified or invalid. Please specify 'malconv' or 'emberGBDT' as the classifier.")

@app.post('/analyze')
async def analyze(request: Request):
    global i, X_train, y_train, next_fine_tuning
    
    data = await request.body()
    fp = request.headers.get("Filename")
    # from bytes to CArray
    bytes2CArr = np.frombuffer(data, dtype=np.uint8)
    convertedData = CArray(bytes2CArr).atleast_2d()
    # model initializtion
    _, confidence = net.predict(convertedData, True)
    i+=1
    print(f"> Request number: {i}")
    print(f"> The file named: {fp} is a malware with confidence {confidence[0, 1].item()}")
    conf = confidence[1][0].item()
       
    encoded_data = {
        "file name": fp, 
        "score": conf,
        "time": str(datetime.datetime.now())
    }
    with open('log_file.txt', "a") as file:
        json.dump(encoded_data, file)
        file.write('\n')
    
    if fine_tuning :
        files.append(convertedData)
        
        if len(files) >= int(samples_for_fine_tuning) and time.time() >= next_fine_tuning:
            asyncio.create_task(process_fine_tuning())

    return str(conf)

async def process_fine_tuning():
    print("Fine tuning in progress...")
    global X_train, y_train, next_fine_tuning
    X = []
    for file in files:
        X.append(np.squeeze(net.extract_features(file).tondarray()))
    y = label_data(files)
    X = np.array(X)
    y = np.array(y)

    X_train = np.concatenate((X_train, X), axis=0)
    y_train = np.concatenate((y_train, y), axis=0)
    net.classifier._fit(X_train, y_train)

    files.clear()
    print("Fine tuning completed.")
    one_day_in_seconds = 24 * 60 * 60
    current_time = time.time()
    next_fine_tuning = current_time + one_day_in_seconds
    print("Next fine-tuning: ", datetime.datetime.fromtimestamp(next_fine_tuning).strftime('%Y-%m-%d %H:%M:%S'))

def label_data(files):
    if isValidUrl(labeling_service):
        remote_classifier = CClassifierRemote(url=labeling_service)
    else:
        remote_classifier = CClassifierRemote(antivirus=labeling_service, apiKey=apiKeys.split(","))
    remote_classifier = CRemoteWrapperPhi(remote_classifier)
    print("antivirus labeling service", labeling_service)
    print("Labeling files...")
    y_new = []
    for file in files:
        pred, confidence = remote_classifier.predict(file)
        print("pred ", pred.get_data()[0], " confidence ", confidence)
        y_new.append(pred.get_data()[0])
    print("Labeling complete.")
    return y_new