import os
import json
import numpy as np
import datetime
from fastapi import FastAPI, Request
from secml.array import CArray
from secml_malware.attack.blackbox.c_wrapper_phi import CEnd2EndWrapperPhi, CEmberWrapperPhi
from secml_malware.models import MalConv, CClassifierEnd2EndMalware, CClassifierEmber

app = FastAPI()

i = 0
classifier_argument = os.getenv("classifier")
print(f"Classfier passed: {classifier_argument}")

net = None
if classifier_argument == "malconv":
    net = CClassifierEnd2EndMalware(MalConv())
    net.load_pretrained_model()
    net = CEnd2EndWrapperPhi(net)
elif classifier_argument == "ember":
    net = CClassifierEmber(tree_path="models/ember_model_2018.txt")
    net = CEmberWrapperPhi(net)
else:
    raise ValueError("Classifier not specified or invalid. Please specify 'malconv' or 'ember' as the classifier.")

@app.post('/analyze')
async def analyze(request: Request):
    global i
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
    
    file_path = 'log_file.txt'

    encoded_data = {
        "file name": fp, 
        "score": conf,
        "time": str(datetime.datetime.now())
    }
    with open(file_path, "a") as file:
        json.dump(encoded_data, file)
        file.write('\n')
    return str(conf)