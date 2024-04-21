import os
import json
import numpy as np
import datetime
from fastapi import FastAPI, Request
from secml.array import CArray
from secml_malware.attack.blackbox.c_wrapper_phi import CEnd2EndWrapperPhi, CEmberWrapperPhi
from secml_malware.models import MalConv, CClassifierEnd2EndMalware, CClassifierEmber, CClassifierRemote
from embernn import EmberNN
from secml_malware.utils.is_valid_url import isValidUrl
import ember
import asyncio
import time
import hashlib
from sklearn.metrics import roc_curve

app = FastAPI()

files = []
hash_list = []
X_train = None
y_train = None
X_validation = None
y_validation = None
next_fine_tuning = 0
count = 0
model_version = 0
selected_threshold = 0

classifier = os.getenv("classifier")
labeling_service = os.getenv("labeling_service")
apiKeys = os.getenv("apiKeys")
training_samples = os.getenv("training_samples")
validation_samples = os.getenv("validation_samples")
fine_tuning = os.getenv("fine_tuning", "false").lower() == "true"
continue_training = os.getenv("continue_training", "false").lower() == "true"
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

elif classifier == "emberGBDT" or classifier == "embernn":
    if load_pretrained_model and classifier == "emberGBDT":
        print("Loading Ember GBDT pretrained model")
        net = CClassifierEmber(tree_path="ember2018/ember_model_2018.txt")
        net = CEmberWrapperPhi(net)
        print("Ember GBDT pretrained model loading complete.")
    else: 
        print("Loading Ember dataset..")
        if int(training_samples) + int(validation_samples) > 200000:
            subset = "train"
            file_paths = [
                "ember2018/train_features0.jsonl",
                "ember2018/train_features1.jsonl",
                "ember2018/train_features2.jsonl",
                "ember2018/train_features3.jsonl",
                "ember2018/train_features4.jsonl",
                "ember2018/train_features5.jsonl"
            ]
        else:
            subset = "test"
            file_paths = ["ember2018/test_features.jsonl"]

        X, y = ember.read_vectorized_features(
            "ember2018/",
            subset=subset,
            feature_version=2
        )
        for file_path in file_paths:
            with open(file_path, 'r') as file:
                for line in file:
                    sample = json.loads(line.strip())
                    hash_value = sample.get("sha256", None)
                    if hash_value:
                        hash_entry = {
                            "sha256": hash_value
                        }
                        hash_list.append(hash_entry)
                        
        hash_list = np.array(hash_list)
        hash_list = hash_list[y != -1]
        X = X[y != -1].astype(dtype='float64')
        y = y[y != -1]
        
        random_indices = np.random.choice(len(X), int(training_samples) + int(validation_samples), replace=False)
        
        train_indices = random_indices[:int(training_samples)]
        validation_indices = random_indices[int(training_samples):]

        X_train = X[train_indices]
        y_train = y[train_indices]
        hash_list = hash_list[train_indices]

        X_validation = X[validation_indices]
        y_validation = y[validation_indices]

        print("Ember dataset loading complete.")
        print("shape X_train: ", X_train.shape)
        print("shape y_train: ", y_train.shape)
        print("shape X_validation: ", X_validation.shape)
        print("shape y_validation: ", y_validation.shape)
        
        del X
        del y

        hash_list = list(hash_list)  
        
        
        if classifier == "emberGBDT":
            print("Loading Ember GBDT model...")
            net = CClassifierEmber(X=X_train, y=y_train)
            net = CEmberWrapperPhi(net)
            _, conf = net.classifier.predict(CArray(X_validation), True)
            conf = conf.tondarray()[:, 1] 
        elif classifier == "embernn":
            print("Loading Ember NN model...")
            net = EmberNN(X_train.shape[1])
            net.fit(X_train, y_train)
            conf = net.predict(X_validation) 
            
        print("Calculating ROC curve to determine model threshold (1% FP on the validation set)...")
        fpr, tpr, thresholds = roc_curve(y_validation, conf)
        # Define the target false positive rate (1%)
        target_fp_rate = 0.01
        fp_index = np.argmax(fpr > target_fp_rate)
        selected_threshold = thresholds[fp_index]

        print("ROC curve calculation completed.")
        print(f"Selected threshold at {target_fp_rate*100:.2f}% false positive rate: {selected_threshold}")

        if classifier == "emberGBDT":
            net.classifier.set_threshold(selected_threshold)
            net.classifier.save_model(f"emberGBDT_model{model_version}.txt")
            print("Ember GBDT model loading complete.")
        elif classifier == "embernn":
            net.save(save_path="", file_name="ember_nn")
            print("Ember NN model loading complete.")

        if not fine_tuning:
            del X_train
            del y_train
            del X_validation
            del y_validation
            
else:
    raise ValueError("Classifier not specified or invalid. Please specify 'malconv' or 'emberGBDT' or 'embernn' as the classifier.")

@app.post('/analyze')
async def analyze(request: Request):
    global count, next_fine_tuning, selected_threshold, net
    
    data = await request.body()
    fp = request.headers.get("Filename")
    
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data)
    hash_value = sha256_hash.hexdigest()

    if hash_value not in [entry['sha256'] for entry in hash_list]:
        if classifier == "malconv" or classifier == "emberGBDT":
            bytes2CArr = np.frombuffer(data, dtype=np.uint8)
            convertedData = CArray(bytes2CArr).atleast_2d()
            prediction, confidence = net.predict(convertedData, True)
            confidence = confidence[0, 1].item()
            prediction= prediction.item()
        elif classifier == "embernn":
            extractor = ember.PEFeatureExtractor(feature_version=2)
            features = extractor.feature_vector(data).astype(dtype='float64')
            confidence = float(net.predict(features.reshape(1, -1))[0][0])
            prediction = 1 if confidence > selected_threshold else 0
        hash_entry = {
            "sha256": hash_value,
            "prediction": prediction,
            "confidence": confidence,    
        }
        hash_list.append(hash_entry)
        if fine_tuning and (classifier == "emberGBDT" or classifier == "embernn"):
            files.append(data)
    else:
        existing_entry_index = next((i for i, entry in enumerate(hash_list) if entry['sha256'] == hash_value))
        existing_entry = hash_list[existing_entry_index]
        if existing_entry.get('prediction') is not None and existing_entry.get('confidence') is not None:
            prediction = existing_entry.get('prediction')
            confidence = existing_entry.get('confidence')
        else:
            if classifier == "malconv" or classifier == "emberGBDT":
                bytes2CArr = np.frombuffer(data, dtype=np.uint8)
                convertedData = CArray(bytes2CArr).atleast_2d()
                prediction, confidence = net.predict(convertedData, True)
                confidence = confidence[0, 1].item()
                prediction= prediction.item()
            elif classifier == "embernn":
                extractor = ember.PEFeatureExtractor(feature_version=2)
                features = extractor.feature_vector(data).astype(dtype='float64')
                confidence = float(net.predict(features.reshape(1, -1))[0][0])
                prediction = 1 if confidence > selected_threshold else 0
            existing_entry['prediction'] = prediction
            existing_entry['confidence'] = confidence
            hash_list[existing_entry_index] = existing_entry

    count+=1
    print(f"> Request number: {count}")
    print(f"> The file named: {fp} is a {'malware' if prediction == 1 else 'goodware'}. Score: {confidence}")
        
    encoded_data = {
        "file name": fp, 
        "score": confidence,
        "time": str(datetime.datetime.now())
    }
    with open('log_file.txt', "a") as file:
        json.dump(encoded_data, file)
        file.write('\n')
       
    if fine_tuning and len(files) >= int(samples_for_fine_tuning) and time.time() >= next_fine_tuning:
        asyncio.create_task(process_fine_tuning())

    response = {
        "label": prediction,
        "score": confidence
    }
    return response

async def process_fine_tuning():
    print("Fine tuning in progress...")
    global X_train, y_train, X_validation, y_validation, next_fine_tuning, model_version, selected_threshold, net
    X = []
    extractor = ember.PEFeatureExtractor(feature_version=2)
    for file in files:
        X.append(extractor.feature_vector(file).astype(dtype='float64'))
    y = label_data(files)
    X = np.array(X)
    y = np.array(y)

    X_train = np.concatenate((X_train, X), axis=0)
    y_train = np.concatenate((y_train, y), axis=0)
    if continue_training:
        print("Continuing training...")
        if classifier == "emberGBDT":
            net.classifier._fit(X=X_train, y=y_train, init_model=f"emberGBDT_model{model_version}.txt")
        elif classifier == "embernn":
            net.fit(X_train, y_train)
    else:
        print("Training from scratch...")
        if classifier == "emberGBDT":
            net.classifier._fit(X=X_train, y=y_train)
        elif classifier == "embernn":
            net = EmberNN(X_train.shape[1])
            net.fit(X_train, y_train)

    files.clear()
    for entry in hash_list:
        if 'prediction' in entry:
            del entry['prediction']
        if 'confidence' in entry:
            del entry['confidence']
    print("Fine tuning completed.")
    
    print("Calculating new ROC curve to determine model threshold (1% FP on the validation set)...")

    if classifier == "emberGBDT":
        _, conf = net.classifier.predict(CArray(X_validation), True)
        conf = conf.tondarray()[:, 1] 
    elif classifier == "embernn":
        conf = net.predict(X_validation)
        
    fpr, tpr, thresholds = roc_curve(y_validation, conf)

    # Define the target false positive rate (1%)
    target_fp_rate = 0.01
    fp_index = np.argmax(fpr > target_fp_rate)
    selected_threshold = thresholds[fp_index]

    print("ROC curve calculation completed.")
    print(f"Selected threshold at {target_fp_rate*100:.2f}% false positive rate: {selected_threshold}")

    model_version+=1
    if classifier == "emberGBDT":
        net.classifier.set_threshold(selected_threshold)
        net.classifier.save_model(f"emberGBDT_model{model_version}.txt")
    elif classifier == "embernn":
        net.save(save_path="", file_name=f"ember_nn{model_version}")

        
    one_day_in_seconds = 24 * 60 * 60
    current_time = time.time()
    next_fine_tuning = current_time + one_day_in_seconds
    print("Next fine-tuning: ", datetime.datetime.fromtimestamp(next_fine_tuning).strftime('%Y-%m-%d %H:%M:%S'))

def label_data(files):
    if isValidUrl(labeling_service):
        remote_classifier = CClassifierRemote(url=labeling_service)
    else:
        remote_classifier = CClassifierRemote(antivirus=labeling_service, apiKey=apiKeys.split(","))
    print("antivirus labeling service", labeling_service)
    print("Labeling files...")
    y_new = []
    for file in files:
        pred, confidence = remote_classifier.predict(CArray(np.frombuffer(file, dtype=np.uint8)).atleast_2d(), return_decision_function=True)
        print(f"Prediction: {'malware' if pred.item() == 1 else 'goodware'}. Score: {confidence[0, 1].item()}")
        y_new.append(pred.item())
    print("Labeling complete.")
    return y_new