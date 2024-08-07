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
import threading
from fastapi.responses import JSONResponse

app = FastAPI()

# global variables
hash_list = []
X_train = None
y_train = None
X_validation = None
y_validation = None
next_fine_tuning = 0
count = 0
model_version = 0
selected_threshold = 0
n_files_to_label = 0
new_files_directory = "new_files"
remote_classifier = None
is_updating = False

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
        
        # Ember training dataset has 600,000 samples
        # Ember validation dataset has 200,000 samples
        file_paths_train = [
            "ember2018/train_features_0.jsonl",
            "ember2018/train_features_1.jsonl",
            "ember2018/train_features_2.jsonl",
            "ember2018/train_features_3.jsonl",
            "ember2018/train_features_4.jsonl",
            "ember2018/train_features_5.jsonl"
        ]
        file_paths_validation = ["ember2018/test_features.jsonl"]
        
        if training_samples is None or validation_samples is None or int(training_samples) <= 0 or int(validation_samples) <= 0:
            raise ValueError("Invalid training and validation samples. Please specify a positive number <= 600,000 and <= 200,000 respectively.")
        elif int(training_samples) > 600000 or int(validation_samples) > 200000:
            raise ValueError("Training and validation samples should not exceed 600,000 and 200,000 respectively.")
        
        hash_list_train = []
        hash_list_validation = []
        for file_paths, hash_list in zip([file_paths_train, file_paths_validation], [hash_list_train, hash_list_validation]):
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
                
        hash_list_train = np.array(hash_list_train)
        hash_list_validation = np.array(hash_list_validation)
        
        print("Reading vectorized features for training set..")
        X_train, y_train = ember.read_vectorized_features(
            "ember2018",
            subset="train",
            feature_version=2
        )

        print(f"Shuffling and selecting training samples ({training_samples})..")
        indices_train_gw = np.where(y_train == 0)[0]
        indices_train_mw = np.where(y_train == 1)[0]

        # Set seed and shuffle indices
        np.random.seed(47)
        np.random.shuffle(indices_train_gw)
        np.random.shuffle(indices_train_mw)
        
        # Select half of the samples from each class
        half_training_samples = int(training_samples) // 2
        selected_indices_train_gw = indices_train_gw[:half_training_samples]
        selected_indices_train_mw = indices_train_mw[:half_training_samples]

        # Create new arrays by concatenating the selections
        X_train = np.concatenate((X_train[selected_indices_train_gw], X_train[selected_indices_train_mw]), axis=0)
        y_train = np.concatenate((y_train[selected_indices_train_gw], y_train[selected_indices_train_mw]), axis=0)

        print("Reading vectorized features for validation set..")
        X_validation, y_validation = ember.read_vectorized_features(
            "ember2018",
            subset="test",
            feature_version=2
        )

        print(f"Shuffling and selecting validation samples ({validation_samples})..")
        indices_validation_gw = np.where(y_validation == 0)[0]
        indices_validation_mw = np.where(y_validation == 1)[0]
        
        np.random.seed(47)
        np.random.shuffle(indices_validation_gw)
        np.random.shuffle(indices_validation_mw)
        
        half_validation_samples = int(validation_samples) // 2
        selected_indices_validation_gw = indices_validation_gw[:half_validation_samples]
        selected_indices_validation_mw = indices_validation_mw[:half_validation_samples]
        
        X_validation = np.concatenate((X_validation[selected_indices_validation_gw], X_validation[selected_indices_validation_mw]), axis=0)
        y_validation = np.concatenate((y_validation[selected_indices_validation_gw], y_validation[selected_indices_validation_mw]), axis=0)
        
        print("Combining hash lists..")

        hash_list = np.concatenate((hash_list_train[selected_indices_train_gw],
                                    hash_list_train[selected_indices_train_mw],
                                    hash_list_validation[selected_indices_validation_gw],
                                    hash_list_validation[selected_indices_validation_mw]), axis=0)
        
        del hash_list_train, hash_list_validation
        del indices_train_gw, indices_train_mw, indices_validation_gw, indices_validation_mw
        del selected_indices_train_gw, selected_indices_train_mw, selected_indices_validation_gw, selected_indices_validation_mw

        print("Ember dataset loading complete.")
        
        print("shape X_train: ", X_train.shape)
        print("shape y_train: ", y_train.shape)
        print("shape X_validation: ", X_validation.shape)
        print("shape y_validation: ", y_validation.shape)
        print("shape hash_list: ", hash_list.shape)
        
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
            del X_train, y_train, X_validation, y_validation         
else:
    raise ValueError("Classifier not specified or invalid. Please specify 'malconv' or 'emberGBDT' or 'embernn' as the classifier.")


def label_data(file, file_name):
    global remote_classifier
    if remote_classifier is None:
        if isValidUrl(labeling_service):
            remote_classifier = CClassifierRemote(url=labeling_service)
        else:
            remote_classifier = CClassifierRemote(antivirus=labeling_service, apiKey=apiKeys.split(","))
        print("Antivirus Labeling Service: ", labeling_service)
        
    print("Labeling file: ", file_name)
    
    pred, confidence = remote_classifier.predict(CArray(np.frombuffer(file, dtype=np.uint8)).atleast_2d(), return_decision_function=True)
    print(f"Prediction: {'malware' if pred.item() == 1 else 'goodware'}. Score: {confidence[0, 1].item()}")

    return pred.item()


def process_fine_tuning():
    print("Fine tuning in progress...")
    global X_train, y_train, X_validation, y_validation, next_fine_tuning, model_version, selected_threshold, net, new_files_directory, is_updating
    
    is_updating = True
    X = []
    y = []
    extractor = ember.PEFeatureExtractor(feature_version=2)
    for filename in os.listdir(new_files_directory):
        file_path = os.path.join(new_files_directory, filename)
        if os.path.isfile(file_path):
            with open(file_path, 'rb') as file:
                file_content = file.read()
                
            X.append(extractor.feature_vector(file_content).astype(dtype='float64'))
            y.append(label_data(file_content, filename))
            os.remove(file_path)
    
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
        
    fpr, _, thresholds = roc_curve(y_validation, conf)

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
    is_updating = False


@app.post('/analyze')
async def analyze(request: Request):
    global count, next_fine_tuning, selected_threshold, net, n_files_to_label, new_files_directory, is_updating
    
    if is_updating:
        return JSONResponse(
            status_code=503,
            content={"message": "Server is updating the model. Please try again later."}
        )
    
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
            file_path = os.path.join(new_files_directory, f"{hash_value}.file")
            with open(file_path, 'wb') as file:
                file.write(data)
            n_files_to_label+=1
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
       
    if fine_tuning and n_files_to_label >= int(samples_for_fine_tuning) and time.time() >= next_fine_tuning:
        threading.Thread(target=process_fine_tuning).start()
        n_files_to_label = 0

    response = {
        "label": prediction,
        "score": confidence
    }
    return response