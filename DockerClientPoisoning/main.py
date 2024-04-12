import os
import random
import numpy as np
import ember
import lightgbm as lgb
from embernn import EmberNN
from secml_malware.models import CClassifierEmber
import math
import pefile
import features_utils
import plotext as plt
from secml.array import CArray
from secml_malware.models import CClassifierRemote
import time
import requests

def check_server_availability(url):
    try:
        requests.get(url) 
    except requests.ConnectionError:
        return False
    return True

while not check_server_availability("http://server:8000"):
    time.sleep(5)

byte_histogram_features = np.array(features_utils.get_byte_histogram_features())
header_features =  np.array(features_utils.get_header_features())

surrogate_model = os.getenv("surrogate_model")
attack = os.getenv("attack")
perc_bytes_poisoning = os.getenv("perc_bytes_poisoning")
num_malware_files = os.getenv("num_malware_files")
num_goodware_files = os.getenv("num_goodware_files")
training_samples = os.getenv("training_samples")

if attack != "increase_false_negatives" and attack != "increase_false_positives":
    raise ValueError("Unrecognized attack. Attack strategy must be either 'increase_false_negatives' or 'increase_false_positives'")

malware_folder = "/app/malware_samples/"
goodware_folder = "/app/goodware_samples/"
poisoned_malware_folder = "/app/poisoned_malware_samples/"
poisoned_goodware_folder = "/app/poisoned_goodware_samples/"

malware_files = os.listdir(malware_folder)
goodware_files = os.listdir(goodware_folder)

random.seed(50)

try:
    selected_malware_files = random.sample(malware_files, int(num_malware_files))
except ValueError as e:
    if str(e) == "Sample larger than population or is negative" and int(num_malware_files) > 0:
        selected_malware_files = random.choices(malware_files, k=int(num_malware_files))
    else:
        raise ValueError(e)

try:
    selected_goodware_files = random.sample(goodware_files, int(num_goodware_files))
except ValueError as e:
    if str(e) == "Sample larger than population or is negative" and int(num_goodware_files) > 0:
        selected_goodware_files = random.choices(goodware_files, k=int(num_goodware_files))
    else:
        raise ValueError(e)

X_gw = []
X_mw = []
y_gw = []
y_mw = []
length_gw = []
length_mw = []
file_path_gw = []
file_path_mw = []

extractor = ember.PEFeatureExtractor(feature_version=2)

for file_name in selected_goodware_files:
    file_path = os.path.join(goodware_folder, file_name)
    with open(file_path, 'rb') as file:
        content = file.read()
        try:
            X_gw.append(extractor.feature_vector(content).astype(dtype='float64'))
            y_gw.append(0)
            length_gw.append(len(content))
            file_path_gw.append(file_path)
        except Exception as e:
            print("Error for file ", file_name, ": ", e)

for file_name in selected_malware_files:
    file_path = os.path.join(malware_folder, file_name)
    with open(file_path, 'rb') as file:
        content = file.read()
        try: 
            X_mw.append(extractor.feature_vector(content).astype(dtype='float64'))
            y_mw.append(1)
            length_mw.append(len(content))
            file_path_mw.append(file_path)
        except Exception as e:
            print("Error for file ", file_name, ": ", e)
         
X_gw = np.array(X_gw)
X_mw = np.array(X_mw)
y_gw = np.array(y_gw)
y_mw = np.array(y_mw)
print("shape X_gw: ", X_gw.shape)
print("shape X_mw: ", X_mw.shape) 

print("Loading Ember dataset...")
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

if surrogate_model == "emberGBDT":
    print("Training emberGBDT (surrogate) model...")
    model = CClassifierEmber(X=X_train, y=y_train)
    print("emberGBDT (surrogate) model training complete.")
    
    if attack == "increase_false_negatives":
        _, results_mw_pre = model.predict(X_mw, True)
        results_mw_pre = results_mw_pre.tondarray()[:, 1]
    else:
        _, results_gw_pre = model.predict(X_gw, True)
        results_gw_pre = results_gw_pre.tondarray()[:, 1]

elif surrogate_model == "embernn":
    print("Training emberNN (surrogate) model...")
    model = EmberNN(X_train.shape[1])
    model.fit(X_train, y_train)
    print("emberNN (surrogate) model training complete.")
    
    if attack == "increase_false_negatives":
        results_mw_pre = model.predict(X_mw)
    else:
        results_gw_pre = model.predict(X_gw)
    
else:
    raise ValueError("Surrogate model not specified or invalid. Please specify 'embernn' or 'emberGBDT' as the surrogate model.")

byte_histogram_features_gw = X_gw[:, byte_histogram_features]
total_histogram_gw = np.sum(byte_histogram_features_gw, axis=0)
byte_probability_distribution_gw = total_histogram_gw / np.sum(total_histogram_gw)

byte_histogram_features_mw = X_mw[:, byte_histogram_features]
total_histogram_mw = np.sum(byte_histogram_features_mw, axis=0)
byte_probability_distribution_mw = total_histogram_mw / np.sum(total_histogram_mw)

x_values = np.arange(256)

plt.title("Byte Distribution of Goodwares")
plt.plot(x_values, byte_probability_distribution_gw*100, label = "Goodwares", marker="braille", color="green")
plt.yfrequency(10)
plt.xfrequency(10)
plt.grid(horizontal=True)
plt.show()
plt.clf()
plt.title("Byte Distribution of Malwares")
plt.plot(x_values, byte_probability_distribution_mw*100, label = "Malwares", marker="braille", color="red")
plt.yfrequency(10)
plt.xfrequency(10)
plt.grid(horizontal=True)
plt.show()

if attack == "increase_false_negatives":
    X_to_poison = X_gw
    X_to_analyze = X_mw
    if not os.path.exists(poisoned_goodware_folder):
        os.makedirs(poisoned_goodware_folder)
    poisoned_folder = poisoned_goodware_folder
    file_path_to_poison = file_path_gw
    file_path_attack = file_path_mw
    length_file_to_poison = length_gw
    y_value = 0
    byte_histogram_to_analyze = byte_probability_distribution_mw
elif attack == "increase_false_positives":
    X_to_poison = X_mw
    X_to_analyze = X_gw
    if not os.path.exists(poisoned_malware_folder):
        os.makedirs(poisoned_malware_folder)
    poisoned_folder = poisoned_malware_folder
    file_path_to_poison = file_path_mw
    file_path_attack = file_path_gw
    length_file_to_poison = length_mw
    y_value = 1
    byte_histogram_to_analyze = byte_probability_distribution_gw

header_feature_values = {}

print("Poisoning: modifying header...")   
for i in range(len(header_features)):
    feature_values = X_to_analyze[:, header_features[i]]
    unique_values, counts = np.unique(feature_values.astype(dtype='int64'), return_counts=True)
    prob_distribution = counts / np.sum(counts)
    extracted_values = np.random.choice(unique_values, size=len(file_path_to_poison), p=prob_distribution)
    header_feature_values[header_features[i]] = extracted_values  

for i in range(len(file_path_to_poison)):
    pe = pefile.PE(file_path_to_poison[i])

    pe.FILE_HEADER.TimeDateStamp = header_feature_values[626][i]
    pe.OPTIONAL_HEADER.MajorImageVersion = header_feature_values[677][i]
    pe.OPTIONAL_HEADER.MinorImageVersion = header_feature_values[678][i]
    pe.OPTIONAL_HEADER.MajorLinkerVersion = header_feature_values[679][i]
    pe.OPTIONAL_HEADER.MinorLinkerVersion = header_feature_values[680][i]
    pe.OPTIONAL_HEADER.MajorOperatingSystemVersion = header_feature_values[681][i]
    pe.OPTIONAL_HEADER.MinorOperatingSystemVersion = header_feature_values[682][i]
    pe.OPTIONAL_HEADER.MajorSubsystemVersion = header_feature_values[683][i]
    pe.OPTIONAL_HEADER.MinorSubsystemVersion = header_feature_values[684][i]
    pe.OPTIONAL_HEADER.SizeOfCode = header_feature_values[685][i]
    pe.OPTIONAL_HEADER.SizeOfHeaders = header_feature_values[686][i]
    pe.OPTIONAL_HEADER.SizeOfHeapCommit = header_feature_values[687][i]

    file_path = poisoned_folder + str(i) + ".file"
    pe.write(file_path)    
print("Header modification completed.")

X_poisoned = []
y_poisoned = []

print("Poisoning: modifying byte distribution...")
i = 0
for file_name in os.listdir(poisoned_folder):
    file_path = os.path.join(poisoned_folder, file_name)
    size = math.ceil((length_file_to_poison[i])*float(perc_bytes_poisoning))
    i+=1
    random_bytes = np.random.choice(np.arange(256), size=size, p=byte_histogram_to_analyze)
    with open(file_path, 'rb') as file:
        content = file.read()
        updated_content = content + bytes(random_bytes.tolist())
    try: 
        X_poisoned.append(extractor.feature_vector(updated_content).astype(dtype='float64'))
        y_poisoned.append(y_value)
        with open(file_path, "wb") as file:
            file.write(updated_content)
    except Exception as e:
        print("Error for file ", file_name, ": ", e)
X_poisoned = np.array(X_poisoned)
y_poisoned = np.array(y_poisoned)

byte_histogram_features_poisoned = X_poisoned[:, byte_histogram_features]
total_histogram_poisoned = np.sum(byte_histogram_features_poisoned, axis=0)
byte_probability_distribution_poisoned = total_histogram_poisoned / np.sum(total_histogram_poisoned)
print("Byte distribution modification completed.")

if attack == "increase_false_negatives":
    plt.clf()
    plt.title("Byte Distribution of Goodwares after poisoning")
    plt.plot(x_values, byte_probability_distribution_poisoned*100, label = "Goodwares after poisoning", marker="braille", color="green")
    plt.yfrequency(10)
    plt.xfrequency(10)
    plt.grid(horizontal=True)
    plt.show()
elif attack == "increase_false_positives":
    plt.clf()
    plt.title("Byte Distribution of Malwares after poisoning")
    plt.plot(x_values, byte_probability_distribution_poisoned*100, label = "Malwares  after poisoning", marker="braille", color="red")
    plt.yfrequency(10)
    plt.xfrequency(10)
    plt.grid(horizontal=True)
    plt.show()

X_train_poisoned = np.concatenate((X_train, X_poisoned), axis=0)
y_train_poisoned = np.concatenate((y_train, y_poisoned), axis=0)

if surrogate_model == "emberGBDT":
    print("Retraining emberGBDT (surrogate) model...")
    model = CClassifierEmber(X=X_train, y=y_train)
    print("emberGBDT (surrogate) model training complete.")
    if attack == "increase_false_negatives":
        _, results_mw_pre = model.predict(X_mw, True)
        results_mw_pre = results_mw_pre.tondarray()[:, 1]
    else:
        _, results_gw_pre = model.predict(X_gw, True)
        results_gw_pre = results_gw_pre.tondarray()[:, 1]

elif surrogate_model == "embernn":
    print("Retraining emberNN (surrogate) model...")
    model = EmberNN(X_train.shape[1])
    model.fit(X_train_poisoned, y_train_poisoned)
    print("emberNN (surrogate) model retraining complete.")
    if attack == "increase_false_negatives":
        results_mw_post = model.predict(X_mw)
    else:
        results_gw_post = model.predict(X_gw)

if attack == "increase_false_negatives":
    print(f'number of false negatives before the attack (SURROGATE MODEL): {len(results_mw_pre[results_mw_pre < 0.5])} / {len(results_mw_pre)}')
    print(f'number of false negatives after the attack (SURROGATE MODEL): {len(results_mw_post[results_mw_post < 0.5])} / {len(results_mw_pre)}')
    print(f'Average confidence level of Malwares before the attack (SURROGATE MODEL): {np.sum(results_mw_pre)/len(results_mw_pre)}')
    print(f'Average confidence level of Malwares after the attack (SURROGATE MODEL): {np.sum(results_mw_post)/len(results_mw_post)}\n')
else:
    print(f'number of false positives before the attack (SURROGATE MODEL): {len(results_gw_pre[results_gw_pre > 0.5])}')
    print(f'number of false positives after the attack (SURROGATE MODEL): {len(results_gw_post[results_gw_post > 0.5])}')
    print(f'Average confidence level of Goodwares before the attack (SURROGATE MODEL): {np.sum(results_gw_pre)/len(results_gw_pre) / {len(results_gw_pre)}}')
    print(f'Average confidence level of Goodwares after the attack (SURROGATE MODEL): {np.sum(results_gw_post)/len(results_gw_post) / {len(results_gw_pre)}}')

print("\nBeginning of Attack\n")
    
antivirus_url = "http://server:8000/analyze"
remote_classifier = CClassifierRemote(antivirus_url)

print("Poisoning Phase\n")

for file_name in os.listdir(poisoned_folder):
    file_path = os.path.join(poisoned_folder, file_name)
    pe = pefile.PE(file_path)
    with open(file_path, 'rb') as file:
        code = file.read()
    print(f'Computing prediction for {file_name}')
    code = CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
    y_pred, confidence = remote_classifier.predict(code, return_decision_function=True)
    y_pred = y_pred.item()
    score = confidence[0, 1].item()
    print(f'predicted label: {y_pred}')
    print(f'confidence: {score}')
    print('-' * 20)
time.sleep(250)

print("\nAttack Phase\n")

stats = {
    'detected': 0,
    'total': 0,
    'confidence': 0,
}
for file_path in file_path_attack:
    with open(file_path, 'rb') as file:
        content = file.read()
    print(f'Computing prediction for {os.path.basename(file_path)}')
    code = CArray(np.frombuffer(content, dtype=np.uint8)).atleast_2d()
    y_pred, confidence = remote_classifier.predict(code, return_decision_function=True)
    y_pred = y_pred.item()
    score = confidence[0, 1].item()
    stats['detected'] += int(y_pred != 0)
    stats['total'] += 1
    stats['confidence'] += score
    print(f'predicted label: {y_pred}')
    print(f'confidence: {score}')
    print('-' * 20)
    
print("\nAttack completed, report:")
if attack == "increase_false_negatives":
    print(f'number of false negatives after the attack: {stats["total"] - stats["detected"]} / {stats["total"]}')
else:
    print(f'number of false positives after the attack: {stats["detected"]} / {stats["total"]}')
print(f'Average Confidence: {stats["confidence"]/stats["total"]}')