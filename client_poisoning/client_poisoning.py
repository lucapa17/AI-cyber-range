import os
import random
import numpy as np
import ember
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


if __name__ == "__main__":
    while not check_server_availability("http://server:8000"):
        time.sleep(5)

    byte_histogram_features = np.array(features_utils.get_byte_histogram_features())
    header_features =  np.array(features_utils.get_header_features())
    data_directories_features =  np.array(features_utils.get_data_directories_features())

    attack = os.getenv("attack")
    perc_bytes_poisoning = os.getenv("perc_bytes_poisoning")
    num_malware_files = os.getenv("num_malware_files")
    num_goodware_files = os.getenv("num_goodware_files")

    if attack not in ["increase_false_negatives", "increase_false_positives"]:
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

    print("***** CREATING POISONED SAMPLES *****")
    
    if attack == "increase_false_negatives":
        X_to_poison = X_gw
        X_to_analyze = X_mw
        if not os.path.exists(poisoned_goodware_folder):
            os.makedirs(poisoned_goodware_folder)
        poisoned_folder = poisoned_goodware_folder
        file_path_to_poison = file_path_gw
        file_path_to_analyze = file_path_mw
        length_file_to_poison = length_gw
        y_value = 0
        
    elif attack == "increase_false_positives":
        X_to_poison = X_mw
        X_to_analyze = X_gw
        if not os.path.exists(poisoned_malware_folder):
            os.makedirs(poisoned_malware_folder)
        poisoned_folder = poisoned_malware_folder
        file_path_to_poison = file_path_mw
        file_path_to_analyze = file_path_gw
        length_file_to_poison = length_mw
        y_value = 1
    
    
    byte_histograms_to_analyze = X_to_analyze[:, byte_histogram_features]
    sum_of_elements = np.sum(byte_histograms_to_analyze, axis=1)
    byte_histograms_to_analyze  = byte_histograms_to_analyze / sum_of_elements.reshape(-1, 1)
    
    header_features_to_analyze = X_to_analyze[:, header_features].astype(dtype='int64')
    data_directories_to_analyze = X_to_analyze[:, data_directories_features].astype(dtype='int64')
    
    header_hashed_features_to_analyze = []
    for _, file in enumerate(file_path_to_analyze):   
        pe = pefile.PE(file)
        machine = pe.FILE_HEADER.Machine
        characteristics = pe.FILE_HEADER.Characteristics
        subsystem = pe.OPTIONAL_HEADER.Subsystem
        ddl_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
        magic = pe.OPTIONAL_HEADER.Magic
        header_hashed_features_to_analyze.append([machine, characteristics, subsystem, ddl_characteristics, magic])
        pe.close()
    header_hashed_features_to_analyze = np.array(header_hashed_features_to_analyze)

    X_poisoned = []
    y_poisoned = []

    for i, file in enumerate(file_path_to_poison):
        k = random.randint(0, len(X_to_analyze) - 1)
        try:
            pe = pefile.PE(file)
        
            pe.FILE_HEADER.TimeDateStamp = header_features_to_analyze[k, 0]
            pe.OPTIONAL_HEADER.MajorImageVersion = header_features_to_analyze[k, 1]
            pe.OPTIONAL_HEADER.MinorImageVersion = header_features_to_analyze[k, 2]
            pe.OPTIONAL_HEADER.MajorLinkerVersion = header_features_to_analyze[k, 3]
            pe.OPTIONAL_HEADER.MinorLinkerVersion = header_features_to_analyze[k, 4]
            pe.OPTIONAL_HEADER.MajorOperatingSystemVersion = header_features_to_analyze[k, 5]
            pe.OPTIONAL_HEADER.MinorOperatingSystemVersion = header_features_to_analyze[k, 6]
            pe.OPTIONAL_HEADER.MajorSubsystemVersion = header_features_to_analyze[k, 7]
            pe.OPTIONAL_HEADER.MinorSubsystemVersion = header_features_to_analyze[k, 8]
            pe.OPTIONAL_HEADER.SizeOfCode = header_features_to_analyze[k, 9]
            pe.OPTIONAL_HEADER.SizeOfHeaders = header_features_to_analyze[k, 10]
            pe.OPTIONAL_HEADER.SizeOfHeapCommit = header_features_to_analyze[k, 11]

            pe.FILE_HEADER.Machine = header_hashed_features_to_analyze[k, 0]
            pe.FILE_HEADER.Characteristics = header_hashed_features_to_analyze[k, 1]
            pe.OPTIONAL_HEADER.Subsystem = header_hashed_features_to_analyze[k, 2]
            pe.OPTIONAL_HEADER.DllCharacteristics = header_hashed_features_to_analyze[k, 3]
            # Magic cannot be changed because switching between 32 and 64 bit corrupts the file.
            #pe.OPTIONAL_HEADER.Magic = header_hashed_features_to_analyze[k, 4]

            data_directories = [
                'IMAGE_DIRECTORY_ENTRY_EXPORT',
                'IMAGE_DIRECTORY_ENTRY_IMPORT',
                'IMAGE_DIRECTORY_ENTRY_RESOURCE',
                'IMAGE_DIRECTORY_ENTRY_EXCEPTION',
                'IMAGE_DIRECTORY_ENTRY_SECURITY',
                'IMAGE_DIRECTORY_ENTRY_BASERELOC',
                'IMAGE_DIRECTORY_ENTRY_DEBUG',
                'IMAGE_DIRECTORY_ENTRY_COPYRIGHT',
                'IMAGE_DIRECTORY_ENTRY_GLOBALPTR',
                'IMAGE_DIRECTORY_ENTRY_TLS',
                'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG',
                'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT',
                'IMAGE_DIRECTORY_ENTRY_IAT',
                'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT',
                'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR'
            ]

            for n, directory in enumerate(data_directories):
                pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY[directory]].Size = data_directories_to_analyze[k, n*2]
                pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY[directory]].VirtualAddress = data_directories_to_analyze[k, n*2+1]
            
            file_path = poisoned_folder + str(i) + ".file"
            pe.write(file_path)
            pe.close()
            
            size = math.ceil((length_file_to_poison[i])*int(perc_bytes_poisoning))
            random_bytes = np.random.choice(np.arange(256), size=size, p=byte_histograms_to_analyze[k])
            
            with open(file_path, 'rb') as file:
                content = file.read()
                updated_content = content + bytes(random_bytes.tolist())
                X_poisoned.append(extractor.feature_vector(updated_content).astype(dtype='float64'))
                y_poisoned.append(y_value)
                with open(file_path, "wb") as file:
                    file.write(updated_content)
                    file.close()
            
        except Exception as e:
            print("Error for file ", file_path_to_poison[i], ": ", e)
            if os.path.exists(file_path):
                os.remove(file_path)
                
    X_poisoned = np.array(X_poisoned)
    y_poisoned = np.array(y_poisoned)

    byte_histogram_features_poisoned = X_poisoned[:, byte_histogram_features]
    total_histogram_poisoned = np.sum(byte_histogram_features_poisoned, axis=0)
    byte_probability_distribution_poisoned = total_histogram_poisoned / np.sum(total_histogram_poisoned)
    
    print("***** POISONED SAMPLES CREATED *****")

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

    print("***** SENDING POISONED FILES TO THE SERVER *****")
        
    antivirus_url = "http://server:8000/analyze"
    remote_classifier = CClassifierRemote(antivirus_url)

    for file_name in os.listdir(poisoned_folder):
        file_path = os.path.join(poisoned_folder, file_name)
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
    
    # Wait for the server to update the model   
    print("***** WAITING FOR THE SERVER TO UPDATE THE MODEL *****")
    time.sleep(500)

    print("***** SENDING FILES TO THE SERVER AFTER POISONING *****")

    stats = {
        'detected': 0,
        'total': 0,
        'confidence': 0,
    }
    for file_path in       file_path_to_analyze:
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