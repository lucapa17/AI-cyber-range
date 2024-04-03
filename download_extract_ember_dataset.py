import requests
import tarfile
import os
import ember

try:
    if not os.path.exists("lock"):
        with open("lock", "w") as f:
            pass

        url = "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
        tar_file_path = "ember_dataset_2018_2.tar.bz2"

        print("Downloading the Ember dataset...")
        response = requests.get(url)
        with open(tar_file_path, "wb") as f:
            f.write(response.content)
        print("Ember dataset downloaded successfully.")

        # Extract the tar.bz2 file
        print("Extracting the Ember dataset...")
        with tarfile.open(tar_file_path, "r:bz2") as tar:
            tar.extractall(path="data/", filter="data")
        print("Ember dataset extracted successfully.")

        # Remove the downloaded tar.bz2 file
        print("Deleting the zip file...")
        os.remove(tar_file_path)
        print("Zip file deleted successfully.")

        # Create vectorized features
        print("Creating vectorized features...")
        ember.create_vectorized_features("data/ember2018/", feature_version=2)
        print("Vectorized features created successfully.")

        os.remove("lock")
        
except (KeyboardInterrupt, Exception):
    os.remove("lock")