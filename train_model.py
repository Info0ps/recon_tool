# recon_tool/train_model.py

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
import logging

def setup_environment(base_dir):
    """
    Ensure that the necessary directories and files exist.
    
    Args:
        base_dir (str): The base directory of the project.
    
    Returns:
        tuple: Paths to the data file and model file.
    """
    data_dir = os.path.join(base_dir, 'data')
    models_dir = os.path.join(base_dir, 'models')

    # Create directories if they don't exist
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)

    data_file = os.path.join(data_dir, 'scan_data.csv')
    model_file = os.path.join(models_dir, 'stealthy_mode_model.pkl')

    # If scan_data.csv doesn't exist, create a template
    if not os.path.isfile(data_file):
        logging.warning(f"Data file not found at: {data_file}. Creating a template.")
        df = pd.DataFrame(columns=['response_time', 'status_code', 'content_length', 'waf_detected', 'stealthy_mode'])
        df.to_csv(data_file, index=False)
        logging.info(f"Created template for scan_data.csv at: {data_file}")
        print(f"Created a template for scan_data.csv at: {data_file}. Please populate it with relevant data and rerun the script.")
        exit(0)  # Exit since there's no data to train on

    return data_file, model_file

def train_model(data_path: str, model_path: str):
    """
    Train a RandomForest model and save it to disk.
    
    Args:
        data_path (str): Path to the CSV data file.
        model_path (str): Path where the trained model will be saved.
    """
    try:
        data = pd.read_csv(data_path)
    except Exception as e:
        logging.error(f"Failed to read data file: {data_path}")
        logging.exception(e)
        raise e

    # Check if required columns exist
    required_columns = ['response_time', 'status_code', 'content_length', 'waf_detected', 'stealthy_mode']
    for col in required_columns:
        if col not in data.columns:
            logging.error(f"Missing required column '{col}' in data file.")
            raise ValueError(f"Missing required column '{col}' in data file.")

    X = data[['response_time', 'status_code', 'content_length', 'waf_detected']]
    y = data['stealthy_mode']

    # Check for missing values
    if X.isnull().any().any() or y.isnull().any():
        logging.warning("Missing values detected in the dataset. Dropping missing values.")
        X = X.dropna()
        y = y.dropna()

    if X.empty:
        logging.error("No data available after dropping missing values.")
        raise ValueError("No data available after dropping missing values.")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    # Evaluate the model
    accuracy = clf.score(X_test, y_test)
    logging.info(f"Model trained with accuracy: {accuracy:.2f}")
    print(f"Model trained with accuracy: {accuracy:.2f}")

    # Save the model
    joblib.dump(clf, model_path)
    logging.info(f"Model saved to {model_path}")
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Determine the base directory (recon_tool/)
    base_directory = os.path.dirname(os.path.abspath(__file__))

    # Setup environment and get paths
    data_file_path, model_file_path = setup_environment(base_directory)

    # Train the model
    train_model(data_file_path, model_file_path)
