import os
import sys
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# Add parent directory to path to allow importing feature_extraction if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.feature_extraction import extract_features

def train_phishing_model(csv_path="dataset.csv", output_model_path="models/phishing_model.pkl"):
    """
    Trains a Random Forest model on URL features and saves the model as a pickle file.
    Assumes CSV has columns: 'url' and 'label' (where label is 1 for Phishing, 0 for Safe).
    """
    if not os.path.exists(csv_path):
        print(f"Dataset file not found at: {csv_path}")
        print("Please provide a dataset CSV file with columns: 'url' and 'label'.")
        return

    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)

    if 'url' not in df.columns or 'label' not in df.columns:
        raise ValueError("CSV dataset must contain 'url' and 'label' columns.")

    print("Extracting features from URLs...")
    features_list = df['url'].apply(extract_features).tolist()
    X = pd.DataFrame(features_list)
    y = df['label']

    print("Splitting dataset into train and test sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model Training Complete! Accuracy: {accuracy * 100:.2f}%")
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    # Save model
    os.makedirs(os.path.dirname(output_model_path), exist_ok=True)
    joblib.dump(model, output_model_path)
    print(f"Saved trained model to {output_model_path}")

if __name__ == '__main__':
    csv_file = sys.argv[1] if len(sys.argv) > 1 else "dataset.csv"
    train_phishing_model(csv_file)
