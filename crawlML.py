import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from feature_extractor import extract_all_features # Import feature extraction

# Load data
data = pd.read_csv('/content/new_data_urls.csv')

# ✅ Apply feature extraction
features = data['url'].apply(extract_all_features).apply(pd.Series)
data = pd.concat([data, features], axis=1)
data = data.drop('url', axis=1)

# ✅ Convert all features to numeric types
data = data.apply(pd.to_numeric, errors='coerce')

# ✅ Drop rows with NaNs
data = data.dropna()

# ✅ Split data into features and labels
X = data.drop('status', axis=1)
y = data['status']

# ✅ Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ✅ Check training set size
print("Training set shape:", X_train.shape)
print("Testing set shape:", X_test.shape)

# ✅ Train LightGBM model with full feature set
model = lgb.LGBMClassifier(
    n_estimators=200,
    max_depth=10,
    learning_rate=0.05
)

print("Training the LightGBM model...")
model.fit(X_train, y_train)

# ✅ Evaluate the model
y_pred = model.predict(X_test)

print("\n--- LightGBM Model Evaluation ---")
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# ✅ Save the trained model
model.booster_.save_model('phishing_model.txt')
print("\n✅ Model saved as phishing_model.txt")