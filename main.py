# Install via terminal first: pip install scikit-learn pandas
import pandas as pd
from sklearn.ensemble import RandomForestClassifier  # Or RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.datasets import load_iris  # Lightweight built-in dataset

# 1. Load a tiny sample dataset
data = load_iris()
X, y = data.data, data.target

# 2. Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_test_split=0.2, random_state=42)

# 3. Initialize the lightweight forest
# n_jobs=-1 utilizes ALL your CPU cores to speed up training
model = RandomForestClassifier(n_estimators=100, max_depth=5, n_jobs=-1, random_state=42)

# 4. Train the model
model.fit(X_train, y_train)

# 5. Check accuracy
print(f"Training Complete! Test Accuracy: {model.score(X_test, y_test):.4f}")