import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import json

# Load the full parsed dataset
with open('all_parsed_data.json', 'r') as f:
    data = json.load(f)

df = pd.DataFrame(data)

# Handle potential missing values by filling with 0
df.fillna(0, inplace=True)

# Use all four features for training
feature_columns = ['feat1', 'feat2', 'feat3', 'feat4']
X = df[feature_columns]
y = df['target']

# Train a new, more powerful model
# Increased n_estimators for the larger dataset
new_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
new_model.fit(X, y)

# Save the new model
joblib.dump(new_model, 'new_model.joblib')

print(f"Successfully trained a new model on {len(df)} records.")
print("Model saved as new_model.joblib")
