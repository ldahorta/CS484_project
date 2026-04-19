import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, recall_score, accuracy_score
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import StandardScaler # <--- NEW IMPORT

print("Loading dataset from the internet...")

columns = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
            "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
            "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
            "num_shells","num_access_files","num_outbound_cmds","is_host_login",
            "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
            "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
            "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
            "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
            "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"]

url_dataset = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B.txt"
df = pd.read_csv(url_dataset, names=columns)

print("Preprocessing data...")
df = df.drop('difficulty', axis=1)
df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)
df = pd.get_dummies(df, columns=["protocol_type", "service", "flag"])



X = df.drop('label', axis=1) 
y = df['label']              

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


print("Scaling features...")
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

print(f"Ready! Training on {len(X_train)} samples, Testing on {len(X_test)} samples.\n")

models = {
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "SVM": SVC(),
    "LDA": LinearDiscriminantAnalysis(),
    "Naive Bayes": GaussianNB()
}

for name, model in models.items():
    print(f"Training {name}...")
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    
    matrix = confusion_matrix(y_test, predictions)
    false_negatives = matrix[1][0] 
    attack_recall = recall_score(y_test, predictions) * 100 
    overall_accuracy = accuracy_score(y_test, predictions) * 100
    
    print(f"--- {name} ---")
    print(f"Accuracy: {overall_accuracy:.2f}%")
    print(f"Attacks Detected (Recall): {attack_recall:.2f}%")
    print(f"DANGER (False Negatives / Missed Attacks): {false_negatives}")
    print("-" * 40)