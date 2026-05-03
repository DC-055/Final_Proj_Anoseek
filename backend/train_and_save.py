import numpy
import torch
from sklearn.svm import SVC
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from imblearn.over_sampling import SMOTE
import joblib


def _build_sequences(X_scaled_tensor: torch.Tensor, seq_size: int) -> torch.Tensor:
    """
    X_scaled_tensor: [N, num_features]
    returns X_seq: [N - seq_size + 1, seq_size, num_features]
    """
    N, D = X_scaled_tensor.shape
    if seq_size == 1:
        return X_scaled_tensor.unsqueeze(1)  # [N, 1, D]

    windows = []
    for i in range(N - seq_size + 1):
        windows.append(X_scaled_tensor[i:i+seq_size, :])
    return torch.stack(windows, dim=0)

def train_and_save(dataset_csv_path):
    """ Phase 0 """
    ### 0.1: GPU Usage ###
    device = torch.device("cpu")
    # device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    # print(f"Using {device}")

    ### 0.2: Data Size ###
    data_size = 50000

    """ Phase 1 Data Import and Preprocessing """
    ### 1.1: Data Import, Severity Map ###

    df = pd.read_csv("C:/Users/Daniel/PycharmProjects/Final_Proj_Anoseek/datasets/NF-UNSW-NB15-v2_50000.csv")
    # now we'll remove the unwanted features which aren't numerical
    cols_to_drop = [
        "IPV4_SRC_ADDR", "IPV4_DST_ADDR",
        "L4_SRC_PORT", "L4_DST_PORT",
        "IN_PKTS", "OUT_PKTS",
        "TCP_FLAGS", "CLIENT_TCP_FLAGS",
        "MAX_TTL", "ICMP_TYPE",
        "RETRANSMITTED_IN_PKTS", "RETRANSMITTED_OUT_PKTS",
        "Label",
    ]
    df = df.drop(columns=cols_to_drop, errors='ignore')

    # convertion of Attack severity to numbers
    severity_dict = {
        "Benign": 0, 'Reconnaissance': 1, 'Fuzzers': 2, 'Generic': 2,
        'DoS': 3, 'Default_Attack': 3, 'Exploits': 4, 'Shellcode': 4,
        'Worms': 4, 'Backdoor': 4
    }
    feature_cols = df.columns

    df['Attack'] = df['Attack'].map(severity_dict)

    X = df.iloc[:, :-1].values  # all rows of all features without the label and attack type
    y = df.iloc[:, -1:].values  # all rows of attack type (severity)

    # convertion to Tensors
    X = torch.from_numpy(X).float()
    print(X.shape)
    y = torch.tensor(y, dtype=torch.long)

    # data split
    X_train, X_test, y_train_tensor, y_test = (
        train_test_split(X, y, test_size=0.9, random_state=42)
    )
    #print("y_test positive\n", y_test[y_test[:, 0] == 1])
    # dropping anomalies from training
    # mask = (y_train[:, 0] == 0)
    # X_train = X_train[mask]
    # y_train = y_train[mask]

    ### 1.2: Feature Scaling ###
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_train_scaled_tensor = torch.from_numpy(X_train_scaled).float()
    smote = SMOTE(random_state=42)
    X_resampled_np, y_resampled_np = smote.fit_resample(X_train_scaled, y_train_tensor)
    # Convert resampled data back to Tensors for windowing
    X_resampled_tensor = torch.from_numpy(X_resampled_np).float()
    y_resampled_tensor = torch.from_numpy(y_resampled_np).long()

    ### 1.3: Time Series Windowing ###

    X_seq_list = []
    y_seq_list = []
    seq_size = 1
    # print(f"Poor people's debugger: \n {X_train_scaled_tensor.shape[0]}")
    num_sequences = X_resampled_tensor.shape[0]  # num of sequences
    input_size = X_train_scaled_tensor.shape[1]  # num of features
    print(input_size)
    for i in range(num_sequences - seq_size + 1):
        # X
        window_X = X_resampled_tensor[i: i + seq_size, :]
        window_y = y_resampled_tensor[i + seq_size - 1]
        # y
        X_seq_list.append(window_X)
        y_seq_list.append(window_y)

    # Stack all windows into one tensor: [num_sequences, seq_len, input_size]
    X_seq = torch.stack(X_seq_list, dim=0)
    y_seq = torch.stack(y_seq_list, dim=0)
    #print("X_seq shape:", X_seq.shape)  # [num_sequences, seq_size, num_features]
    #print("y_seq shape:", y_seq.shape)  # [num_sequences, seq_size, num_features]

    """ Phase 2 Model Architecture Design """

    ### 2.1: Class Model ###
    class LSTM(nn.Module):
        def __init__(self, inp_size, hidden_dim):
            super().__init__()
            self.device = device
            self.lstm = nn.LSTM(input_size=inp_size, hidden_size=hidden_dim, batch_first=True)
            self.classifier = nn.Linear(hidden_dim, 5)

        def forward(self, x, return_hidden=False):
            _, (h_n, _) = self.lstm(x)
            if return_hidden:
                return h_n[-1]  # for the SVM
            return self.classifier(h_n[-1])  # for CrossEntropy training

    """ Phase 3: Dataset, DataLoader, and training loop """

    ### 3.1: Variables ###

    lstm_model = LSTM(input_size, 64)
    svc_model = SVC(kernel='rbf', C=0.5, decision_function_shape='ovr')

    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(lstm_model.parameters(), lr=1e-03, weight_decay=1e-05)

    batch_size = 64
    num_epochs = 15

    ### 3.2: Create DataLoader for batched training ###

    dataset = TensorDataset(X_seq, y_seq)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    ### 3.2 Training loop ###

    for epoch in range(num_epochs):
        lstm_model.train()
        epoch_loss = 0.0
        for (batch, targets) in loader:  # each batch is a tuple from TensorDataset
            # batch: [batch_size, seq_len, input_size]
            batch = batch.to(device)
            # forward
            vector = lstm_model(batch)
            # loss
            # targets shape is [64, 1, 1], we want [64]
            loss = criterion(vector, targets.view(-1).long())
            # backward
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

    lstm_model.eval()
    all_features = []
    all_targets = []
    with torch.no_grad():
        for (batch, targets) in loader:  # each batch is a tuple from TensorDataset
            # batch: [batch_size, seq_len, input_size]
            batch = batch.to(device)
            # We need the hidden state h_n, not the classifier output
            _, (h_n, _) = lstm_model.lstm(batch)
            # h_n[-1] is [batch, hidden_dim]
            all_features.append(h_n[-1].cpu().numpy())
            all_targets.append(targets.view(-1).numpy())

    # Combine all batches into giant NumPy arrays
    X_svm_train = np.vstack(all_features)
    y_svm_train = np.concatenate(all_targets)

    # Now the SVM can learn the boundaries
    svc_model.fit(X_svm_train, y_svm_train)

    # saving models
    torch.save(lstm_model.state_dict(), "artifacts/lstm.pt")

    cols_to_drop.append("Attack")
    feature_cols = feature_cols.drop("Attack")
    print(feature_cols.shape)
    joblib.dump(
        {
            "svc_model": svc_model,
            "scaler": scaler,
            "cols_to_drop": cols_to_drop,
            "seq_size": seq_size,
            "input_size": input_size,
            "hidden_dim": 64,
            "class_names": ["Benign", "Reconnaissance", "Fuzzers/Generic", "DoS/Default", "Exploits/Other"],
            "feature_cols": feature_cols,
    },"artifacts/bundle.joblib")

train_and_save("C:/Users/Daniel/PycharmProjects/Final_Proj_Anoseek/datasets/NF-UNSW-NB15-v2_50000.csv")