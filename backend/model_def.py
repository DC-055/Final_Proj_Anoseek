import torch.nn as nn

class LSTM(nn.Module):
    def __init__(self, inp_size, hidden_dim):
        super().__init__()
        self.lstm = nn.LSTM(input_size=inp_size, hidden_size=hidden_dim, batch_first=True)
        self.classifier = nn.Linear(hidden_dim, 5)

    def forward(self, x, return_hidden=False):
        _, (h_n, _) = self.lstm(x)
        if return_hidden:
            return h_n[-1]  # for the SVM
        return self.classifier(h_n[-1])  # for CrossEntropy training

def build_lstm_model(input_size: int, hidden_dim: int):
    return LSTM(input_size, hidden_dim)