import torch.nn as nn

class NetworkLSTMEmbeddings(nn.Module):
    def __init__(self, inp_size, hidden_size, num_layers, num_classes, embedding_dim=16):
        super().__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        
        # Sequence extraction processing
        self.lstm = nn.LSTM(
            input_size=inp_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.15 if num_layers > 1 else 0.0
        )
        
        # Compress final hidden state to your fixed embedding output space
        self.embedding_bottleneck = nn.Sequential(
            nn.Linear(hidden_size, embedding_dim),
            nn.ReLU()
        )
        self.classifier = nn.Linear(embedding_dim, num_classes)

    def forward(self, x):
        # Map temporal steps through LSTM
        out, _ = self.lstm(x)
        # Use only the last structural time-step's output context
        last_timestep = out[:, -1, :]
        embedding = self.embedding_bottleneck(last_timestep)
        return self.classifier(embedding)

    def extract_embeddings(self, x):
        out, _ = self.lstm(x)
        return self.embedding_bottleneck(out[:, -1, :])
    
def build_lstm_model(input_size: int, hidden_dim: int, num_layers: int, num_classes: int):
    return NetworkLSTMEmbeddings(input_size, hidden_dim, num_layers, num_classes, embedding_dim=16)