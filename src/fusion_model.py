import torch
import torch.nn as nn



class Fusion_Model(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers, statistical_features_size, fc_layers_sizes,
                 n_classes, batch_norm=False, dropout=0):
        super(Fusion_Model, self).__init__()

        # Save model parameters
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.statistical_features_size = statistical_features_size
        self.fc_layers_sizes = fc_layers_sizes
        self.n_classes = n_classes
        self.batch_norm = batch_norm
        self.dropout = dropout

        # Device and criterion
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.criterion = nn.CrossEntropyLoss()

        # LSTM network
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)

        # Define the fully connected layers
        fc_input_size = hidden_size + statistical_features_size

        fc_layers = []
        in_size = fc_input_size
        for out_size in fc_layers_sizes:
            fc_layers.append(nn.Linear(in_size, out_size))
            fc_layers.append(nn.ReLU())
            if batch_norm:
                fc_layers.append(nn.BatchNorm1d(out_size))
            if dropout > 0:
                fc_layers.append(nn.Dropout(dropout))
            in_size = out_size
        # Final layer to n_classes
        fc_layers.append(nn.Linear(in_size, n_classes))

        self.fc = nn.Sequential(*fc_layers)



    def forward(self, x_tabular, x_statistical_features):
        # x_tabular: (batch_size, seq_length, input_size)
        # x_statistical_features: (batch_size, statistical_features_size)

        # Set initial hidden and cell states
        h0 = torch.zeros(self.num_layers, x_tabular.size(0), self.hidden_size).to(self.device)
        c0 = torch.zeros(self.num_layers, x_tabular.size(0), self.hidden_size).to(self.device)

        # Forward propagate LSTM
        out, _ = self.lstm(x_tabular, (h0, c0))  # out: tensor of shape (batch_size, seq_length, hidden_size)

        # Get the last time step output
        out = out[:, -1, :]  # (batch_size, hidden_size)

        # Concatenate extra features
        out = torch.cat((out, x_statistical_features), dim=1)  # (batch_size, hidden_size + statistical_features_size)

        # Pass through fully connected layers
        out = self.fc(out)

        return out



    def predict(self, x_tabular, x_statistical_features, batch_size=32):
        # Convert numpy arrays to torch tensors
        x_tabular = torch.from_numpy(x_tabular).float().to(self.device)
        x_statistical_features = torch.from_numpy(x_statistical_features).float().to(self.device)
        
        # Reshape x_tabular from (batch_size, N) to (batch_size, M, input_size)
        N = x_tabular.size(1)
        if N % self.input_size != 0:
            raise ValueError(f"Tabular data size must be divisible by LSTM input_size ({self.input_size})")
        M = N // self.input_size
        x_tabular = x_tabular.view(x_tabular.size(0), M, self.input_size)

        # Switch model to evaluation mode
        self.eval()

        # Disable gradient calculation
        with torch.no_grad():
            # Store predictions
            predictions = []

            # Process data in batches
            num_samples = x_tabular.size(0)
            for start_idx in range(0, num_samples, batch_size):
                end_idx = min(start_idx + batch_size, num_samples)
                batch_x_tabular = x_tabular[start_idx:end_idx]
                batch_x_statistical_features = x_statistical_features[start_idx:end_idx]

                # Forward pass
                outputs = self.forward(batch_x_tabular, batch_x_statistical_features)
                # Get predicted classes
                _, predicted = torch.max(outputs.data, 1)
                predictions.extend(predicted.cpu().numpy())

        return predictions


