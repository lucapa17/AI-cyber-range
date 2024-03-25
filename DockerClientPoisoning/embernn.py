import os
import joblib
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.preprocessing import StandardScaler
import shap

class EmberNN(nn.Module):
    def __init__(self, n_features):
        super(EmberNN, self).__init__()
        self.n_features = n_features
        self.normal = StandardScaler()
        self.model = self.build_model()
        self.exp = None

    def forward(self, x):
        x_normalized = self.normal.transform(x)
        return self.model(x_normalized)

    def fit(self, X, y):
        self.normal.fit(X)
        X_normalized = torch.tensor(self.normal.transform(X), dtype=torch.float32)
        y_tensor = torch.tensor(y, dtype=torch.float32)
        dataset = torch.utils.data.TensorDataset(X_normalized, y_tensor)
        loader = torch.utils.data.DataLoader(dataset, batch_size=512, shuffle=True)
        criterion = nn.BCEWithLogitsLoss()
        optimizer = optim.SGD(self.parameters(), lr=0.1, momentum=0.9, weight_decay=0.000001)

        for epoch in range(10):
            for inputs, targets in loader:
                optimizer.zero_grad()
                outputs = self.model(inputs) 
                loss = criterion(outputs, targets.view(-1, 1))
                loss.backward()
                optimizer.step()

    def predict(self, X):
        with torch.no_grad():
            self.eval()
            X_normalized = torch.tensor(self.normal.transform(X), dtype=torch.float32)
            outputs = self.model(X_normalized)
            predictions = torch.sigmoid(outputs)
        return predictions.numpy()

    def build_model(self):
        model = nn.Sequential(
            nn.Linear(self.n_features, 4000),
            nn.ReLU(),
            nn.BatchNorm1d(4000),
            nn.Dropout(0.5),
            nn.Linear(4000, 2000),
            nn.ReLU(),
            nn.BatchNorm1d(2000),
            nn.Dropout(0.5),
            nn.Linear(2000, 100),
            nn.ReLU(),
            nn.BatchNorm1d(100),
            nn.Dropout(0.5),
            nn.Linear(100, 1)
        )
        return model
    
    def explain(self, X_exp, n_samples=100):
        if self.exp is None:
            X_exp_normalized = torch.tensor(self.normal.transform(X_exp), dtype=torch.float32)
            self.exp = shap.DeepExplainer(self.model, X_exp_normalized)
        else:
            X_exp_normalized = torch.tensor(self.normal.transform(X_exp), dtype=torch.float32)
        return self.exp.shap_values(X_exp_normalized)

    def save(self, save_path, file_name='ember_nn'):
        # Save the trained scaler so that it can be reused at test time
        joblib.dump(self.normal, os.path.join(save_path, file_name + '_scaler.pkl'))
        torch.save(self.state_dict(), os.path.join(save_path, file_name + '.pt'))

    def load(self, save_path, file_name):
        # Load the trained scaler
        self.normal = joblib.load(os.path.join(save_path, file_name + '_scaler.pkl'))

        self.load_state_dict(torch.load(os.path.join(save_path, file_name + '.pt')))
