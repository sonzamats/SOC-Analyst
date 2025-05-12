#!/usr/bin/env python3
"""
Network Traffic Anomaly Detection

This script analyzes network traffic logs from Elasticsearch to detect anomalies 
using isolation forest and autoencoder methods.

Author: SOC Analyst SIEM Project
Date: 2023-07-15
Version: 1.0
"""

import pandas as pd
import numpy as np
import json
import os
import logging
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from tensorflow.keras.models import Sequential, Model, load_model
from tensorflow.keras.layers import Dense, Input
from tensorflow.keras.callbacks import EarlyStopping

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_anomaly.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NetworkAnomalyDetection")

class NetworkAnomalyDetector:
    """Class for detecting anomalies in network traffic"""
    
    def __init__(self, es_host="elasticsearch", es_port=9200, 
                 es_user="elastic", es_password="secureSIEMpassword123"):
        """Initialize the anomaly detector with Elasticsearch connection"""
        self.es = Elasticsearch(
            [f"http://{es_host}:{es_port}"],
            http_auth=(es_user, es_password)
        )
        self.model_path = "models"
        
        # Create models directory if it doesn't exist
        if not os.path.exists(self.model_path):
            os.makedirs(self.model_path)
            
        # Features to use for anomaly detection
        self.features = [
            'bytes_in', 'bytes_out', 'packets_in', 'packets_out', 
            'duration', 'unique_ips', 'unique_ports', 'conn_per_second'
        ]
        
        self.scaler = None
        self.isolation_forest = None
        self.autoencoder = None
        
    def fetch_data(self, index="packetbeat-*", time_range=24):
        """Fetch network data from Elasticsearch"""
        logger.info(f"Fetching data from {index} for the last {time_range} hours")
        
        # Define the time range
        now = datetime.utcnow()
        time_from = (now - timedelta(hours=time_range)).isoformat()
        
        # Define the query to get network flow data
        query = {
            "size": 10000,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_from}}},
                        {"exists": {"field": "source.ip"}},
                        {"exists": {"field": "destination.ip"}}
                    ]
                }
            },
            "_source": [
                "@timestamp", "source.ip", "destination.ip", "source.port", 
                "destination.port", "network.bytes", "network.packets", 
                "event.duration", "network.protocol"
            ]
        }
        
        try:
            # Execute the query
            response = self.es.search(index=index, body=query)
            
            # Process the results
            results = []
            for hit in response['hits']['hits']:
                source = hit['_source']
                
                # Extract required fields with safe defaults
                timestamp = source.get('@timestamp', '')
                src_ip = source.get('source', {}).get('ip', '')
                dst_ip = source.get('destination', {}).get('ip', '')
                src_port = source.get('source', {}).get('port', 0)
                dst_port = source.get('destination', {}).get('port', 0)
                bytes_total = source.get('network', {}).get('bytes', 0)
                packets = source.get('network', {}).get('packets', 0)
                duration = source.get('event', {}).get('duration', 0)
                protocol = source.get('network', {}).get('protocol', '')
                
                # Add to results
                results.append({
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'bytes_total': bytes_total,
                    'packets': packets,
                    'duration': duration,
                    'protocol': protocol
                })
            
            logger.info(f"Fetched {len(results)} records from Elasticsearch")
            return results
            
        except Exception as e:
            logger.error(f"Error fetching data from Elasticsearch: {str(e)}")
            return []
    
    def preprocess_data(self, records):
        """Preprocess the data for anomaly detection"""
        if not records:
            logger.warning("No records to preprocess")
            return None
            
        # Convert records to DataFrame
        df = pd.DataFrame(records)
        
        # Parse timestamps
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Feature engineering
        # 1. Group by source IP and compute aggregated features
        ip_aggs = df.groupby('src_ip').agg({
            'bytes_total': 'sum',
            'packets': 'sum',
            'duration': 'mean',
            'dst_ip': 'nunique',
            'dst_port': 'nunique',
            'timestamp': 'count'
        }).reset_index()
        
        # Rename columns for clarity
        ip_aggs.columns = ['ip', 'bytes_out', 'packets_out', 'duration', 
                          'unique_ips', 'unique_ports', 'connection_count']
        
        # 2. Group by destination IP for inbound traffic
        dest_aggs = df.groupby('dst_ip').agg({
            'bytes_total': 'sum',
            'packets': 'sum',
        }).reset_index()
        
        dest_aggs.columns = ['ip', 'bytes_in', 'packets_in']
        
        # Merge outbound and inbound statistics
        merged_df = pd.merge(ip_aggs, dest_aggs, on='ip', how='outer').fillna(0)
        
        # Calculate connections per second
        merged_df['conn_per_second'] = merged_df['connection_count'] / (time_range * 3600)
        
        # Select and return relevant features
        features_df = merged_df[['ip'] + self.features]
        
        logger.info(f"Preprocessed data into {len(features_df)} IP-based records")
        return features_df
        
    def train_isolation_forest(self, df):
        """Train an Isolation Forest model for anomaly detection"""
        if df is None or df.empty:
            logger.warning("No data for training Isolation Forest")
            return None
            
        logger.info("Training Isolation Forest model")
        
        # Scale the features
        X = df[self.features]
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Train the model
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=0.05,  # Assuming 5% of the data are anomalies
            random_state=42
        )
        self.isolation_forest.fit(X_scaled)
        
        # Save the model
        import joblib
        joblib.dump(self.isolation_forest, f"{self.model_path}/isolation_forest.joblib")
        joblib.dump(self.scaler, f"{self.model_path}/scaler.joblib")
        
        return self.isolation_forest
    
    def train_autoencoder(self, df):
        """Train an autoencoder model for anomaly detection"""
        if df is None or df.empty:
            logger.warning("No data for training Autoencoder")
            return None
            
        logger.info("Training Autoencoder model")
        
        # Scale the features
        X = df[self.features]
        mmscaler = MinMaxScaler()
        X_scaled = mmscaler.fit_transform(X)
        
        # Define the autoencoder architecture
        input_dim = X_scaled.shape[1]
        encoding_dim = 3  # Compress to 3 dimensions
        
        # Encoder
        input_layer = Input(shape=(input_dim,))
        encoder = Dense(10, activation='relu')(input_layer)
        encoder = Dense(encoding_dim, activation='relu')(encoder)
        
        # Decoder
        decoder = Dense(10, activation='relu')(encoder)
        decoder = Dense(input_dim, activation='sigmoid')(decoder)
        
        # Autoencoder model
        self.autoencoder = Model(inputs=input_layer, outputs=decoder)
        
        # Compile the model
        self.autoencoder.compile(optimizer='adam', loss='mse')
        
        # Train the model with early stopping
        early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
        
        history = self.autoencoder.fit(
            X_scaled, X_scaled,
            epochs=50,
            batch_size=32,
            shuffle=True,
            validation_split=0.2,
            callbacks=[early_stopping],
            verbose=1
        )
        
        # Save the model and scaler
        self.autoencoder.save(f"{self.model_path}/autoencoder.h5")
        joblib.dump(mmscaler, f"{self.model_path}/mmscaler.joblib")
        
        # Plot training history
        plt.figure(figsize=(10, 6))
        plt.plot(history.history['loss'], label='Training Loss')
        plt.plot(history.history['val_loss'], label='Validation Loss')
        plt.title('Autoencoder Training History')
        plt.ylabel('Loss')
        plt.xlabel('Epoch')
        plt.legend()
        plt.savefig(f"{self.model_path}/autoencoder_training.png")
        
        return self.autoencoder
    
    def detect_anomalies(self, df, method='both'):
        """Detect anomalies in the data using the specified method(s)"""
        if df is None or df.empty:
            logger.warning("No data for anomaly detection")
            return []
            
        logger.info(f"Detecting anomalies using method: {method}")
        
        results = []
        
        # Extract features
        X = df[self.features]
        ips = df['ip'].values
        
        if method in ['isolation_forest', 'both']:
            # Load or train Isolation Forest model
            if self.isolation_forest is None:
                try:
                    import joblib
                    self.scaler = joblib.load(f"{self.model_path}/scaler.joblib")
                    self.isolation_forest = joblib.load(f"{self.model_path}/isolation_forest.joblib")
                except:
                    self.train_isolation_forest(df)
            
            # Scale data and predict
            X_scaled = self.scaler.transform(X)
            if_scores = self.isolation_forest.decision_function(X_scaled)
            if_predictions = self.isolation_forest.predict(X_scaled)
            
            # Collect anomalies (predictions of -1 are anomalies)
            for i, pred in enumerate(if_predictions):
                if pred == -1:  # Anomaly
                    anomaly_score = abs(if_scores[i])
                    results.append({
                        'ip': ips[i],
                        'method': 'Isolation Forest',
                        'anomaly_score': float(anomaly_score),
                        'features': {feat: float(X.iloc[i][feat]) for feat in self.features}
                    })
        
        if method in ['autoencoder', 'both']:
            # Load or train Autoencoder model
            if self.autoencoder is None:
                try:
                    import joblib
                    from tensorflow.keras.models import load_model
                    self.autoencoder = load_model(f"{self.model_path}/autoencoder.h5")
                    mmscaler = joblib.load(f"{self.model_path}/mmscaler.joblib")
                except:
                    self.train_autoencoder(df)
                    import joblib
                    mmscaler = joblib.load(f"{self.model_path}/mmscaler.joblib")
            
            # Scale data
            X_scaled = mmscaler.transform(X)
            
            # Get reconstruction error
            X_pred = self.autoencoder.predict(X_scaled)
            mse = np.mean(np.power(X_scaled - X_pred, 2), axis=1)
            
            # Define threshold (mean + 2*std is a common choice)
            threshold = np.mean(mse) + 2 * np.std(mse)
            
            # Collect anomalies
            for i, err in enumerate(mse):
                if err > threshold:  # Anomaly
                    results.append({
                        'ip': ips[i],
                        'method': 'Autoencoder',
                        'anomaly_score': float(err),
                        'features': {feat: float(X.iloc[i][feat]) for feat in self.features}
                    })
        
        # Log the results
        logger.info(f"Detected {len(results)} anomalies")
        
        return results
    
    def send_to_elasticsearch(self, anomalies, index="siem-network-anomalies"):
        """Send detected anomalies to Elasticsearch"""
        if not anomalies:
            logger.info("No anomalies to send to Elasticsearch")
            return
            
        logger.info(f"Sending {len(anomalies)} anomalies to Elasticsearch")
        
        # Prepare for bulk indexing
        bulk_data = []
        timestamp = datetime.now().isoformat()
        
        for anomaly in anomalies:
            # Add metadata for indexing
            index_op = {
                "index": {
                    "_index": index
                }
            }
            
            # Add timestamp to anomaly data
            anomaly['@timestamp'] = timestamp
            
            # Add to bulk data
            bulk_data.append(index_op)
            bulk_data.append(anomaly)
        
        try:
            # Send to Elasticsearch
            if bulk_data:
                self.es.bulk(body=bulk_data)
                logger.info(f"Successfully sent anomalies to Elasticsearch index: {index}")
        except Exception as e:
            logger.error(f"Error sending anomalies to Elasticsearch: {str(e)}")

def main():
    """Main function to run the network anomaly detection"""
    # Initialize detector
    detector = NetworkAnomalyDetector()
    
    # Fetch data
    data = detector.fetch_data()
    
    # Preprocess data
    processed_data = detector.preprocess_data(data)
    
    # Detect anomalies
    anomalies = detector.detect_anomalies(processed_data)
    
    # Send to Elasticsearch
    detector.send_to_elasticsearch(anomalies)
    
    logger.info("Network anomaly detection completed")

if __name__ == "__main__":
    # Define time range in global scope for use in preprocessing
    time_range = 24  # hours
    main()